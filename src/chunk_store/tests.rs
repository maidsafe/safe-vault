// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    chunk::{Chunk, ChunkId},
    ChunkStore, Result as ChunkStoreResult, Subdir, UsedSpace,
};
use crate::{to_db_key::ToDbKey, Error, Result};
use rand::{distributions::Standard, rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};
use std::{path::Path, u64};
use tempdir::TempDir;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Data {
    id: Id,
    value: Vec<u8>,
}

impl Chunk for Data {
    type Id = Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Id(u64);

impl ToDbKey for Id {}
impl ChunkId for Id {}

impl Subdir for ChunkStore<Data> {
    fn subdir() -> &'static Path {
        Path::new("test")
    }
}

// TODO: use seedable rng
fn new_rng() -> ThreadRng {
    rand::thread_rng()
}

fn temp_dir() -> ChunkStoreResult<TempDir> {
    TempDir::new("test").map_err(|e| Error::TempDirCreationFailed(e.to_string()))
}

struct Chunks {
    data_and_sizes: Vec<(Vec<u8>, u64)>,
    total_size: u64,
}

impl Chunks {
    // Construct random amount of randomly-sized chunks, keeping track of the total size of all
    // chunks when serialised.
    fn gen<R: Rng>(rng: &mut R) -> Result<Self> {
        let mut chunks = Self {
            data_and_sizes: vec![],
            total_size: 0,
        };
        let chunk_count: u8 = rng.gen();
        for _ in 0..chunk_count {
            let size: u8 = rng.gen();
            let data = Data {
                id: Id(0),
                value: rng.sample_iter(&Standard).take(size as usize).collect(),
            };
            let serialised_size = bincode::serialized_size(&data).map_err(Error::Bincode)?;

            chunks.total_size += serialised_size;
            chunks.data_and_sizes.push((data.value, serialised_size));
        }
        Ok(chunks)
    }
}

#[tokio::test]
async fn successful_put() -> Result<()> {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng)?;

    let root = temp_dir()?;
    let used_space = UsedSpace::new(u64::MAX);
    let mut chunk_store = ChunkStore::<Data>::new(root.path(), used_space.clone()).await?;

    for (index, (data, size)) in chunks.data_and_sizes.iter().enumerate().rev() {
        let the_data = &Data {
            id: Id(index as u64),
            value: data.clone(),
        };
        let used_space_before = chunk_store.total_used_space().await;
        assert!(!chunk_store.has(&the_data.id));
        chunk_store.put(the_data).await?;
        let used_space_after = chunk_store.total_used_space().await;
        assert_eq!(used_space_after, used_space_before + size);
        assert!(chunk_store.has(&the_data.id));
        assert!(used_space_after <= chunks.total_size);
    }

    assert_eq!(chunk_store.total_used_space().await, chunks.total_size);

    let mut keys = chunk_store.keys();
    keys.sort();
    assert_eq!(
        (0..chunks.data_and_sizes.len())
            .map(|i| Id(i as u64))
            .collect::<Vec<_>>(),
        keys
    );

    Ok(())
}

#[tokio::test]
async fn failed_put_when_not_enough_space() -> Result<()> {
    let mut rng = new_rng();
    let root = temp_dir()?;
    let capacity = 32;
    let used_space = UsedSpace::new(capacity);
    let mut chunk_store = ChunkStore::new(root.path(), used_space.clone()).await?;

    let data = Data {
        id: Id(rng.gen()),
        value: rng
            .sample_iter(&Standard)
            .take((capacity + 1) as usize)
            .collect(),
    };

    match chunk_store.put(&data).await {
        Err(Error::NotEnoughSpace) => (),
        x => return Err(crate::Error::Logic(format!("Unexpected: {:?}", x))),
    }

    Ok(())
}

#[tokio::test]
async fn delete() -> Result<()> {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng)?;

    let root = temp_dir()?;
    let used_space = UsedSpace::new(u64::MAX);
    let mut chunk_store = ChunkStore::new(root.path(), used_space.clone()).await?;

    for (index, (data, size)) in chunks.data_and_sizes.iter().enumerate() {
        let the_data = &Data {
            id: Id(index as u64),
            value: data.clone(),
        };
        chunk_store.put(the_data).await?;
        assert_eq!(chunk_store.total_used_space().await, *size);
        assert!(chunk_store.has(&the_data.id));
        chunk_store.delete(&the_data.id).await?;
        assert!(!chunk_store.has(&the_data.id));
        assert_eq!(chunk_store.total_used_space().await, 0);
    }

    Ok(())
}

#[tokio::test]
async fn put_and_get_value_should_be_same() -> Result<()> {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng)?;

    let root = temp_dir()?;
    let used_space = UsedSpace::new(u64::MAX);
    let mut chunk_store = ChunkStore::new(root.path(), used_space.clone()).await?;

    for (index, (data, _)) in chunks.data_and_sizes.iter().enumerate() {
        chunk_store
            .put(&Data {
                id: Id(index as u64),
                value: data.clone(),
            })
            .await?
    }

    for (index, (data, _)) in chunks.data_and_sizes.iter().enumerate() {
        let retrieved_value = chunk_store.get(&Id(index as u64))?;
        assert_eq!(*data, retrieved_value.value);
    }

    Ok(())
}

#[tokio::test]
async fn overwrite_value() -> Result<()> {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng)?;

    let root = temp_dir()?;
    let used_space = UsedSpace::new(u64::MAX);
    let mut chunk_store = ChunkStore::new(root.path(), used_space.clone()).await?;

    for (data, size) in chunks.data_and_sizes {
        chunk_store
            .put(&Data {
                id: Id(0),
                value: data.clone(),
            })
            .await?;
        assert_eq!(chunk_store.total_used_space().await, size);
        let retrieved_data = chunk_store.get(&Id(0))?;
        assert_eq!(data, retrieved_data.value);
    }

    Ok(())
}

#[tokio::test]
async fn get_fails_when_key_does_not_exist() -> Result<()> {
    let root = temp_dir()?;
    let used_space = UsedSpace::new(u64::MAX);
    let chunk_store: ChunkStore<Data> = ChunkStore::new(root.path(), used_space.clone()).await?;

    let id = Id(new_rng().gen());
    match chunk_store.get(&id) {
        Err(Error::NoSuchChunk) => (),
        x => return Err(crate::Error::Logic(format!("Unexpected {:?}", x))),
    }

    Ok(())
}

#[tokio::test]
async fn keys() -> Result<()> {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng)?;

    let root = temp_dir()?;
    let used_space = UsedSpace::new(u64::MAX);
    let mut chunk_store = ChunkStore::new(root.path(), used_space.clone()).await?;

    for (index, (data, _)) in chunks.data_and_sizes.iter().enumerate() {
        let id = Id(index as u64);
        assert!(!chunk_store.keys().contains(&id));
        chunk_store
            .put(&Data {
                id,
                value: data.clone(),
            })
            .await?;

        let keys = chunk_store.keys();
        assert!(keys.contains(&id));
        assert_eq!(keys.len(), index + 1);
    }

    for (index, _) in chunks.data_and_sizes.iter().enumerate() {
        let id = Id(index as u64);

        assert!(chunk_store.keys().contains(&id));
        chunk_store.delete(&id).await?;

        let keys = chunk_store.keys();
        assert!(!keys.contains(&id));
        assert_eq!(keys.len(), chunks.data_and_sizes.len() - index - 1);
    }

    Ok(())
}
