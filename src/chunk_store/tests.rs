// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    chunk::{Chunk, ChunkId},
    error::Error,
    ChunkStore, Subdir,
};
use crate::{utils::Init, ToDbKey};
use rand::{distributions::Standard, rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};
use std::{cell::Cell, path::Path, rc::Rc, u64};
use tempdir::TempDir;
use unwrap::unwrap;

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

fn temp_dir() -> TempDir {
    unwrap!(TempDir::new("test"))
}

struct Chunks {
    data_and_sizes: Vec<(Vec<u8>, u64)>,
    total_size: u64,
}

impl Chunks {
    // Construct random amount of randomly-sized chunks, keeping track of the total size of all
    // chunks when serialised.
    fn gen<R: Rng>(rng: &mut R) -> Self {
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
            let serialised_size = unwrap!(bincode::serialized_size(&data));

            chunks.total_size += serialised_size;
            chunks.data_and_sizes.push((data.value, serialised_size));
        }
        chunks
    }
}

#[test]
fn successful_put() {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng);

    let root = temp_dir();
    let used_space = Rc::new(Cell::new(0));
    let mut chunk_store = unwrap!(ChunkStore::<Data>::new(
        root.path(),
        u64::MAX,
        Rc::clone(&used_space),
        Init::New
    ));

    let mut put = |data: &Data, size| {
        let used_space_before = used_space.get();
        assert!(!chunk_store.has(&data.id));
        unwrap!(chunk_store.put(data));
        let used_space_after = used_space.get();
        assert_eq!(used_space_after, used_space_before + size);
        assert!(chunk_store.has(&data.id));
        assert!(used_space_after <= chunks.total_size);
    };

    for (index, (data, size)) in chunks.data_and_sizes.iter().enumerate().rev() {
        put(
            &Data {
                id: Id(index as u64),
                value: data.clone(),
            },
            size,
        );
    }
    assert_eq!(used_space.get(), chunks.total_size);

    let mut keys = chunk_store.keys();
    keys.sort();
    assert_eq!(
        (0..chunks.data_and_sizes.len())
            .map(|i| Id(i as u64))
            .collect::<Vec<_>>(),
        keys
    );
}

#[test]
fn failed_put_when_not_enough_space() {
    let mut rng = new_rng();
    let root = temp_dir();
    let capacity = 32;
    let used_space = Rc::new(Cell::new(0));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path(),
        capacity,
        used_space,
        Init::New
    ));

    let data = Data {
        id: Id(rng.gen()),
        value: rng
            .sample_iter(&Standard)
            .take((capacity + 1) as usize)
            .collect(),
    };

    match chunk_store.put(&data) {
        Err(Error::NotEnoughSpace) => (),
        x => panic!("Unexpected: {:?}", x),
    }
}

#[test]
fn delete() {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng);

    let root = temp_dir();
    let used_space = Rc::new(Cell::new(0));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path(),
        u64::MAX,
        Rc::clone(&used_space),
        Init::New
    ));

    let mut put_and_delete = |data: &Data, size| {
        unwrap!(chunk_store.put(data));
        assert_eq!(used_space.get(), size);
        assert!(chunk_store.has(&data.id));
        unwrap!(chunk_store.delete(&data.id));
        assert!(!chunk_store.has(&data.id));
        assert_eq!(used_space.get(), 0);
    };

    for (index, (data, size)) in chunks.data_and_sizes.iter().enumerate() {
        put_and_delete(
            &Data {
                id: Id(index as u64),
                value: data.clone(),
            },
            *size,
        );
    }
}

#[test]
fn put_and_get_value_should_be_same() {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng);

    let root = temp_dir();
    let used_space = Rc::new(Cell::new(0));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path(),
        u64::MAX,
        Rc::clone(&used_space),
        Init::New
    ));

    for (index, (data, _)) in chunks.data_and_sizes.iter().enumerate() {
        unwrap!(chunk_store.put(&Data {
            id: Id(index as u64),
            value: data.clone()
        }))
    }

    for (index, (data, _)) in chunks.data_and_sizes.iter().enumerate() {
        let retrieved_value = unwrap!(chunk_store.get(&Id(index as u64)));
        assert_eq!(*data, retrieved_value.value);
    }
}

#[test]
fn overwrite_value() {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng);

    let root = temp_dir();
    let used_space = Rc::new(Cell::new(0));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path(),
        u64::MAX,
        Rc::clone(&used_space),
        Init::New
    ));

    for (data, size) in chunks.data_and_sizes {
        unwrap!(chunk_store.put(&Data {
            id: Id(0),
            value: data.clone(),
        }));
        assert_eq!(used_space.get(), size);
        let retrieved_data = unwrap!(chunk_store.get(&Id(0)));
        assert_eq!(data, retrieved_data.value);
    }
}

#[test]
fn get_fails_when_key_does_not_exist() {
    let root = temp_dir();
    let used_space = Rc::new(Cell::new(0));
    let chunk_store: ChunkStore<Data> = unwrap!(ChunkStore::new(
        root.path(),
        u64::MAX,
        used_space,
        Init::New
    ));

    let id = Id(new_rng().gen());
    match chunk_store.get(&id) {
        Err(Error::NoSuchChunk) => (),
        x => panic!("Unexpected {:?}", x),
    }
}

#[test]
fn keys() {
    let mut rng = new_rng();
    let chunks = Chunks::gen(&mut rng);

    let root = temp_dir();
    let used_space = Rc::new(Cell::new(0));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path(),
        u64::MAX,
        used_space,
        Init::New
    ));

    for (index, (data, _)) in chunks.data_and_sizes.iter().enumerate() {
        let id = Id(index as u64);
        assert!(!chunk_store.keys().contains(&id));
        unwrap!(chunk_store.put(&Data {
            id,
            value: data.clone()
        }));

        let keys = chunk_store.keys();
        assert!(keys.contains(&id));
        assert_eq!(keys.len(), index + 1);
    }

    for (index, _) in chunks.data_and_sizes.iter().enumerate() {
        let id = Id(index as u64);

        assert!(chunk_store.keys().contains(&id));
        unwrap!(chunk_store.delete(&id));

        let keys = chunk_store.keys();
        assert!(!keys.contains(&id));
        assert_eq!(keys.len(), chunks.data_and_sizes.len() - index - 1);
    }
}
