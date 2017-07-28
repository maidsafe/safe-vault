// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

macro_rules! assert_err {
    ($cond : expr, $error : pat) => {
        match $cond {
            Err($error) => (),
            result => panic!(concat!("Expecting ", stringify!($error), " got {:?}"), result),
        }
    }
}

use chunk_store::{Chunk, ChunkId, ChunkStore, Error};
use maidsafe_utilities::serialisation;
use rand::{self, Rng};
use tempdir::TempDir;

fn generate_random_bytes(size: u64) -> Vec<u8> {
    rand::thread_rng().gen_iter().take(size as usize).collect()
}

struct Chunks {
    data_and_sizes: Vec<(Vec<u8>, u64)>,
    total_size: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Data(Vec<u8>);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Id(u64);

impl Chunk<Id> for Data {
    type Id = Id;
}

impl ChunkId<Id> for Id {
    type Chunk = Data;
    fn to_key(&self) -> Id {
        *self
    }
}

// Construct random amount of randomly-sized chunks, keeping track of the total size of all
// chunks when serialised.
fn generate_random_chunks() -> Chunks {
    let mut chunks = Chunks {
        data_and_sizes: vec![],
        total_size: 0,
    };
    let chunk_count: u8 = rand::random();
    for _ in 0..chunk_count {
        let size: u8 = rand::random();
        let data = generate_random_bytes(size as u64);
        let serialised_size = unwrap!(serialisation::serialise(&data)).len() as u64;
        chunks.total_size += serialised_size;
        chunks.data_and_sizes.push((data, serialised_size));
    }
    chunks
}

#[test]
fn create_multiple_instances_in_the_same_root() {
    // root already exists
    {
        let root = unwrap!(TempDir::new("test"));

        let _1 = unwrap!(ChunkStore::<Id>::new(root.path().join("store-1"), 64));
        let _2 = unwrap!(ChunkStore::<Id>::new(root.path().join("store-2"), 64));
    }

    // root doesn't exist yet
    {
        let root = unwrap!(TempDir::new("test"));
        let root_path = root.path().join("foo").join("bar");

        let _1 = unwrap!(ChunkStore::<Id>::new(root_path.join("store-1"), 64));
        let _2 = unwrap!(ChunkStore::<Id>::new(root_path.join("store-2"), 64));
    }
}

#[test]
fn storedir_should_cleanup() {
    let tempdir = unwrap!(TempDir::new("test"));
    let storedir = tempdir.path().join("test");

    {
        let mut store = unwrap!(ChunkStore::<Id>::new(storedir.clone(), 64));
        assert!(storedir.exists());
        unwrap!(store.put(&Id(4), &Data(vec![3])));
        // Creating another instance with the same directory should fail.
        assert!(ChunkStore::<Id>::new(storedir.clone(), 64).is_err());
        // The failed attempt should not interfere with the existing chunk store.
        assert_eq!(Data(vec![3]), unwrap!(store.get(&Id(4))));
        assert!(storedir.exists());
    }

    assert!(!storedir.exists());
}

#[test]
fn successful_put() {
    let chunks = generate_random_chunks();
    let root = unwrap!(TempDir::new("test"));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path().to_path_buf(),
        chunks.total_size,
    ));
    {
        let mut put = |id, data, size| {
            let size_before_insert = chunk_store.used_space();
            assert!(!chunk_store.has(&id));
            unwrap!(chunk_store.put(&id, &data));
            assert_eq!(chunk_store.used_space(), size + size_before_insert);
            assert!(chunk_store.has(&id));
            assert!(chunk_store.used_space() <= chunks.total_size);
        };

        for (index, &(ref data, ref size)) in chunks.data_and_sizes.iter().enumerate().rev() {
            put(Id(index as u64), Data(data.clone()), size);
        }
    }
    assert_eq!(chunk_store.used_space(), chunks.total_size);

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
    let k_disk_size = 32;
    let root = unwrap!(TempDir::new("test"));
    let mut store = unwrap!(ChunkStore::new(root.path().to_path_buf(), k_disk_size));
    let id = Id(rand::random());
    let data = Data(generate_random_bytes(k_disk_size + 1));

    assert_err!(store.put(&id, &data), Error::NotEnoughSpace);
}

#[test]
fn delete() {
    let chunks = generate_random_chunks();
    let root = unwrap!(TempDir::new("test"));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path().to_path_buf(),
        chunks.total_size,
    ));
    let mut put_and_delete = |id, value, size| {
        unwrap!(chunk_store.put(&id, &value));
        assert_eq!(chunk_store.used_space(), size);
        assert!(chunk_store.has(&id));
        unwrap!(chunk_store.delete(&id));
        assert!(!chunk_store.has(&id));
        assert_eq!(chunk_store.used_space(), 0);
    };

    for (index, &(ref data, ref size)) in chunks.data_and_sizes.iter().enumerate() {
        put_and_delete(Id(index as u64), Data(data.clone()), *size);
    }
}

#[test]
fn put_and_get_value_should_be_same() {
    let chunks = generate_random_chunks();
    let root = unwrap!(TempDir::new("test"));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path().to_path_buf(),
        chunks.total_size,
    ));
    for (index, &(ref data, _)) in chunks.data_and_sizes.iter().enumerate() {
        unwrap!(chunk_store.put(&Id(index as u64), &Data(data.clone())));
    }
    for (index, &(ref data, _)) in chunks.data_and_sizes.iter().enumerate() {
        let retrieved_value = unwrap!(chunk_store.get(&Id(index as u64)));
        assert_eq!(*data, retrieved_value.0);
    }
}

#[test]
fn overwrite_value() {
    let chunks = generate_random_chunks();
    let root = unwrap!(TempDir::new("test"));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path().to_path_buf(),
        chunks.total_size,
    ));
    for (ref data, ref size) in chunks.data_and_sizes {
        unwrap!(chunk_store.put(&Id(0), &Data(data.clone())));
        assert_eq!(chunk_store.used_space(), *size);
        let retrieved_value = unwrap!(chunk_store.get(&Id(0)));
        assert_eq!(*data, retrieved_value.0);
    }
}

#[test]
fn get_fails_when_key_does_not_exist() {
    let root = unwrap!(TempDir::new("test"));
    let chunk_store = unwrap!(ChunkStore::<Id>::new(root.path().to_path_buf(), 64));
    let id = Id(rand::random());
    assert_err!(chunk_store.get(&id), Error::NotFound);
}

#[test]
fn keys() {
    let chunks = generate_random_chunks();
    let root = unwrap!(TempDir::new("test"));
    let mut chunk_store = unwrap!(ChunkStore::new(
        root.path().to_path_buf(),
        chunks.total_size,
    ));

    for (index, &(ref data, _)) in chunks.data_and_sizes.iter().enumerate() {
        let id = Id(index as u64);

        assert!(!chunk_store.keys().contains(&id));
        unwrap!(chunk_store.put(&id, &Data(data.clone())));
        assert!(chunk_store.keys().contains(&id));
        assert_eq!(chunk_store.keys().len(), index + 1);
    }

    for (index, _) in chunks.data_and_sizes.iter().enumerate() {
        let id = Id(index as u64);

        assert!(chunk_store.keys().contains(&id));
        unwrap!(chunk_store.delete(&id));
        assert!(!chunk_store.keys().contains(&id));
        assert_eq!(
            chunk_store.keys().len(),
            chunks.data_and_sizes.len() - index - 1
        );
    }
}
