// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::state_db::Init, Network, Result};
use bls::{self, serde_impl::SerdeSecret};
use bytes::Bytes;
use log::{error, trace};
use pickledb::{PickleDb, PickleDbDumpPolicy};
use rand::{distributions::Standard, CryptoRng, Rng};
use safe_nd::{BlsKeypairShare, Keypair};
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, path::Path};
use unwrap::unwrap;

pub(crate) fn new_db<D: AsRef<Path>, N: AsRef<Path>>(
    db_dir: D,
    db_name: N,
    init_mode: Init,
) -> Result<PickleDb> {
    let db_path = db_dir.as_ref().join(db_name);
    if init_mode == Init::New {
        trace!("Creating database at {}", db_path.display());
        fs::create_dir_all(db_dir)?;
        let mut db = PickleDb::new_bin(db_path, PickleDbDumpPolicy::AutoDump);
        // Write then delete a value to ensure DB file is actually written to disk.
        db.set("", &"")?;
        let _ = db.rem("")?;
        return Ok(db);
    }
    trace!("Loading database at {}", db_path.display());
    let result = PickleDb::load_bin(db_path.clone(), PickleDbDumpPolicy::AutoDump);
    if let Err(ref error) = &result {
        error!("Failed to load {}: {}", db_path.display(), error);
    }
    Ok(result?)
}

pub(crate) fn random_vec<R: CryptoRng + Rng>(rng: &mut R, size: usize) -> Vec<u8> {
    rng.sample_iter(&Standard).take(size).collect()
}

pub(crate) fn serialise<T: Serialize>(data: &T) -> Bytes {
    let serialised_data = unwrap!(bincode::serialize(data));
    Bytes::copy_from_slice(serialised_data.as_slice())
}

pub(crate) fn deserialise<T: DeserializeOwned>(bytes: &[u8]) -> T {
    unwrap!(bincode::deserialize(bytes))
}

// NB: needs to allow for nodes not having a key share yet?
pub(crate) fn key_pair(routing: Network) -> Result<Keypair> {
    let index = routing.our_index()?;
    let bls_secret_key = routing.secret_key_share()?;
    let secret = SerdeSecret(bls_secret_key.clone());
    let public = bls_secret_key.public_key_share();
    let public_key_set = routing.public_key_set()?;
    Ok(Keypair::BlsShare(BlsKeypairShare {
        index,
        secret,
        public,
        public_key_set,
    }))
}
