// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Result;
use crate::{node::keys::NodeSigningKeys, utils};
use ed25519_dalek::Keypair as Ed25519Keypair;
use safe_nd::PublicKey;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

const AGE_GROUP_FILENAME: &str = "age_group";
const REWARD_PUBLIC_KEY_FILENAME: &str = "reward_public_key";
const REWARD_SECRET_KEY_FILENAME: &str = "reward_ed25519_secret_key";

/// Writes the public and secret key to different locations at disk.
pub fn store_new_reward_keypair(root_dir: &Path, keys: &Ed25519Keypair) -> Result<()> {
    let secret_key_path = root_dir.join(REWARD_SECRET_KEY_FILENAME);
    let public_key_path = root_dir.join(REWARD_PUBLIC_KEY_FILENAME);
    fs::write(secret_key_path, utils::serialise(&keys.secret))?;
    fs::write(
        public_key_path,
        utils::serialise(&PublicKey::Ed25519(keys.public)),
    )?;
    Ok(())
}

/// Writes the info to disk.
pub fn store_age_group(root_dir: &Path, age_group: AgeGroup) -> Result<()> {
    let path = root_dir.join(AGE_GROUP_FILENAME);
    Ok(fs::write(path, utils::serialise(&age_group))?)
}

/// Returns Some(AgeGroup) or None if file doesn't exist.
pub fn get_age_group(root_dir: &Path) -> Result<Option<AgeGroup>> {
    let path = root_dir.join(AGE_GROUP_FILENAME);
    if !path.is_file() {
        return Ok(None);
    }
    let contents = fs::read(path)?;
    Ok(Some(bincode::deserialize(&contents)?))
}

/// A node is within one
/// out of three age groups.
#[derive(Serialize, Deserialize, Clone)]
pub enum AgeGroup {
    Infant,
    Adult,
    Elder,
}

/// Specifies whether to try loading cached data from disk, or to just construct a new instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Init {
    Load,
    New,
}

/// Command that the user can send to a running node to control its execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Shutdown the vault
    Shutdown,
}

/// Info about the node used
/// to init its various dbs
/// (among things).
#[derive(Clone)]
pub struct NodeInfo {
    pub keys: NodeSigningKeys,
    pub root_dir: PathBuf,
    pub init_mode: Init,
    /// Upper limit in bytes for allowed network storage on this node.
    /// An Adult would be using the space for chunks,
    /// while an Elder uses it for metadata.
    pub max_storage_capacity: u64,
}

impl NodeInfo {
    pub fn path(&self) -> &Path {
        self.root_dir.as_path()
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        self.keys.public_key()
    }

    pub fn keys(&self) -> NodeSigningKeys {
        self.keys.clone()
    }
}
