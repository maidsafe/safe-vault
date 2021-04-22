// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
pub use ed25519_dalek::{Keypair, PublicKey, SecretKey, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH};
use hex::{decode, encode};
use std::path::Path;
use tokio::fs;

// Filename for storing the node's reward (Ed25519 hex-encoded) public key
const REWARD_PUBLIC_KEY_FILENAME: &str = "reward_public_key";
// Filename for storing the node's reward (Ed25519 hex-encoded) secret key
const REWARD_SECRET_KEY_FILENAME: &str = "reward_secret_key";

const NETWORK_KEYPAIR_FILENAME: &str = "network_keypair";

/// Writes the network keypair to disk.
pub async fn store_network_keypair(
    root_dir: &Path,
    keypair_as_bytes: [u8; KEYPAIR_LENGTH],
) -> Result<()> {
    let keypair_path = root_dir.join(NETWORK_KEYPAIR_FILENAME);
    fs::write(keypair_path, keypair_to_hex(keypair_as_bytes)).await?;
    Ok(())
}

fn keypair_to_hex(keypair_as_bytes: [u8; KEYPAIR_LENGTH]) -> String {
    vec_to_hex(keypair_as_bytes.to_vec())
}

/// Returns Some(KeyPair) or None if file doesn't exist.
pub async fn get_network_keypair(root_dir: &Path) -> Result<Option<Keypair>> {
    let path = root_dir.join(NETWORK_KEYPAIR_FILENAME);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path).await?;
    Ok(Some(keypair_from_bytes(bytes)?))
}

fn keypair_from_bytes(bytes: Vec<u8>) -> Result<Keypair> {
    let hex = String::from_utf8(bytes)
        .map_err(|_| Error::Logic("Config error: Could not parse bytes as string".to_string()))?;
    keypair_from_hex(&hex)
}

fn keypair_from_hex(hex_str: &str) -> Result<Keypair> {
    let keypair_bytes = parse_hex(&hex_str);
    let mut keypair_bytes_array: [u8; KEYPAIR_LENGTH] = [0; KEYPAIR_LENGTH];
    keypair_bytes_array.copy_from_slice(&keypair_bytes[..KEYPAIR_LENGTH]);
    Keypair::from_bytes(&keypair_bytes_array)
        .map_err(|_| Error::Logic("Config error: Invalid network keypair bytes".to_string()))
}

/// Writes the public and secret key (hex-encoded) to different locations at disk.
pub async fn store_new_reward_keypair(root_dir: &Path, keypair: &Keypair) -> Result<()> {
    let secret_key_path = root_dir.join(REWARD_SECRET_KEY_FILENAME);
    let public_key_path = root_dir.join(REWARD_PUBLIC_KEY_FILENAME);
    fs::write(secret_key_path, encode(keypair.secret.to_bytes())).await?;
    fs::write(public_key_path, encode(keypair.public.to_bytes())).await?;
    Ok(())
}

/// Returns Some(PublicKey) or None if file doesn't exist. It assumes it's hex-encoded.
pub async fn get_reward_pk(root_dir: &Path) -> Result<Option<PublicKey>> {
    let path = root_dir.join(REWARD_PUBLIC_KEY_FILENAME);
    if !path.is_file() {
        return Ok(None);
    }
    let pk_hex_bytes = fs::read(path).await?;
    let pk_bytes = decode(pk_hex_bytes).map_err(|err| {
        Error::Logic(format!(
            "Couldn't hex-decode Ed25519 public key bytes: {}",
            err
        ))
    })?;

    let pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|_| Error::Logic("Config error: Invalid Ed25519 public key bytes".to_string()))?;

    Ok(Some(pk))
}

fn vec_to_hex(hash: Vec<u8>) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_hex(hex_str: &str) -> Vec<u8> {
    let mut hex_bytes = hex_str
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    bytes
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rngs::OsRng;
    use tempdir::TempDir;

    #[tokio::test]
    async fn pubkey_to_and_from_file() -> Result<()> {
        let mut rng = OsRng;
        let keypair = ed25519_dalek::Keypair::generate(&mut rng);

        let root = create_temp_root(&"rewardkey")?;
        let root_dir = root.path();
        store_new_reward_keypair(root_dir, &keypair).await?;
        let pk_result = get_reward_pk(root_dir).await?;

        assert_eq!(pk_result, Some(keypair.public));
        Ok(())
    }

    /// creates a temp dir for the root of all stores
    fn create_temp_root(dir: &str) -> Result<TempDir> {
        TempDir::new(dir).map_err(|e| Error::TempDirCreationFailed(e.to_string()))
    }
}
