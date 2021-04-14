// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use bls::{self, serde_impl::SerdeSecret, PublicKey, SecretKey, PK_SIZE};
use std::path::Path;
use tokio::fs;

const REWARD_PUBLIC_KEY_FILENAME: &str = "reward_public_key";
const REWARD_SECRET_KEY_FILENAME: &str = "reward_secret_key";

/// Writes the public and secret key to different locations at disk.
pub async fn store_new_reward_keypair(
    root_dir: &Path,
    secret: &SecretKey,
    public: &PublicKey,
) -> Result<()> {
    let secret_key_path = root_dir.join(REWARD_SECRET_KEY_FILENAME);
    let public_key_path = root_dir.join(REWARD_PUBLIC_KEY_FILENAME);
    fs::write(secret_key_path, sk_to_hex(secret)).await?;
    fs::write(public_key_path, pk_to_hex(public)).await?;
    Ok(())
}

/// Returns Some(PublicKey) or None if file doesn't exist.
pub async fn get_reward_pk(root_dir: &Path) -> Result<Option<PublicKey>> {
    let path = root_dir.join(REWARD_PUBLIC_KEY_FILENAME);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path).await?;
    Ok(Some(pk_from_bytes(bytes)?))
}

///
pub fn pk_to_hex(pk: &PublicKey) -> String {
    let pk_as_bytes: [u8; PK_SIZE] = pk.to_bytes();
    vec_to_hex(pk_as_bytes.to_vec())
}

///
pub fn pk_from_bytes(bytes: Vec<u8>) -> Result<PublicKey> {
    let hex = String::from_utf8(bytes)
        .map_err(|_| Error::Logic("Config error: Could not parse bytes as string".to_string()))?;
    pk_from_hex(&hex)
}

///
pub fn pk_from_hex(hex_str: &str) -> Result<PublicKey> {
    let pk_bytes = parse_hex(&hex_str);
    let mut pk_bytes_array: [u8; PK_SIZE] = [0; PK_SIZE];
    pk_bytes_array.copy_from_slice(&pk_bytes[..PK_SIZE]);
    PublicKey::from_bytes(pk_bytes_array)
        .map_err(|_| Error::Logic("Config error: Invalid public key bytes".to_string()))
}

fn sk_to_hex(secret: &SecretKey) -> String {
    let sk_serialised = bincode::serialize(&SerdeSecret(secret))
        .expect("Failed to serialise the generated secret key");
    vec_to_hex(sk_serialised)
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
    use tempdir::TempDir;

    /// Hex encoding public keys.
    #[test]
    fn pubkey_hex() -> Result<()> {
        let key = gen_key();
        let encoded = pk_to_hex(&key);
        println!("{:?}", encoded);
        let decoded: PublicKey = pk_from_hex(&encoded)?;
        assert_eq!(decoded, key);
        Ok(())
    }

    #[tokio::test]
    async fn pubkey_to_and_from_file() -> Result<()> {
        let sk = SecretKey::random();
        let pk = sk.public_key();

        let root = create_temp_root(&"rewardkey")?;
        let root_dir = root.path();
        store_new_reward_keypair(root_dir, &sk, &pk).await?;
        let pk_result = get_reward_pk(root_dir).await?;

        assert_eq!(pk_result, Some(pk));
        Ok(())
    }

    fn gen_key() -> PublicKey {
        SecretKey::random().public_key()
    }

    /// creates a temp dir for the root of all stores
    fn create_temp_root(dir: &str) -> Result<TempDir> {
        TempDir::new(dir).map_err(|e| Error::TempDirCreationFailed(e.to_string()))
    }
}
