//! Filesystem storage for encrypted document packages.
//!
//! A package on disk never contains anything the storage layer (or a
//! host that only has read access to this directory) could use to
//! recover plaintext: the AES-GCM file ciphertext, the ABE-wrapped DEK,
//! and the access tree in the clear (policies are not secret — they're
//! metadata used to decide who *should* be able to decrypt, not a
//! secret in themselves).

use abe_core::codec;
use abe_core::keys::AbeCiphertext;
use abe_envelope::{EncryptedPackage, SealedDocument};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("encoding error: {0}")]
    Encoding(#[from] abe_core::AbeError),
    #[error("package '{0}' was not found")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackageManifest {
    id: String,
    original_filename: String,
    policy_summary: String,
    created_unix: u64,
}

pub struct PackageStore {
    root: PathBuf,
}

impl PackageStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(PackageStore { root })
    }

    fn package_dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    /// Persists a package under a fresh random id, returning that id.
    pub fn put(
        &self,
        original_filename: &str,
        package: &EncryptedPackage,
    ) -> Result<String, StorageError> {
        let id = new_id();
        let dir = self.package_dir(&id);
        fs::create_dir_all(&dir)?;

        fs::write(
            dir.join("sealed.json"),
            serde_json::to_string_pretty(&package.sealed)?,
        )?;
        fs::write(
            dir.join("key_ciphertext.json"),
            codec::ciphertext_to_json(&package.key_ciphertext),
        )?;

        let manifest = PackageManifest {
            id: id.clone(),
            original_filename: original_filename.to_string(),
            policy_summary: package.sealed.policy_summary.clone(),
            created_unix: now_unix(),
        };
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?,
        )?;

        Ok(id)
    }

    pub fn get(&self, id: &str) -> Result<EncryptedPackage, StorageError> {
        let dir = self.package_dir(id);
        if !dir.exists() {
            return Err(StorageError::NotFound(id.to_string()));
        }
        let sealed: SealedDocument =
            serde_json::from_str(&fs::read_to_string(dir.join("sealed.json"))?)?;
        let key_ciphertext: AbeCiphertext =
            codec::ciphertext_from_json(&fs::read_to_string(dir.join("key_ciphertext.json"))?)?;
        Ok(EncryptedPackage {
            sealed,
            key_ciphertext,
        })
    }

    pub fn list(&self) -> Result<Vec<PackageSummary>, StorageError> {
        let mut out = Vec::new();
        if !self.root.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let manifest_path = entry.path().join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }
            let manifest: PackageManifest =
                serde_json::from_str(&fs::read_to_string(manifest_path)?)?;
            out.push(PackageSummary {
                id: manifest.id,
                original_filename: manifest.original_filename,
                policy_summary: manifest.policy_summary,
                created_unix: manifest.created_unix,
            });
        }
        out.sort_by_key(|p| p.created_unix);
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct PackageSummary {
    pub id: String,
    pub original_filename: String,
    pub policy_summary: String,
    pub created_unix: u64,
}

fn new_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut rng_bytes = [0u8; 4];
    getrandom_bytes(&mut rng_bytes);
    format!("{:x}-{}", nanos, hex::encode(rng_bytes))
}

fn getrandom_bytes(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
