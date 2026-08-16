//! Revocation for a scheme where decryption keys are, by construction,
//! offline material a user can keep forever once issued. Attribute-
//! based encryption (like plain public-key encryption) cannot un-issue
//! a key that has already left the authority's hands; what it *can* do
//! is make that key stop matching *future* ciphertexts and *future*
//! reissuance. This module implements the standard mitigation for that
//! limitation: **epoch-tagged attributes**.
//!
//! Every attribute is silently suffixed with `@epoch<N>` before it ever
//! reaches the ABE core. Revoking an attribute (or a user's holding of
//! it) bumps that attribute's epoch counter. From that point on:
//!
//! - Newly encrypted documents are tagged with the new epoch and are
//!   unreadable by keys minted under the old epoch.
//! - Newly issued keys are minted under the new epoch.
//!
//! What this does **not** do, and cannot do without re-encrypting
//! already-issued ciphertexts, is retroactively block a previously
//! issued key from opening documents that were already encrypted under
//! the epoch that key was issued for. Document this limitation to
//! operators; if a document's confidentiality must not survive a
//! revoked user having *already* had a valid key and the document, the
//! document must be re-encrypted (and ideally rotated to a new DEK) as
//! part of the revocation procedure, not just have its epoch bumped.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RevocationState {
    epochs: HashMap<String, u64>,
    revoked_users: Vec<String>,
}

pub struct RevocationList {
    path: PathBuf,
    state: RevocationState,
}

impl RevocationList {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RevocationError> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            serde_json::from_str(&fs::read_to_string(&path)?)?
        } else {
            RevocationState::default()
        };
        Ok(RevocationList { path, state })
    }

    fn save(&self) -> Result<(), RevocationError> {
        fs::write(&self.path, serde_json::to_string_pretty(&self.state)?)?;
        Ok(())
    }

    /// Current epoch for a base attribute name (before tagging).
    pub fn current_epoch(&self, base_attribute: &str) -> u64 {
        *self.state.epochs.get(base_attribute).unwrap_or(&0)
    }

    /// Applies the current epoch tag to a base attribute string, e.g.
    /// `"clearance>=4"` -> `"clearance>=4@epoch0"`.
    pub fn tag(&self, base_attribute: &str) -> String {
        format!("{base_attribute}@epoch{}", self.current_epoch(base_attribute))
    }

    /// Revokes an attribute by bumping its epoch. Existing keys and
    /// ciphertexts at the old epoch are unaffected (see module docs);
    /// everything issued or encrypted from now on uses the new epoch.
    pub fn revoke_attribute(&mut self, base_attribute: &str) -> Result<u64, RevocationError> {
        let next = self.current_epoch(base_attribute) + 1;
        self.state
            .epochs
            .insert(base_attribute.to_string(), next);
        self.save()?;
        Ok(next)
    }

    pub fn revoke_user(&mut self, subject: &str) -> Result<(), RevocationError> {
        if !self.state.revoked_users.iter().any(|u| u == subject) {
            self.state.revoked_users.push(subject.to_string());
        }
        self.save()
    }

    pub fn is_user_revoked(&self, subject: &str) -> bool {
        self.state.revoked_users.iter().any(|u| u == subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_bumps_change_the_tag() {
        let dir = std::env::temp_dir().join(format!("abe-revocation-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revocation.json");
        let mut rl = RevocationList::open(&path).unwrap();
        let before = rl.tag("clearance>=4");
        rl.revoke_attribute("clearance>=4").unwrap();
        let after = rl.tag("clearance>=4");
        assert_ne!(before, after);
        let _ = fs::remove_dir_all(&dir);
    }
}
