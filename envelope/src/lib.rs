//! Hybrid encryption layer. Large payloads are never touched by the
//! pairing-based ABE layer directly: a random 256-bit data-encryption
//! key (DEK) encrypts the payload with AES-256-GCM, and only that small
//! DEK is wrapped under the access-tree policy via `abe_core`.

use abe_core::{decrypt_key, encrypt_key, AbeCiphertext, AccessTree, PublicParams};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// Domain separator for the file-level AES-256-GCM AAD that authenticates
/// the human-readable policy summary stored alongside the ciphertext.
const FILE_AAD_DOMAIN: &[u8] = b"SECURE_ABE_FILE_v1";

/// Builds AAD for the payload AEAD: `SECURE_ABE_FILE_v1 || policy_summary`.
/// Binding the policy summary into the tag means an attacker who edits
/// `sealed.json` to change the displayed policy cannot still open the
/// file under the original DEK.
fn file_aad(policy_summary: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FILE_AAD_DOMAIN.len() + policy_summary.len());
    aad.extend_from_slice(FILE_AAD_DOMAIN);
    aad.extend_from_slice(policy_summary.as_bytes());
    aad
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("data-key wrapping failed: {0}")]
    KeyWrap(#[from] abe_core::AbeError),
    #[error("file encryption failed: {0}")]
    FileCrypto(String),
}

/// A self-contained encrypted document: the AES-GCM ciphertext of the
/// original bytes plus the ABE-wrapped key needed to open it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedDocument {
    pub file_nonce: [u8; 12],
    pub file_ciphertext: Vec<u8>,
    pub policy_summary: String,
}

/// Everything needed to store and later decrypt a document: the sealed
/// bytes plus the ABE ciphertext wrapping the DEK. Kept as two pieces so
/// callers can serialize them independently if desired.
pub struct EncryptedPackage {
    pub sealed: SealedDocument,
    pub key_ciphertext: AbeCiphertext,
}

pub fn seal<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    plaintext: &[u8],
    tree: &AccessTree,
    policy_summary: &str,
    rng: &mut R,
) -> Result<EncryptedPackage, EnvelopeError> {
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);

    let aad = file_aad(policy_summary);
    let result = (|| -> Result<EncryptedPackage, EnvelopeError> {
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| EnvelopeError::FileCrypto(e.to_string()))?;
        let mut file_nonce = [0u8; 12];
        rng.fill_bytes(&mut file_nonce);
        let nonce = Nonce::from_slice(&file_nonce);
        let file_ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| EnvelopeError::FileCrypto(e.to_string()))?;

        let key_ciphertext = encrypt_key(pp, &dek, tree, rng)?;

        Ok(EncryptedPackage {
            sealed: SealedDocument {
                file_nonce,
                file_ciphertext,
                policy_summary: policy_summary.to_string(),
            },
            key_ciphertext,
        })
    })();

    dek.zeroize();
    result
}

pub fn open(
    pp: &PublicParams,
    usk: &abe_core::UserSecretKey,
    package: &EncryptedPackage,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut dek = decrypt_key(pp, usk, &package.key_ciphertext)?;
    let aad = file_aad(&package.sealed.policy_summary);
    let result = (|| -> Result<Vec<u8>, EnvelopeError> {
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|e| EnvelopeError::FileCrypto(e.to_string()))?;
        let nonce = Nonce::from_slice(&package.sealed.file_nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: package.sealed.file_ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|e| EnvelopeError::FileCrypto(e.to_string()))
    })();

    dek.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use abe_core::{keygen, register_attribute, setup};

    #[test]
    fn round_trips_a_document() {
        let mut rng = rand::thread_rng();
        let (mut pp, msk) = setup(&mut rng);
        register_attribute(&mut pp, "department=security", &mut rng);
        register_attribute(&mut pp, "clearance>=4", &mut rng);

        let usk = keygen(
            &pp,
            &msk,
            "ali",
            &["department=security".into(), "clearance>=4".into()],
            &mut rng,
        )
        .unwrap();

        let tree = AccessTree::and(vec![
            AccessTree::leaf("department=security"),
            AccessTree::leaf("clearance>=4"),
        ]);
        let pkg = seal(
            &pp,
            b"top secret incident report",
            &tree,
            "department=security AND clearance>=4",
            &mut rng,
        )
        .unwrap();

        let opened = open(&pp, &usk, &pkg).unwrap();
        assert_eq!(opened, b"top secret incident report");
    }

    /// Editing the stored policy_summary must cause file decryption to
    /// fail, because the summary is bound as AAD to the AES-GCM tag.
    #[test]
    fn tampered_policy_summary_fails_aad() {
        let mut rng = rand::thread_rng();
        let (mut pp, msk) = setup(&mut rng);
        register_attribute(&mut pp, "department=security", &mut rng);
        register_attribute(&mut pp, "clearance>=4", &mut rng);

        let usk = keygen(
            &pp,
            &msk,
            "ali",
            &["department=security".into(), "clearance>=4".into()],
            &mut rng,
        )
        .unwrap();

        let tree = AccessTree::and(vec![
            AccessTree::leaf("department=security"),
            AccessTree::leaf("clearance>=4"),
        ]);
        let mut pkg = seal(
            &pp,
            b"top secret incident report",
            &tree,
            "department=security AND clearance>=4",
            &mut rng,
        )
        .unwrap();

        // Attacker changes the human-readable policy metadata in storage.
        pkg.sealed.policy_summary = "role=admin".to_string();
        assert!(open(&pp, &usk, &pkg).is_err());
    }
}