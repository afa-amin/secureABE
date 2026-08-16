use abe_policy::AccessTree;
use bls12_381::{G1Affine, G2Affine, Gt, Scalar};
use std::collections::HashMap;

/// Per-attribute public commitment. `t1 = g1^t`, `t2 = g2^t` for a single
/// random exponent `t` chosen once when the attribute is registered. The
/// matching exponent is discarded; only the two group elements are ever
/// needed again, and they are what let ciphertext-side and key-side
/// pairings cancel correctly under an asymmetric (Type-3) pairing.
#[derive(Debug, Clone)]
pub struct AttributeCommitment {
    pub t1: G1Affine,
    pub t2: G2Affine,
}

/// System-wide public parameters. Safe to publish and distribute freely.
#[derive(Debug, Clone)]
pub struct PublicParams {
    pub g1: G1Affine,
    pub g2: G2Affine,
    pub h: G1Affine,
    pub egg_alpha: Gt,
    pub attributes: HashMap<String, AttributeCommitment>,
}

/// System master secret. Must never leave the attribute authority.
#[derive(Debug, Clone)]
pub struct MasterSecret {
    pub alpha: Scalar,
    pub beta: Scalar,
}

/// A single attribute's key material for one user.
#[derive(Debug, Clone)]
pub struct AttributeKeyShare {
    pub d_j: G2Affine,
    pub d_j_prime: G2Affine,
}

/// A user's decryption key for a set of attributes. `r` binds every
/// component in this struct together; mixing components from two
/// different users' keys (different `r`) cannot be used to satisfy a
/// policy that neither user individually satisfies.
#[derive(Debug, Clone)]
pub struct UserSecretKey {
    pub subject: String,
    pub d: G2Affine,
    pub attributes: HashMap<String, AttributeKeyShare>,
}

impl UserSecretKey {
    pub fn attribute_names(&self) -> Vec<String> {
        self.attributes.keys().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub struct LeafCiphertext {
    pub path: Vec<usize>,
    pub attribute: String,
    pub cy: G1Affine,
    pub cy_prime: G1Affine,
}

#[derive(Debug, Clone)]
pub struct WrappedKey {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// The ABE-encrypted form of a symmetric data-encryption key (DEK), bound
/// to an access tree. Safe to store alongside the AES-encrypted file.
#[derive(Debug, Clone)]
pub struct AbeCiphertext {
    pub tree: AccessTree,
    pub c: G1Affine,
    pub leaves: Vec<LeafCiphertext>,
    pub wrapped_key: WrappedKey,
}
