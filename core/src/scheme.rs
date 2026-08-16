//! Ciphertext-Policy Attribute-Based Encryption over the BLS12-381
//! pairing-friendly curve.
//!
//! Construction: a small-universe adaptation of the Bethencourt-Sahai-
//! Waters (BSW07) CP-ABE scheme, restructured for an asymmetric
//! (Type-3) pairing e: G1 x G2 -> GT. Access structures are arbitrary
//! AND/OR/threshold trees, evaluated with Shamir secret sharing and
//! Lagrange interpolation. Collusion resistance across users comes from
//! a single random exponent `r`, chosen fresh per user at key-issuance
//! time and woven into every attribute-key component that user holds:
//! components from two different users cannot be recombined to satisfy
//! a policy that neither user individually satisfies, because the `r`
//! values do not match.
//!
//! The DEK itself is never placed directly in GT. Instead the blinding
//! value `e(g1,g2)^{alpha*s}` is hashed (SHA3-256) into a symmetric key
//! that wraps the DEK with AES-256-GCM, keeping the pairing arithmetic
//! off the hot path of large payloads.

use crate::error::AbeError;
use crate::keys::{
    AbeCiphertext, AttributeCommitment, AttributeKeyShare, LeafCiphertext, MasterSecret,
    PublicParams, UserSecretKey, WrappedKey,
};
use crate::share::{recombine, share_secret, LeafResult};
use abe_policy::AccessTree;
use aes_gcm::aead::{Aead, KeyInit, OsRng as AesOsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Generates fresh system-wide public parameters and the matching
/// master secret. Run once per deployment (or once per attribute
/// authority, in a multi-authority layout).
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicParams, MasterSecret) {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let alpha = Scalar::random(&mut *rng);
    let beta = Scalar::random(&mut *rng);

    let h: G1Affine = (G1Projective::from(g1) * beta).into();
    let egg_alpha = pairing(&g1, &g2) * alpha;

    (
        PublicParams {
            g1,
            g2,
            h,
            egg_alpha,
            attributes: HashMap::new(),
        },
        MasterSecret { alpha, beta },
    )
}

/// Registers a new attribute name in the public parameters. Idempotent:
/// re-registering an already-known attribute is a no-op that returns
/// its existing commitment. Any authority holding a mutable reference to
/// the shared `PublicParams` can call this; the exponent behind the
/// commitment is generated fresh and immediately discarded, so no
/// secret material needs to be shared between authorities to add
/// attributes to the universe.
pub fn register_attribute<R: RngCore + CryptoRng>(
    pp: &mut PublicParams,
    name: &str,
    rng: &mut R,
) {
    if pp.attributes.contains_key(name) {
        return;
    }
    let t = Scalar::random(&mut *rng);
    let t1: G1Affine = (G1Projective::from(pp.g1) * t).into();
    let t2: G2Affine = (G2Projective::from(pp.g2) * t).into();
    pp.attributes
        .insert(name.to_string(), AttributeCommitment { t1, t2 });
}

/// Issues a decryption key binding the given attribute set to a fresh,
/// per-user random `r`.
pub fn keygen<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    msk: &MasterSecret,
    subject: &str,
    attrs: &[String],
    rng: &mut R,
) -> Result<UserSecretKey, AbeError> {
    for a in attrs {
        if !pp.attributes.contains_key(a) {
            return Err(AbeError::UnknownAttribute(a.clone()));
        }
    }

    let r = Scalar::random(&mut *rng);
    let beta_inv = msk.beta.invert().expect("beta is sampled nonzero w.o.p.");
    let d_exp = (msk.alpha + r) * beta_inv;
    let d: G2Affine = (G2Projective::from(pp.g2) * d_exp).into();

    let mut attributes = HashMap::new();
    for a in attrs {
        let commitment = &pp.attributes[a];
        let r_j = Scalar::random(&mut *rng);
        // D_j = g2^r * T2^{r_j}
        let d_j: G2Affine = (G2Projective::from(pp.g2) * r
            + G2Projective::from(commitment.t2) * r_j)
            .into();
        // D_j' = g2^{r_j}
        let d_j_prime: G2Affine = (G2Projective::from(pp.g2) * r_j).into();
        attributes.insert(
            a.clone(),
            AttributeKeyShare { d_j, d_j_prime },
        );
    }

    Ok(UserSecretKey {
        subject: subject.to_string(),
        d,
        attributes,
    })
}

fn kdf(gt: &bls12_381::Gt) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(format!("{:?}", gt).as_bytes());
    hasher.finalize().into()
}

/// Encrypts a 32-byte data-encryption key (DEK) under an access tree.
/// The returned ciphertext can only be opened by a user secret key
/// whose attribute set satisfies `tree`.
pub fn encrypt_key<R: RngCore + CryptoRng>(
    pp: &PublicParams,
    dek: &[u8; 32],
    tree: &AccessTree,
    rng: &mut R,
) -> Result<AbeCiphertext, AbeError> {
    for leaf in tree.leaves() {
        if !pp.attributes.contains_key(leaf) {
            return Err(AbeError::UnknownAttribute(leaf.to_string()));
        }
    }

    let s = Scalar::random(&mut *rng);
    let c: G1Affine = (G1Projective::from(pp.h) * s).into();
    let blinding = pp.egg_alpha * s;

    let shares = share_secret(tree, s, rng);
    let mut leaves = Vec::with_capacity(shares.len());
    for (path, attr, lambda) in shares {
        let commitment = &pp.attributes[&attr];
        let cy: G1Affine = (G1Projective::from(pp.g1) * lambda).into();
        let cy_prime: G1Affine = (G1Projective::from(commitment.t1) * lambda).into();
        leaves.push(LeafCiphertext {
            path,
            attribute: attr,
            cy,
            cy_prime,
        });
    }

    let key_bytes = kdf(&blinding);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| AbeError::Encoding(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    AesOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, dek.as_slice())
        .map_err(|e| AbeError::Encoding(e.to_string()))?;

    Ok(AbeCiphertext {
        tree: tree.clone(),
        c,
        leaves,
        wrapped_key: WrappedKey {
            nonce: nonce_bytes,
            ciphertext,
        },
    })
}

/// Attempts to recover the 32-byte DEK using the given user secret key.
/// Fails with `AbeError::PolicyNotSatisfied` if the user's attributes do
/// not satisfy the ciphertext's access tree.
pub fn decrypt_key(
    _pp: &PublicParams,
    usk: &UserSecretKey,
    ct: &AbeCiphertext,
) -> Result<[u8; 32], AbeError> {
    let mut leaf_results: LeafResult = HashMap::new();
    for leaf in &ct.leaves {
        if let Some(key_share) = usk.attributes.get(&leaf.attribute) {
            // F_y = e(Cy, D_j) / e(Cy', D_j')  =  e(g1,g2)^{r * lambda_y}
            let num = pairing(&leaf.cy, &key_share.d_j);
            let den = pairing(&leaf.cy_prime, &key_share.d_j_prime);
            leaf_results.insert(leaf.path.clone(), num - den);
        }
    }

    let mut path = Vec::new();
    let f_root = recombine(&ct.tree, &leaf_results, &mut path)
        .ok_or(AbeError::PolicyNotSatisfied)?;

    // e(g1,g2)^{s*alpha} = e(C, D) - F_root   (Gt is written additively)
    let e_c_d = pairing(&ct.c, &usk.d);
    let blinding = e_c_d - f_root;

    let key_bytes = kdf(&blinding);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| AbeError::Encoding(e.to_string()))?;
    let nonce = Nonce::from_slice(&ct.wrapped_key.nonce);
    let plaintext = cipher
        .decrypt(nonce, ct.wrapped_key.ciphertext.as_slice())
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    plaintext
        .try_into()
        .map_err(|_| AbeError::Encoding("unexpected DEK length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use abe_policy::AccessTree;

    fn setup_with_attrs(names: &[&str]) -> (PublicParams, MasterSecret) {
        let mut rng = rand::thread_rng();
        let (mut pp, msk) = setup(&mut rng);
        for n in names {
            register_attribute(&mut pp, n, &mut rng);
        }
        (pp, msk)
    }

    #[test]
    fn matching_attributes_decrypt() {
        let mut rng = rand::thread_rng();
        let (pp, msk) = setup_with_attrs(&["department=security", "clearance>=4"]);
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
        let dek = [7u8; 32];
        let ct = encrypt_key(&pp, &dek, &tree, &mut rng).unwrap();
        let recovered = decrypt_key(&pp, &usk, &ct).unwrap();
        assert_eq!(dek, recovered);
    }

    #[test]
    fn missing_attribute_is_denied() {
        let mut rng = rand::thread_rng();
        let (pp, msk) = setup_with_attrs(&[
            "department=security",
            "department=marketing",
            "clearance>=4",
        ]);
        let sara = keygen(
            &pp,
            &msk,
            "sara",
            &["department=marketing".into()],
            &mut rng,
        )
        .unwrap();

        let tree = AccessTree::and(vec![
            AccessTree::leaf("department=security"),
            AccessTree::leaf("clearance>=4"),
        ]);
        let dek = [9u8; 32];
        let ct = encrypt_key(&pp, &dek, &tree, &mut rng).unwrap();
        assert!(decrypt_key(&pp, &sara, &ct).is_err());
    }

    #[test]
    fn two_partial_users_cannot_collude() {
        // Ali only has department=security; Reza only has clearance>=4.
        // Neither individually satisfies the AND policy, and per the
        // security argument they must not be able to combine their key
        // material to recover the DEK either.
        let mut rng = rand::thread_rng();
        let (pp, msk) = setup_with_attrs(&["department=security", "clearance>=4"]);
        let ali = keygen(&pp, &msk, "ali", &["department=security".into()], &mut rng).unwrap();
        let reza = keygen(&pp, &msk, "reza", &["clearance>=4".into()], &mut rng).unwrap();

        let tree = AccessTree::and(vec![
            AccessTree::leaf("department=security"),
            AccessTree::leaf("clearance>=4"),
        ]);
        let dek = [3u8; 32];
        let ct = encrypt_key(&pp, &dek, &tree, &mut rng).unwrap();

        // Naively splice Reza's clearance share onto Ali's key. Because
        // the two keys carry different random `r`, the pairing algebra
        // no longer cancels and the recombined value is not the
        // encryptor's blinding factor.
        let mut spliced = ali.clone();
        spliced.attributes.insert(
            "clearance>=4".into(),
            reza.attributes.get("clearance>=4").unwrap().clone(),
        );
        assert!(decrypt_key(&pp, &spliced, &ct).is_err());
    }

    #[test]
    fn or_gate_admin_bypass() {
        let mut rng = rand::thread_rng();
        let (pp, msk) = setup_with_attrs(&[
            "department=security",
            "clearance>=4",
            "role=admin",
        ]);
        let admin = keygen(&pp, &msk, "admin1", &["role=admin".into()], &mut rng).unwrap();

        let tree = AccessTree::or(vec![
            AccessTree::and(vec![
                AccessTree::leaf("department=security"),
                AccessTree::leaf("clearance>=4"),
            ]),
            AccessTree::leaf("role=admin"),
        ]);
        let dek = [5u8; 32];
        let ct = encrypt_key(&pp, &dek, &tree, &mut rng).unwrap();
        assert_eq!(dek, decrypt_key(&pp, &admin, &ct).unwrap());
    }
}
