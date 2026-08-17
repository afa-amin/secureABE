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
//! value `e(g1,g2)^{alpha*s}` is run through `kdf` (see below) into a
//! symmetric key that wraps the DEK with AES-256-GCM, keeping the
//! pairing arithmetic off the hot path of large payloads.
//!
//! Secret scalars and key material are zeroized where practical (see
//! `crate::keys` for the `Drop`/`ZeroizeOnDrop` impls on `MasterSecret`,
//! `AttributeKeyShare`, and `UserSecretKey`, and the explicit
//! `.zeroize()` calls below on ephemeral values such as `r`, `s`, and
//! derived symmetric key bytes). Because `Scalar`/`G1Affine`/`G2Affine`
//! are `Copy`, this is best-effort hygiene, not a hard guarantee: Rust
//! is free to leave earlier copies of a `Copy` value in registers or
//! stack slots that a zeroize call on one binding cannot reach. It
//! still meaningfully shrinks the window during which the *canonical*
//! copy of each secret sits in memory after it's no longer needed.

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
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroize;

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
    let mut t = Scalar::random(&mut *rng);
    let t1: G1Affine = (G1Projective::from(pp.g1) * t).into();
    let t2: G2Affine = (G2Projective::from(pp.g2) * t).into();
    t.zeroize();
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

    let mut r = Scalar::random(&mut *rng);
    let mut beta_inv = msk.beta.invert().expect("beta is sampled nonzero w.o.p.");
    let mut d_exp = (msk.alpha + r) * beta_inv;
    let d: G2Affine = (G2Projective::from(pp.g2) * d_exp).into();
    d_exp.zeroize();
    beta_inv.zeroize();

    let mut attributes = HashMap::new();
    for a in attrs {
        let commitment = &pp.attributes[a];
        let mut r_j = Scalar::random(&mut *rng);
        // D_j = g2^r * T2^{r_j}
        let d_j: G2Affine = (G2Projective::from(pp.g2) * r
            + G2Projective::from(commitment.t2) * r_j)
            .into();
        // D_j' = g2^{r_j}
        let d_j_prime: G2Affine = (G2Projective::from(pp.g2) * r_j).into();
        r_j.zeroize();
        attributes.insert(
            a.clone(),
            AttributeKeyShare { d_j, d_j_prime },
        );
    }
    r.zeroize();

    Ok(UserSecretKey {
        subject: subject.to_string(),
        d,
        attributes,
    })
}

/// Extracts a canonical byte representation of a `Gt` (pairing target
/// group) element.
///
/// **Why this goes through `Debug`.** `bls12_381` 0.8.0 keeps `Gt`'s
/// inner field element (`Fp12`) `pub(crate)` and, unlike
/// `G1Affine`/`G2Affine`/`Scalar` (all of which expose
/// `to_bytes`/`to_compressed`), does not expose *any* public method to
/// read a `Gt`'s bytes. This is a known, still-open gap in the upstream
/// crate: it is exactly why the `cosmian_bls12_381` fork exists ("In
/// order to serialize/deserialize Gt elements ... Cosmian added this
/// implementation"), and the corresponding upstream feature request is
/// still unresolved. Concretely, that means there is no *safe* Rust API
/// in this exact dependency version that reads a `Gt`'s raw bytes
/// except a trait the crate implements itself, using its own privileged
/// access to the private field -- and in this crate that trait is
/// `Debug`/`Display` (`Display` for `Gt` literally forwards to
/// `Debug`). The derived `Debug` walks the private `Fp12 -> Fp6 -> Fp2
/// -> Fp` tree and hex-encodes each leaf `Fp`'s own canonical, public
/// `to_bytes()` output, so the resulting string *is* a full, canonical,
/// deterministic encoding of the element's 12 underlying field limbs --
/// it is just not exposed through an API that promises to stay
/// byte-for-byte identical across crate releases the way `to_bytes`
/// would.
///
/// **Why not `unsafe` transmute instead.** Reading the private `Fp12`
/// out of a `Gt` via `std::mem::transmute` was considered and rejected:
/// Rust's default (`repr(Rust)`) struct layout makes no guarantee about
/// field order or padding, so a transmute-based extractor could be
/// silently wrong (undefined behavior) on some future compiler
/// revision even without any change to `bls12_381` at all. Relying on
/// `Debug`'s text output is merely *unergonomic*; relying on an
/// unguaranteed memory layout would be *unsound*. The former is the
/// lesser risk.
///
/// **How the residual risk is contained.** Because this is still a
/// dependency on formatting rather than a documented byte encoding,
/// three things pin it down:
///   1. `Cargo.toml` requires `bls12_381 = "=0.8.0"` (an *exact*
///      version), so `cargo update` can never silently change this
///      formatting out from under us.
///   2. `tests::kdf_matches_known_answer_vector` hard-codes the
///      expected 32-byte `kdf` output for `Gt::identity()`. If the
///      derived `Debug` output ever changes for any reason -- a crate
///      upgrade past the pin, a toolchain change, an edit here -- that
///      test fails loudly at build/test time instead of silently
///      deriving different key material for ciphertexts that already
///      exist on disk.
///   3. This function is the *only* place in the whole codebase that
///      reads a `Gt` through `Debug`/`Display`; `codec::gt_display_hex`
///      (a display/audit-only export that is never parsed back into a
///      working value) delegates to it too, so there is exactly one
///      thing to re-verify if `bls12_381` is ever intentionally
///      upgraded past the pin.
pub(crate) fn gt_canonical_bytes(gt: &bls12_381::Gt) -> Vec<u8> {
    format!("{:?}", gt).into_bytes()
}

/// Domain-separation label for [`kdf`]. Any future incompatible change
/// to the KDF construction (switching hash functions, changing what
/// `gt_canonical_bytes` returns, changing the HKDF `info` structure)
/// should introduce a new, differently-suffixed label so that old and
/// new derivations can never collide or be confused with one another.
const KDF_DOMAIN: &[u8] = b"SECURE_ABE_KDF_v1";

/// Derives the 32-byte AES-256-GCM key used to wrap/unwrap a DEK from a
/// CP-ABE blinding value `K = e(g1,g2)^{alpha*s}`.
///
/// `K` is only computable by the encryptor (who knows `alpha` and `s`
/// directly) or by a decryptor whose attributes satisfy the ciphertext
/// policy (via the pairing recombination in [`decrypt_key`]); it is the
/// actual secret this scheme protects. Rather than hashing
/// `gt_canonical_bytes(K)` directly with a general-purpose hash, this
/// runs it through HKDF-SHA256 (RFC 5869) as input keying material,
/// with `KDF_DOMAIN` as the `info` parameter. Using a real KDF instead
/// of a bare hash, with an explicit domain-separation label, means:
///   - the output is a proper pseudorandom key rather than "whatever a
///     hash of a formatted string happens to look like";
///   - the label ties every derived key to this specific scheme and
///     version, so `K` could never be confused with, or accidentally
///     reused as, a key derived for some unrelated purpose elsewhere in
///     a larger system that also happens to hash the same bytes;
///   - changing the hash function or construction later is a one-line
///     change to `KDF_DOMAIN`/the `Hkdf<_>` type parameter, not a
///     restructuring of every call site.
fn kdf(gt: &bls12_381::Gt) -> [u8; 32] {
    let ikm = gt_canonical_bytes(gt);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(KDF_DOMAIN, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
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

    let mut s = Scalar::random(&mut *rng);
    let c: G1Affine = (G1Projective::from(pp.h) * s).into();
    let mut blinding = pp.egg_alpha * s;

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
    // `s` was moved by-value into `share_secret` above, but `Scalar` is
    // `Copy`, so this binding still holds its own copy; wipe it now
    // that every use (computing `c`, `blinding`, and the leaf shares)
    // is done.
    s.zeroize();

    let mut key_bytes = kdf(&blinding);
    blinding.zeroize();

    // Scope the AES-GCM key material tightly so `key_bytes` can be
    // zeroized immediately after its only use (constructing the
    // cipher, which copies it internally) regardless of which branch
    // below returns.
    let result = (|| {
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| AbeError::Encoding(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        AesOsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, dek.as_slice())
            .map_err(|e| AbeError::Encoding(e.to_string()))?;
        Ok((nonce_bytes, ciphertext))
    })();
    key_bytes.zeroize();
    let (nonce_bytes, ciphertext) = result?;

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
    // The per-leaf pairing results are intermediate key material too;
    // wipe them once `recombine` has consumed what it needs from them.
    for v in leaf_results.values_mut() {
        v.zeroize();
    }

    // e(g1,g2)^{s*alpha} = e(C, D) - F_root   (Gt is written additively)
    let e_c_d = pairing(&ct.c, &usk.d);
    let mut blinding = e_c_d - f_root;

    let mut key_bytes = kdf(&blinding);
    blinding.zeroize();

    let result = (|| {
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| AbeError::Encoding(e.to_string()))?;
        let nonce = Nonce::from_slice(&ct.wrapped_key.nonce);
        cipher
            .decrypt(nonce, ct.wrapped_key.ciphertext.as_slice())
            .map_err(|_| AbeError::PolicyNotSatisfied)
    })();
    key_bytes.zeroize();
    let mut plaintext = result?;

    if plaintext.len() != 32 {
        // Wipe the partially/incorrectly recovered plaintext before
        // bailing out on the error path too.
        plaintext.zeroize();
        return Err(AbeError::Encoding("unexpected DEK length".into()));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abe_policy::AccessTree;

    /// Known-answer vector for `kdf(Gt::identity())`, generated once via
    /// `print_known_answer_vector` against the pinned `bls12_381 =
    /// "=0.8.0"` dependency. See `kdf_matches_known_answer_vector`.
    const KDF_IDENTITY_KAT_HEX: &str =
        "f44d8f2dd929d6f27a157a7005eaf5fef92c0ed181c0b0fe94bf54b2bd6904a7";

    fn setup_with_attrs(names: &[&str]) -> (PublicParams, MasterSecret) {
        let mut rng = rand::thread_rng();
        let (mut pp, msk) = setup(&mut rng);
        for n in names {
            register_attribute(&mut pp, n, &mut rng);
        }
        (pp, msk)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The same `Gt` value must always produce the identical 32-byte
    /// KDF output, and different `Gt` values must (overwhelmingly
    /// likely) produce different output.
    #[test]
    fn kdf_is_deterministic() {
        let a = kdf(&bls12_381::Gt::identity());
        let b = kdf(&bls12_381::Gt::identity());
        assert_eq!(a, b);

        let mut rng = rand::thread_rng();
        let (pp, _msk) = setup(&mut rng);
        let random_gt = pp.egg_alpha * Scalar::random(&mut rng);
        assert_ne!(a, kdf(&random_gt));
    }

    /// Known-answer test: pins `kdf(Gt::identity())` to a fixed value
    /// computed once against the exact pinned `bls12_381 = "=0.8.0"`
    /// dependency (see `gt_canonical_bytes`'s doc comment for why this
    /// matters). If this ever fails, `Gt`'s `Debug` formatting or the
    /// KDF construction changed and every previously issued
    /// ciphertext's key material is at risk of no longer round-tripping
    /// -- that must be treated as a breaking change, never silently
    /// absorbed. Regenerate with:
    ///   cargo test -p abe-core print_known_answer_vector -- --ignored --nocapture
    #[test]
    fn kdf_matches_known_answer_vector() {
        let expected_hex = KDF_IDENTITY_KAT_HEX;
        let actual = kdf(&bls12_381::Gt::identity());
        let actual_hex = hex_encode(&actual);
        assert_eq!(actual_hex.len(), 64, "kdf must always produce exactly 32 bytes");
        assert_eq!(
            actual_hex, expected_hex,
            "kdf(Gt::identity()) changed -- bls12_381's Debug formatting or the KDF \
             construction moved; see gt_canonical_bytes's doc comment before touching \
             either, and regenerate KDF_IDENTITY_KAT_HEX deliberately if this change \
             is intentional (it invalidates all previously issued key material)"
        );
    }

    /// Not a real test: run with
    ///   cargo test -p abe-core print_known_answer_vector -- --ignored --nocapture
    /// to print the current `kdf(Gt::identity())` value so it can be
    /// pasted into `KDF_IDENTITY_KAT_HEX` below.
    #[test]
    #[ignore]
    fn print_known_answer_vector() {
        let v = kdf(&bls12_381::Gt::identity());
        println!("KDF_IDENTITY_KAT_HEX = \"{}\"", hex_encode(&v));
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
