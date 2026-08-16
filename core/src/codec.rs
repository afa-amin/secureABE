//! JSON (de)serialization for the curve-based types in [`crate::keys`].
//! `bls12_381` group elements don't implement `serde::Serialize`
//! upstream, so this module round-trips them through their canonical
//! compressed byte encodings instead.

use crate::error::AbeError;
use crate::keys::{
    AbeCiphertext, AttributeCommitment, AttributeKeyShare, LeafCiphertext, MasterSecret,
    PublicParams, UserSecretKey, WrappedKey,
};
use abe_policy::AccessTree;
use bls12_381::{G1Affine, G2Affine, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn enc(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn dec(s: &str) -> Result<Vec<u8>, AbeError> {
    hex::decode(s).map_err(|e| AbeError::Encoding(e.to_string()))
}

fn g1_to_hex(p: &G1Affine) -> String {
    enc(&p.to_compressed())
}
fn g1_from_hex(s: &str) -> Result<G1Affine, AbeError> {
    let bytes = dec(s)?;
    let arr: [u8; 48] = bytes
        .try_into()
        .map_err(|_| AbeError::Encoding("bad G1 length".into()))?;
    Option::<G1Affine>::from(G1Affine::from_compressed(&arr))
        .ok_or_else(|| AbeError::Encoding("invalid G1 point".into()))
}

fn g2_to_hex(p: &G2Affine) -> String {
    enc(&p.to_compressed())
}
fn g2_from_hex(s: &str) -> Result<G2Affine, AbeError> {
    let bytes = dec(s)?;
    let arr: [u8; 96] = bytes
        .try_into()
        .map_err(|_| AbeError::Encoding("bad G2 length".into()))?;
    Option::<G2Affine>::from(G2Affine::from_compressed(&arr))
        .ok_or_else(|| AbeError::Encoding("invalid G2 point".into()))
}

fn scalar_to_hex(s: &Scalar) -> String {
    enc(&s.to_bytes())
}
fn scalar_from_hex(s: &str) -> Result<Scalar, AbeError> {
    let bytes = dec(s)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AbeError::Encoding("bad scalar length".into()))?;
    Option::<Scalar>::from(Scalar::from_bytes(&arr))
        .ok_or_else(|| AbeError::Encoding("invalid scalar".into()))
}

// --- Public parameters ---------------------------------------------

#[derive(Serialize, Deserialize)]
struct AttrCommitmentDto {
    t1: String,
    t2: String,
}

#[derive(Serialize, Deserialize)]
struct PublicParamsDto {
    g1: String,
    g2: String,
    h: String,
    egg_alpha: String,
    attributes: HashMap<String, AttrCommitmentDto>,
}

fn gt_to_hex(gt: &bls12_381::Gt) -> String {
    // Gt has no canonical compressed encoding upstream; its Debug
    // output is a deterministic hex dump of every underlying Fp limb,
    // which is sufficient for our purposes (round-tripping our own
    // values, and as KDF input in `scheme.rs`). It cannot be parsed
    // back into a `Gt`, so PublicParams round-tripping stores it only
    // for display/audit purposes and callers must not rely on
    // reconstructing `egg_alpha` from this string; the field is
    // recomputed instead (see `public_params_from_json`).
    format!("{:?}", gt)
}

pub fn public_params_to_json(pp: &PublicParams) -> String {
    let dto = PublicParamsDto {
        g1: g1_to_hex(&pp.g1),
        g2: g2_to_hex(&pp.g2),
        h: g1_to_hex(&pp.h),
        egg_alpha: gt_to_hex(&pp.egg_alpha),
        attributes: pp
            .attributes
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    AttrCommitmentDto {
                        t1: g1_to_hex(&v.t1),
                        t2: g2_to_hex(&v.t2),
                    },
                )
            })
            .collect(),
    };
    serde_json::to_string_pretty(&dto).expect("serialization cannot fail")
}

/// A setup bundle keeps `PublicParams` and `MasterSecret` together so
/// that `egg_alpha` can always be recomputed exactly (`e(g1,g2)^alpha`)
/// instead of needing a (nonexistent) `Gt` parser.
#[derive(Serialize, Deserialize)]
pub struct SetupBundleDto {
    alpha: String,
    beta: String,
    attributes: HashMap<String, AttrCommitmentDto>,
}

pub fn setup_bundle_to_json(pp: &PublicParams, msk: &MasterSecret) -> String {
    let dto = SetupBundleDto {
        alpha: scalar_to_hex(&msk.alpha),
        beta: scalar_to_hex(&msk.beta),
        attributes: pp
            .attributes
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    AttrCommitmentDto {
                        t1: g1_to_hex(&v.t1),
                        t2: g2_to_hex(&v.t2),
                    },
                )
            })
            .collect(),
    };
    serde_json::to_string_pretty(&dto).expect("serialization cannot fail")
}

pub fn setup_bundle_from_json(s: &str) -> Result<(PublicParams, MasterSecret), AbeError> {
    let dto: SetupBundleDto =
        serde_json::from_str(s).map_err(|e| AbeError::Encoding(e.to_string()))?;
    let alpha = scalar_from_hex(&dto.alpha)?;
    let beta = scalar_from_hex(&dto.beta)?;
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let h: G1Affine = (bls12_381::G1Projective::from(g1) * beta).into();
    let egg_alpha = bls12_381::pairing(&g1, &g2) * alpha;
    let mut attributes = HashMap::new();
    for (k, v) in dto.attributes {
        attributes.insert(
            k,
            AttributeCommitment {
                t1: g1_from_hex(&v.t1)?,
                t2: g2_from_hex(&v.t2)?,
            },
        );
    }
    Ok((
        PublicParams {
            g1,
            g2,
            h,
            egg_alpha,
            attributes,
        },
        MasterSecret { alpha, beta },
    ))
}

// NOTE: `public_params_to_json` above is a display/audit export only —
// it cannot be parsed back into a working `PublicParams` because `Gt`
// has no canonical byte decoder in the underlying curve crate. Any
// process that needs a *working* `PublicParams` (to encrypt or to
// verify a key) must load it via `setup_bundle_from_json`, i.e. it must
// run alongside (or be trusted with) the authority's master secret
// bundle. In this reference implementation the CLI plays that role: it
// keeps the setup bundle in `<data-dir>/setup.json` and every command
// loads `PublicParams` through it. A production deployment would keep
// `setup.json` inside an HSM or isolated authority process and expose
// only the operations (`register_attribute`, `issue`, `encrypt`) as an
// API, never the file itself.

// --- User secret key -------------------------------------------------

#[derive(Serialize, Deserialize)]
struct AttrKeyShareDto {
    d_j: String,
    d_j_prime: String,
}

#[derive(Serialize, Deserialize)]
struct UserSecretKeyDto {
    subject: String,
    d: String,
    attributes: HashMap<String, AttrKeyShareDto>,
}

pub fn user_key_to_json(usk: &UserSecretKey) -> String {
    let dto = UserSecretKeyDto {
        subject: usk.subject.clone(),
        d: g2_to_hex(&usk.d),
        attributes: usk
            .attributes
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    AttrKeyShareDto {
                        d_j: g2_to_hex(&v.d_j),
                        d_j_prime: g2_to_hex(&v.d_j_prime),
                    },
                )
            })
            .collect(),
    };
    serde_json::to_string_pretty(&dto).expect("serialization cannot fail")
}

pub fn user_key_from_json(s: &str) -> Result<UserSecretKey, AbeError> {
    let dto: UserSecretKeyDto =
        serde_json::from_str(s).map_err(|e| AbeError::Encoding(e.to_string()))?;
    let mut attributes = HashMap::new();
    for (k, v) in dto.attributes {
        attributes.insert(
            k,
            AttributeKeyShare {
                d_j: g2_from_hex(&v.d_j)?,
                d_j_prime: g2_from_hex(&v.d_j_prime)?,
            },
        );
    }
    Ok(UserSecretKey {
        subject: dto.subject,
        d: g2_from_hex(&dto.d)?,
        attributes,
    })
}

// --- Ciphertext --------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct LeafCiphertextDto {
    path: Vec<usize>,
    attribute: String,
    cy: String,
    cy_prime: String,
}

#[derive(Serialize, Deserialize)]
struct WrappedKeyDto {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct AbeCiphertextDto {
    tree: AccessTree,
    c: String,
    leaves: Vec<LeafCiphertextDto>,
    wrapped_key: WrappedKeyDto,
}

pub fn ciphertext_to_json(ct: &AbeCiphertext) -> String {
    let dto = AbeCiphertextDto {
        tree: ct.tree.clone(),
        c: g1_to_hex(&ct.c),
        leaves: ct
            .leaves
            .iter()
            .map(|l| LeafCiphertextDto {
                path: l.path.clone(),
                attribute: l.attribute.clone(),
                cy: g1_to_hex(&l.cy),
                cy_prime: g1_to_hex(&l.cy_prime),
            })
            .collect(),
        wrapped_key: WrappedKeyDto {
            nonce: enc(&ct.wrapped_key.nonce),
            ciphertext: enc(&ct.wrapped_key.ciphertext),
        },
    };
    serde_json::to_string_pretty(&dto).expect("serialization cannot fail")
}

pub fn ciphertext_from_json(s: &str) -> Result<AbeCiphertext, AbeError> {
    let dto: AbeCiphertextDto =
        serde_json::from_str(s).map_err(|e| AbeError::Encoding(e.to_string()))?;
    let mut leaves = Vec::new();
    for l in dto.leaves {
        leaves.push(LeafCiphertext {
            path: l.path,
            attribute: l.attribute,
            cy: g1_from_hex(&l.cy)?,
            cy_prime: g1_from_hex(&l.cy_prime)?,
        });
    }
    let nonce_bytes = dec(&dto.wrapped_key.nonce)?;
    let nonce: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| AbeError::Encoding("bad nonce length".into()))?;
    Ok(AbeCiphertext {
        tree: dto.tree,
        c: g1_from_hex(&dto.c)?,
        leaves,
        wrapped_key: WrappedKey {
            nonce,
            ciphertext: dec(&dto.wrapped_key.ciphertext)?,
        },
    })
}
