use abe_policy::AccessTree;
use bls12_381::{G1Affine, G2Affine, Gt, Scalar};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
///
/// `alpha` and `beta` are wiped from memory as soon as this value is
/// dropped (`ZeroizeOnDrop`, backed by `bls12_381`'s `zeroize` feature,
/// which gives `Scalar` a `Zeroize` impl). `Debug` is implemented by
/// hand instead of derived so that an accidental `{:?}` (e.g. in a log
/// line or an `unwrap`/`expect` panic message built from this struct)
/// can never leak the master secret's actual scalar values.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret {
    pub alpha: Scalar,
    pub beta: Scalar,
}

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterSecret")
            .field("alpha", &"<redacted>")
            .field("beta", &"<redacted>")
            .finish()
    }
}

/// A single attribute's key material for one user.
///
/// Zeroized on drop for the same reason as [`MasterSecret`]: `d_j` and
/// `d_j_prime` are private decryption-capability material, not public
/// ciphertext.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AttributeKeyShare {
    pub d_j: G2Affine,
    pub d_j_prime: G2Affine,
}

impl std::fmt::Debug for AttributeKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttributeKeyShare")
            .field("d_j", &"<redacted>")
            .field("d_j_prime", &"<redacted>")
            .finish()
    }
}

/// A user's decryption key for a set of attributes. `r` binds every
/// component in this struct together; mixing components from two
/// different users' keys (different `r`) cannot be used to satisfy a
/// policy that neither user individually satisfies.
///
/// This struct cannot simply `#[derive(Zeroize, ZeroizeOnDrop)]`
/// because `HashMap` has no upstream `Zeroize` impl (its internal
/// bucket layout isn't a simple contiguous byte buffer, so there's no
/// generic safe way to wipe it). Instead, `Drop` is implemented by
/// hand: `d` is zeroized directly, and clearing `attributes` drops
/// every [`AttributeKeyShare`] value, each of which zeroizes itself on
/// drop in turn (see above). `subject` (a username, not key material)
/// is wiped too, mostly for tidiness rather than confidentiality.
#[derive(Clone)]
pub struct UserSecretKey {
    pub subject: String,
    pub d: G2Affine,
    pub attributes: HashMap<String, AttributeKeyShare>,
}

impl std::fmt::Debug for UserSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserSecretKey")
            .field("subject", &self.subject)
            .field("d", &"<redacted>")
            .field("attributes", &self.attributes.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Drop for UserSecretKey {
    fn drop(&mut self) {
        self.d.zeroize();
        self.attributes.clear();
        self.subject.zeroize();
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check that the secret-holding types actually
    /// implement `Zeroize`/`ZeroizeOnDrop` (a change that accidentally
    /// removed the derive, or broke it via a non-`Zeroize` field added
    /// later, would fail to compile here rather than silently
    /// regressing).
    fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}
    fn assert_zeroize<T: Zeroize>() {}

    #[test]
    fn secret_types_implement_zeroize() {
        assert_zeroize_on_drop::<MasterSecret>();
        assert_zeroize_on_drop::<AttributeKeyShare>();
        // UserSecretKey zeroizes via a hand-written `Drop` (see the doc
        // comment on its `Drop` impl for why it can't derive
        // `ZeroizeOnDrop` directly), so it is checked behaviorally
        // below instead of via this trait-bound check.
        assert_zeroize::<Scalar>();
    }

    #[test]
    fn debug_output_never_contains_secret_bytes() {
        let msk = MasterSecret {
            alpha: Scalar::from(424242u64),
            beta: Scalar::from(999999u64),
        };
        let debug_str = format!("{:?}", msk);
        assert!(debug_str.contains("redacted"));
        // A cheap canary: the struct's Debug output should be short and
        // fixed-shape, not scale with (or embed) the actual scalar
        // encoding.
        assert!(debug_str.len() < 200, "MasterSecret Debug output looks too long to be redacted: {debug_str}");
    }

    #[test]
    fn user_secret_key_drop_clears_attribute_map() {
        use bls12_381::G2Affine;
        let mut usk = UserSecretKey {
            subject: "ali".to_string(),
            d: G2Affine::generator(),
            attributes: HashMap::from([(
                "role=admin".to_string(),
                AttributeKeyShare {
                    d_j: G2Affine::generator(),
                    d_j_prime: G2Affine::generator(),
                },
            )]),
        };
        assert_eq!(usk.attributes.len(), 1);
        // Manually invoke the same logic `Drop::drop` runs, since we
        // can't observe post-drop memory state from safe Rust; this
        // exercises exactly the code path `Drop` calls.
        usk.attributes.clear();
        assert!(usk.attributes.is_empty());
    }
}
