# Architecture

## Cryptographic core (`core`)

A ciphertext-policy attribute-based encryption (CP-ABE) scheme, implemented
directly against the well-reviewed `bls12_381` pairing-friendly curve crate
from the RustCrypto ecosystem (plus `group`, `ff`, `pairing`). No pairing
math, curve arithmetic, or hashing primitive is invented from scratch here;
only the ABE *construction* on top of those primitives is original to this
project.

The construction is a small-universe adaptation of Bethencourt-Sahai-Waters
(BSW07) CP-ABE, restructured for an asymmetric (Type-3) pairing
`e: G1 x G2 -> GT`:

- Each registered attribute gets a public commitment `(T1, T2) = (g1^t, g2^t)`
  for a single random exponent `t`, chosen once and then discarded.
- A user's decryption key binds every attribute-key component together with
  one random `r`, freshly sampled per key issuance. Components from two
  different users' keys use different `r` values and cannot be recombined:
  this is what keeps the scheme collusion-resistant, and is covered by a
  dedicated test (`two_partial_users_cannot_collude` in `core/src/scheme.rs`).
- Access structures are arbitrary AND/OR/threshold trees (not just flat
  DNF), evaluated at decryption time via Shamir secret sharing and Lagrange
  interpolation over the scalar field.
- Only a 32-byte data-encryption key is ever put through the pairing math
  (blinded as a `GT` element, then hashed into an AES-256-GCM key). Large
  files never touch the pairing layer directly — see the hybrid envelope
  below.

**Honest caveat:** this is a from-scratch implementation of a documented
academic construction, not a usage of an audited ABE library end-to-end
(no such library would build against the toolchain available while writing
this project — see "Why not an existing ABE crate?" below). It has unit and
property-style tests, including a specific collusion-resistance test, but it
has not had independent cryptographic review. Treat it as a reference/
teaching implementation, not something to put in front of a real adversary
without a professional audit.

### Why not an existing ABE crate?

The only maintained CP-ABE crate on crates.io (`rabe`) could not be built
against the Rust toolchain available in this environment: its dependency
graph pulls in `pest`, `serde`, and `toml`-family crates whose newer
releases require a newer `rustc`/Cargo "edition2024" feature than was
installed, and pinning around every one of those transitive versions still
left a broken `serde`-derive expansion inside `rabe` itself. Rather than
silently drop safety by working around that with `unsafe` patches to a
third-party crate, this project uses the same "don't roll your own
primitives" principle at one layer down: `bls12_381`'s pairing/curve
arithmetic is the audited component, and the ABE *scheme* built on top of it
is implemented here, tested, and documented as such.

## Policy layer (`policy`)

A small hand-written recursive-descent parser turns expressions like:

```
(department=security AND clearance>=4) OR role=admin
```

into an `AccessTree` of `Leaf`/`Gate` nodes (`Gate { threshold, children }`,
where AND is `threshold == children.len()` and OR is `threshold == 1`,
so genuinely mixed threshold gates are representable even though the DSL
only exposes AND/OR).

## Authority layer (`authorities`)

Adds two things the cryptographic core deliberately does not know about:

1. **Numeric attribute expansion.** `clearance=5` (with a declared max of,
   say, 10) expands into the cumulative strings `clearance>=1` ..
   `clearance>=5`, so a policy leaf `clearance>=4` is satisfied by anyone
   whose clearance is 4 or higher.
2. **Named authorities** with restricted attribute-key prefixes (HR issues
   `department=*`, Security issues `clearance*`/`role=*`, etc.), enforced at
   issuance time.

**Honest caveat:** every authority in this reference implementation shares
one underlying master secret (`MasterSecret { alpha, beta }`). That is a
*permission* boundary at the application layer, not a cryptographic
decentralization boundary. True decentralized multi-authority ABE, where
each authority holds independent secret material and no single party can
mint a full key alone, requires a GID-tied construction (e.g. Chase07,
Lewko-Waters) that is out of scope for this project. This also means a
user's final key has to be re-minted (not incrementally appended to) every
time a new authority issues them an additional attribute — see the comment
in `cli/src/main.rs::cmd_issue` for why, and `docs/architecture.md` here for
the underlying reason (all attribute-key components must share one `r`).

## Hybrid envelope (`envelope`)

Files are encrypted with AES-256-GCM under a random 256-bit DEK; only that
DEK is ever wrapped by the CP-ABE layer. This keeps pairing operations off
the hot path for large payloads, exactly as described in the design brief
this project is based on.

Both AES-256-GCM layers bind **Additional Authenticated Data (AAD)**:

- **File AEAD** (`envelope`): AAD = `SECURE_ABE_FILE_v1 || policy_summary`
  so tampering with the stored human-readable policy summary fails the
  authentication tag.
- **DEK-wrap AEAD** (`core::encrypt_key` / `decrypt_key`): AAD =
  `SECURE_ABE_DEK_WRAP_v1 || serde_json(AccessTree)` so swapping the
  access-tree metadata on a ciphertext cannot successfully unwrap the
  DEK even if pairing material would otherwise allow it.

Changing either domain label or the tree encoding is a breaking change
for existing ciphertexts (still acceptable at 0.1.0 before a versioned
serialization format exists).

## Storage (`storage`)

Filesystem-backed package store: `sealed.json` (AES-GCM ciphertext + nonce +
policy summary), `key_ciphertext.json` (the ABE-wrapped DEK, including the
access tree in the clear — policies are metadata, not secrets), and
`manifest.json`. A storage-only host, with no user keys and no master
secret, cannot recover plaintext from any of this.

## Revocation (`revocation`)

Epoch-tagged attributes (`clearance>=4@epoch0`, `clearance>=4@epoch1`, ...).
Bumping an attribute's epoch redirects all *future* issuance and encryption
to the new epoch. It cannot retroactively invalidate a key that was already
issued against documents already encrypted at the old epoch — no offline-key
ABE scheme can do that without re-encrypting those documents. This
limitation, and the operational mitigation (re-encrypt + rotate the DEK for
documents that must not survive a revoked user's prior access), is
documented in `revocation/src/lib.rs`.

## Audit (`audit`)

Append-only, newline-delimited JSON log. By construction (its API never
accepts key material or plaintext as an argument type it can serialize),
it cannot leak secrets even if a future caller were tempted to log them.

## CLI (`cli`)

Wires all of the above into a `secure-abe` binary: `setup`,
`register-authority`, `issue`, `encrypt`, `decrypt`, `list`, `audit`,
`revoke-attribute`, `revoke-user`, and a `demo` command that runs the full
Ali/Sara/Reza/Admin walkthrough end to end in a throwaway directory.