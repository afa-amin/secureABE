# Secure Modern ABE (Rust)

A Rust implementation of a cryptographically enforced access-control system
built on Ciphertext-Policy Attribute-Based Encryption (CP-ABE): hybrid
encryption (AES-256-GCM for the file, ABE for the file's key), a policy DSL,
a multi-authority layer, revocation, audit logging, and a full CLI.

**No Persian comments and no reference to "mosaic" exist anywhere in the
source code** (this file and the rest of `docs/` are the only exception,
since they're documentation, not code).

## An important, honest note about the cryptographic core

No ready-made, trustworthy ABE library in Rust would build against the
toolchain available in this environment (rustc 1.75) — the one known crate
(`rabe`) failed to build because of a broken dependency chain (newer
`pest`/`serde`/`toml` releases that require a newer Cargo edition). Rather
than work around that with unsafe patches to a third-party library, the
CP-ABE scheme is implemented directly on top of standard, well-reviewed
primitives (`bls12_381`, `group`, `ff`, `pairing` from RustCrypto) — a
small-universe adaptation of the well-known academic Bethencourt-Sahai-
Waters (BSW07) construction for an asymmetric (Type-3) pairing. Full details
and honest caveats about this decision are in `docs/architecture.md`.

In other words: the pairing/curve arithmetic itself is handled by the
reviewed library, but the ABE *scheme* built on top of it is this project's
own implementation — with unit tests, including a dedicated collusion-
resistance test, but without independent cryptographic review. For real-
world/production use it must be reviewed by a cryptography specialist.

## Project structure

```
secure-abe-rs/
├── core/              CP-ABE core (setup, keygen, encrypt, decrypt, codec)
├── policy/            Policy DSL parser and AccessTree
├── authorities/        Multi-authority layer + numeric attribute expansion
├── envelope/           Hybrid AES-256-GCM + ABE encryption
├── storage/            Filesystem storage for encrypted packages
├── revocation/          Epoch-based revocation
├── audit/               Append-only audit log
├── cli/                secure-abe binary
├── docs/architecture.md Full architecture writeup and limitations
├── Dockerfile
└── Cargo.toml           workspace
```

## Prerequisites

Rust (a recent stable release). To install via rustup:

```bash
curl https://sh.rustup.rs -sSf | sh
```

> This project was built and tested against `rustc 1.75`; a few
> dependencies in `Cargo.lock` are deliberately pinned to versions
> compatible with it (`clap`, `zeroize`, `pest*`). If you're on a newer
> rustc and want the latest dependency versions, just delete
> `Cargo.lock` and run `cargo build` again.

## Build

```bash
cd secure-abe-rs
cargo build --workspace
```

## Test

```bash
cargo test --workspace
```

Key tests:
- `core/src/scheme.rs::two_partial_users_cannot_collude` — two users who
  each hold only one attribute cannot combine their keys to satisfy a
  policy that neither individually satisfies.
- `core/src/scheme.rs::or_gate_admin_bypass` — the OR branch of a policy
  works correctly.
- `envelope/src/lib.rs::round_trips_a_document` — end-to-end hybrid
  encryption/decryption.
- `revocation/src/lib.rs::epoch_bumps_change_the_tag`.

## Full end-to-end demo

```bash
cargo run -p abe-cli -- demo
```

This runs exactly the scenario from the project brief: Ali (security,
clearance=5), Sara (marketing, clearance=2), Reza (security, clearance=3),
and admin1 (role=admin), against a file with the policy:

```
(department=security AND clearance>=4) OR role=admin
```

Expected output:

```
--- ali attempts to decrypt ---
Access granted.

--- sara attempts to decrypt ---
ACCESS DENIED ...

--- reza attempts to decrypt ---
ACCESS DENIED ...

--- admin1 attempts to decrypt ---
Access granted.
```

followed by the full audit trail.

## Manual CLI usage

```bash
# initialize a fresh deployment (generates the master secret + public params)
cargo run -p abe-cli -- --data ./data setup

# register authorities
cargo run -p abe-cli -- --data ./data register-authority --name hr --controls department
cargo run -p abe-cli -- --data ./data register-authority --name security --controls clearance,role

# issue a key for Ali (two authorities, two separate claims; the final key is merged automatically)
cargo run -p abe-cli -- --data ./data issue --authority hr --user ali --text department=security
cargo run -p abe-cli -- --data ./data issue --authority security --user ali --numeric clearance=5:10

# encrypt a file
echo "top secret" > secret.txt
cargo run -p abe-cli -- --data ./data encrypt --file secret.txt \
  --policy "(department=security AND clearance>=4) OR role=admin"

# list packages
cargo run -p abe-cli -- --data ./data list

# decrypt as Ali
cargo run -p abe-cli -- --data ./data decrypt --id <PACKAGE_ID> --user ali --out opened.txt

# audit log
cargo run -p abe-cli -- --data ./data audit

# revocation
cargo run -p abe-cli -- --data ./data revoke-attribute --attribute "clearance>=4"
cargo run -p abe-cli -- --data ./data revoke-user --user sara
```

## Docker

```bash
docker build -t secure-abe .
docker run --rm secure-abe demo
```

## Known limitations (honest, not sales copy)

1. The ABE core is this project's own implementation, not an independently
   audited library (see the reasoning above and in
   `docs/architecture.md`).
2. The multi-authority layer is built on **one** shared master secret — it
   is a permission boundary, not an independent cryptographic boundary.
   True multi-authority ABE (where each authority holds independent
   secret material) requires a construction like Lewko-Waters, which is
   out of scope for this version.
3. Revocation is epoch-based: keys already issued and files already
   encrypted before a revocation are unaffected until they are reissued
   or re-encrypted — this is an inherent limitation of any ABE scheme
   with offline keys, not a bug.
4. `setup.json` contains the master secret and is stored on disk in this
   reference version; in production it should live in an HSM or an
   isolated authority process.