//! Attribute-authority layer sitting above the raw CP-ABE primitive.
//!
//! Two things live here that the cryptographic core deliberately knows
//! nothing about:
//!
//! 1. **Numeric attribute expansion.** The core only understands opaque
//!    attribute strings. A claim like `clearance=5` is expanded here
//!    into the cumulative strings `clearance>=1` .. `clearance>=5`, so
//!    that a policy leaf `clearance>=4` is satisfied by anyone whose
//!    clearance is 4 or higher, without the pairing layer ever needing
//!    to reason about integers.
//!
//! 2. **Named authorities.** Real deployments want HR to control
//!    `department=*`, a security team to control `clearance*`, etc.
//!    This module lets you register named authorities and restrict
//!    which attribute prefixes each may issue. Note this is an
//!    application-layer access-control convenience on top of a single
//!    shared master secret, not a decentralized multi-authority ABE
//!    scheme (that would require independent master secrets per
//!    authority, e.g. Lewko-Waters-style constructions) — see the
//!    project README for this trade-off.

use abe_audit::{AuditEvent, AuditLog};
use abe_core::{keygen, register_attribute, AbeError, MasterSecret, PublicParams, UserSecretKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error(transparent)]
    Abe(#[from] AbeError),
    #[error("authority '{0}' is not registered")]
    UnknownAuthority(String),
    #[error("authority '{0}' is not permitted to issue attribute '{1}'")]
    NotPermitted(String, String),
    #[error(transparent)]
    Audit(#[from] abe_audit::AuditError),
}

/// A single attribute claim made about a user, before expansion into
/// the flat attribute strings the ABE core understands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Claim {
    /// A boolean/flag attribute, e.g. "role=admin".
    Flag(String),
    /// A textual attribute, e.g. key="department", value="security"
    /// resolves to "department=security".
    Text { key: String, value: String },
    /// A numeric attribute with cumulative threshold semantics, e.g.
    /// key="clearance", value=5, max=10 resolves to the five strings
    /// "clearance>=1" .. "clearance>=5".
    Numeric { key: String, value: i64, max: i64 },
}

impl Claim {
    pub fn resolve(&self) -> Vec<String> {
        match self {
            Claim::Flag(s) => vec![s.clone()],
            Claim::Text { key, value } => vec![format!("{key}={value}")],
            Claim::Numeric { key, value, max } => {
                let top = (*value).min(*max).max(0);
                (1..=top).map(|i| format!("{key}>={i}")).collect()
            }
        }
    }

    pub fn key_prefix(&self) -> String {
        match self {
            Claim::Flag(s) => s.split('=').next().unwrap_or(s).to_string(),
            Claim::Text { key, .. } => key.clone(),
            Claim::Numeric { key, .. } => key.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authority {
    pub name: String,
    /// Attribute key prefixes (e.g. "department", "clearance") this
    /// authority is permitted to issue claims for. Empty means
    /// unrestricted.
    pub controls: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthorityRegistry {
    pub authorities: HashMap<String, Authority>,
}

impl AuthorityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, name: &str, controls: Vec<String>) {
        self.authorities.insert(
            name.to_string(),
            Authority {
                name: name.to_string(),
                controls,
            },
        );
    }

    pub fn check_permission(&self, authority: &str, claim: &Claim) -> Result<(), AuthorityError> {
        let a = self
            .authorities
            .get(authority)
            .ok_or_else(|| AuthorityError::UnknownAuthority(authority.to_string()))?;
        if a.controls.is_empty() {
            return Ok(());
        }
        let prefix = claim.key_prefix();
        if a.controls.iter().any(|c| c == &prefix) {
            Ok(())
        } else {
            Err(AuthorityError::NotPermitted(
                authority.to_string(),
                prefix,
            ))
        }
    }
}

/// Issues attribute claims for `subject`, expanding them into flat
/// attribute strings, registering any new ones in the public
/// parameters, minting the CP-ABE user key, and recording an audit
/// trail entry per claim. Never logs key material.
#[allow(clippy::too_many_arguments)]
pub fn issue<R: RngCore + CryptoRng>(
    pp: &mut PublicParams,
    msk: &MasterSecret,
    registry: &AuthorityRegistry,
    authority: &str,
    subject: &str,
    claims: &[Claim],
    audit: &AuditLog,
    rng: &mut R,
) -> Result<UserSecretKey, AuthorityError> {
    let mut flat_attrs = Vec::new();
    for claim in claims {
        registry.check_permission(authority, claim)?;
        for a in claim.resolve() {
            register_attribute(pp, &a, rng);
            flat_attrs.push(a);
        }
    }

    let usk = keygen(pp, msk, subject, &flat_attrs, rng)?;

    audit.record(AuditEvent::new(
        authority,
        "ISSUE_KEY",
        subject,
        &format!("attributes={}", flat_attrs.join(",")),
    ))?;

    Ok(usk)
}
