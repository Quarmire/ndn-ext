//! v2 service layer (service-layer spec §4, §12).
//!
//! The v2 correction relative to the NDNSF compat layer: **an authority's
//! decisions are signed, named, cacheable Data objects, not the live state of a
//! running daemon** (§4.1). This crate starts that layer with [`PolicyAuthority`]
//! — a *scoped* authority (§4.3) that holds **versioned, signed** access grants
//! and mutates them at runtime (grant / revoke) **without a restart**: each
//! change bumps a version and the authority re-signs the affected grant object.
//!
//! Why this shape (vs. mutating a running daemon's hidden config):
//! - **Dynamic by construction.** Granting or revoking is publishing a new signed
//!   version; key issuance reads the current version, so changes take effect live.
//! - **Cacheable / available.** A consumer can validate a grant from a peer or a
//!   repo even if the authority is momentarily offline.
//! - **Auditable.** The signed version history *is* the audit log.
//! - **Revocation is honest.** A revoked grant publishes a `revoked` version;
//!   because ABE keys are not individually revocable once issued, real revocation
//!   pairs this with short validity / epoch rotation (the `confidentiality`
//!   `EpochPolicy`) — pull-based revocation alone is not relied upon.
//!
//! The operator→authority *input* channel (a config file + reload, or a signed
//! `/<scope>/policy/{grant,revoke}` command Interest) drives [`PolicyAuthority`]'s
//! grant/revoke API; both converge on "mutate → bump version → re-sign →
//! republish". That mgmt/config front-end is a later increment; this is the core
//! dynamic mechanism it builds on.

#![deny(missing_docs)]

/// The operator→authority command front-end: signed grant/revoke commands that
/// drive a live [`PolicyAuthority`].
pub mod command;
pub use command::{PolicyController, grant_command, revoke_command};

/// Tier-2 typed pub/sub: [`topic::Topic<T>`], the feed primitive.
pub mod topic;
pub use topic::{Subscription, Topic};

/// Tier-2 collaboration: scoped [`session::Session`]s with confidential typed
/// topics, plus role-scoped keys ([`session::RoleScopePolicy`] / [`session::ScopedSession`]).
pub mod session;
pub use session::{
    ArtifactShare, RoleScopePolicy, ScopeKeyring, ScopedSession, ScopedSubscription, ScopedTopic,
    Session,
};

/// Key distribution: seal a member's role-scoped keyring to its X25519 key.
pub mod key_dist;
pub use key_dist::{open_keyring, provision_keyring};

/// Tier-1 discovery-selection carrier: discover providers, select, invoke over an
/// inner Tier-0 carrier.
pub mod discovery_carrier;
pub use discovery_carrier::{
    DiscoveryCarrier, MemoryDirectory, NamingConvention, ProviderDirectory, ProviderEntry,
};

/// A production [`ProviderDirectory`] backed by `ndn-discovery` (feature `discovery`).
#[cfg(feature = "discovery")]
pub mod sd_directory;
#[cfg(feature = "discovery")]
pub use sd_directory::ServiceDiscoveryDirectory;

/// The policy→issuance bridge (feature `issuance`): gate KP-ABE key issuance on
/// the current [`PolicyAuthority`] grant.
#[cfg(feature = "issuance")]
pub mod issuance;
#[cfg(feature = "issuance")]
pub use issuance::{IssueError, issue_decryption_key};

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::validator::ValidationResult;
use ndn_security::{SignWith, Signer, Validator};
use ndn_service_core::framing::{encode_fields, read_field};
use ndn_service_core::{Frame, ServiceError};

/// One principal's access grant as published by a [`PolicyAuthority`]: the
/// KP-ABE key-policy expression it is granted, whether it is currently revoked,
/// and the policy version at which this state was set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The granted KP-ABE key-policy expression (parsed by the key authority).
    pub policy: String,
    /// Whether this grant is currently revoked.
    pub revoked: bool,
    /// The authority policy version at which this grant reached its current state.
    pub version: u64,
}

impl Grant {
    /// Encode the grant body (the signed Data's content).
    pub fn encode(&self) -> Bytes {
        encode_fields(&[
            Frame::encode(&self.policy),
            Frame::encode(&self.revoked),
            Frame::encode(&self.version),
        ])
    }

    /// Decode a grant body.
    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        let mut pos = 0usize;
        Ok(Grant {
            policy: String::decode(read_field(bytes, &mut pos)?)?,
            revoked: bool::decode(read_field(bytes, &mut pos)?)?,
            version: u64::decode(read_field(bytes, &mut pos)?)?,
        })
    }
}

/// The name of the signed grant object for `principal` at `version`:
/// `<scope>/policy/<principal-uri>/v=<version>`. The principal name is carried as
/// a single URI component so it never collides with the scope path.
fn grant_name(scope: &Name, principal: &Name, version: u64) -> Name {
    scope
        .clone()
        .append("policy")
        .append(principal.to_string().as_bytes())
        .append(format!("v={version}").as_bytes())
}

/// A scoped policy authority (§4.3): it signs access grants over the namespace it
/// is trust-rooted for. The authority's signing identity must be under `scope`
/// (so its signature validates hierarchically for `<scope>/policy/…`).
///
/// Mutations ([`grant`](Self::grant) / [`revoke`](Self::revoke)) take effect
/// immediately on the live authority and bump the policy [`version`](Self::version);
/// [`signed_grant`](Self::signed_grant) produces the current signed object for a
/// principal. No restart is required to change policy.
pub struct PolicyAuthority {
    scope: Name,
    signer: Arc<dyn Signer>,
    grants: HashMap<Name, Grant>,
    version: u64,
}

impl PolicyAuthority {
    /// A new authority for `scope`, signing with `signer` (whose identity must be
    /// under `scope`). Starts at version 0 with no grants.
    pub fn new(scope: Name, signer: Arc<dyn Signer>) -> Self {
        Self {
            scope,
            signer,
            grants: HashMap::new(),
            version: 0,
        }
    }

    /// The current policy version (incremented on every mutation).
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The scope this authority is trust-rooted for.
    pub fn scope(&self) -> &Name {
        &self.scope
    }

    /// Grant (or re-grant) `principal` the KP-ABE key-`policy`. Takes effect live
    /// and returns the new policy version.
    pub fn grant(&mut self, principal: Name, policy: impl Into<String>) -> u64 {
        self.version += 1;
        let version = self.version;
        self.grants.insert(
            principal,
            Grant {
                policy: policy.into(),
                revoked: false,
                version,
            },
        );
        version
    }

    /// Revoke `principal`'s grant (marks it revoked; the signed object then
    /// reports `revoked = true`). Takes effect live and returns the new policy
    /// version. A no-op returns the current version if there is no such grant.
    pub fn revoke(&mut self, principal: &Name) -> u64 {
        let Some(grant) = self.grants.get_mut(principal) else {
            return self.version;
        };
        self.version += 1;
        grant.revoked = true;
        grant.version = self.version;
        self.version
    }

    /// The current [`Grant`] for `principal`, if any.
    pub fn grant_state(&self, principal: &Name) -> Option<&Grant> {
        self.grants.get(principal)
    }

    /// Produce the signed, named grant object for `principal` at its current
    /// state: a Data `<scope>/policy/<principal>/v=<grant-version>` whose content
    /// is the [`Grant`], signed by the authority. `None` if the principal has no
    /// grant (or signing fails).
    pub fn signed_grant(&self, principal: &Name) -> Option<Bytes> {
        let grant = self.grants.get(principal)?;
        let name = grant_name(&self.scope, principal, grant.version);
        DataBuilder::new(name, grant.encode().as_ref())
            .sign_with_sync(&*self.signer)
            .ok()
    }
}

/// Validate a signed grant object against `validator`'s trust anchors and return
/// the [`Grant`] — only if the signature is valid (fail closed). The caller
/// inspects [`Grant::revoked`] / [`Grant::version`]; an unverifiable or malformed
/// object yields `None`.
pub async fn verify_grant(validator: &Validator, wire: Bytes) -> Option<Grant> {
    let data = Data::decode(wire).ok()?;
    match validator.validate(&data).await {
        ValidationResult::Valid(safe) => {
            let content = safe.data().content()?;
            Grant::decode(content).ok()
        }
        _ => None,
    }
}
