//! The policy→issuance bridge (feature `issuance`): gate KP-ABE key issuance on
//! the **current** [`PolicyAuthority`] grant, closing the v2 loop. The
//! `PolicyAuthority` is the source of truth (signed, versioned policy); the
//! `KpAuthority` is the key authority (keygen + sealing). Issuance reads policy
//! live, so a grant/revoke takes effect with no restart.

use bytes::Bytes;
use ndn_nacabe::KpAuthority;
use ndn_packet::Name;
use ndn_security::abe::PolicyExpr;

use crate::PolicyAuthority;

/// Why a policy-gated key issuance was refused (all fail closed — no key bytes).
#[derive(Debug)]
pub enum IssueError {
    /// The requester has no grant from this policy authority.
    Unauthorized,
    /// The requester's grant exists but is revoked.
    Revoked,
    /// The grant's key-policy expression does not parse.
    BadPolicy(String),
    /// Keygen or sealing failed.
    Issue(String),
}

impl std::fmt::Display for IssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueError::Unauthorized => write!(f, "no grant for the requester"),
            IssueError::Revoked => write!(f, "the requester's grant is revoked"),
            IssueError::BadPolicy(e) => write!(f, "grant policy does not parse: {e}"),
            IssueError::Issue(e) => write!(f, "key issuance failed: {e}"),
        }
    }
}

impl std::error::Error for IssueError {}

/// Issue a KP decryption key to `requester`, gated by the **current** policy in
/// `policy` (read live): the requester must have a non-revoked grant whose
/// key-policy expression parses; otherwise fail closed. `kp` performs the keygen
/// and seals the key to `recipient_public` (the requester's ephemeral X25519
/// key) under the granted policy — it is the key authority, while `policy` is the
/// source of truth. A grant or revoke since the previous call takes effect
/// immediately, with no restart of either authority.
#[tracing::instrument(skip(policy, kp, recipient_public), fields(requester = %requester))]
pub fn issue_decryption_key(
    policy: &PolicyAuthority,
    kp: &KpAuthority,
    requester: &Name,
    recipient_public: &[u8],
) -> Result<Bytes, IssueError> {
    let grant = policy.grant_state(requester).ok_or(IssueError::Unauthorized)?;
    if grant.revoked {
        return Err(IssueError::Revoked);
    }
    let expr = PolicyExpr::parse(&grant.policy).map_err(|e| IssueError::BadPolicy(format!("{e:?}")))?;
    kp.issue_with_policy(requester, &expr, recipient_public)
        .map_err(|e| IssueError::Issue(e.to_string()))
}
