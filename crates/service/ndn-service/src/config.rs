//! Declarative policy front-end (feature `config`): load a TOML policy file and
//! **reload** it into a live [`PolicyAuthority`] — the declarative twin of the
//! signed-command front-end ([`crate::command`]).
//!
//! Reload diffs the desired grants against the authority's current state and
//! applies the difference: a new or changed principal is (re)granted, a principal
//! dropped from the file is revoked. Each change bumps the version and re-signs —
//! the same "mutate → bump version → re-sign → republish" effect as a command,
//! driven by an operator editing a file (matching NDNSF's `policy_file` workflow).
//! Reload is idempotent: applying the same file twice changes nothing.
//!
//! ```toml
//! [[grant]]
//! principal = "/muas/alice"
//! policy    = "service:echo OR service:cam"
//!
//! [[grant]]
//! principal = "/muas/bob"
//! policy    = "service:telemetry"
//! ```

use std::collections::HashMap;

use ndn_packet::Name;

use crate::PolicyAuthority;

/// Why a policy config could not be loaded.
#[derive(Debug)]
pub enum ConfigError {
    /// The TOML did not parse.
    Toml(String),
    /// A `principal` value was not a valid name.
    BadPrincipal(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Toml(e) => write!(f, "policy config did not parse: {e}"),
            ConfigError::BadPrincipal(p) => write!(f, "invalid principal name: {p}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(serde::Deserialize)]
struct PolicyConfig {
    #[serde(default)]
    grant: Vec<GrantEntry>,
}

#[derive(serde::Deserialize)]
struct GrantEntry {
    principal: String,
    policy: String,
}

/// Parse a policy TOML into the desired `(principal, policy)` grants.
pub fn load_policy_toml(src: &str) -> Result<Vec<(Name, String)>, ConfigError> {
    let config: PolicyConfig = toml::from_str(src).map_err(|e| ConfigError::Toml(e.to_string()))?;
    config
        .grant
        .into_iter()
        .map(|g| {
            let name = g
                .principal
                .parse::<Name>()
                .map_err(|_| ConfigError::BadPrincipal(g.principal.clone()))?;
            Ok((name, g.policy))
        })
        .collect()
}

/// What a [`reload`] changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReloadReport {
    /// Principals (re)granted because they were new or their policy changed.
    pub granted: Vec<Name>,
    /// Principals revoked because they were dropped from the desired set.
    pub revoked: Vec<Name>,
    /// The authority's policy version after the reload.
    pub version: u64,
}

impl ReloadReport {
    /// Whether the reload changed anything.
    pub fn is_noop(&self) -> bool {
        self.granted.is_empty() && self.revoked.is_empty()
    }
}

/// Reload `desired` grants into the live `authority`: (re)grant new/changed
/// principals, revoke principals no longer present. Each change bumps the version
/// and re-signs (no restart). Idempotent for an unchanged file.
///
/// ## Trust boundary (SEC-26)
///
/// The config file is a **full-state source of truth**, not a delta: a reload
/// revokes any active principal absent from the file and (re)grants those present —
/// so it *will* re-grant a principal that the signed-command channel
/// ([`crate::command`]) previously revoked, if the file still lists it. Its
/// authorization is therefore **filesystem write-access** to the file, which MUST be
/// operator-controlled (not a networked/shared path). Do not drive one authority
/// from both the file and the command channel — pick a single source of truth, or a
/// file edit and a command revoke will fight. (A signed-config object validated
/// against the admin anchor would let the file be delivered untrusted; not built.)
pub fn reload(authority: &mut PolicyAuthority, desired: &[(Name, String)]) -> ReloadReport {
    let desired_map: HashMap<&Name, &String> = desired.iter().map(|(n, p)| (n, p)).collect();
    let mut report = ReloadReport::default();

    // (Re)grant: a principal that is new, revoked, or whose policy changed.
    for (principal, policy) in desired {
        let needs_grant = match authority.grant_state(principal) {
            None => true,
            Some(grant) => grant.revoked || &grant.policy != policy,
        };
        if needs_grant {
            authority.grant(principal.clone(), policy.clone());
            report.granted.push(principal.clone());
        }
    }

    // Revoke: an active principal no longer in the desired set.
    let to_revoke: Vec<Name> = authority
        .grants()
        .filter(|(p, g)| !g.revoked && !desired_map.contains_key(p))
        .map(|(p, _)| p.clone())
        .collect();
    for principal in to_revoke {
        authority.revoke(&principal);
        report.revoked.push(principal);
    }

    report.version = authority.version();
    report
}
