//! Service-access policy model (feature `driver`).
//!
//! The NDNSF `ServiceController` is driven by a policy file mapping identities to
//! the services they may use; it compiles each into a KP-ABE key-policy and
//! issues it. This module mirrors that: a TOML policy (the §11 convention) parses
//! into [`ServicePolicy`], and [`ServicePolicy::apply_to`] compiles each
//! principal's `allowed_services` into the OR-join KP-ABE policy
//! `service:<a> OR service:<b> …` and grants it on a [`KpAuthority`].
//!
//! ```toml
//! [[users]]
//! identity = "/muas/alice"
//! allowed_services = ["echo", "cam"]
//!
//! [[providers]]
//! identity = "/muas/bob"
//! allowed_services = ["echo"]
//! ```

use ndn_nacabe::KpAuthority;
use ndn_packet::Name;
use ndn_security::abe::PolicyExpr;
use serde::Deserialize;

/// Errors building or applying a service policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The TOML failed to parse.
    #[error("policy parse error: {0}")]
    Toml(String),
    /// A principal's `identity` was not a valid NDN name.
    #[error("invalid identity name: {0}")]
    Identity(String),
    /// A principal granted no services (an empty KP-ABE policy is meaningless).
    #[error("principal '{0}' has no allowed services")]
    Empty(String),
    /// The compiled KP-ABE policy expression was rejected.
    #[error("policy expression error: {0}")]
    Expr(String),
}

/// One principal's access grant: an identity and the services it may use.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PrincipalPolicy {
    /// The principal's NDN identity name.
    pub identity: String,
    /// The service names it is allowed to use (bare, e.g. `"echo"`).
    pub allowed_services: Vec<String>,
}

impl PrincipalPolicy {
    /// Compile into the OR-join KP-ABE policy `service:<a> OR service:<b> …`.
    pub fn to_policy_expr(&self) -> Result<PolicyExpr, PolicyError> {
        if self.allowed_services.is_empty() {
            return Err(PolicyError::Empty(self.identity.clone()));
        }
        let joined = self
            .allowed_services
            .iter()
            .map(|s| format!("service:{s}"))
            .collect::<Vec<_>>()
            .join(" OR ");
        PolicyExpr::parse(&joined).map_err(|e| PolicyError::Expr(format!("{e:?}")))
    }
}

/// A parsed service-access policy: provider and user grants.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct ServicePolicy {
    /// Providers and the services they may serve.
    #[serde(default)]
    pub providers: Vec<PrincipalPolicy>,
    /// Users and the services they may invoke.
    #[serde(default)]
    pub users: Vec<PrincipalPolicy>,
}

impl ServicePolicy {
    /// Parse a TOML policy file.
    pub fn from_toml(src: &str) -> Result<Self, PolicyError> {
        toml::from_str(src).map_err(|e| PolicyError::Toml(e.to_string()))
    }

    /// Grant every **user**'s compiled key-policy on `aa` (the controller's
    /// KP-ABE authority). Returns how many grants were applied.
    pub fn apply_to(&self, aa: &mut KpAuthority) -> Result<usize, PolicyError> {
        let mut n = 0;
        for u in &self.users {
            let identity: Name = u
                .identity
                .parse()
                .map_err(|_| PolicyError::Identity(u.identity.clone()))?;
            aa.grant(identity, u.to_policy_expr()?);
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::abe::lsw_setup;

    const SAMPLE: &str = r#"
        [[users]]
        identity = "/muas/alice"
        allowed_services = ["echo", "cam"]

        [[users]]
        identity = "/muas/mallory"
        allowed_services = ["other"]

        [[providers]]
        identity = "/muas/bob"
        allowed_services = ["echo"]
    "#;

    #[test]
    fn parses_users_and_providers() {
        let p = ServicePolicy::from_toml(SAMPLE).unwrap();
        assert_eq!(p.users.len(), 2);
        assert_eq!(p.providers.len(), 1);
        assert_eq!(p.users[0].identity, "/muas/alice");
        assert_eq!(p.users[0].allowed_services, vec!["echo", "cam"]);
    }

    #[test]
    fn compiles_or_join_policy() {
        let pp = PrincipalPolicy {
            identity: "/muas/alice".into(),
            allowed_services: vec!["echo".into(), "cam".into()],
        };
        // Parses without error (the OR-join is a valid KP-ABE policy).
        assert!(pp.to_policy_expr().is_ok());
    }

    #[test]
    fn empty_services_is_rejected() {
        let pp = PrincipalPolicy {
            identity: "/x".into(),
            allowed_services: vec![],
        };
        assert!(matches!(pp.to_policy_expr(), Err(PolicyError::Empty(_))));
    }

    #[test]
    fn apply_grants_take_effect_on_the_authority() {
        // After applying the policy, granted users can be issued a key; an
        // identity absent from the policy fails closed (Unauthorized).
        let (mp, ms) = lsw_setup().unwrap();
        let mut aa = KpAuthority::new(mp, ms);
        let policy = ServicePolicy::from_toml(SAMPLE).unwrap();
        assert_eq!(policy.apply_to(&mut aa).unwrap(), 2);

        let recipient = ndn_sealed_box::Recipient::generate().unwrap();
        assert!(
            aa.issue_dkey(&"/muas/alice".parse().unwrap(), &recipient.public)
                .is_ok()
        );

        let recipient2 = ndn_sealed_box::Recipient::generate().unwrap();
        assert!(
            aa.issue_dkey(&"/muas/stranger".parse().unwrap(), &recipient2.public)
                .is_err(),
            "an identity absent from the policy must not be issued a key"
        );
    }
}
