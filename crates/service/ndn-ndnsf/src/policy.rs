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

use std::collections::{HashMap, HashSet};

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

    /// Compile the `providers` grants into a [`ProviderAuthorizer`] — the runtime
    /// check the four-phase client uses to refuse an ACK from a provider not
    /// authorized to serve the invoked service (the enforcement of the
    /// otherwise doc-only [`providers`](Self::providers) allow-list).
    pub fn authorizer(&self) -> ProviderAuthorizer {
        ProviderAuthorizer::from_policy(self)
    }
}

/// A compiled provider-authorization table derived from [`ServicePolicy::providers`]:
/// which provider identities may serve each service. The four-phase client consults
/// it on ACK acceptance so that a trusted-but-unauthorized group member — one whose
/// signature verifies but whom the policy does not list for this service — cannot be
/// selected (the SEC-05 gap: group membership was the only provider authorization).
///
/// Keyed by the **service short name** — the last component of the service's NDN
/// name, e.g. `echo` for `/svc/echo` — which is the bare name the policy file lists.
/// Matching is **fail-closed**: a service the policy does not mention authorizes no
/// provider, and a provider absent from a listed service's set is refused.
#[derive(Clone, Debug, Default)]
pub struct ProviderAuthorizer {
    /// service short-name → the set of provider identities allowed to serve it.
    allowed: HashMap<String, HashSet<Name>>,
}

impl ProviderAuthorizer {
    /// Compile a policy's `providers` into the authorization table. A provider
    /// whose `identity` is not a valid NDN name is skipped (it can authorize no
    /// one anyway).
    pub fn from_policy(policy: &ServicePolicy) -> Self {
        let mut allowed: HashMap<String, HashSet<Name>> = HashMap::new();
        for p in &policy.providers {
            let Ok(identity) = p.identity.parse::<Name>() else {
                continue;
            };
            for service in &p.allowed_services {
                allowed
                    .entry(service.clone())
                    .or_default()
                    .insert(identity.clone());
            }
        }
        Self { allowed }
    }

    /// The policy key for a service name: its last component as a string
    /// (`/svc/echo` → `echo`). `None` for an empty name.
    fn service_key(service: &Name) -> Option<String> {
        service
            .components()
            .last()
            .map(|c| String::from_utf8_lossy(c.value.as_ref()).into_owned())
    }

    /// Whether `provider` is authorized to serve `service`. **Fail closed:** a
    /// service with no listed providers authorizes no one, and a provider absent
    /// from a listed service's set is refused.
    pub fn allows(&self, service: &Name, provider: &Name) -> bool {
        match Self::service_key(service) {
            Some(key) => self
                .allowed
                .get(&key)
                .is_some_and(|providers| providers.contains(provider)),
            None => false,
        }
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
    fn provider_authorizer_enforces_per_service_allow_list() {
        // From SAMPLE: only /muas/bob is listed, and only for service "echo".
        let policy = ServicePolicy::from_toml(SAMPLE).unwrap();
        let auth = policy.authorizer();
        let bob: Name = "/muas/bob".parse().unwrap();
        let mallory: Name = "/muas/mallory".parse().unwrap();

        // bob is authorized for /svc/echo (matched by the service's last component).
        assert!(auth.allows(&"/svc/echo".parse().unwrap(), &bob));
        // A trusted-but-unlisted provider is refused (the SEC-05 case).
        assert!(!auth.allows(&"/svc/echo".parse().unwrap(), &mallory));
        // Fail closed: bob is not authorized for a service the policy omits.
        assert!(!auth.allows(&"/svc/cam".parse().unwrap(), &bob));
        // Fail closed: an empty policy authorizes no one.
        let empty = ProviderAuthorizer::from_policy(&ServicePolicy::default());
        assert!(!empty.allows(&"/svc/echo".parse().unwrap(), &bob));
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
