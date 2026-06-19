//! The operator→authority command front-end (service-layer §4.4): signed
//! `grant` / `revoke` command Interests that drive a live [`PolicyAuthority`].
//!
//! This is the *input* channel that produces new signed policy versions — not a
//! hidden-state mutator. An operator builds a signed command ([`grant_command`] /
//! [`revoke_command`]); a [`PolicyController`] validates it (signature valid
//! **and** signer under the admin prefix — fail closed), applies it to the live
//! authority (bumping the version), and returns the freshly signed grant object
//! (the new published version). No restart.
//!
//! Names are `<scope>/policy/grant` and `<scope>/policy/revoke`; the command
//! arguments ride in the Interest's `ApplicationParameters`. The response here is
//! the new signed grant Data; a face-backed deployment wraps it in a command
//! reply named after the Interest (deferred, the same sans-IO core).

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Interest, Name};
use ndn_security::validator::InterestValidationOutcome;
use ndn_security::{SignWith, Signer, Validator};
use ndn_service_core::Frame;
use ndn_service_core::framing::{encode_fields, read_field};

use crate::PolicyAuthority;

const POLICY: &str = "policy";
const GRANT: &str = "grant";
const REVOKE: &str = "revoke";

/// Build a signed `grant` command: `<scope>/policy/grant` carrying `(principal,
/// policy)`, signed by an authorized operator's `signer`. `None` on signing
/// failure.
pub fn grant_command(
    scope: &Name,
    signer: &dyn Signer,
    principal: &Name,
    policy: &str,
) -> Option<Bytes> {
    let name = scope.clone().append(POLICY).append(GRANT);
    let params = encode_fields(&[
        Frame::encode(&principal.to_string()),
        Frame::encode(&policy.to_string()),
    ]);
    InterestBuilder::new(name)
        .must_be_fresh()
        .app_parameters(params.to_vec())
        .sign_with_sync(signer)
        .ok()
}

/// Build a signed `revoke` command: `<scope>/policy/revoke` carrying `principal`,
/// signed by an authorized operator's `signer`.
pub fn revoke_command(scope: &Name, signer: &dyn Signer, principal: &Name) -> Option<Bytes> {
    let name = scope.clone().append(POLICY).append(REVOKE);
    let params = encode_fields(&[Frame::encode(&principal.to_string())]);
    InterestBuilder::new(name)
        .must_be_fresh()
        .app_parameters(params.to_vec())
        .sign_with_sync(signer)
        .ok()
}

/// A runtime policy controller: the operator→authority input channel. It owns a
/// live [`PolicyAuthority`] and applies signed grant/revoke commands from
/// authorized operators, with no restart.
pub struct PolicyController {
    authority: PolicyAuthority,
    admin: Arc<Validator>,
    admin_prefix: Name,
}

impl PolicyController {
    /// A controller over `authority`, accepting commands whose signature
    /// validates against `admin` and whose signer is under `admin_prefix`.
    pub fn new(authority: PolicyAuthority, admin: Arc<Validator>, admin_prefix: Name) -> Self {
        Self {
            authority,
            admin,
            admin_prefix,
        }
    }

    /// Read access to the underlying authority (e.g. to publish signed grants).
    pub fn authority(&self) -> &PolicyAuthority {
        &self.authority
    }

    /// Process a signed command Interest. On an authorized, well-formed grant or
    /// revoke, applies it (bumping the version) and returns the new signed grant
    /// object. `None` — fail closed, **no mutation** — if the command is
    /// unauthorized, malformed, or an unknown verb.
    pub async fn handle(&mut self, interest_wire: Bytes) -> Option<Bytes> {
        let interest = Interest::decode(interest_wire).ok()?;
        let verb = command_verb(&interest.name, self.authority.scope())?;

        // Authorize before any mutation: signature valid AND signer under the
        // admin prefix (a node cannot grant itself rights it was not delegated).
        if !matches!(
            self.admin.validate_interest(&interest).await,
            InterestValidationOutcome::Valid
        ) {
            return None;
        }
        let signer = interest.sig_info().and_then(|si| si.key_locator_name())?;
        if !signer.has_prefix(&self.admin_prefix) {
            return None;
        }

        let params = interest.app_parameters()?;
        match verb.as_str() {
            GRANT => {
                let (principal, policy) = decode_grant(params)?;
                self.authority.grant(principal.clone(), policy);
                self.authority.signed_grant(&principal)
            }
            REVOKE => {
                let principal = decode_revoke(params)?;
                self.authority.revoke(&principal);
                self.authority.signed_grant(&principal)
            }
            _ => None,
        }
    }
}

/// Extract the command verb from `<scope>/policy/<verb>` — the component right
/// after `policy` (a signed Interest also carries a trailing
/// `params-sha256=…` digest component, so the verb is not the last component).
fn command_verb(name: &Name, scope: &Name) -> Option<String> {
    if !name.has_prefix(scope) {
        return None;
    }
    let comps = name.components();
    let idx = comps.iter().position(|c| c.value.as_ref() == POLICY.as_bytes())?;
    let verb = comps.get(idx + 1)?;
    Some(String::from_utf8_lossy(verb.value.as_ref()).into_owned())
}

fn decode_grant(params: &[u8]) -> Option<(Name, String)> {
    let mut pos = 0usize;
    let principal = String::decode(read_field(params, &mut pos).ok()?).ok()?;
    let policy = String::decode(read_field(params, &mut pos).ok()?).ok()?;
    Some((principal.parse().ok()?, policy))
}

fn decode_revoke(params: &[u8]) -> Option<Name> {
    let mut pos = 0usize;
    let principal = String::decode(read_field(params, &mut pos).ok()?).ok()?;
    principal.parse().ok()
}
