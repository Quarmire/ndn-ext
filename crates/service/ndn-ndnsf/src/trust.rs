//! Per-message trust validation (the trust half of NSF-A3, feature `driver`).
//!
//! NDNSF validates each four-phase message against the configured trust validator
//! before its payload affects runtime state. This module is that mechanism: a
//! message is published as a **signed Data** ([`sign_message`]); a receiver
//! [`verify_message`]s it before acting — the signature must validate against the
//! trust anchors **and** the signer identity must be under the message's expected
//! sender (so a node cannot publish a `/<provider>/NDNSF/ACK/…` it did not sign).
//! Either failure rejects the message (fail closed) — its payload never affects
//! state. Reuses `ndn_security`'s real `Signer`/`Validator`, not new crypto.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::Data;
use ndn_security::validator::ValidationResult;
use ndn_security::{SignWith, Signer, Validator};

/// Sign `payload` as a Data named `name`, producing the wire blob a four-phase
/// publisher puts on the group. The Data's `KeyLocator` records the signer.
pub fn sign_message(signer: &dyn Signer, name: Name, payload: &[u8]) -> Option<Bytes> {
    DataBuilder::new(name, payload).sign_with_sync(signer).ok()
}

/// Validate a signed-message blob before acting on it. Returns the inner payload
/// only if (a) the signature validates against `validator`'s anchors and (b) the
/// signer identity is under `expected_sender`. `None` (fail closed) otherwise.
pub async fn verify_message(
    validator: &Validator,
    blob: Bytes,
    expected_sender: &Name,
) -> Option<Bytes> {
    let data = Data::decode(blob).ok()?;
    // The signer (KeyLocator) must be under the expected sender identity — a
    // provider cannot answer "as" another, even with a valid key of its own.
    let signer = data.sig_info()?.key_locator_name()?;
    if !signer.has_prefix(expected_sender) {
        return None;
    }
    match validator.validate(&data).await {
        ValidationResult::Valid(safe) => safe.data().content().cloned(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::KeyChain;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn valid_message_from_expected_sender_accepted() {
        let kc = KeyChain::ephemeral("/muas/alice").unwrap();
        let blob = sign_message(&*kc.signer().unwrap(), n("/muas/alice/NDNSF/REQUEST/x/r1"), b"hi")
            .unwrap();
        let got = verify_message(&kc.validator(), blob, &n("/muas/alice")).await;
        assert_eq!(got.as_deref(), Some(b"hi".as_slice()));
    }

    #[tokio::test]
    async fn wrong_sender_prefix_rejected() {
        let kc = KeyChain::ephemeral("/muas/alice").unwrap();
        let blob =
            sign_message(&*kc.signer().unwrap(), n("/muas/alice/NDNSF/REQUEST/x/r1"), b"hi").unwrap();
        // The message claims to be from /muas/bob, but alice signed it.
        assert!(verify_message(&kc.validator(), blob, &n("/muas/bob")).await.is_none());
    }

    #[tokio::test]
    async fn untrusted_signer_rejected() {
        let alice = KeyChain::ephemeral("/muas/alice").unwrap();
        let mallory = KeyChain::ephemeral("/muas/mallory").unwrap();
        let blob = sign_message(
            &*mallory.signer().unwrap(),
            n("/muas/mallory/NDNSF/ACK/x/r1"),
            b"spoof",
        )
        .unwrap();
        // alice's validator does not trust mallory's anchor.
        assert!(verify_message(&alice.validator(), blob, &n("/muas/mallory")).await.is_none());
    }

    #[tokio::test]
    async fn tampered_message_rejected() {
        let kc = KeyChain::ephemeral("/muas/alice").unwrap();
        let blob = sign_message(&*kc.signer().unwrap(), n("/muas/alice/NDNSF/REQUEST/x/r1"), b"hi")
            .unwrap();
        let mut bad = blob.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(
            verify_message(&kc.validator(), Bytes::from(bad), &n("/muas/alice"))
                .await
                .is_none()
        );
    }
}
