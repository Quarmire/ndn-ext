//! Dashboard-held operator signing keyring — the operator's *own*, portable
//! signing identities, independent of any forwarder.
//!
//! The dashboard holds a **set** of operator identities (generated in-page or
//! imported from a SafeBag) in an [`InPageCustodian`], with one marked
//! *active*. Management commands are signed through a [`CustodianSigner`] over
//! the active identity; with none active, [`command_signer`] is `None` and the
//! client falls back to `DigestSha256` — that fallback is the "gate".
//!
//! This module is deliberately Dioxus-free so it stays unit-testable and is
//! shared verbatim by the native and wasm builds. UI reactivity is handled by
//! the *caller's* UI layer after a mutation (the Dioxus dashboard bumps a
//! change generation; a native UI re-reads or subscribes) — this core neither
//! knows nor depends on any UI framework.
//!
//! Each held identity carries its *own* backing [`Custodian`]: on-host
//! identities share the keyring's [`InPageCustodian`], while a remote-signer
//! identity ([`provision_remote_signer`]) carries a `RemoteCustodian` whose key
//! lives off-host on a paired device — `command_signer` delegates signing to
//! whichever custodian backs the active identity. OS-keyring / extension
//! custodians plug into the same seam; local persistence of the in-page
//! identities is layered on top (see `operator_keyring_store`).
#![allow(dead_code)]

use std::sync::{Arc, OnceLock, RwLock};

use bytes::Bytes;
use ndn_security::custodian::{
    Custodian, CustodianRef, CustodianSigner, InPageCustodian, KeyId, RemoteCustodian,
    RemoteSignerTransport,
};
use ndn_packet::{Name, SignatureType};
use ndn_security::{EcdsaP256Signer, Ed25519Signer, Signer};

/// One identity the dashboard holds and can sign as.
#[derive(Clone)]
struct Held {
    key_id: KeyId,
    /// Operator certificate name, advertised in the command KeyLocator so the
    /// forwarder can resolve the signing cert to its trust anchor.
    cert_name: Option<Name>,
    sig_type: SignatureType,
    public_key: Option<Bytes>,
    /// Present for identities the dashboard fully holds (generated in-page, or
    /// imported with the key): the private key + certificate Data needed to
    /// re-emit a SafeBag and to persist the identity locally.
    exportable: Option<Exportable>,
    /// The custodian that signs for this identity. In-page identities share the
    /// keyring's `InPageCustodian`; a remote-signer identity carries its own
    /// `RemoteCustodian` (the key lives off-host, on a paired device).
    custodian: Arc<dyn Custodian>,
    /// Where this identity's key lives — drives the security-tier badge and the
    /// "key never touches this host" property for remote signers.
    custodian_ref: CustodianRef,
}

/// Material needed to export / persist a dashboard-held identity as a SafeBag.
#[derive(Clone)]
struct Exportable {
    pkcs8: Vec<u8>,
    cert_wire: Bytes,
}

struct OperatorKeyring {
    custodian: Arc<InPageCustodian>,
    identities: RwLock<Vec<Held>>,
    /// The key id of the active identity (the one that signs), if any.
    active: RwLock<Option<KeyId>>,
}

fn keyring() -> &'static OperatorKeyring {
    static K: OnceLock<OperatorKeyring> = OnceLock::new();
    K.get_or_init(|| OperatorKeyring {
        custodian: Arc::new(InPageCustodian::new()),
        identities: RwLock::new(Vec::new()),
        active: RwLock::new(None),
    })
}

/// A public, render-friendly summary of a held identity (no secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySummary {
    /// Identity name (`/op/alice`) — the key name with `/KEY/…` stripped.
    pub identity: String,
    /// Full key name (`/op/alice/KEY/<id>`).
    pub key_name: String,
    /// Certificate name, when known.
    pub cert_name: Option<String>,
    /// Algorithm label (`Ed25519` / `ECDSA P-256`).
    pub algorithm: String,
    /// Short public-key fingerprint (SHA-256 hex, first 16 chars) — the trust
    /// property, distinct from the navigation name.
    pub fingerprint: String,
    /// Whether the dashboard fully holds this identity (can export / persist).
    pub exportable: bool,
    /// Whether this is the active signing identity.
    pub active: bool,
    /// Human label for where the signing key lives (`In-page (memory)`,
    /// `Remote signer`, `Hardware fob`, …) — the security tier, taken from the
    /// backing custodian.
    pub custodian_label: String,
    /// Whether the private key physically resides on this machine. `false` for
    /// a remote signer (phone / hardware token): the key never touches the host.
    pub key_on_this_machine: bool,
    /// Whether every signature requires an explicit user action on the
    /// custodian (a remote tap / biometric). `false` for a silent in-page key.
    pub prompts_per_action: bool,
}

fn identity_of(key_name: &str) -> String {
    key_name
        .split_once("/KEY/")
        .map(|(id, _)| id.to_string())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| key_name.to_string())
}

fn algorithm_label(t: SignatureType) -> String {
    match t {
        SignatureType::SignatureEd25519 => "Ed25519",
        SignatureType::SignatureSha256WithEcdsa => "ECDSA P-256",
        SignatureType::SignatureSha256WithRsa => "RSA",
        _ => "other",
    }
    .to_string()
}

fn fingerprint_of(pk: Option<&Bytes>) -> String {
    use sha2::{Digest, Sha256};
    match pk {
        Some(pk) => {
            let digest = Sha256::digest(pk);
            digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
        }
        None => "unknown".to_string(),
    }
}

/// Core: add (or replace) a held identity in the keyring and make it active.
/// `custodian` is the backend that signs for it (the shared `InPageCustodian`
/// for on-host keys, a `RemoteCustodian` for off-host ones); `custodian_ref`
/// records where the key lives. Callers should refresh their UI's keyring view
/// after a mutation.
#[allow(clippy::too_many_arguments)]
fn insert_held(
    key_id: KeyId,
    cert_name: Option<Name>,
    sig_type: SignatureType,
    public_key: Option<Bytes>,
    custodian: Arc<dyn Custodian>,
    custodian_ref: CustodianRef,
    exportable: Option<Exportable>,
) {
    let kr = keyring();
    let held = Held {
        key_id: key_id.clone(),
        cert_name,
        sig_type,
        public_key,
        exportable,
        custodian,
        custodian_ref,
    };
    {
        let mut ids = kr.identities.write().expect("operator keyring lock");
        if let Some(slot) = ids.iter_mut().find(|h| h.key_id == key_id) {
            *slot = held;
        } else {
            ids.push(held);
        }
    }
    *kr.active.write().expect("operator keyring lock") = Some(key_id);
}

/// Provision an in-page identity: the keyring's `InPageCustodian` gains the
/// signer and signs for it (the key is held on this host).
fn provision_inner(
    key_name: Name,
    cert_name: Option<Name>,
    signer: Arc<dyn Signer>,
    exportable: Option<Exportable>,
) {
    let kr = keyring();
    let sig_type = signer.sig_type();
    let public_key = signer.public_key();
    let key_id = KeyId(key_name);
    kr.custodian.insert_signer(key_id.clone(), signer);
    insert_held(
        key_id,
        cert_name,
        sig_type,
        public_key,
        kr.custodian.clone(),
        CustodianRef::InPage,
        exportable,
    );
}

/// Provision an identity whose key lives on a **remote signer** — a paired
/// phone, another machine, or a hardware token that gates each signature there.
/// The private key never touches this host; [`command_signer`] delegates
/// signing to the remote device over `transport`. `sig_type` / `public_key` /
/// `cert_name` come from pairing (the dashboard learns the operator's public
/// key + certificate, never the key). Not exportable — there's nothing on-host
/// to export.
///
/// `kind` says what the signer is ([`CustodianRef::Fob`] for a phone,
/// [`CustodianRef::Remote`] for a networked signer); it drives the
/// security-tier badge. Per the 2026-06-01 design decision the operator key
/// should be ECDSA P-256, so a PWA software key can later upgrade to a native
/// secure-enclave key without re-keying (see
/// `.claude/notes/remote-fob-design-2026-06-01.md`).
pub fn provision_remote_signer(
    key_name: Name,
    cert_name: Option<Name>,
    sig_type: SignatureType,
    public_key: Option<Bytes>,
    transport: Arc<dyn RemoteSignerTransport>,
    kind: CustodianRef,
) {
    let custodian: Arc<dyn Custodian> = Arc::new(RemoteCustodian::new(transport, kind.clone()));
    insert_held(
        KeyId(key_name),
        cert_name,
        sig_type,
        public_key,
        custodian,
        kind,
        None,
    );
}

/// Provision a remote-signer identity from the operator certificate learned at
/// pairing. The paired device sends its **self-signed** operator certificate
/// (the reply to a [`ndn_security::custodian::PairingOffer`]); the public key, names, and
/// algorithm all live inside it, so this is the single entry point from a
/// completed pairing to an active off-host identity.
///
/// `transport` is the channel to the device; `kind` says what it is
/// (`CustodianRef::Fob` for a phone). Returns the active identity name.
///
/// The algorithm is read from the certificate's own `SignatureInfo` — correct
/// because a pairing cert is self-signed (it carries the operator key's own
/// signature). A CA-issued certificate would report the issuer's algorithm, so
/// this path assumes the TOFU self-signed pairing cert.
pub fn provision_remote_signer_from_cert(
    cert_wire: Bytes,
    transport: Arc<dyn RemoteSignerTransport>,
    kind: CustodianRef,
) -> Result<String, String> {
    let cert = ndn_packet::Data::decode(cert_wire).map_err(|e| format!("certificate decode: {e:?}"))?;
    let cert_name = (*cert.name).clone();
    let key_name = key_name_from_cert(&cert_name);
    let sig_type = cert
        .sig_info()
        .map(|si| si.sig_type)
        .ok_or("certificate has no SignatureInfo")?;
    let public_key = cert.content().cloned();
    provision_remote_signer(key_name, Some(cert_name), sig_type, public_key, transport, kind);
    active_identity_name().ok_or_else(|| "provisioned but no active identity".into())
}

/// Provision a generated identity (in-page key + self-signed cert) as the
/// active signer, retaining the material to export / persist it.
pub fn provision_generated(
    key_name: Name,
    cert_name: Name,
    signer: Arc<dyn Signer>,
    pkcs8: Vec<u8>,
    cert_wire: Bytes,
) {
    provision_inner(
        key_name,
        Some(cert_name),
        signer,
        Some(Exportable { pkcs8, cert_wire }),
    );
}

/// Provision a freshly-seeded Ed25519 operator key (tests / quick generate).
pub fn provision_ed25519(key_name: Name, seed: &[u8; 32]) {
    provision_inner(
        key_name.clone(),
        None,
        Arc::new(Ed25519Signer::from_seed(seed, key_name)),
        None,
    );
}

/// Build a `dyn Signer` from a decrypted PKCS#8 key of either supported
/// algorithm, dispatching on the algorithm OID via the concrete signers.
fn signer_from_pkcs8(key_name: &Name, pkcs8_der: &[u8]) -> Result<Arc<dyn Signer>, String> {
    if let Ok(s) = Ed25519Signer::from_pkcs8_der(pkcs8_der, key_name.clone()) {
        return Ok(Arc::new(s));
    }
    EcdsaP256Signer::from_pkcs8_der(pkcs8_der, key_name.clone())
        .map(|s| Arc::new(s) as Arc<dyn Signer>)
        .map_err(|e| format!("operator key load: {e}"))
}

/// Provision a fully-held imported identity (key + the certificate Data it
/// arrived with), so it can be re-exported and persisted like a generated one.
/// Algorithm is dispatched from the PKCS#8 OID.
pub fn provision_imported(
    key_name: Name,
    cert_name: Name,
    pkcs8_der: &[u8],
    cert_wire: Bytes,
) -> Result<(), String> {
    let signer = signer_from_pkcs8(&key_name, pkcs8_der)?;
    provision_inner(
        key_name,
        Some(cert_name),
        signer,
        Some(Exportable {
            pkcs8: pkcs8_der.to_vec(),
            cert_wire,
        }),
    );
    Ok(())
}

/// Decode + decrypt a SafeBag wire and provision it as a fully-held active
/// identity. Derives the key and certificate names from the embedded cert, so
/// it's the single entry point for both SafeBag import and unlocking a
/// persisted identity. Returns the identity name on success.
pub fn provision_from_safebag(wire: &[u8], passphrase: &[u8]) -> Result<String, String> {
    let bag = ndn_security::safebag::SafeBag::decode(wire).map_err(|e| format!("SafeBag decode: {e}"))?;
    let pkcs8 = bag
        .decrypt_pkcs8(passphrase)
        .map_err(|e| format!("decrypt failed (wrong passphrase?): {e}"))?;
    let cert_data = ndn_packet::Data::decode(bag.certificate.clone())
        .map_err(|e| format!("certificate decode: {e:?}"))?;
    let cert_name = (*cert_data.name).clone();
    let key_name = key_name_from_cert(&cert_name);
    provision_imported(key_name, cert_name, &pkcs8, bag.certificate)?;
    active_identity_name().ok_or_else(|| "provision succeeded but no active identity".into())
}

/// Reduce a certificate name to its key name: keep components up to and
/// including the key id (`…/KEY/<keyid>`), dropping issuer + version.
fn key_name_from_cert(cert_name: &Name) -> Name {
    use ndn_packet::tlv_type::NAME_COMPONENT;
    let comps = cert_name.components();
    let key_idx = comps
        .iter()
        .position(|c| c.typ == NAME_COMPONENT && c.value.as_ref() == b"KEY");
    match key_idx {
        // identity.../KEY/<keyid> → keep through keyid.
        Some(i) if i + 1 < comps.len() => {
            Name::from_components(comps[..=i + 1].iter().cloned())
        }
        _ => cert_name.clone(),
    }
}

/// Every identity the dashboard holds, with the active one flagged.
pub fn list_identities() -> Vec<IdentitySummary> {
    let kr = keyring();
    let active = kr.active.read().expect("operator keyring lock").clone();
    kr.identities
        .read()
        .expect("operator keyring lock")
        .iter()
        .map(|h| {
            let key_name = h.key_id.as_name().to_string();
            IdentitySummary {
                identity: identity_of(&key_name),
                cert_name: h.cert_name.as_ref().map(|n| n.to_string()),
                algorithm: algorithm_label(h.sig_type),
                fingerprint: fingerprint_of(h.public_key.as_ref()),
                exportable: h.exportable.is_some(),
                active: active.as_ref() == Some(&h.key_id),
                custodian_label: h.custodian_ref.label().to_string(),
                key_on_this_machine: h.custodian_ref.key_on_this_machine(),
                prompts_per_action: h.custodian_ref.prompts_per_action(),
                key_name,
            }
        })
        .collect()
}

/// Make the identity with key name `key_name` the active signer. Returns true
/// when it was found. Follow with [`crate::app_shared::bump_keyring_gen`].
pub fn set_active(key_name: &str) -> bool {
    let kr = keyring();
    let found = kr
        .identities
        .read()
        .expect("operator keyring lock")
        .iter()
        .find(|h| h.key_id.as_name().to_string() == key_name)
        .map(|h| h.key_id.clone());
    match found {
        Some(key_id) => {
            *kr.active.write().expect("operator keyring lock") = Some(key_id);
            true
        }
        None => false,
    }
}

/// Forget a held identity. If it was active, signing closes until another is
/// activated. Returns true when removed.
pub fn remove_identity(key_name: &str) -> bool {
    let kr = keyring();
    let mut ids = kr.identities.write().expect("operator keyring lock");
    let before = ids.len();
    ids.retain(|h| h.key_id.as_name().to_string() != key_name);
    let removed = ids.len() != before;
    drop(ids);
    if removed {
        let mut active = kr.active.write().expect("operator keyring lock");
        if active.as_ref().map(|k| k.as_name().to_string()).as_deref() == Some(key_name) {
            *active = None;
        }
    }
    removed
}

fn with_active<T>(f: impl FnOnce(&Held) -> T) -> Option<T> {
    let kr = keyring();
    let active = kr.active.read().expect("operator keyring lock").clone()?;
    let ids = kr.identities.read().expect("operator keyring lock");
    ids.iter().find(|h| h.key_id == active).map(f)
}

/// Encrypt the active identity into a SafeBag wire under `passphrase`, when the
/// active identity is fully held. `None` when nothing is active or it isn't
/// exportable.
pub fn export_active_safebag(passphrase: &[u8]) -> Option<Result<Vec<u8>, String>> {
    let exp = with_active(|h| h.exportable.clone())??;
    Some(encrypt_safebag(&exp, passphrase))
}

/// Encrypt a specific held identity (by key name) into a SafeBag wire.
pub fn export_safebag_for(key_name: &str, passphrase: &[u8]) -> Option<Result<Vec<u8>, String>> {
    let kr = keyring();
    let ids = kr.identities.read().expect("operator keyring lock");
    let exp = ids
        .iter()
        .find(|h| h.key_id.as_name().to_string() == key_name)?
        .exportable
        .clone()?;
    Some(encrypt_safebag(&exp, passphrase))
}

fn encrypt_safebag(exp: &Exportable, passphrase: &[u8]) -> Result<Vec<u8>, String> {
    ndn_security::safebag::SafeBag::encrypt(exp.cert_wire.clone(), &exp.pkcs8, passphrase)
        .map(|bag| bag.encode().to_vec())
        .map_err(|e| format!("SafeBag encrypt: {e}"))
}

/// Whether the active identity can be exported as a SafeBag.
pub fn active_is_exportable() -> bool {
    with_active(|h| h.exportable.is_some()).unwrap_or(false)
}

/// Whether an operator key is active (the gate is open).
pub fn is_provisioned() -> bool {
    keyring()
        .active
        .read()
        .expect("operator keyring lock")
        .is_some()
}

/// The active operator's identity name (`/op/alice`), or `None`.
pub fn active_identity_name() -> Option<String> {
    with_active(|h| identity_of(&h.key_id.as_name().to_string()))
}

/// The active identity's certificate Data wire — what a forwarder needs as a
/// trust anchor to accept this identity's commands. `None` unless the active
/// identity is fully held (its cert is available).
pub fn active_cert_wire() -> Option<Vec<u8>> {
    with_active(|h| h.exportable.as_ref().map(|e| e.cert_wire.to_vec())).flatten()
}

/// The mgmt-command signer for the active identity, else `None`.
pub fn command_signer() -> Option<Arc<dyn Signer>> {
    with_active(|h| {
        let mut signer = CustodianSigner::new(
            h.custodian.clone(),
            h.key_id.clone(),
            h.sig_type,
            h.public_key.clone(),
        );
        if let Some(cert_name) = h.cert_name.clone() {
            signer = signer.with_cert_name(cert_name);
        }
        Arc::new(signer) as Arc<dyn Signer>
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::custodian::{CustodianError, RemoteSignRequest};
    use ndn_security::verifier::EcdsaSha256Verifier;
    use ndn_security::{VerifyOutcome, Verifier, encode_cert_data};

    /// A loopback "phone": a local signer standing in for a paired remote
    /// device, so the keyring's remote-signer wiring is testable without one.
    struct LoopbackPhone {
        signer: EcdsaP256Signer,
    }

    #[async_trait::async_trait]
    impl RemoteSignerTransport for LoopbackPhone {
        async fn request_signature(
            &self,
            req: &RemoteSignRequest,
        ) -> Result<Bytes, CustodianError> {
            self.signer
                .sign_sync(&req.region)
                .map_err(|e| CustodianError::SignFailed(e.to_string()))
        }
        async fn is_reachable(&self) -> bool {
            true
        }
    }

    // keyring() is process-global, so all steps run in one sequential test.
    #[tokio::test]
    async fn keyring_holds_inpage_and_remote_signer_identities() {
        // Provision an Ed25519 identity → active.
        let ed: Name = "/op/dash/KEY/k1".parse().unwrap();
        provision_ed25519(ed.clone(), &[5u8; 32]);
        assert!(is_provisioned());
        assert_eq!(command_signer().unwrap().key_name().to_string(), "/op/dash/KEY/k1");

        // Provision an ECDSA identity with a cert name → becomes active, and
        // its cert name surfaces in the signer (the command KeyLocator).
        let ec_name: Name = "/op/dash/KEY/ec".parse().unwrap();
        let ec = EcdsaP256Signer::from_seed(&[6u8; 32], ec_name.clone()).unwrap();
        let pkcs8 = ec.to_pkcs8_der().unwrap();
        let cert_name: Name = "/op/dash/KEY/ec/self/v=0".parse().unwrap();
        provision_imported(ec_name, cert_name.clone(), &pkcs8, Bytes::new()).unwrap();
        let signer = command_signer().unwrap();
        assert_eq!(signer.sig_type(), SignatureType::SignatureSha256WithEcdsa);
        assert_eq!(signer.cert_name(), Some(&cert_name));

        // Both identities are held.
        let ids = list_identities();
        assert!(ids.iter().any(|i| i.key_name == "/op/dash/KEY/k1"));
        assert!(ids.iter().any(|i| i.key_name == "/op/dash/KEY/ec" && i.active));
        assert_eq!(ids.iter().filter(|i| i.active).count(), 1);

        // Switch back to the Ed25519 identity.
        assert!(set_active("/op/dash/KEY/k1"));
        assert_eq!(command_signer().unwrap().key_name().to_string(), "/op/dash/KEY/k1");
        assert_eq!(active_identity_name().as_deref(), Some("/op/dash"));

        // Forget it → active clears.
        assert!(remove_identity("/op/dash/KEY/k1"));
        assert!(!is_provisioned());

        // ── Remote-signer identity: the key lives off-host on a paired device.
        // A loopback "phone" (a local ECDSA P-256 signer, per the v1 P-256
        // decision) stands in for the real device.
        let phone_key: Name = "/op/phone/KEY/p1".parse().unwrap();
        let phone = EcdsaP256Signer::from_seed(&[8u8; 32], phone_key.clone()).unwrap();
        let phone_pk = phone.public_key();
        let cert_name: Name = "/op/phone/KEY/p1/self/v=0".parse().unwrap();
        provision_remote_signer(
            phone_key,
            Some(cert_name.clone()),
            SignatureType::SignatureSha256WithEcdsa,
            phone_pk.clone(),
            Arc::new(LoopbackPhone { signer: phone }),
            CustodianRef::Fob {
                fob_id: "phone-1".into(),
            },
        );

        // It's active, and the summary reflects an off-host, per-use signer
        // that the dashboard cannot export (no key material on this host).
        assert!(is_provisioned());
        let phone_summary = list_identities()
            .into_iter()
            .find(|i| i.key_name == "/op/phone/KEY/p1")
            .expect("remote identity held");
        assert!(phone_summary.active);
        assert!(!phone_summary.key_on_this_machine, "key is off-host");
        assert!(phone_summary.prompts_per_action);
        assert!(!phone_summary.exportable, "nothing on-host to export");
        assert_eq!(phone_summary.custodian_label, "Hardware fob");
        assert_eq!(phone_summary.algorithm, "ECDSA P-256");

        // command_signer delegates to the remote signer; the returned signature
        // verifies against the operator public key learned at pairing, and the
        // cert name surfaces in the command KeyLocator.
        let signer = command_signer().expect("remote signer active");
        assert_eq!(signer.sig_type(), SignatureType::SignatureSha256WithEcdsa);
        assert_eq!(signer.cert_name(), Some(&cert_name));
        let region = b"signed mgmt command region";
        let sig = signer.sign(region).await.expect("remote signs");
        let pk = phone_pk.expect("public key");
        assert!(matches!(
            EcdsaSha256Verifier.verify(region, &sig, &pk).await,
            Ok(VerifyOutcome::Valid)
        ));

        // ── Pairing glue: provision straight from the paired self-signed cert.
        let paired_key: Name = "/op/paired/KEY/pk1".parse().unwrap();
        let paired = EcdsaP256Signer::from_seed(&[11u8; 32], paired_key.clone()).unwrap();
        let paired_pk = paired.public_key().unwrap();
        let paired_cert_name: Name = "/op/paired/KEY/pk1/self/v=0".parse().unwrap();
        let cert_wire = encode_cert_data(&paired_cert_name, &paired_pk, &paired, 0, u64::MAX)
            .await
            .expect("self-sign pairing cert");

        // The phone keeps the key; a loopback stands in for it here.
        let phone = Arc::new(LoopbackPhone {
            signer: EcdsaP256Signer::from_seed(&[11u8; 32], paired_key).unwrap(),
        });
        let id = provision_remote_signer_from_cert(
            Bytes::from(cert_wire.to_vec()),
            phone,
            CustodianRef::Fob {
                fob_id: "paired-phone".into(),
            },
        )
        .expect("provision from cert");
        assert_eq!(id, "/op/paired");

        let summary = list_identities()
            .into_iter()
            .find(|i| i.key_name == "/op/paired/KEY/pk1")
            .expect("paired identity held");
        assert!(summary.active);
        assert!(!summary.key_on_this_machine);
        assert_eq!(summary.algorithm, "ECDSA P-256");
        assert_eq!(summary.custodian_label, "Hardware fob");
        // The cert name (derived from the cert) flows into the command signer.
        assert_eq!(
            command_signer().unwrap().cert_name(),
            Some(&paired_cert_name)
        );
    }
}
