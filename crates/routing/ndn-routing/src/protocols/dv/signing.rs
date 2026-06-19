//! ndn-dv trust integration.
//!
//! Mirrors ndnd's `TrustConfig` (`std/security/trust.go` +
//! `std/object/client_trust.go`): a single object decides what
//! [`Signer`] to use for outgoing inner Data
//! ([`DvTrust::suggest_signer`]) and whether an incoming inner Data is
//! trusted ([`DvTrust::validate`]). [`InsecureTrust`] matches ndnd's
//! `KeyChainUri = "insecure"` mode.
//!
//! New call sites should prefer [`ndn_security::TrustPolicy`]; the
//! DV-local impls below stay because they bundle a `validate(&Data)`
//! predicate the abstract `TrustPolicy` does not carry.
//!
//! [`DvSync`]: crate::protocols::dv::sync::DvSync
//! [`DvPfxSync`]: crate::protocols::dv::pfx_sync::DvPfxSync

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::executor::block_on;
use ndn_packet::encode::{DataBuilder, encode_data_digest_sha256};
use ndn_packet::{Data, KeyLocator, Name, SignatureType};
pub use ndn_security::TrustPolicy as _TrustPolicy;
use ndn_security::verifier::verify_by_sig_type;
use ndn_security::{LvsModel, SignWith, Signer, VerifyOutcome};

/// Decision object owned by [`DvSync`] / [`DvPfxSync`] that controls
/// both *what we sign with* and *what we accept*. Implementations
/// model the same trust spectrum as ndnd's `TrustConfig`:
///
/// | Impl | `suggest_signer` | `validate` |
/// |---|---|---|
/// | [`InsecureTrust`] | `None` → `DigestSha256` | always `true` |
/// | [`StaticTrust`] | configured `default_signer` | hash-only for `DigestSha256`, key-map lookup for key-based sigs |
/// | [`LvsTrust`] | configured `default_signer` (LVS Suggest is 5c-experimental) | LVS schema check + sig verify |
///
/// [`DvSync`]: crate::protocols::dv::sync::DvSync
/// [`DvPfxSync`]: crate::protocols::dv::pfx_sync::DvPfxSync
pub trait DvTrust: Send + Sync + 'static {
    /// Pick a [`Signer`] for an outgoing Data packet named `_name`.
    /// `None` → [`DigestSha256`]. Default impl returns `None`.
    ///
    /// [`DigestSha256`]: ndn_packet::SignatureType::DigestSha256
    fn suggest_signer(&self, _name: &Name) -> Option<Arc<dyn Signer>> {
        None
    }

    /// Validate an incoming inner Data. Default impl accepts
    /// everything (mirrors ndnd's `trust == nil` short-circuit).
    fn validate(&self, _data: &Data) -> bool {
        true
    }
}

/// Type-erased trust handle threaded through DvSync / DvPfxSync.
pub type DvTrustHandle = Arc<dyn DvTrust>;

/// Wire-compatible with ndnd's `KeyChainUri = "insecure"` mode
/// (`ndnd/dv/dv/router.go:78`): no signing, validation always passes.
pub struct InsecureTrust;
impl DvTrust for InsecureTrust {}

impl InsecureTrust {
    pub fn handle() -> DvTrustHandle {
        Arc::new(InsecureTrust)
    }
}

/// Pre-shared-key trust. One default signer for every outgoing Data,
/// plus a name→public-key map for verifying incoming key-based
/// signatures. Acceptance:
///
/// 1. `DigestSha256` — accepted iff the embedded hash matches the
///    signed region (gated by [`accept_digest_sha256`]).
/// 2. Key-based signatures (Ed25519, RSA, ECDSA, HMAC) — accepted iff
///    the [`KeyLocator`] name resolves to a key in `trusted_keys` and
///    the cryptographic check passes.
pub struct StaticTrust {
    /// `None` → emit `DigestSha256`.
    pub default_signer: Option<Arc<dyn Signer>>,
    /// Key = the `KeyLocator` name in the incoming Data's
    /// `SignatureInfo`. Value = raw public-key bytes for
    /// [`ndn_security::verify_by_sig_type`].
    pub trusted_keys: HashMap<Name, Bytes>,
    /// Default `true`. Set `false` to require every packet be signed
    /// by a known key.
    pub accept_digest_sha256: bool,
}

impl StaticTrust {
    pub fn new(default_signer: Option<Arc<dyn Signer>>) -> Self {
        Self {
            default_signer,
            trusted_keys: HashMap::new(),
            accept_digest_sha256: true,
        }
    }

    pub fn trust_key(mut self, name: Name, public_key: Bytes) -> Self {
        self.trusted_keys.insert(name, public_key);
        self
    }

    pub fn require_signatures(mut self) -> Self {
        self.accept_digest_sha256 = false;
        self
    }

    pub fn handle(self) -> DvTrustHandle {
        Arc::new(self)
    }
}

impl DvTrust for StaticTrust {
    fn suggest_signer(&self, _name: &Name) -> Option<Arc<dyn Signer>> {
        self.default_signer.clone()
    }

    fn validate(&self, data: &Data) -> bool {
        validate_data_against_static(data, self)
    }
}

/// LVS-driven trust. Validation runs the schema check
/// `model.check(data_name, key_name)` first; only then does it invoke
/// the signature verifier.
///
/// `suggest_signer` returns the configured `default_signer`. Full
/// LVS-walk signer selection (`ndnd`'s `client.SuggestSigner`) is
/// deferred — it requires a runtime keychain.
pub struct LvsTrust {
    pub model: Arc<LvsModel>,
    pub default_signer: Option<Arc<dyn Signer>>,
    pub trusted_keys: HashMap<Name, Bytes>,
}

impl LvsTrust {
    pub fn new(model: Arc<LvsModel>, default_signer: Option<Arc<dyn Signer>>) -> Self {
        Self {
            model,
            default_signer,
            trusted_keys: HashMap::new(),
        }
    }

    pub fn trust_key(mut self, name: Name, public_key: Bytes) -> Self {
        self.trusted_keys.insert(name, public_key);
        self
    }

    pub fn handle(self) -> DvTrustHandle {
        Arc::new(self)
    }
}

impl DvTrust for LvsTrust {
    fn suggest_signer(&self, _name: &Name) -> Option<Arc<dyn Signer>> {
        self.default_signer.clone()
    }

    fn validate(&self, data: &Data) -> bool {
        let Some(sig_info) = data.sig_info() else {
            return false;
        };
        // Pull the key-locator name (if any) for the schema check.
        // `DigestSha256` has no key — fall back to a synthetic empty
        // name; LVS schemas that reject empty key names will deny.
        // `DigestSha256` has no KeyLocator; fall back to a synthetic
        // empty name so LVS schemas that reject empty key names deny.
        let key_name = match sig_info.key_locator.as_ref() {
            Some(KeyLocator::Name(n)) => (**n).clone(),
            _ => Name::root(),
        };
        if !self.model.check(&data.name, &key_name) {
            return false;
        }
        crypto_verify(data, &self.trusted_keys, true)
    }
}

/// `freshness = 0` so served Data is never cached.
///
/// # Panics
///
/// Panics if the signer fails — DV's outgoing path has no recovery
/// story.
pub fn encode_inner_data(name: &Name, content: &[u8], trust: &dyn DvTrust) -> Bytes {
    match trust.suggest_signer(name) {
        None => encode_data_digest_sha256(name, content),
        Some(s) => DataBuilder::new(name.clone(), content)
            .freshness(Duration::ZERO)
            .sign_with_sync(s.as_ref())
            .expect("DvTrust::suggest_signer returned a Signer that failed to sign"),
    }
}

pub fn validate_inner_data(data: &Data, trust: &dyn DvTrust) -> bool {
    trust.validate(data)
}

/// rdr_2024-style segmented inner Data: caller passes the full
/// segmented name (`/.../seg=<n>`); we set `FinalBlockId` to the
/// typed segment component for `last_seg`.
///
/// ndnd's `client.Produce` always emits segmented Data — even a
/// one-segment payload ships as `/.../seg=0` with `FinalBlockId = /seg=0`
/// — and `client.Consume` rejects un-segmented Data outright.
///
/// # Panics
///
/// Same as [`encode_inner_data`].
pub fn encode_inner_segmented_data(
    segmented_name: &Name,
    content: &[u8],
    last_seg: u64,
    trust: &dyn DvTrust,
) -> Bytes {
    let builder = DataBuilder::new(segmented_name.clone(), content)
        .freshness(Duration::ZERO)
        .final_block_id_typed_seg(last_seg);
    match trust.suggest_signer(segmented_name) {
        None => builder.sign_digest_sha256(),
        Some(s) => builder
            .sign_with_sync(s.as_ref())
            .expect("DvTrust::suggest_signer returned a Signer that failed to sign"),
    }
}

fn validate_data_against_static(data: &Data, trust: &StaticTrust) -> bool {
    let Some(sig_info) = data.sig_info() else {
        return false;
    };
    match sig_info.sig_type {
        SignatureType::DigestSha256 if trust.accept_digest_sha256 => {
            crypto_verify(data, &trust.trusted_keys, false)
        }
        SignatureType::DigestSha256 => false,
        _ => crypto_verify(data, &trust.trusted_keys, true),
    }
}

/// `key_required = false` bypasses the trusted-keys map
/// (`DigestSha256` path). Returns `true` iff the algorithm is
/// supported, the required key is in `trusted_keys`, and the
/// cryptographic check passes.
fn crypto_verify(data: &Data, trusted_keys: &HashMap<Name, Bytes>, key_required: bool) -> bool {
    let Some(sig_info) = data.sig_info() else {
        return false;
    };
    let sig_type = sig_info.sig_type;
    let region = data.signed_region();
    let sig_value = data.sig_value();

    let public_key: &[u8] = if key_required {
        let Some(KeyLocator::Name(key_name)) = sig_info.key_locator.as_ref() else {
            return false;
        };
        match trusted_keys.get(key_name.as_ref()) {
            Some(k) => k.as_ref(),
            None => return false,
        }
    } else {
        &[]
    };

    match block_on(verify_by_sig_type(sig_type, region, sig_value, public_key)) {
        Ok(VerifyOutcome::Valid) => true,
        Ok(VerifyOutcome::Invalid) => false,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::Ed25519Signer;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn insecure_trust_produces_digest_sha256() {
        let trust = InsecureTrust;
        let bytes = encode_inner_data(&name("/ndn/dv/test"), b"hello", &trust);
        let data = Data::decode(bytes).unwrap();
        assert_eq!(
            data.sig_info().unwrap().sig_type,
            SignatureType::DigestSha256,
        );
    }

    #[test]
    fn static_trust_with_ed25519_signer_produces_ed25519_data() {
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[7u8; 32],
            name("/ndn/r1/KEY/abc"),
        ));
        let trust = StaticTrust::new(Some(Arc::clone(&signer)));
        let bytes = encode_inner_data(&name("/ndn/r1/dv/data"), b"sv", &trust);
        let data = Data::decode(bytes).unwrap();
        let sig = data.sig_info().unwrap();
        assert_eq!(sig.sig_type, SignatureType::SignatureEd25519);
        assert_eq!(
            sig.key_locator.as_ref().unwrap().to_string(),
            "/ndn/r1/KEY/abc",
        );
    }

    #[test]
    fn insecure_trust_accepts_anything() {
        let trust = InsecureTrust;
        let bytes = encode_inner_data(&name("/foo"), b"x", &InsecureTrust);
        assert!(validate_inner_data(&Data::decode(bytes).unwrap(), &trust));
    }

    #[test]
    fn static_trust_accepts_digest_sha256_by_default() {
        let trust = StaticTrust::new(None);
        let bytes = encode_inner_data(&name("/foo"), b"x", &InsecureTrust);
        assert!(validate_inner_data(&Data::decode(bytes).unwrap(), &trust));
    }

    #[test]
    fn static_trust_can_reject_digest_sha256_when_signatures_required() {
        let trust = StaticTrust::new(None).require_signatures();
        let bytes = encode_inner_data(&name("/foo"), b"x", &InsecureTrust);
        assert!(!validate_inner_data(&Data::decode(bytes).unwrap(), &trust));
    }

    fn ed25519_public_key(seed: [u8; 32], key: &Name) -> Bytes {
        let signer = Ed25519Signer::from_seed(&seed, key.clone());
        signer
            .public_key()
            .expect("Ed25519 signer exposes public key")
    }

    #[test]
    fn static_trust_accepts_ed25519_with_registered_key() {
        let key_name = name("/ndn/r1/KEY/abc");
        let public_key = ed25519_public_key([3u8; 32], &key_name);

        let signer: Arc<dyn Signer> =
            Arc::new(Ed25519Signer::from_seed(&[3u8; 32], key_name.clone()));
        let producer = StaticTrust::new(Some(Arc::clone(&signer)));
        let bytes = encode_inner_data(&name("/ndn/r1/dv/data"), b"sv", &producer);

        let consumer = StaticTrust::new(None).trust_key(key_name, public_key);
        assert!(validate_inner_data(
            &Data::decode(bytes).unwrap(),
            &consumer,
        ));
    }

    /// Forged data signed by an unknown key is rejected: the
    /// consumer doesn't recognize the producer's `KeyLocator`, so
    /// even though the signature cryptographically checks out,
    /// validation fails on the trusted-keys lookup.
    #[test]
    fn static_trust_rejects_ed25519_signed_by_unknown_key() {
        let attacker_signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[9u8; 32],
            name("/attacker/KEY/evil"),
        ));
        let producer = StaticTrust::new(Some(attacker_signer));
        let bytes = encode_inner_data(&name("/ndn/r1/dv/data"), b"sv", &producer);

        // Consumer's only trusted key is /ndn/r1/KEY/abc — the
        // attacker's KeyLocator names /attacker/KEY/evil, which
        // isn't in the map.
        let consumer = StaticTrust::new(None).trust_key(
            name("/ndn/r1/KEY/abc"),
            ed25519_public_key([3u8; 32], &name("/ndn/r1/KEY/abc")),
        );
        assert!(!validate_inner_data(
            &Data::decode(bytes).unwrap(),
            &consumer,
        ));
    }

    /// Empty schema rejects every key-based packet even when the
    /// signature cryptographically checks out — pins the
    /// `check`-before-`verify` ordering in `LvsTrust::validate`.
    #[test]
    fn lvs_trust_rejects_when_schema_walk_finds_no_signing_path() {
        let model = LvsModel::decode(&minimal_lvs_no_edges())
            .expect("hand-built minimal LVS model decodes");

        let key_name = name("/ndn/r1/KEY/abc");
        let signer: Arc<dyn Signer> =
            Arc::new(Ed25519Signer::from_seed(&[3u8; 32], key_name.clone()));
        let producer = StaticTrust::new(Some(Arc::clone(&signer)));
        let bytes = encode_inner_data(&name("/ndn/r1/dv/data"), b"sv", &producer);

        let consumer = LvsTrust::new(Arc::new(model), None).trust_key(
            key_name,
            ed25519_public_key([3u8; 32], &name("/ndn/r1/KEY/abc")),
        );
        assert!(!validate_inner_data(
            &Data::decode(bytes).unwrap(),
            &consumer,
        ));
    }

    #[test]
    fn lvs_trust_suggests_default_signer_for_outgoing() {
        let model = LvsModel::decode(&minimal_lvs_no_edges()).unwrap();
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[3u8; 32],
            name("/ndn/r1/KEY/abc"),
        ));
        let trust = LvsTrust::new(Arc::new(model), Some(Arc::clone(&signer)));
        let bytes = encode_inner_data(&name("/ndn/r1/dv/data"), b"sv", &trust);
        let data = Data::decode(bytes).unwrap();
        assert_eq!(
            data.sig_info().unwrap().sig_type,
            SignatureType::SignatureEd25519,
        );
    }

    /// One node, no edges, no sign constraints — `check(_, _)`
    /// returns `false` for every non-empty name.
    fn minimal_lvs_no_edges() -> Vec<u8> {
        use ndn_security::lvs::{LVS_VERSION, type_number as t};

        let mut buf = Vec::new();
        let mut tmp = [0u8; 8];

        push_tlv(&mut buf, t::VERSION, encode_u64_be(LVS_VERSION, &mut tmp));
        push_tlv(&mut buf, t::NODE_ID, encode_u64_be(0, &mut tmp));
        push_tlv(&mut buf, t::NAMED_PATTERN_NUM, encode_u64_be(0, &mut tmp));
        let node_body = {
            let mut nb = Vec::new();
            push_tlv(&mut nb, t::NODE_ID, encode_u64_be(0, &mut tmp));
            nb
        };
        push_tlv(&mut buf, t::NODE, &node_body);
        buf
    }

    fn push_tlv(out: &mut Vec<u8>, t: u64, v: &[u8]) {
        write_varu64(out, t);
        write_varu64(out, v.len() as u64);
        out.extend_from_slice(v);
    }

    fn write_varu64(out: &mut Vec<u8>, v: u64) {
        if v < 0xFD {
            out.push(v as u8);
        } else if v <= 0xFFFF {
            out.push(0xFD);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= 0xFFFF_FFFF {
            out.push(0xFE);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            out.push(0xFF);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// LVS `read_uint` accepts only 1/2/4/8-byte widths.
    fn encode_u64_be(v: u64, buf: &mut [u8; 8]) -> &[u8] {
        buf.copy_from_slice(&v.to_be_bytes());
        let width = if v <= 0xFF {
            1
        } else if v <= 0xFFFF {
            2
        } else if v <= 0xFFFF_FFFF {
            4
        } else {
            8
        };
        &buf[8 - width..]
    }
}
