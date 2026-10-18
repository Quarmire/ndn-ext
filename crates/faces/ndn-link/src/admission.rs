//! Who a peer is, whether its link is admitted, and what the link carries.

use std::sync::Arc;

use ndn_cert::onboarding::rdr_prefix;
use ndn_cert::roles::{Role, parse_device_key};
use ndn_face_quic::{
    Admission, Carries, CloseReason, KeyFingerprint, LinkHello, LinkScope, LinkVerdict, PeerKey,
};
use ndn_packet::{Data, Name};
use ndn_security::{CertCache, Certificate, Keyring, ValidationResult, Validator};

use crate::host::{LinkHints, LinkTrust};
use crate::peer::{PeerId, Peers};
use crate::policy::{ENROLLMENT_ANSWERS, ENROLLMENT_INTERESTS, MAX_CHAIN};

/// Who the peer is, from its certificate validated in a held namespace.
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    pub(crate) namespace: Name,
    pub(crate) version: u64,
    pub(crate) device: Name,
    pub(crate) role: Role,
    /// The certificate and its issuers, for revocation checks.
    pub(crate) certificates: Vec<Name>,
}

/// What the certificate a peer sent establishes.
pub(crate) enum Identified {
    /// A device of a namespace this device holds.
    Device(Identity),
    /// Nothing this device can use: no certificate, or one this device
    /// cannot validate (the reason). A peer's expected key may still admit
    /// it.
    Unknown(String),
}

#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) reason: CloseReason,
    pub(crate) text: String,
}

impl Refusal {
    pub(crate) fn new(reason: CloseReason, text: impl Into<String>) -> Self {
        Self {
            reason,
            text: text.into(),
        }
    }
}

/// Why a link is an enrollment link, on this side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Enrollment {
    /// This relay admitted a device it does not know, for its enrollment in
    /// these namespaces.
    Relay(Vec<Name>),
    /// This device, holding no certificate in the namespace, dialled a relay
    /// of it that it cannot confirm yet.
    Device(Name),
}

pub(crate) struct Admitted {
    pub(crate) fingerprint: KeyFingerprint,
    pub(crate) identity: Option<Identity>,
    pub(crate) peer: Option<PeerId>,
    pub(crate) enrollment: Option<Enrollment>,
}

impl Admitted {
    pub(crate) fn describe(&self) -> String {
        match &self.identity {
            Some(id) => format!("{} (key {})", id.device, self.fingerprint),
            None => format!("key {}", self.fingerprint),
        }
    }
}

/// The admission rules over the host's trust data and peers.
pub(crate) struct Judge<'a> {
    pub(crate) trust: &'a dyn LinkTrust,
    pub(crate) peers: &'a Peers,
    pub(crate) hints: &'a LinkHints,
}

impl Judge<'_> {
    fn keyring(&self) -> &Arc<Keyring> {
        self.trust.keyring()
    }

    /// The certificate this device links with now, if it has one.
    pub(crate) fn own_certificate(&self) -> Option<Certificate> {
        let chain = self.trust.own_chain();
        let wire = chain.first()?;
        let data = Data::decode(wire.clone()).ok()?;
        Certificate::decode(&data).ok()
    }

    /// This device's role in `namespace`, from the certificate it links
    /// with now; `None` when that certificate is not of `namespace`.
    pub(crate) fn own_role_in(&self, namespace: &Name) -> Option<Role> {
        let cert = self.own_certificate()?;
        parse_device_key(namespace, &cert.name).map(|d| d.role)
    }

    /// The namespace of `device` (`/<ns>/<role>/<device>`): the held one it
    /// is in, else its name without the role and device.
    fn namespace_of(&self, device: &Name) -> Name {
        let ctx = self.keyring().context_for(device);
        if !ctx.namespace().is_empty() {
            return ctx.namespace().clone();
        }
        Name::from_components(
            device.components()[..device.len().saturating_sub(2)]
                .iter()
                .cloned(),
        )
    }

    /// The namespaces this relay admits enrollment links for: held ones
    /// whose link policy allows them and whose trust context names a CA
    /// endpoint, where this device holds a certificate of a role the policy
    /// lets relay. `Err`: why none, for the refusal.
    fn enrollment_namespaces(&self) -> Result<Vec<Name>, String> {
        let mut namespaces = Vec::new();
        let mut why_not = Vec::new();
        for ctx in self.keyring().contexts() {
            let ns = ctx.namespace();
            if ns.is_empty() {
                continue;
            }
            let policy = ctx.link_policy();
            if !policy.enrollment_links {
                why_not.push(format!("{ns}'s link policy turns enrollment links off"));
                continue;
            }
            if ctx.ca_endpoints().is_empty() {
                why_not.push(format!("{ns}'s trust context names no CA to enroll at"));
                continue;
            }
            match self.own_role_in(ns) {
                Some(role) if policy.allows_relay(role.as_str()) => namespaces.push(ns.clone()),
                Some(role) => why_not.push(format!(
                    "{ns}'s link policy does not let {role} devices (this one) relay"
                )),
                None => why_not.push(format!("this device holds no certificate in {ns}")),
            }
        }
        if namespaces.is_empty() {
            Err(if why_not.is_empty() {
                "it holds no namespace".into()
            } else {
                why_not.join("; ")
            })
        } else {
            Ok(namespaces)
        }
    }

    /// What the certificates `hello` carries establish about `key`.
    pub(crate) async fn identify(&self, key: &PeerKey, hello: &LinkHello) -> Result<Identified, Refusal> {
        let Some((leaf_wire, issuers)) = hello.certificates.split_first() else {
            return Ok(Identified::Unknown("it sent no certificate".into()));
        };
        let decode = |wire: &bytes::Bytes| {
            Data::decode(wire.clone())
                .map_err(|e| e.to_string())
                .and_then(|data| Certificate::decode(&data).map(|c| (data, c)).map_err(|e| e.to_string()))
        };
        let (leaf_data, leaf) = decode(leaf_wire).map_err(|e| {
            Refusal::new(CloseReason::Protocol, format!("the certificate in your link hello does not decode: {e}"))
        })?;
        if leaf.public_key != key.ndn_public_key() {
            return Err(Refusal::new(
                CloseReason::CertificateForAnotherKey,
                format!(
                    "the certificate {} you sent is for another key than the one your link \
                     handshake proved ({}); a device links with the key its certificate certifies",
                    leaf.name,
                    key.fingerprint()
                ),
            ));
        }
        let ctx = self.keyring().context_for(&leaf.name);
        if ctx.namespace().is_empty() {
            return Ok(Identified::Unknown(format!(
                "its certificate {} is not of a namespace this device holds",
                leaf.name
            )));
        }
        let ns = ctx.namespace().clone();
        let version = ctx.version();
        if ctx.is_revoked(&leaf.name) {
            return Err(Refusal::new(
                CloseReason::Revoked,
                format!("your key {} is revoked in {ns} (trust context v{version})", leaf.key_name()),
            ));
        }
        let Some(device) = parse_device_key(&ns, &leaf.name) else {
            return Ok(Identified::Unknown(format!(
                "{} is not a device certificate of {ns} (/<namespace>/<role>/<device>/KEY/…)",
                leaf.name
            )));
        };
        if !leaf.is_valid_now() {
            return Ok(Identified::Unknown(format!(
                "its certificate {} is outside its validity period (renew it: {})",
                leaf.name, self.hints.renew
            )));
        }
        let mut chain: Vec<Certificate> = Vec::new();
        for wire in issuers.iter().take(MAX_CHAIN) {
            match decode(wire) {
                Ok((_, cert)) => chain.push(cert),
                Err(e) => {
                    return Err(Refusal::new(
                        CloseReason::Protocol,
                        format!("an issuer certificate in your link hello does not decode: {e}"),
                    ));
                }
            }
        }
        if let Some(revoked) = chain.iter().find(|c| ctx.is_revoked(&c.name)) {
            return Err(Refusal::new(
                CloseReason::Revoked,
                format!(
                    "your certificate's issuer {} is revoked in {ns} (trust context v{version})",
                    revoked.name
                ),
            ));
        }
        match self.validate(&leaf_data, &chain).await {
            ValidationResult::Valid(safe) if safe.is_authenticated() => {}
            ValidationResult::Valid(_) => {
                return Ok(Identified::Unknown(format!(
                    "its certificate {} is not signed by a key of {ns} (a DigestSha256 proves \
                     integrity, not who made it)",
                    leaf.name
                )));
            }
            ValidationResult::Invalid(e) => {
                return Ok(Identified::Unknown(format!(
                    "its certificate {} does not validate in {ns} v{version}: {e}",
                    leaf.name
                )));
            }
            ValidationResult::Pending => {
                return Ok(Identified::Unknown(format!(
                    "its certificate {}'s issuer chain was not sent and is not known here",
                    leaf.name
                )));
            }
        }
        let mut certificates = vec![(*leaf.name).clone()];
        certificates.extend(chain.iter().map(|c| (*c.name).clone()));
        let device_name = ns
            .clone()
            .append(device.role.as_str())
            .append(device.device.as_str());
        Ok(Identified::Device(Identity {
            namespace: ns,
            version,
            device: device_name,
            role: device.role,
            certificates,
        }))
    }

    /// Validate a peer's certificate against the held trust contexts, with
    /// the issuers it sent, then the certificates this device knows —
    /// never fetching (the link is not up yet) and never adding the peer's
    /// certificates to the host's cache.
    async fn validate(&self, leaf: &Data, issuers: &[Certificate]) -> ValidationResult {
        let cache = Arc::new(CertCache::new());
        for cert in issuers {
            cache.insert(cert.clone());
        }
        let validator = Validator::with_keyring(Arc::clone(self.keyring()), Arc::clone(&cache), None, MAX_CHAIN);
        for _ in 0..MAX_CHAIN {
            match validator.validate_chain_cached(leaf).await {
                (ValidationResult::Pending, Some(missing)) => match self.trust.known_certificate(&missing) {
                    Some(cert) => cache.insert(cert),
                    None => return ValidationResult::Pending,
                },
                (result, _) => return result,
            }
        }
        ValidationResult::Pending
    }

    /// Decide whether the link from `key` (which sent `hello`) is admitted.
    /// `dialed` is the peer this device dialed, `None` for a link another
    /// device opened.
    pub(crate) async fn decide(
        &self,
        key: &PeerKey,
        hello: &LinkHello,
        dialed: Option<PeerId>,
    ) -> Result<Admitted, Refusal> {
        let fingerprint = key.fingerprint();
        let identity = match self.identify(key, hello).await? {
            Identified::Device(id) => Ok(id),
            Identified::Unknown(why) => Err(why),
        };
        let peer = dialed.or_else(|| {
            self.peers
                .find(fingerprint, identity.as_ref().ok().map(|id| &id.device))
        });
        decide_identified(self, fingerprint, identity, peer, dialed)
    }

    /// How this side admits the link: what it tells the peer, and what the
    /// link carries.
    pub(crate) fn admission_for(&self, admitted: &Admitted) -> Admission {
        match &admitted.enrollment {
            None => Admission::default(),
            Some(Enrollment::Relay(namespaces)) => {
                let keyring = Arc::clone(self.keyring());
                let scoped = namespaces.clone();
                Admission {
                    verdict: LinkVerdict {
                        enrollment_link: Some(namespaces.clone()),
                    },
                    scope: Some(LinkScope {
                        receives: Carries::Interests,
                        sends: Carries::Answers,
                        names: Box::new(move |name: &Name| in_enrollment(&keyring, &scoped, name, true)),
                        rate: ENROLLMENT_INTERESTS,
                        explain: format!(
                            "the enrollment link of key {} carries only that device's enrollment in \
                             {} (Interests for its CA, trust context and certificates, and their \
                             answers); it links fully once it enrolls",
                            admitted.fingerprint,
                            list(namespaces)
                        ),
                    }),
                }
            }
            Some(Enrollment::Device(ns)) => {
                let keyring = Arc::clone(self.keyring());
                let scoped = vec![ns.clone()];
                let label = self.label(admitted);
                Admission {
                    verdict: LinkVerdict::default(),
                    scope: Some(LinkScope {
                        receives: Carries::Answers,
                        sends: Carries::Interests,
                        names: Box::new(move |name: &Name| in_enrollment(&keyring, &scoped, name, false)),
                        rate: ENROLLMENT_ANSWERS,
                        explain: format!(
                            "the link to {label} carries only this device's enrollment in {ns} (its \
                             CA, trust context and certificates) until this device enrolls: {}",
                            self.hints.enroll
                        ),
                    }),
                }
            }
        }
    }

    /// How messages name the admitted peer: its label, else its device and
    /// key.
    pub(crate) fn label(&self, admitted: &Admitted) -> String {
        admitted
            .peer
            .map(|i| self.peers.get(i).label.clone())
            .unwrap_or_else(|| admitted.describe())
    }
}

/// The admission matrix, once the peer's certificate is judged
/// (`identity`) and its peer entry found (`peer`).
fn decide_identified(
    judge: &Judge<'_>,
    fingerprint: KeyFingerprint,
    identity: Result<Identity, String>,
    peer: Option<PeerId>,
    dialed: Option<PeerId>,
) -> Result<Admitted, Refusal> {
    let hints = judge.hints;
    let config = peer.map(|i| judge.peers.get(i));
    let key_expected = config.is_some_and(|p| p.key == Some(fingerprint));

    if let Some(p) = config {
        if let Some(expected) = p.key
            && expected != fingerprint
        {
            return Err(Refusal::new(
                CloseReason::NotTheExpectedDevice,
                format!(
                    "this device expects {} to link with key {expected}, and yours is \
                     {fingerprint}",
                    p.label
                ),
            ));
        }
        if let Some(device) = &p.device {
            match &identity {
                Ok(id) if id.device != *device => {
                    return Err(Refusal::new(
                        CloseReason::NotTheExpectedDevice,
                        format!("this device expects {device} here, and you are {}", id.device),
                    ));
                }
                Err(why) if !key_expected => {
                    // Not enrolled in the namespace of the relay it
                    // dialled, this device cannot confirm it yet, and
                    // links to it for its enrollment only.
                    let ns = judge.namespace_of(device);
                    if dialed.is_some() && judge.own_role_in(&ns).is_none() {
                        return Ok(Admitted {
                            fingerprint,
                            identity: None,
                            peer,
                            enrollment: Some(Enrollment::Device(ns)),
                        });
                    }
                    return Err(Refusal::new(
                        CloseReason::Unrecognized,
                        format!(
                            "this device expects {device} here and cannot confirm you are it: \
                             {why}. It links once it holds {device}'s namespace, or once its \
                             {} names your key",
                            hints.peer_entry
                        ),
                    ));
                }
                _ => {}
            }
        }
    }

    match &identity {
        Ok(id) => {
            let ctx = judge.keyring().context_for(&id.device);
            let policy = ctx.link_policy();
            if !policy.allows_link(id.role.as_str()) {
                return Err(Refusal::new(
                    CloseReason::RoleNotAllowed,
                    format!(
                        "{}'s link policy (trust context v{}) does not let {} devices link",
                        id.namespace, id.version, id.role
                    ),
                ));
            }
            if peer.is_some_and(|p| judge.peers.is_relay(p)) && !policy.allows_relay(id.role.as_str()) {
                return Err(Refusal::new(
                    CloseReason::RoleNotAllowed,
                    format!(
                        "this device reaches others through you, and {}'s link policy (trust \
                         context v{}) does not let {} devices relay",
                        id.namespace, id.version, id.role
                    ),
                ));
            }
        }
        Err(why) if !key_expected => {
            // A device this relay does not know may enroll over it.
            let no_enrollment_link = if dialed.is_none() && config.is_none() {
                match judge.enrollment_namespaces() {
                    Ok(namespaces) => {
                        return Ok(Admitted {
                            fingerprint,
                            identity: None,
                            peer,
                            enrollment: Some(Enrollment::Relay(namespaces)),
                        });
                    }
                    Err(why_not) => format!(" It admits no enrollment link either: {why_not}."),
                }
            } else {
                String::new()
            };
            let held: Vec<String> = judge
                .keyring()
                .contexts()
                .iter()
                .map(|c| c.namespace().to_string())
                .collect();
            let held = if held.is_empty() {
                "none".to_string()
            } else {
                held.join(", ")
            };
            return Err(Refusal::new(
                CloseReason::Unrecognized,
                format!(
                    "this device links with devices of the namespaces it holds ({held}) and with \
                     the keys its {} entries expect; your key {fingerprint} is neither \
                     ({why}).{no_enrollment_link} Enroll this device in the namespace, or {}",
                    hints.peer_entry,
                    hints.expect_key.replace("{key}", &fingerprint.to_string())
                ),
            ));
        }
        Err(_) => {}
    }
    Ok(Admitted {
        fingerprint,
        identity: identity.ok(),
        peer,
        enrollment: None,
    })
}

/// Whether `name` is within the enrollment in one of `namespaces`: an
/// Interest (or its answer) for the namespace's trust context, for a CA
/// endpoint its held trust context names, or for a key or certificate name
/// in it (`<identity>/KEY/<key-id>[/<issuer>/<version>]`: the certificates
/// an enrollment fetches, the issued one and its issuers). On a relay
/// (`relay`), only while the namespace's link policy still admits
/// enrollment links.
pub(crate) fn in_enrollment(keyring: &Keyring, namespaces: &[Name], name: &Name, relay: bool) -> bool {
    namespaces.iter().any(|ns| {
        if !name.has_prefix(ns) {
            return false;
        }
        let ctx = keyring.contexts().into_iter().find(|c| c.namespace() == ns);
        if relay && !ctx.as_ref().is_some_and(|c| c.admits_enrollment_links()) {
            return false;
        }
        name.has_prefix(&rdr_prefix(ns))
            || ctx.is_some_and(|c| c.ca_endpoints().iter().any(|ca| name.has_prefix(ca)))
            || is_key_or_certificate_name(&name.components()[ns.len()..])
    })
}

/// `…/KEY/<key-id>`, optionally followed by `<issuer>/<version>`.
fn is_key_or_certificate_name(components: &[ndn_packet::NameComponent]) -> bool {
    components
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::NAME_COMPONENT && c.value.as_ref() == b"KEY")
        .is_some_and(|key| (1..=3).contains(&(components.len() - key - 1)))
}

pub(crate) fn list(names: &[Name]) -> String {
    names.iter().map(Name::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerSpec;
    use bytes::Bytes;
    use ndn_security::{LinkPolicy, SignedTrustContext};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn keyring_with(ctx: SignedTrustContext) -> Keyring {
        let keyring = Keyring::new();
        assert!(keyring.adopt(Arc::new(ctx)));
        keyring
    }

    #[test]
    fn an_enrollment_link_carries_only_the_enrollment() {
        let ctx = || {
            SignedTrustContext::hierarchical(n("/home"))
                .with_version(1)
                .with_ca_endpoint(n("/home/CA"))
        };
        let keyring = keyring_with(ctx());
        let ns = [n("/home")];
        let trust_context = rdr_prefix(&ns[0]).append("x");
        for (name, carried) in [
            (trust_context.clone(), true),
            (n("/home/CA/NEW"), true),
            (n("/home/CA/CHALLENGE/abc"), true),
            (n("/home/member/phone/KEY/k1/NDNCERT/v=1"), true),
            (n("/home/KEY/root"), true),
            (n("/home/member/phone/album"), false),
            (n("/home/node/relay/hello"), false),
            (n("/home/member/phone/KEY"), false),
            (n("/home/member/phone/files/KEY/a/b/c/d"), false),
            (n("/elsewhere/CA/NEW"), false),
        ] {
            for relay in [true, false] {
                assert_eq!(in_enrollment(&keyring, &ns, &name, relay), carried, "{name} (relay: {relay})");
            }
        }
        // A relay stops carrying enrollments once the namespace's link
        // policy turns enrollment links off.
        let off = keyring_with(ctx().with_link_policy(LinkPolicy {
            enrollment_links: false,
            ..LinkPolicy::default()
        }));
        assert!(!in_enrollment(&off, &ns, &n("/home/CA/NEW"), true));
        assert!(in_enrollment(&off, &ns, &n("/home/CA/NEW"), false));
    }

    /// Trust data with no certificate of its own.
    struct Bare(Arc<Keyring>);

    impl LinkTrust for Bare {
        fn keyring(&self) -> &Arc<Keyring> {
            &self.0
        }
        fn own_chain(&self) -> Vec<Bytes> {
            Vec::new()
        }
        fn known_certificate(&self, _: &Name) -> Option<Certificate> {
            None
        }
    }

    fn hints() -> LinkHints {
        LinkHints {
            enroll: "enroll it".into(),
            renew: "renew it".into(),
            refresh: "refresh".into(),
            peer_entry: "[[peer]]".into(),
            expect_key: "expect {key}".into(),
        }
    }

    fn spec(key: Option<KeyFingerprint>, device: Option<&str>) -> PeerSpec {
        PeerSpec {
            label: "p".into(),
            key,
            device: device.map(n),
            endpoints: Vec::new(),
            relay: None,
            routes: None,
            persistent: false,
            reliability: false,
        }
    }

    const THEIRS: KeyFingerprint = KeyFingerprint([7; 32]);

    fn decide(
        keyring: Keyring,
        peers: Vec<PeerSpec>,
        peer: Option<PeerId>,
        dialed: Option<PeerId>,
    ) -> Result<Admitted, Refusal> {
        let trust = Bare(Arc::new(keyring));
        let peers = Peers::new(peers);
        let hints = hints();
        let judge = Judge {
            trust: &trust,
            peers: &peers,
            hints: &hints,
        };
        decide_identified(&judge, THEIRS, Err("it sent no certificate".into()), peer, dialed)
    }

    #[test]
    fn an_expected_key_admits_an_unknown_device() {
        let admitted = decide(Keyring::new(), vec![spec(Some(THEIRS), None)], Some(PeerId(0)), None).unwrap();
        assert_eq!(admitted.peer, Some(PeerId(0)));
        assert!(admitted.enrollment.is_none() && admitted.identity.is_none());
    }

    #[test]
    fn another_key_than_the_expected_one_is_refused() {
        let other = KeyFingerprint([9; 32]);
        let refusal = decide(Keyring::new(), vec![spec(Some(other), None)], Some(PeerId(0)), Some(PeerId(0)))
            .err()
            .unwrap();
        assert_eq!(refusal.reason, CloseReason::NotTheExpectedDevice);
    }

    #[test]
    fn a_device_dialling_a_relay_of_a_namespace_it_is_not_in_links_for_its_enrollment() {
        let peers = vec![spec(None, Some("/home/node/relay"))];
        let admitted = decide(Keyring::new(), peers.clone(), Some(PeerId(0)), Some(PeerId(0))).unwrap();
        assert_eq!(admitted.enrollment, Some(Enrollment::Device(n("/home"))));
        // The same peer linking in is not confirmed.
        let refusal = decide(Keyring::new(), peers, Some(PeerId(0)), None).err().unwrap();
        assert_eq!(refusal.reason, CloseReason::Unrecognized);
    }

    #[test]
    fn a_relay_without_a_certificate_admits_no_enrollment_link() {
        let keyring = keyring_with(
            SignedTrustContext::hierarchical(n("/home"))
                .with_version(1)
                .with_ca_endpoint(n("/home/CA")),
        );
        let refusal = decide(keyring, Vec::new(), None, None).err().unwrap();
        assert_eq!(refusal.reason, CloseReason::Unrecognized);
        assert!(
            refusal.text.contains("this device holds no certificate in /home"),
            "{}",
            refusal.text
        );
        assert!(refusal.text.contains(&format!("expect {THEIRS}")), "{}", refusal.text);
    }

    /// One TLV element (types and lengths in NDN's variable-size encoding).
    fn tlv(typ: u64, value: &[u8]) -> Vec<u8> {
        let var = |n: u64| -> Vec<u8> {
            if n < 253 {
                vec![n as u8]
            } else {
                let mut v = vec![253];
                v.extend_from_slice(&(n as u16).to_be_bytes());
                v
            }
        };
        let mut out = var(typ);
        out.extend(var(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    /// A peer that proved its key in the handshake sends a device
    /// "certificate" for it carrying only a DigestSha256 — which anyone can
    /// compute, so it names no issuer. It identifies nobody: no namespace
    /// key certified it.
    #[tokio::test]
    async fn a_digest_only_certificate_identifies_no_device() {
        use ndn_packet::tlv_type as t;

        let keyring = keyring_with(SignedTrustContext::hierarchical(n("/home")).with_version(1));
        let raw = [3u8; 32];
        let spki = ndn_security::spki::wrap_ed25519(&raw);
        let peer = PeerKey::from_spki(&spki).unwrap();

        let name: Vec<u8> = ["home", "member", "phone", "KEY", "k1", "NDNCERT"]
            .iter()
            .flat_map(|c| tlv(t::NAME_COMPONENT, c.as_bytes()))
            .chain(tlv(0x36, &[1]))
            .collect();
        // ValidityPeriod (0xfd) { NotBefore (0xfe), NotAfter (0xff) }.
        let validity = [
            tlv(0xfe, b"20200101T000000"),
            tlv(0xff, b"20990101T000000"),
        ]
        .concat();
        let signed = [
            tlv(t::NAME, &name),
            tlv(t::META_INFO, &tlv(t::CONTENT_TYPE, &[2])),
            tlv(t::CONTENT, &spki),
            tlv(
                t::SIGNATURE_INFO,
                &[tlv(t::SIGNATURE_TYPE, &[0]), tlv(0xfd, &validity)].concat(),
            ),
        ]
        .concat();
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&signed)
        };
        let cert = tlv(t::DATA, &[signed, tlv(t::SIGNATURE_VALUE, digest.as_slice())].concat());
        let hello = LinkHello {
            certificates: vec![Bytes::from(cert)],
        };

        let trust = Bare(Arc::new(keyring));
        let peers = Peers::new(Vec::new());
        let hints = hints();
        let judge = Judge {
            trust: &trust,
            peers: &peers,
            hints: &hints,
        };
        match judge.identify(&peer, &hello).await {
            Ok(Identified::Unknown(why)) => assert!(why.contains("DigestSha256"), "{why}"),
            Ok(Identified::Device(id)) => panic!("a digest-only certificate identified {}", id.device),
            Err(refusal) => panic!("expected an unknown device, refused: {refusal:?}"),
        }
    }
}
