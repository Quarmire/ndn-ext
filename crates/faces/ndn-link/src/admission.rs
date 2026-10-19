//! Who a peer is, whether its link is admitted, and what the link carries.
//!
//! A peer is identified by its link key's certificate chain and by each
//! [`Membership`] its hello carries (a namespace it is a member of with
//! another key, bound to this connection): every one it proves is an
//! [`Identity`], and the link is admitted by any the local policy accepts.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::onboarding::rdr_prefix;
use ndn_cert::roles::{Role, parse_device_key};
use ndn_face_quic::{
    Admission, Carries, ChannelBinding, CloseReason, KeyFingerprint, LinkHello, LinkKey, LinkScope,
    LinkVerdict, MEMBERSHIPS_MAX, Membership, PeerKey,
};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use ndn_packet::{Data, Name};
use ndn_security::cert_name::key_name_of;
use ndn_security::{
    CertCache, Certificate, Keyring, SignedTrustContext, ValidationResult, Validator,
};

use crate::host::{LinkTrust, OwnMembership};
use crate::peer::{PeerId, Peers};
use crate::policy::{ENROLLMENT_ANSWERS, ENROLLMENT_INTERESTS, MAX_CHAIN};
use crate::serving::{QuotaSlot, QuotaState, ServePolicy};

/// Who the peer is, from its certificate validated in a held namespace —
/// or, for a namespace this device does not hold, offline against the
/// self-signed root certificate its hello carries.
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    pub(crate) namespace: Name,
    /// The held trust context's version; 0 for a namespace not held.
    pub(crate) version: u64,
    pub(crate) device: Name,
    pub(crate) role: Role,
    /// The certificate and its issuers, for revocation checks.
    pub(crate) certificates: Vec<Name>,
    /// `Some(root key fingerprint)`: a device of a namespace this device
    /// does not hold, checked offline against that root.
    pub(crate) served: Option<KeyFingerprint>,
}

/// What one certificate chain a peer sent establishes.
pub(crate) enum Identified {
    /// A device of a namespace this device holds, or of one whose root
    /// certificate the chain carries.
    Device(Identity),
    /// Nothing this device can use. A peer's expected key may still admit
    /// it.
    Unknown(Unidentified),
}

/// What a peer's hello establishes: every identity it proves (its link
/// key's certificate first, then its memberships), and why its link key's
/// certificate identifies nobody when it does not.
pub(crate) struct Proven {
    pub(crate) identities: Vec<Identity>,
    pub(crate) why: Unidentified,
}

/// Why a peer's certificate identifies nobody.
#[derive(Debug)]
pub(crate) enum Unidentified {
    /// Its hello carries no certificate.
    NoCertificate,
    /// One this device cannot validate (why).
    Unusable(LinkDetail),
}

impl Unidentified {
    pub(crate) fn detail(&self) -> LinkDetail {
        match self {
            Self::NoCertificate => LinkDetail::new(code::NO_CERTIFICATE, "it sent no certificate"),
            Self::Unusable(why) => why.clone(),
        }
    }
}

/// Why a link is refused: the close reason the other device gets, and what
/// this device says (its sentence is the close text).
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) reason: CloseReason,
    pub(crate) detail: LinkDetail,
}

impl Refusal {
    pub(crate) fn new(reason: CloseReason, detail: LinkDetail) -> Self {
        Self { reason, detail }
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
    /// Every identity the peer proved that this device's policy accepts,
    /// the one that decides the link (the device a peer entry expects, else
    /// one of this device's own namespaces) first. Empty for a peer
    /// admitted by its expected key alone, or on an enrollment link.
    pub(crate) identities: Vec<Identity>,
    pub(crate) peer: Option<PeerId>,
    pub(crate) enrollment: Option<Enrollment>,
    /// The link's place among the serving quotas, when the identity that
    /// decides it is served for a namespace other than this device's own
    /// (its limits bound the link): kept as long as the link.
    pub(crate) quota: Option<QuotaSlot>,
    /// The places of the other identities served for other namespaces:
    /// they hold their namespace's name and count against its quotas.
    pub(crate) quotas: Vec<QuotaSlot>,
}

impl Admitted {
    /// The identity that decides the link, if any.
    pub(crate) fn identity(&self) -> Option<&Identity> {
        self.identities.first()
    }

    pub(crate) fn describe(&self) -> String {
        if self.identities.is_empty() {
            return format!("key {}", self.fingerprint);
        }
        let devices: Vec<String> = self
            .identities
            .iter()
            .map(|id| id.device.to_string())
            .collect();
        format!("{} (key {})", devices.join(", "), self.fingerprint)
    }
}

/// The admission rules over the host's trust data and peers.
pub(crate) struct Judge<'a> {
    pub(crate) trust: &'a dyn LinkTrust,
    pub(crate) peers: &'a Peers,
    pub(crate) serve: &'a ServePolicy,
    pub(crate) quotas: &'a QuotaState,
}

impl Judge<'_> {
    fn keyring(&self) -> &Arc<Keyring> {
        self.trust.keyring()
    }

    /// This device's certificates: the one of the key it links with now
    /// (if it has one) first, then the one of each membership with another
    /// key ([`LinkTrust::own_memberships`]), with that membership.
    pub(crate) fn own_certificates(&self) -> Vec<(Certificate, Option<OwnMembership>)> {
        let mut out: Vec<(Certificate, Option<OwnMembership>)> = Vec::new();
        if let Some(cert) = self.trust.own_chain().first().and_then(decode_certificate) {
            out.push((cert, None));
        }
        for m in self.trust.own_memberships() {
            let Some(cert) = m.chain.first().and_then(decode_certificate) else {
                continue;
            };
            if out
                .iter()
                .any(|(c, _)| c.name == cert.name || c.public_key == cert.public_key)
            {
                continue;
            }
            out.push((cert, Some(m)));
        }
        out
    }

    /// This device's role in `namespace`, from the certificate it holds
    /// there (its link key's or a membership's); `None` when it holds none.
    pub(crate) fn own_role_in(&self, namespace: &Name) -> Option<Role> {
        self.own_certificates()
            .iter()
            .find_map(|(cert, _)| parse_device_key(namespace, &cert.name).map(|d| d.role))
    }

    /// This device's names (`/<ns>/<role>/<device>`), one per certificate
    /// it holds, the link key's first.
    pub(crate) fn own_devices(&self) -> Vec<Name> {
        self.own_certificates()
            .iter()
            .filter_map(|(cert, _)| device_of(&cert.name))
            .collect()
    }

    /// The namespace of `device` (`/<ns>/<role>/<device>`): the held one it
    /// is in, else its name without the role and device.
    pub(crate) fn namespace_of(&self, device: &Name) -> Name {
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
    /// lets relay. `Err`: why none, for the refusal
    /// ([`NO_ENROLLMENT_LINK`](code::NO_ENROLLMENT_LINK), one cause per
    /// namespace).
    fn enrollment_namespaces(&self) -> Result<Vec<Name>, LinkDetail> {
        let mut namespaces = Vec::new();
        let mut why_not = Vec::new();
        for ctx in self.keyring().contexts() {
            let ns = ctx.namespace();
            if ns.is_empty() {
                continue;
            }
            let policy = ctx.link_policy();
            if !policy.enrollment_links {
                why_not.push(
                    LinkDetail::new(
                        code::ENROLLMENT_LINKS_OFF,
                        format!("{ns}'s link policy turns enrollment links off"),
                    )
                    .with("namespace", ns),
                );
                continue;
            }
            if ctx.ca_endpoints().is_empty() {
                why_not.push(
                    LinkDetail::new(
                        code::ENROLLMENT_NO_CA,
                        format!("{ns}'s trust context names no CA to enroll at"),
                    )
                    .with("namespace", ns),
                );
                continue;
            }
            match self.own_role_in(ns) {
                Some(role) if policy.allows_relay(role.as_str()) => namespaces.push(ns.clone()),
                Some(role) => why_not.push(
                    LinkDetail::new(
                        code::ENROLLMENT_ROLE_MAY_NOT_RELAY,
                        format!("{ns}'s link policy does not let {role} devices (this one) relay"),
                    )
                    .with("namespace", ns)
                    .with("role", role),
                ),
                None => why_not.push(
                    LinkDetail::new(
                        code::ENROLLMENT_NO_CERTIFICATE,
                        format!("this device holds no certificate in {ns}"),
                    )
                    .with("namespace", ns),
                ),
            }
        }
        if !namespaces.is_empty() {
            return Ok(namespaces);
        }
        if why_not.is_empty() {
            why_not.push(LinkDetail::new(
                code::ENROLLMENT_NO_NAMESPACE,
                "it holds no namespace",
            ));
        }
        let text = format!(
            "It admits no enrollment link either: {}.",
            why_not
                .iter()
                .map(|d| d.text.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
        let mut detail = LinkDetail::new(code::NO_ENROLLMENT_LINK, text);
        detail.causes = why_not;
        Err(detail)
    }

    /// What `hello` (from the link key `key`, on the connection or punch
    /// whose binding value is `channel`) establishes: the identity of its
    /// link key's certificate and of each membership it proves.
    ///
    /// A malformed certificate, a link key certificate for another key or a
    /// membership not bound to this link refuse the link. A revoked
    /// certificate (or known revoked key), or a collision with a held name,
    /// only refuses it when no other identity is proved.
    pub(crate) async fn identify(
        &self,
        key: &PeerKey,
        hello: &LinkHello,
        channel: &ChannelBinding,
    ) -> Result<Proven, Refusal> {
        let mut identities: Vec<Identity> = Vec::new();
        let mut held_back: Option<Refusal> = None;
        let mut why = Unidentified::NoCertificate;
        if let Some(refusal) = self.revoked_key(key) {
            held_back = Some(refusal);
        } else if let Some((leaf_wire, issuers)) = hello.certificates.split_first() {
            let (leaf_data, leaf) = decode_with_data(leaf_wire).map_err(|e| {
                Refusal::new(
                    CloseReason::Protocol,
                    LinkDetail::new(
                        code::CERTIFICATE_UNDECODABLE,
                        format!("the certificate in your link hello does not decode: {e}"),
                    )
                    .with("error", &e),
                )
            })?;
            if leaf.public_key != key.ndn_public_key() {
                return Err(Refusal::new(
                    CloseReason::CertificateForAnotherKey,
                    LinkDetail::new(
                        code::CERTIFICATE_FOR_ANOTHER_KEY,
                        format!(
                            "the certificate {} you sent is for another key than the one your link \
                             handshake proved ({}); a device links with the key its certificate certifies",
                            leaf.name,
                            key.fingerprint()
                        ),
                    )
                    .with("certificate", &leaf.name)
                    .with("key", key.fingerprint()),
                ));
            }
            match self.identify_chain(&leaf_data, &leaf, issuers).await {
                Ok(Identified::Device(id)) => identities.push(id),
                Ok(Identified::Unknown(w)) => why = w,
                Err(refusal) if refusal.reason == CloseReason::Protocol => return Err(refusal),
                Err(refusal) => held_back = Some(refusal),
            }
        }
        let link_key = key.fingerprint();
        for membership in hello.memberships.iter().take(MEMBERSHIPS_MAX) {
            let (leaf_wire, issuers) = membership
                .certificates
                .split_first()
                .expect("a decoded membership carries a certificate");
            let (leaf_data, leaf) = decode_with_data(leaf_wire).map_err(|e| {
                Refusal::new(
                    CloseReason::Protocol,
                    LinkDetail::new(
                        code::MEMBERSHIP_UNDECODABLE,
                        format!("a membership certificate in your link hello does not decode: {e}"),
                    )
                    .with("error", &e),
                )
            })?;
            membership.verify(&leaf.public_key, &link_key, channel).await.map_err(|e| {
                Refusal::new(
                    CloseReason::MembershipNotBound,
                    LinkDetail::new(
                        code::MEMBERSHIP_NOT_BOUND,
                        format!(
                            "your membership certificate {} is not shown by its key: {e}. A device shows a \
                             membership only with the key that certificate certifies, bound anew to each link",
                            leaf.name
                        ),
                    )
                    .with("certificate", &leaf.name)
                    .with("error", &e),
                )
            })?;
            match self.identify_chain(&leaf_data, &leaf, issuers).await {
                Ok(Identified::Device(id)) => {
                    if !identities.iter().any(|i| i.namespace == id.namespace) {
                        identities.push(id);
                    }
                }
                Ok(Identified::Unknown(w)) => {
                    tracing::debug!(
                        target: "face.quic",
                        key = %link_key,
                        "a membership identifies nobody here: {}",
                        w.detail().text
                    );
                    if matches!(why, Unidentified::NoCertificate) && hello.certificates.is_empty() {
                        why = w;
                    }
                }
                Err(refusal) if refusal.reason == CloseReason::Protocol => return Err(refusal),
                Err(refusal) => {
                    held_back.get_or_insert(refusal);
                }
            }
        }
        if identities.is_empty()
            && let Some(refusal) = held_back
        {
            return Err(refusal);
        }
        Ok(Proven { identities, why })
    }

    /// What the certificate `leaf` (its Data `leaf_data`), with the issuers
    /// `issuers` sent with it, establishes (§7.1 steps 4–11, or R1–R7 for a
    /// namespace this device does not hold). The key it certifies was
    /// proved already.
    async fn identify_chain(
        &self,
        leaf_data: &Data,
        leaf: &Certificate,
        issuers: &[Bytes],
    ) -> Result<Identified, Refusal> {
        let unusable = |why: LinkDetail| Ok(Identified::Unknown(Unidentified::Unusable(why)));
        let mut chain: Vec<Certificate> = Vec::new();
        for wire in issuers.iter().take(MAX_CHAIN) {
            match decode_with_data(wire) {
                Ok((_, cert)) => chain.push(cert),
                Err(e) => {
                    return Err(Refusal::new(
                        CloseReason::Protocol,
                        LinkDetail::new(
                            code::ISSUER_UNDECODABLE,
                            format!(
                                "an issuer certificate in your link hello does not decode: {e}"
                            ),
                        )
                        .with("error", &e),
                    ));
                }
            }
        }
        let ctx = self.keyring().context_for(&leaf.name);
        if ctx.namespace().is_empty() {
            return Ok(self.identify_foreign(leaf_data, leaf, &chain).await);
        }
        let ns = ctx.namespace().clone();
        let version = ctx.version();
        if ctx.is_revoked(&leaf.name) {
            return Err(Refusal::new(
                CloseReason::Revoked,
                LinkDetail::new(
                    code::KEY_REVOKED,
                    format!(
                        "your key {} is revoked in {ns} (trust context v{version})",
                        leaf.key_name()
                    ),
                )
                .with("key", leaf.key_name())
                .with("namespace", &ns)
                .with("version", version),
            ));
        }
        let Some(device) = parse_device_key(&ns, &leaf.name) else {
            return unusable(
                LinkDetail::new(
                    code::NOT_DEVICE_CERTIFICATE,
                    format!(
                        "{} is not a device certificate of {ns} (/<namespace>/<role>/<device>/KEY/…)",
                        leaf.name
                    ),
                )
                .with("certificate", &leaf.name)
                .with("namespace", &ns),
            );
        };
        if !leaf.is_valid_now() {
            return unusable(certificate_expired(&leaf.name));
        }
        if let Some(revoked) = chain.iter().find(|c| ctx.is_revoked(&c.name)) {
            return Err(Refusal::new(
                CloseReason::Revoked,
                LinkDetail::new(
                    code::ISSUER_REVOKED,
                    format!(
                        "your certificate's issuer {} is revoked in {ns} (trust context v{version})",
                        revoked.name
                    ),
                )
                .with("issuer", &revoked.name)
                .with("namespace", &ns)
                .with("version", version),
            ));
        }
        let why = match self.validate(leaf_data, &chain).await {
            ValidationResult::Valid(safe) if safe.is_authenticated() => None,
            ValidationResult::Valid(_) => Some(certificate_unauthenticated(&leaf.name, &ns)),
            ValidationResult::Invalid(e) => Some(
                LinkDetail::new(
                    code::CERTIFICATE_INVALID,
                    format!(
                        "its certificate {} does not validate in {ns} v{version}: {e}",
                        leaf.name
                    ),
                )
                .with("certificate", &leaf.name)
                .with("namespace", &ns)
                .with("version", version)
                .with("error", &e),
            ),
            ValidationResult::Pending => Some(
                LinkDetail::new(
                    code::CERTIFICATE_CHAIN_UNKNOWN,
                    format!(
                        "its certificate {}'s issuer chain was not sent and is not known here",
                        leaf.name
                    ),
                )
                .with("certificate", &leaf.name),
            ),
        };
        if let Some(why) = why {
            // A namespace of another root under a held name: a relay
            // serving other namespaces says why it cannot.
            if !matches!(self.serve, ServePolicy::Own)
                && let Some(root) = chain
                    .last()
                    .filter(|c| is_self_signed(c) && !ctx.is_anchor(&c.name))
            {
                let root = KeyFingerprint::of_ndn_key(&root.public_key);
                return Err(Refusal::new(
                    CloseReason::NotServed,
                    LinkDetail::new(
                        code::ROOT_COLLIDES,
                        format!(
                            "your certificate {} chains to the root key {root}, and this relay holds {ns} \
                             with another root key: the names collide, and the relay cannot route both. \
                             Use a relay that does not hold {ns}",
                            leaf.name,
                        ),
                    )
                    .with("certificate", &leaf.name)
                    .with("root", root)
                    .with("namespace", &ns),
                ));
            }
            return unusable(why);
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
            served: None,
        }))
    }

    /// A device of a namespace this device does not hold: its certificate
    /// checked offline against the self-signed root certificate at the end
    /// of the chain its hello carries, under the rules of a namespace as
    /// `ndn-cert` makes them ([`namespace_context`]). Nothing can be
    /// revoked without the trust context.
    async fn identify_foreign(
        &self,
        leaf_data: &Data,
        leaf: &Certificate,
        chain: &[Certificate],
    ) -> Identified {
        let unusable = |why: LinkDetail| Identified::Unknown(Unidentified::Unusable(why));
        let Some(root) = chain.last().filter(|c| is_self_signed(c)) else {
            return unusable(
                LinkDetail::new(
                    code::FOREIGN_NO_ROOT,
                    format!(
                        "its certificate {} is not of a namespace this device holds, and its hello carries \
                         no self-signed root certificate to check it against",
                        leaf.name
                    ),
                )
                .with("certificate", &leaf.name),
            );
        };
        let Some(ns) = key_identity(&root.key_name()).filter(|ns| !ns.is_empty()) else {
            return unusable(
                LinkDetail::new(
                    code::FOREIGN_ROOT_NO_NAMESPACE,
                    format!("its root certificate {} names no namespace", root.name),
                )
                .with("root", &root.name),
            );
        };
        let Some(device) = parse_device_key(&ns, &leaf.name) else {
            return unusable(
                LinkDetail::new(
                    code::FOREIGN_NOT_DEVICE_CERTIFICATE,
                    format!(
                        "{} is not a device certificate of {ns}, the namespace of its root {} \
                         (/<namespace>/<role>/<device>/KEY/…)",
                        leaf.name, root.name
                    ),
                )
                .with("certificate", &leaf.name)
                .with("namespace", &ns)
                .with("root", &root.name),
            );
        };
        if !leaf.is_valid_now() {
            return unusable(certificate_expired(&leaf.name));
        }
        let Some(ctx) = namespace_context(&ns) else {
            return unusable(
                LinkDetail::new(
                    code::FOREIGN_ROOT_INVALID_NAMESPACE,
                    format!(
                        "its root certificate {} names no valid namespace",
                        root.name
                    ),
                )
                .with("root", &root.name),
            );
        };
        if !ctx.add_anchor(root.clone()) {
            return unusable(
                LinkDetail::new(
                    code::FOREIGN_ROOT_EXPIRED,
                    format!(
                        "its root certificate {} is outside its validity period",
                        root.name
                    ),
                )
                .with("root", &root.name),
            );
        }
        let keyring = Keyring::new();
        keyring.adopt(Arc::new(ctx));
        let cache = Arc::new(CertCache::new());
        for cert in chain {
            cache.insert(cert.clone());
        }
        let validator = Validator::with_keyring(Arc::new(keyring), cache, None, MAX_CHAIN);
        match validator.validate_chain_cached(leaf_data).await.0 {
            ValidationResult::Valid(safe) if safe.is_authenticated() => {}
            ValidationResult::Valid(_) => {
                return unusable(certificate_unauthenticated(&leaf.name, &ns));
            }
            ValidationResult::Invalid(e) => {
                return unusable(
                    LinkDetail::new(
                        code::FOREIGN_CERTIFICATE_INVALID,
                        format!(
                            "its certificate {} does not validate against its root {}: {e}",
                            leaf.name, root.name
                        ),
                    )
                    .with("certificate", &leaf.name)
                    .with("root", &root.name)
                    .with("error", &e),
                );
            }
            ValidationResult::Pending => {
                return unusable(
                    LinkDetail::new(
                        code::FOREIGN_CHAIN_INCOMPLETE,
                        format!(
                            "its hello does not carry the whole chain of its certificate {} to its root {}",
                            leaf.name, root.name
                        ),
                    )
                    .with("certificate", &leaf.name)
                    .with("root", &root.name),
                );
            }
        }
        let mut certificates = vec![(*leaf.name).clone()];
        certificates.extend(chain.iter().map(|c| (*c.name).clone()));
        let device_name = ns
            .clone()
            .append(device.role.as_str())
            .append(device.device.as_str());
        Identified::Device(Identity {
            namespace: ns,
            version: 0,
            device: device_name,
            role: device.role,
            certificates,
            served: Some(KeyFingerprint::of_ndn_key(&root.public_key)),
        })
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
        let validator = Validator::with_keyring(
            Arc::clone(self.keyring()),
            Arc::clone(&cache),
            None,
            MAX_CHAIN,
        );
        for _ in 0..MAX_CHAIN {
            match validator.validate_chain_cached(leaf).await {
                (ValidationResult::Pending, Some(missing)) => {
                    match self.trust.known_certificate(&missing) {
                        Some(cert) => cache.insert(cert),
                        None => return ValidationResult::Pending,
                    }
                }
                (result, _) => return result,
            }
        }
        ValidationResult::Pending
    }

    /// A refusal of `key` when this device knows a certificate of it that a
    /// held trust context revokes, whatever the peer's hello carries: a
    /// revoked device that sends no certificate gets no enrollment link
    /// either. A key this device knows no certificate of cannot be told
    /// from a new one; the CA refuses what it revoked.
    fn revoked_key(&self, key: &PeerKey) -> Option<Refusal> {
        let cert = self.trust.known_certificate_of_key(&key.fingerprint())?;
        let ctx = self.keyring().context_for(&cert.name);
        if ctx.namespace().is_empty() || !ctx.is_revoked(&cert.name) {
            return None;
        }
        Some(Refusal::new(
            CloseReason::Revoked,
            LinkDetail::new(
                code::KEY_REVOKED,
                format!(
                    "your key {} is revoked in {} (trust context v{})",
                    cert.key_name(),
                    ctx.namespace(),
                    ctx.version()
                ),
            )
            .with("key", cert.key_name())
            .with("namespace", ctx.namespace())
            .with("version", ctx.version()),
        ))
    }

    /// Decide whether the link from `key` (which sent `hello` on the
    /// connection or punch whose binding value is `channel`) is admitted.
    /// `dialed` is the peer this device dialed, `None` for a link another
    /// device opened.
    pub(crate) async fn decide(
        &self,
        key: &PeerKey,
        hello: &LinkHello,
        channel: &ChannelBinding,
        dialed: Option<PeerId>,
    ) -> Result<Admitted, Refusal> {
        let fingerprint = key.fingerprint();
        let proven = self.identify(key, hello, channel).await?;
        // A device name only a root this device does not hold vouches for
        // finds no peer entry.
        let devices: Vec<&Name> = proven
            .identities
            .iter()
            .filter(|id| id.served.is_none())
            .map(|id| &id.device)
            .collect();
        let peer = dialed.or_else(|| self.peers.find_any(fingerprint, &devices));
        let identities = if proven.identities.is_empty() {
            Err(proven.why)
        } else {
            Ok(proven.identities)
        };
        decide_identified(self, fingerprint, identities, peer, dialed)
    }

    /// How this side admits the link: what it tells the peer, and what the
    /// link carries.
    pub(crate) fn admission_for(&self, admitted: &Admitted) -> Admission {
        match &admitted.enrollment {
            None => match admitted
                .quota
                .as_ref()
                .and_then(|slot| slot.limits.clone().map(|l| (slot, l)))
            {
                None => Admission::default(),
                Some((slot, (rate, shared))) => Admission {
                    verdict: LinkVerdict::default(),
                    scope: Some(LinkScope {
                        receives: Carries::Everything,
                        sends: Carries::Everything,
                        names: Box::new(|_: &Name| true),
                        rate,
                        shared: Some(shared),
                        explain: format!(
                            "this relay serves {} of {} under its quotas: {}/s from that device, and \
                             a share of the namespace's limit of all its devices here; to carry more, \
                             its operator raises the quotas, or the namespace uses another relay",
                            admitted.describe(),
                            slot.namespace,
                            rate.per_sec
                        ),
                    }),
                },
            },
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
                        names: Box::new(move |name: &Name| {
                            in_enrollment(&keyring, &scoped, name, true)
                        }),
                        rate: ENROLLMENT_INTERESTS,
                        shared: None,
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
                        names: Box::new(move |name: &Name| {
                            in_enrollment(&keyring, &scoped, name, false)
                        }),
                        rate: ENROLLMENT_ANSWERS,
                        shared: None,
                        explain: format!(
                            "the link to {label} carries only this device's enrollment in {ns} (its \
                             CA, trust context and certificates) until this device enrolls"
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
            .map(|i| self.peers.label(i))
            .unwrap_or_else(|| admitted.describe())
    }
}

/// The admission matrix, once the peer's certificates are judged
/// (`identities`: every identity it proved, never empty when `Ok`) and its
/// peer entry found (`peer`).
fn decide_identified(
    judge: &Judge<'_>,
    fingerprint: KeyFingerprint,
    identities: Result<Vec<Identity>, Unidentified>,
    peer: Option<PeerId>,
    dialed: Option<PeerId>,
) -> Result<Admitted, Refusal> {
    let config = peer.and_then(|i| judge.peers.get(i));
    let key_expected = config.as_ref().is_some_and(|p| p.key == Some(fingerprint));
    // Only a held namespace confirms a device a peer entry names.
    let identities = match identities {
        Ok(ids) if config.is_some() => {
            let (held, served): (Vec<Identity>, Vec<Identity>) =
                ids.into_iter().partition(|id| id.served.is_none());
            if held.is_empty() {
                let namespaces: Vec<Name> = served.into_iter().map(|id| id.namespace).collect();
                Err(Unidentified::Unusable(
                    LinkDetail::new(
                        code::NAMESPACE_NOT_HELD,
                        format!(
                            "its certificate is of {}, a namespace this device does not hold",
                            list(&namespaces)
                        ),
                    )
                    .with("namespaces", list(&namespaces)),
                ))
            } else {
                Ok(held)
            }
        }
        other => other,
    };
    let admitted = |identities, enrollment, quota, quotas| Admitted {
        fingerprint,
        identities,
        peer,
        enrollment,
        quota,
        quotas,
    };

    if let Some(p) = &config {
        if let Some(expected) = p.key
            && expected != fingerprint
        {
            return Err(Refusal::new(
                CloseReason::NotTheExpectedDevice,
                LinkDetail::new(
                    code::NOT_EXPECTED_KEY,
                    format!(
                        "this device expects {} to link with key {expected}, and yours is \
                         {fingerprint}",
                        p.label
                    ),
                )
                .with("peer", &p.label)
                .with("expected", expected)
                .with("key", fingerprint),
            ));
        }
        if let Some(device) = &p.device {
            match &identities {
                Ok(ids) if !ids.iter().any(|id| id.device == *device) => {
                    let devices: Vec<Name> = ids.iter().map(|id| id.device.clone()).collect();
                    return Err(Refusal::new(
                        CloseReason::NotTheExpectedDevice,
                        LinkDetail::new(
                            code::NOT_EXPECTED_DEVICE,
                            format!(
                                "this device expects {device} here, and you are {}",
                                list(&devices)
                            ),
                        )
                        .with("expected", device)
                        .with("devices", list(&devices)),
                    ));
                }
                Err(why) if !key_expected => {
                    // Not enrolled in the namespace of the relay it
                    // dialled, this device cannot confirm it yet, and
                    // links to it for its enrollment only.
                    let ns = judge.namespace_of(device);
                    if dialed.is_some() && judge.own_role_in(&ns).is_none() {
                        return Ok(admitted(
                            Vec::new(),
                            Some(Enrollment::Device(ns)),
                            None,
                            Vec::new(),
                        ));
                    }
                    let why = why.detail();
                    return Err(Refusal::new(
                        CloseReason::Unrecognized,
                        LinkDetail::new(
                            code::EXPECTED_DEVICE_UNCONFIRMED,
                            format!(
                                "this device expects {device} here and cannot confirm you are it: \
                                 {}. It links once it holds {device}'s namespace, or once its \
                                 peer entry names your key",
                                why.text
                            ),
                        )
                        .with("device", device)
                        .caused_by(why),
                    ));
                }
                _ => {}
            }
        }
    }

    // Nobody asked for the link: it may be an enrollment link.
    let unasked = dialed.is_none() && config.is_none();
    match identities {
        Ok(mut ids) => {
            // The device a peer entry expects decides the link.
            let expected = config.as_ref().and_then(|p| p.device.as_ref());
            if let Some(at) = expected.and_then(|d| ids.iter().position(|id| id.device == *d)) {
                let id = ids.remove(at);
                ids.insert(0, id);
            }
            // Each identity in a held namespace is judged by that
            // namespace's link policy; the peer is admitted by the ones it
            // allows.
            let mut refused: Option<Refusal> = None;
            let mut allowed = Vec::new();
            for (i, id) in ids.into_iter().enumerate() {
                match link_policy_refusal(judge, &id, peer) {
                    None => allowed.push(id),
                    Some(refusal) if i == 0 && expected.is_some() => return Err(refusal),
                    Some(refusal) => {
                        refused.get_or_insert(refusal);
                    }
                }
            }
            let Some(first) = refused.filter(|_| allowed.is_empty()) else {
                if config.is_some() {
                    return Ok(admitted(allowed, None, None, Vec::new()));
                }
                return serve(judge, fingerprint, peer, allowed, unasked);
            };
            Err(first)
        }
        Err(why) if !key_expected => {
            // A device this relay does not know may enroll over it.
            let no_enrollment_link = if unasked {
                match judge.enrollment_namespaces() {
                    Ok(namespaces) => {
                        return Ok(admitted(
                            Vec::new(),
                            Some(Enrollment::Relay(namespaces)),
                            None,
                            Vec::new(),
                        ));
                    }
                    Err(why_not) => Some(why_not),
                }
            } else {
                None
            };
            let fragment = no_enrollment_link
                .as_ref()
                .map(|d| format!(" {}", d.text))
                .unwrap_or_default();
            if matches!(why, Unidentified::NoCertificate) && config.is_none() {
                let serves = match judge.serve {
                    ServePolicy::Own => None,
                    ServePolicy::Listed { .. } => Some((
                        "listed",
                        "this relay serves devices of its own and of listed namespaces",
                    )),
                    ServePolicy::Open { .. } => {
                        Some(("open", "an open relay serves devices of namespaces"))
                    }
                };
                if let Some((policy, serves)) = serves {
                    let mut detail = LinkDetail::new(
                        code::NOT_SERVED_NO_CERTIFICATE,
                        format!(
                            "{serves}: it routes your device name from your certificate, and your \
                             hello carries none.{fragment} Enroll this device in a namespace, or have \
                             the other device expect key {fingerprint}"
                        ),
                    )
                    .with("policy", policy)
                    .with("key", fingerprint);
                    detail.causes.extend(no_enrollment_link);
                    return Err(Refusal::new(CloseReason::NotServed, detail));
                }
            }
            let held: Vec<String> = judge
                .keyring()
                .contexts()
                .iter()
                .map(|c| c.namespace().to_string())
                .collect();
            let held = held.join(", ");
            let why = why.detail();
            let mut detail = LinkDetail::new(
                code::UNRECOGNIZED_KEY,
                format!(
                    "this device links with devices of the namespaces it holds ({}) and with \
                     the keys its peer entries expect; your key {fingerprint} is neither \
                     ({}).{fragment} Enroll this device in the namespace, or have the other device \
                     expect key {fingerprint}",
                    if held.is_empty() { "none" } else { &held },
                    why.text
                ),
            )
            .with("key", fingerprint)
            .caused_by(why);
            if !held.is_empty() {
                detail = detail.with("held", held);
            }
            detail.causes.extend(no_enrollment_link);
            Err(Refusal::new(CloseReason::Unrecognized, detail))
        }
        Err(_) => Ok(admitted(Vec::new(), None, None, Vec::new())),
    }
}

/// Why the link policy of `id`'s namespace refuses it here, if it does:
/// its role may not link, or may not relay when this device reaches others
/// through it (`peer` is a relay). A served identity has no policy here.
fn link_policy_refusal(judge: &Judge<'_>, id: &Identity, peer: Option<PeerId>) -> Option<Refusal> {
    if id.served.is_some() {
        return None;
    }
    let ctx = judge.keyring().context_for(&id.device);
    let policy = ctx.link_policy();
    if !policy.allows_link(id.role.as_str()) {
        return Some(Refusal::new(
            CloseReason::RoleNotAllowed,
            LinkDetail::new(
                code::ROLE_MAY_NOT_LINK,
                format!(
                    "{}'s link policy (trust context v{}) does not let {} devices link",
                    id.namespace, id.version, id.role
                ),
            )
            .with("namespace", &id.namespace)
            .with("version", id.version)
            .with("role", id.role.as_str()),
        ));
    }
    if peer.is_some_and(|p| judge.peers.is_relay(p)) && !policy.allows_relay(id.role.as_str()) {
        return Some(Refusal::new(
            CloseReason::RoleNotAllowed,
            LinkDetail::new(
                code::ROLE_MAY_NOT_RELAY,
                format!(
                    "this device reaches others through you, and {}'s link policy (trust \
                     context v{}) does not let {} devices relay",
                    id.namespace, id.version, id.role
                ),
            )
            .with("namespace", &id.namespace)
            .with("version", id.version)
            .with("role", id.role.as_str()),
        ));
    }
    None
}

/// The serving policy's decision on a peer nobody asked for, over the
/// identities its link policies allow (`ids`, never empty): it is served by
/// each identity the policy serves, the ones of this device's own
/// namespaces (never under quota) first, then those served without limits,
/// then those under quotas — the first decides the link's scope. Refused
/// with the first refusal when the policy serves none.
fn serve(
    judge: &Judge<'_>,
    fingerprint: KeyFingerprint,
    peer: Option<PeerId>,
    ids: Vec<Identity>,
    unasked: bool,
) -> Result<Admitted, Refusal> {
    let mut served: Vec<(Identity, Option<QuotaSlot>)> = Vec::new();
    let mut refused: Option<(Refusal, bool)> = None;
    for id in ids {
        match judge.serves(&id) {
            Ok(quota) => served.push((id, quota)),
            Err(refusal) => {
                refused.get_or_insert((refusal, id.served.is_some()));
            }
        }
    }
    if served.is_empty() {
        let (mut refusal, foreign) = refused.expect("an identity was judged");
        // A device of another namespace gets no enrollment link: it proved
        // whom it is, and this relay does not serve it.
        if refusal.reason == CloseReason::NotServed
            && foreign
            && unasked
            && let Ok(namespaces) = judge.enrollment_namespaces()
        {
            refusal.detail.append(
                ". ",
                LinkDetail::new(
                    code::ENROLLMENT_POSSIBLE,
                    format!(
                        "A device enrolls in {} over this relay while its hello holds no \
                         certificate of another namespace",
                        list(&namespaces)
                    ),
                )
                .with("namespaces", list(&namespaces)),
            );
        }
        return Err(refusal);
    }
    served.sort_by_key(|(_, quota)| match quota {
        None => 0,
        Some(slot) if slot.limits.is_none() => 1,
        Some(_) => 2,
    });
    let mut admitted = Admitted {
        fingerprint,
        identities: Vec::with_capacity(served.len()),
        peer,
        enrollment: None,
        quota: None,
        quotas: Vec::new(),
    };
    for (i, (id, quota)) in served.into_iter().enumerate() {
        admitted.identities.push(id);
        match quota {
            Some(slot) if i == 0 => admitted.quota = Some(slot),
            Some(slot) => admitted.quotas.push(slot),
            None => {}
        }
    }
    Ok(admitted)
}

/// This device's certificate chain as a link hello (and a punch message)
/// carries it: [`LinkTrust::own_chain`], ending in its namespace's root
/// ([`with_root`]).
pub(crate) fn hello_chain(trust: &dyn LinkTrust) -> Vec<Bytes> {
    with_root(trust.keyring(), trust.own_chain())
}

/// `chain` (a certificate and its issuers as this device keeps them),
/// ending in the self-signed root certificate of its namespace — the
/// anchor of the held trust context, which the chain a device keeps does
/// not hold — so a relay that does not hold the namespace can check it
/// against its root.
pub(crate) fn with_root(keyring: &Keyring, mut chain: Vec<Bytes>) -> Vec<Bytes> {
    let Some(last) = chain
        .last()
        .and_then(decode_certificate)
        .filter(|c| !is_self_signed(c))
    else {
        return chain;
    };
    let anchor = last.issuer.as_deref().and_then(|issuer| {
        let ctx = keyring.context_for(issuer);
        if ctx.namespace().is_empty() {
            return None;
        }
        ctx.anchor_for(issuer)
    });
    if let Some(wire) = anchor.and_then(|a| a.data_wire()) {
        chain.push(wire);
    }
    chain
}

/// This device's memberships as a hello or a punch message shows them:
/// one per namespace it is a member of with a key other than `link` (its
/// link key), its chain ending in the namespace's root, bound to `link` on
/// `channel`; only the one of `namespace` when given. At most
/// [`MEMBERSHIPS_MAX`]. A membership whose key cannot sign is left out, and
/// said so.
pub(crate) async fn own_memberships(
    trust: &dyn LinkTrust,
    link: &LinkKey,
    channel: &ChannelBinding,
    namespace: Option<&Name>,
) -> Vec<Membership> {
    let link_public = PeerKey::from_spki(link.spki())
        .map(|k| k.ndn_public_key())
        .ok();
    let fingerprint = link.fingerprint();
    let mut shown: Vec<Name> = Vec::new();
    let mut out = Vec::new();
    for m in trust.own_memberships() {
        if out.len() >= MEMBERSHIPS_MAX {
            break;
        }
        if namespace.is_some_and(|ns| *ns != m.namespace) || shown.contains(&m.namespace) {
            continue;
        }
        let Some(cert) = m.chain.first().and_then(decode_certificate) else {
            continue;
        };
        if link_public.as_ref() == Some(&cert.public_key) {
            continue;
        }
        let chain = with_root(trust.keyring(), m.chain.clone());
        match Membership::sign(m.signer.as_ref(), &fingerprint, channel, chain).await {
            Ok(membership) => {
                shown.push(m.namespace.clone());
                out.push(membership);
            }
            Err(e) => tracing::warn!(
                target: "face.quic",
                namespace = %m.namespace,
                "this device's membership of {} is not shown on its links: {e}",
                m.namespace
            ),
        }
    }
    out
}

/// A certificate Data wire, decoded.
fn decode_certificate(wire: &Bytes) -> Option<Certificate> {
    decode_with_data(wire).ok().map(|(_, cert)| cert)
}

/// A certificate Data wire, decoded, with its Data.
fn decode_with_data(wire: &Bytes) -> Result<(Data, Certificate), String> {
    let data = Data::decode(wire.clone()).map_err(|e| e.to_string())?;
    let cert = Certificate::decode(&data).map_err(|e| e.to_string())?;
    Ok((data, cert))
}

/// The device a certificate name `/<ns>/<role>/<device>/KEY/…` is of: the
/// name before its first `KEY` component.
pub(crate) fn device_of(cert: &Name) -> Option<Name> {
    let key = cert.components().iter().position(|c| {
        c.typ == ndn_packet::tlv_type::NAME_COMPONENT && c.value.as_ref() == b"KEY"
    })?;
    Some(Name::from_components(
        cert.components()[..key].iter().cloned(),
    ))
}

/// The trust context of `ns` as `ndn-cert` makes a namespace — its schema
/// (authoritative), its CA at `<ns>/CA` — without anchors, revocations or
/// link policy; `None` when `ns` is not a valid namespace name.
fn namespace_context(ns: &Name) -> Option<SignedTrustContext> {
    let schema = ndn_cert::namespace_schema(ns).ok()?;
    let ctx = SignedTrustContext::hierarchical(ns.clone())
        .with_schema_blobs(schema.blobs())
        .ok()?
        .schema_authoritative()
        .with_ca_endpoint(ns.clone().append("CA"));
    Some(ctx)
}

/// Whether `cert` is signed by its own key.
fn is_self_signed(cert: &Certificate) -> bool {
    cert.issuer.as_deref().map(key_name_of) == Some(cert.key_name())
}

/// The identity of a key name `<identity>/KEY/<key-id>`.
fn key_identity(key: &Name) -> Option<Name> {
    let components = key.components();
    let at = components.len().checked_sub(2)?;
    (components[at].value.as_ref() == b"KEY")
        .then(|| Name::from_components(components[..at].iter().cloned()))
}

/// Whether `name` is within the enrollment in one of `namespaces`: an
/// Interest (or its answer) for the namespace's trust context, for a CA
/// endpoint its held trust context names, or for a key or certificate name
/// in it (`<identity>/KEY/<key-id>[/<issuer>/<version>]`: the certificates
/// an enrollment fetches, the issued one and its issuers). On a relay
/// (`relay`), only while the namespace's link policy still admits
/// enrollment links.
pub(crate) fn in_enrollment(
    keyring: &Keyring,
    namespaces: &[Name],
    name: &Name,
    relay: bool,
) -> bool {
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
    names
        .iter()
        .map(Name::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A peer's certificate `certificate` is outside its validity period: it
/// renews it.
fn certificate_expired(certificate: &Name) -> LinkDetail {
    LinkDetail::new(
        code::CERTIFICATE_EXPIRED,
        format!("its certificate {certificate} is outside its validity period (renew it)"),
    )
    .with("certificate", certificate)
}

/// A peer's certificate `certificate` is not signed by a key of `ns`.
fn certificate_unauthenticated(certificate: &Name, ns: &Name) -> LinkDetail {
    LinkDetail::new(
        code::CERTIFICATE_UNAUTHENTICATED,
        format!(
            "its certificate {certificate} is not signed by a key of {ns} (a DigestSha256 proves \
             integrity, not who made it)"
        ),
    )
    .with("certificate", certificate)
    .with("namespace", ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerSpec;
    use crate::serving::Quotas;
    use ndn_security::{Ed25519Signer, LinkPolicy, Signer, encode_cert_data};

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
                assert_eq!(
                    in_enrollment(&keyring, &ns, &name, relay),
                    carried,
                    "{name} (relay: {relay})"
                );
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

    /// Trust data: a keyring, this device's own chain, and at most one
    /// certificate of a peer's key it knows.
    struct Bare(Arc<Keyring>, Option<Certificate>, Vec<Bytes>);

    impl LinkTrust for Bare {
        fn keyring(&self) -> &Arc<Keyring> {
            &self.0
        }
        fn own_chain(&self) -> Vec<Bytes> {
            self.2.clone()
        }
        fn known_certificate(&self, _: &Name) -> Option<Certificate> {
            None
        }
        fn known_certificate_of_key(&self, fingerprint: &KeyFingerprint) -> Option<Certificate> {
            self.1
                .clone()
                .filter(|c| KeyFingerprint::of_ndn_key(&c.public_key) == *fingerprint)
        }
    }

    /// What a judge judges over.
    struct World {
        trust: Bare,
        peers: Peers,
        serve: ServePolicy,
        quotas: QuotaState,
    }

    impl World {
        fn new(trust: Bare, peers: Vec<PeerSpec>, serve: ServePolicy) -> Self {
            Self {
                trust,
                peers: Peers::new(peers),
                serve,
                quotas: QuotaState::default(),
            }
        }

        fn judge(&self) -> Judge<'_> {
            Judge {
                trust: &self.trust,
                peers: &self.peers,
                serve: &self.serve,
                quotas: &self.quotas,
            }
        }
    }

    fn spec(key: Option<KeyFingerprint>, device: Option<&str>) -> PeerSpec {
        PeerSpec {
            label: "p".into(),
            key,
            device: device.map(n),
            persistent: false,
            ..PeerSpec::default()
        }
    }

    const THEIRS: KeyFingerprint = KeyFingerprint([7; 32]);

    fn decide(
        keyring: Keyring,
        peers: Vec<PeerSpec>,
        peer: Option<PeerId>,
        dialed: Option<PeerId>,
    ) -> Result<Admitted, Refusal> {
        let world = World::new(
            Bare(Arc::new(keyring), None, Vec::new()),
            peers,
            ServePolicy::Own,
        );
        decide_identified(
            &world.judge(),
            THEIRS,
            Err(Unidentified::NoCertificate),
            peer,
            dialed,
        )
    }

    fn now_ns() -> u64 {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        u64::try_from(since.as_nanos()).unwrap()
    }

    /// A certificate Data of `key` (a key name) for `public_key`, issued by
    /// `issuer`, valid from an hour ago for a day.
    async fn certificate(
        key: &Name,
        public_key: [u8; 32],
        issuer: &Ed25519Signer,
        issuer_id: &str,
    ) -> Bytes {
        let hour = 3_600_000_000_000;
        let name = ndn_security::cert_name::new_cert_name(key, issuer_id);
        encode_cert_data(
            &name,
            &public_key,
            issuer,
            now_ns() - hour,
            now_ns() + 24 * hour,
        )
        .await
        .unwrap()
    }

    /// A namespace as `ndn-cert` makes one: a root key with its self-signed
    /// certificate, and the CA (`<ns>/CA`) the root certified.
    struct Namespace {
        name: Name,
        root: Bytes,
        root_key: [u8; 32],
        ca: Ed25519Signer,
        ca_cert: Bytes,
    }

    async fn namespace(name: &str, seed: u8) -> Namespace {
        let name = n(name);
        let root = Ed25519Signer::from_seed(&[seed; 32], name.clone().append("KEY").append("root"));
        let root_cert = certificate(root.key_name(), root.public_key_bytes(), &root, "self").await;
        let ca = Ed25519Signer::from_seed(
            &[seed + 1; 32],
            name.clone().append("CA").append("KEY").append("ca"),
        );
        let ca_cert = certificate(ca.key_name(), ca.public_key_bytes(), &root, "NA").await;
        Namespace {
            name,
            root: root_cert,
            root_key: root.public_key_bytes(),
            ca,
            ca_cert,
        }
    }

    impl Namespace {
        fn root_fingerprint(&self) -> KeyFingerprint {
            KeyFingerprint::of_ndn_key(&self.root_key)
        }

        /// Its trust context, as a device holding it has it.
        fn context(&self) -> SignedTrustContext {
            let ctx = namespace_context(&self.name).unwrap().with_version(1);
            assert!(ctx.add_anchor(
                Certificate::decode(&Data::decode(self.root.clone()).unwrap()).unwrap()
            ));
            ctx
        }

        /// A device `/<ns>/<role>/<device>`: its link key and its
        /// certificate chain as it keeps it (its certificate, then its CA's).
        async fn device(&self, role: &str, device: &str, seed: u8) -> (PeerKey, Vec<Bytes>) {
            let name = self
                .name
                .clone()
                .append(role)
                .append(device)
                .append("KEY")
                .append("k");
            let key = Ed25519Signer::from_seed(&[seed; 32], name);
            let cert =
                certificate(key.key_name(), key.public_key_bytes(), &self.ca, "NDNCERT").await;
            let peer =
                PeerKey::from_spki(&ndn_security::spki::wrap_ed25519(&key.public_key_bytes()))
                    .unwrap();
            (peer, vec![cert, self.ca_cert.clone()])
        }
    }

    fn hello(certificates: Vec<Bytes>) -> LinkHello {
        LinkHello {
            certificates,
            ..LinkHello::default()
        }
    }

    /// A connection's binding value, for hellos without memberships.
    const CH: ChannelBinding = [0; 32];

    /// A relay holding `held` and linking with the certificate of
    /// `/a/node/relay` in `own`, under `serve`. Its namespace turns
    /// enrollment links off, so refusals are not softened into them.
    async fn relay(own: &Namespace, held: &[&Namespace], serve: ServePolicy) -> World {
        let keyring = Keyring::new();
        assert!(
            keyring.adopt(Arc::new(own.context().with_link_policy(LinkPolicy {
                enrollment_links: false,
                ..LinkPolicy::default()
            })))
        );
        for ns in held {
            assert!(keyring.adopt(Arc::new(ns.context())));
        }
        let (_, chain) = own.device("node", "relay", 90).await;
        World::new(Bare(Arc::new(keyring), None, chain), Vec::new(), serve)
    }

    /// Under the default policy a relay serves the devices of its own
    /// namespace only: one of a namespace it holds but holds no certificate
    /// in, or of one it does not hold, is refused as not served, saying
    /// whom it serves.
    #[tokio::test]
    async fn own_serves_only_the_namespaces_this_device_is_in() {
        let (a, b, c) = (
            namespace("/a", 10).await,
            namespace("/b", 20).await,
            namespace("/c", 30).await,
        );
        let world = relay(&a, &[&b], ServePolicy::Own).await;
        let judge = world.judge();

        let (key, chain) = a.device("member", "laptop", 12).await;
        let admitted = judge.decide(&key, &hello(chain), &CH, None).await.unwrap();
        assert!(admitted.quota.is_none());
        assert_eq!(admitted.identity().unwrap().device, n("/a/member/laptop"));

        let (key, chain) = b.device("member", "phone", 22).await;
        let refusal = judge
            .decide(&key, &hello(chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        assert!(
            refusal.detail.is(code::NOT_SERVED_UNCERTIFIED),
            "{:?}",
            refusal.detail
        );
        assert_eq!(refusal.detail.param("own"), Some("/a"));

        let (key, mut chain) = c.device("member", "phone", 32).await;
        chain.push(c.root.clone());
        let refusal = judge
            .decide(&key, &hello(chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        assert!(
            refusal.detail.is(code::NOT_SERVED_OWN),
            "{:?}",
            refusal.detail
        );
        assert_eq!(
            refusal.detail.param("root"),
            Some(c.root_fingerprint().to_string().as_str())
        );
    }

    /// A listed relay serves a namespace it does not hold by its root key:
    /// the device's hello (as [`hello_chain`] makes it) carries the root,
    /// against which its chain is checked offline. Another root is refused.
    #[tokio::test]
    async fn listed_serves_listed_roots_only() {
        let (a, c, d) = (
            namespace("/a", 10).await,
            namespace("/c", 30).await,
            namespace("/d", 40).await,
        );
        let serve = ServePolicy::Listed {
            roots: vec![c.root_fingerprint()],
            quotas: None,
        };
        let world = relay(&a, &[], serve).await;
        let judge = world.judge();

        let (key, chain) = c.device("member", "phone", 32).await;
        let device_side = Bare(Arc::new(keyring_with(c.context())), None, chain);
        let admitted = judge
            .decide(&key, &hello(hello_chain(&device_side)), &CH, None)
            .await
            .unwrap();
        let id = admitted.identity().unwrap();
        assert_eq!(
            (id.device.clone(), id.served),
            (n("/c/member/phone"), Some(c.root_fingerprint()))
        );
        assert!(admitted.quota.as_ref().is_some_and(|q| q.limits.is_none()));
        assert!(judge.admission_for(&admitted).scope.is_none());

        let (key, mut chain) = d.device("member", "phone", 42).await;
        chain.push(d.root.clone());
        let refusal = judge
            .decide(&key, &hello(chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        assert!(
            refusal.detail.is(code::NOT_SERVED_UNLISTED),
            "{:?}",
            refusal.detail
        );
    }

    /// A relay that admits enrollment links still refuses a device that
    /// proves it is of another namespace it does not serve; a device whose
    /// hello carries no certificate gets the enrollment link.
    #[tokio::test]
    async fn a_device_of_another_namespace_gets_no_enrollment_link() {
        let (a, c) = (namespace("/a", 10).await, namespace("/c", 30).await);
        let keyring = keyring_with(a.context());
        let (_, own) = a.device("node", "relay", 90).await;
        let world = World::new(
            Bare(Arc::new(keyring), None, own),
            Vec::new(),
            ServePolicy::Own,
        );
        let judge = world.judge();

        let (key, mut chain) = c.device("member", "phone", 32).await;
        chain.push(c.root.clone());
        let refusal = judge
            .decide(&key, &hello(chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        assert!(
            refusal
                .detail
                .causes
                .iter()
                .any(|d| d.is(code::ENROLLMENT_POSSIBLE) && d.param("namespaces") == Some("/a")),
            "{:?}",
            refusal.detail
        );

        let admitted = judge
            .decide(&key, &hello(Vec::new()), &CH, None)
            .await
            .unwrap();
        assert_eq!(admitted.enrollment, Some(Enrollment::Relay(vec![n("/a")])));
    }

    fn served(namespace: &str, device: &str, root: KeyFingerprint) -> Identity {
        Identity {
            namespace: n(namespace),
            version: 0,
            device: n(device),
            role: Role::Member,
            certificates: Vec::new(),
            served: Some(root),
        }
    }

    /// An open relay bounds the links of each namespace and of all, binds
    /// a namespace name to one root while its links live, rate-limits what
    /// served devices send, and refuses a device whose hello carries no
    /// certificate (it routes device names from certificates).
    #[test]
    fn open_enforces_quotas_and_one_root_per_name() {
        let serve = ServePolicy::Open {
            quotas: Quotas {
                links_total: 2,
                links_per_namespace: 1,
                ..Quotas::default()
            },
        };
        let world = World::new(
            Bare(Arc::new(Keyring::new()), None, Vec::new()),
            Vec::new(),
            serve,
        );
        let judge = world.judge();
        let (c, d, x) = (
            KeyFingerprint([3; 32]),
            KeyFingerprint([4; 32]),
            KeyFingerprint([5; 32]),
        );
        let decide = |id: Identity| decide_identified(&judge, THEIRS, Ok(vec![id]), None, None);

        let first = decide(served("/c", "/c/member/a", c)).unwrap();
        let scope = judge.admission_for(&first).scope.unwrap();
        assert_eq!(
            (scope.receives, scope.sends),
            (Carries::Everything, Carries::Everything)
        );
        assert!(scope.shared.is_some());
        let refusal = decide(served("/c", "/c/member/b", c)).err().unwrap();
        assert_eq!(refusal.reason, CloseReason::Busy, "{}", refusal.detail.text);
        assert!(
            refusal.detail.is(code::QUOTA_NAMESPACE_LINKS),
            "{:?}",
            refusal.detail
        );
        let _second = decide(served("/d", "/d/member/a", d)).unwrap();
        let refusal = decide(served("/d", "/d/member/b", x)).err().unwrap();
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        assert!(
            refusal.detail.is(code::NAMESPACE_COLLIDES),
            "{:?}",
            refusal.detail
        );
        let refusal = decide(served("/x", "/x/member/a", x)).err().unwrap();
        assert_eq!(refusal.reason, CloseReason::Busy, "{}", refusal.detail.text);
        assert!(refusal.detail.is(code::QUOTA_LINKS), "{:?}", refusal.detail);
        // A link that ends gives its place back.
        drop(first);
        let _third = decide(served("/x", "/x/member/a", x)).unwrap();

        let refusal =
            decide_identified(&judge, THEIRS, Err(Unidentified::NoCertificate), None, None)
                .err()
                .unwrap();
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        assert!(
            refusal.detail.is(code::NOT_SERVED_NO_CERTIFICATE),
            "{:?}",
            refusal.detail
        );
        assert_eq!(refusal.detail.param("policy"), Some("open"));
    }

    #[test]
    fn an_expected_key_admits_an_unknown_device() {
        let admitted = decide(
            Keyring::new(),
            vec![spec(Some(THEIRS), None)],
            Some(PeerId(0)),
            None,
        )
        .unwrap();
        assert_eq!(admitted.peer, Some(PeerId(0)));
        assert!(admitted.enrollment.is_none() && admitted.identity().is_none());
        // Also a device of a namespace this device holds and is not in,
        // which the serving policy (own) does not serve.
        let world = World::new(
            Bare(
                Arc::new(keyring_with(
                    SignedTrustContext::hierarchical(n("/b")).with_version(1),
                )),
                None,
                Vec::new(),
            ),
            vec![spec(Some(THEIRS), None)],
            ServePolicy::Own,
        );
        let id = Identity {
            served: None,
            version: 1,
            ..served("/b", "/b/member/phone", THEIRS)
        };
        let admitted =
            decide_identified(&world.judge(), THEIRS, Ok(vec![id]), Some(PeerId(0)), None).unwrap();
        assert!(admitted.identity().is_some() && admitted.quota.is_none());
    }

    #[test]
    fn another_key_than_the_expected_one_is_refused() {
        let other = KeyFingerprint([9; 32]);
        let refusal = decide(
            Keyring::new(),
            vec![spec(Some(other), None)],
            Some(PeerId(0)),
            Some(PeerId(0)),
        )
        .err()
        .unwrap();
        assert_eq!(refusal.reason, CloseReason::NotTheExpectedDevice);
        assert!(
            refusal.detail.is(code::NOT_EXPECTED_KEY),
            "{:?}",
            refusal.detail
        );
    }

    #[test]
    fn a_device_dialling_a_relay_of_a_namespace_it_is_not_in_links_for_its_enrollment() {
        let peers = vec![spec(None, Some("/home/node/relay"))];
        let admitted = decide(
            Keyring::new(),
            peers.clone(),
            Some(PeerId(0)),
            Some(PeerId(0)),
        )
        .unwrap();
        assert_eq!(admitted.enrollment, Some(Enrollment::Device(n("/home"))));
        // The same peer linking in is not confirmed.
        let refusal = decide(Keyring::new(), peers, Some(PeerId(0)), None)
            .err()
            .unwrap();
        assert_eq!(refusal.reason, CloseReason::Unrecognized);
        assert!(
            refusal.detail.is(code::EXPECTED_DEVICE_UNCONFIRMED),
            "{:?}",
            refusal.detail
        );
        assert!(
            refusal.detail.causes[0].is(code::NO_CERTIFICATE),
            "{:?}",
            refusal.detail
        );
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
            refusal.detail.is(code::UNRECOGNIZED_KEY),
            "{:?}",
            refusal.detail
        );
        assert_eq!(
            refusal.detail.param("key"),
            Some(THEIRS.to_string().as_str())
        );
        let no_enrollment = refusal
            .detail
            .causes
            .iter()
            .find(|d| d.is(code::NO_ENROLLMENT_LINK))
            .unwrap();
        assert!(
            no_enrollment
                .causes
                .iter()
                .any(|d| d.is(code::ENROLLMENT_NO_CERTIFICATE)
                    && d.param("namespace") == Some("/home")),
            "{:?}",
            refusal.detail
        );
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
        let validity = [tlv(0xfe, b"20200101T000000"), tlv(0xff, b"20990101T000000")].concat();
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
        let cert = tlv(
            t::DATA,
            &[signed, tlv(t::SIGNATURE_VALUE, digest.as_slice())].concat(),
        );
        let hello = hello(vec![Bytes::from(cert)]);

        let world = World::new(
            Bare(Arc::new(keyring), None, Vec::new()),
            Vec::new(),
            ServePolicy::Own,
        );
        let judge = world.judge();
        match judge.identify(&peer, &hello, &CH).await {
            Ok(proven) if proven.identities.is_empty() => {
                assert!(
                    proven.why.detail().is(code::CERTIFICATE_UNAUTHENTICATED),
                    "{:?}",
                    proven.why
                );
            }
            Ok(proven) => panic!(
                "a digest-only certificate identified {}",
                proven.identities[0].device
            ),
            Err(refusal) => panic!("expected an unknown device, refused: {refusal:?}"),
        }
    }

    /// A device whose key is revoked sends no certificate, hoping for an
    /// enrollment link: a relay that knows a certificate of that key refuses
    /// it as revoked.
    #[tokio::test]
    async fn a_revoked_key_sending_no_certificate_is_refused_as_revoked() {
        let keyring = keyring_with(
            SignedTrustContext::hierarchical(n("/home"))
                .with_version(2)
                .with_ca_endpoint(n("/home/CA"))
                .with_revocation(n("/home/member/phone/KEY/k1")),
        );
        let raw = [5u8; 32];
        let peer = PeerKey::from_spki(&ndn_security::spki::wrap_ed25519(&raw)).unwrap();
        let known = |name: &str| Certificate {
            name: Arc::new(n(name)),
            public_key: Bytes::copy_from_slice(&raw),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        let identify = |trust: Bare| {
            let peer = peer.clone();
            async move {
                let world = World::new(trust, Vec::new(), ServePolicy::Own);
                world
                    .judge()
                    .identify(&peer, &LinkHello::default(), &CH)
                    .await
            }
        };
        let keyring = Arc::new(keyring);
        match identify(Bare(
            Arc::clone(&keyring),
            Some(known("/home/member/phone/KEY/k1/CA/v=1")),
            Vec::new(),
        ))
        .await
        {
            Err(refusal) => {
                assert_eq!(refusal.reason, CloseReason::Revoked);
                assert!(refusal.detail.is(code::KEY_REVOKED), "{:?}", refusal.detail);
                assert_eq!(
                    refusal.detail.param("key"),
                    Some("/home/member/phone/KEY/k1")
                );
            }
            Ok(_) => panic!("a revoked key was not refused"),
        }
        // A key whose known certificate is not revoked, or one this relay
        // knows nothing of, is merely unknown (an enrollment link may admit
        // it).
        for known in [Some(known("/home/member/laptop/KEY/k2/CA/v=1")), None] {
            assert!(matches!(
                identify(Bare(Arc::clone(&keyring), known, Vec::new())).await,
                Ok(proven) if proven.identities.is_empty()
            ));
        }
    }
}
