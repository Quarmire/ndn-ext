//! Who a peer is, whether its link is admitted, and what the link carries.
//!
//! A peer is identified by its link key's certificate chain and by each
//! [`Membership`] its hello carries (a namespace it is a member of with
//! another key, bound to this connection): every one it proves is an
//! [`Identity`], and the link is admitted by any the local policy accepts.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use ndn_cert::onboarding::rdr_prefix;
use ndn_cert::roles::{Role, parse_device_key};
use ndn_face_quic::{
    Admission, Carries, ChannelBinding, ChannelPolicy, CloseReason, KeyFingerprint, LinkHello,
    LinkKey, LinkScope, LinkVerdict, MEMBERSHIPS_MAX, Membership, Narrowing, PeerKey,
    RatedInterests, bounded_text, clean_text,
};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use ndn_packet::{Data, Name};
use ndn_security::cert_name::key_name_of;
use ndn_security::self_certifying::{key_digest, self_certifying_digest};
use ndn_security::{
    CertCache, Certificate, Keyring, SignedTrustContext, ValidationResult, Validator,
};

use crate::departures::Departures;
use crate::grants::{Grant, GrantOutcome, Grants, is_data_ask};
use crate::host::{LinkTrust, OwnMembership};
use crate::introduce::Introductions;
use crate::peer::{PeerId, Peers};
use crate::policy::{DATA_ASKS, ENROLLMENT_ANSWERS, ENROLLMENT_INTERESTS, MAX_CHAIN};
use crate::serving::{Limits, QuotaSlot, QuotaState, ServePolicy, Serving};

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
    /// The certificate of the chain (the leaf or an issuer) that lapses first and
    /// when (its NotAfter), `None` when none has one: the identity holds only
    /// while all of them are valid, so a live link ends at that time
    /// ([`Identity::lapse`]).
    pub(crate) lapses: Option<(Name, SystemTime)>,
}

/// What to do about a lapsed certificate, for the words a link closed for it carries.
pub(crate) const RENEW: &str = "renew the certificate (its CA renews a current one; a device \
                                that was offline across its NotAfter enrolls again) and link again";

impl Identity {
    /// Why this identity's certificate chain no longer holds at `now`, when a
    /// certificate of it lapsed (the clock is past its NotAfter): the sentence a
    /// link closed for it carries ([`RENEW`] says what to do).
    pub(crate) fn lapse(&self, now: SystemTime) -> Option<String> {
        let (certificate, at) = self.lapses.as_ref()?;
        (now > *at).then(|| {
            format!(
                "{certificate} lapsed at {} (its NotAfter), so {} no longer has a valid certificate",
                crate::grants::utc(*at),
                self.device
            )
        })
    }
}

/// The certificate of `leaf` and the `chain` it was validated through that lapses
/// first, with its NotAfter; `None` when none of them has one.
fn first_lapse(leaf: &Certificate, chain: &[Certificate]) -> Option<(Name, SystemTime)> {
    std::iter::once(leaf)
        .chain(chain)
        .filter(|c| c.valid_until != u64::MAX)
        .min_by_key(|c| c.valid_until)
        .map(|c| {
            (
                (*c.name).clone(),
                UNIX_EPOCH + Duration::from_nanos(c.valid_until),
            )
        })
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
    /// these namespaces. A device with no certificate may also be the
    /// joiner of an open offer (a first contact's hello is empty), so while
    /// an offer is open the link carries the introduction's surface too.
    Relay(Vec<Name>, Option<crate::introduce::Surface>),
    /// This device, holding no certificate in the namespace, dialled a relay
    /// of it that it cannot confirm yet.
    Device(Name),
    /// This device admitted a device it does not know on an introduction
    /// link, while an offer is open: it carries only the Interests the
    /// introductions' surface carries (the one exchange of an open offer)
    /// and their answers.
    Introduction(crate::introduce::Surface),
    /// This device admitted a device it let go of a folder on a departure
    /// link (§8.8): it carries only the members records that leave the
    /// person out and the names that validate them, Interests toward this
    /// device and answers toward the peer. Holds the marks the person was
    /// told of.
    Departure(Vec<crate::departures::Departure>),
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
    /// The grant that admitted the link, when no policy did (it closes
    /// when the grant ends).
    pub(crate) grant: Option<Grant>,
    /// The namespaces the peer's hello says it follows (`LinkHello::follows`,
    /// at most [`FOLLOWS_MAX`](ndn_face_quic::FOLLOWS_MAX)): what it tells a
    /// relay it uses, so that the relay routes their sync groups over the
    /// link ([`routes_for`](crate::routes)). Only a claim: it buys that route
    /// on a full link and nothing else.
    pub(crate) follows: Vec<Name>,
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
    /// The peers a code's dial added whose link was made again because this
    /// device came to hold their namespace: a party that answers such a dial
    /// must show a certificate of that namespace.
    pub(crate) relinked: &'a parking_lot::Mutex<std::collections::HashSet<PeerId>>,
    pub(crate) serve: &'a ServePolicy,
    pub(crate) quotas: &'a QuotaState,
    pub(crate) grants: &'a Grants,
    pub(crate) departures: &'a Departures,
    /// What this device's introductions serve: the names a grant link may
    /// carry besides the person's own ([`Introductions::grant_carries`]).
    /// `None`: this device has no data layer to name a folder's collections.
    pub(crate) introductions: Option<Arc<dyn Introductions>>,
    /// The space groups the host says this device follows
    /// ([`Links::set_followed_groups`](crate::Links::set_followed_groups)),
    /// what a relay it uses is told.
    pub(crate) followed_groups: &'a parking_lot::Mutex<Vec<Name>>,
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

    /// The introduction surface of this device while an offer is open
    /// ([`Introductions::open`]): what a link carries besides its own errand
    /// when a joiner may be the one at the other end.
    fn open_introductions(&self) -> Option<crate::introduce::Surface> {
        self.introductions
            .clone()
            .filter(|surface| surface.open())
            .map(crate::introduce::Surface)
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
            return unusable(not_a_device_certificate(
                code::NOT_DEVICE_CERTIFICATE,
                &leaf.name,
                &ns,
                None,
            ));
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
            lapses: first_lapse(leaf, &chain),
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
            return unusable(not_a_device_certificate(
                code::FOREIGN_NOT_DEVICE_CERTIFICATE,
                &leaf.name,
                &ns,
                Some(&root.name),
            ));
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
        // A self-certifying namespace not held is known here only by its
        // name: the root its devices chain to must be the genesis root the
        // name hashes. A recovered or moved root is known only to a device
        // that holds the namespace (adopted by name, from its genesis).
        if let Ok(Some(digest)) = self_certifying_digest(&ns) {
            let genesis_root = <[u8; 32]>::try_from(root.public_key.as_ref())
                .is_ok_and(|key| key_digest(&key) == digest);
            if !genesis_root {
                return unusable(
                    LinkDetail::new(
                        code::FOREIGN_ROOT_INVALID_NAMESPACE,
                        format!(
                            "its root certificate {} is not the key its self-certifying \
                             namespace {ns} hashes: a device that does not hold {ns} knows its \
                             devices only by that genesis root; adopt {ns} by name to follow its \
                             current root",
                            root.name
                        ),
                    )
                    .with("root", &root.name)
                    .with("namespace", &ns),
                );
            }
        }
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
        let keyring =
            Keyring::of_claim(Arc::new(ctx)).expect("a namespace context names a valid namespace");
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
            lapses: first_lapse(leaf, chain),
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
        decide_identified(self, fingerprint, identities, peer, dialed).map(|mut admitted| {
            admitted.follows.clone_from(&hello.follows);
            admitted
        })
    }

    /// What a link to a peer this device dialled from an introduction code
    /// ([`dial_by_key`](crate::Links::dial_by_key), `dial_first`: a peer entry
    /// with `unidentified_routes`) carries while the peer has shown no
    /// certificate: the party at that key was named by a code, not proved by a
    /// namespace, so what it sends toward this device is bounded. Its answers
    /// are carried under the routes this device asked for, its Interests
    /// only under this device's own names (the inviter fetches the joiner's
    /// seal key there), and neither is handed on beyond what the scope
    /// carries; this device's own Interests go out under the routes only.
    /// `None`: not such a link, or the peer showed a certificate (a full
    /// link).
    fn dialled_admission(&self, admitted: &Admitted) -> Option<Admission> {
        if !admitted.identities.is_empty() {
            return None;
        }
        let routes = self
            .peers
            .get(admitted.peer?)?
            .unidentified_routes
            .clone()?;
        let own = self.own_devices();
        let (asked, answered) = (routes.clone(), routes.clone());
        let (named, allowed) = (own.clone(), own.clone());
        Some(Admission {
            verdict: LinkVerdict::default(),
            scope: Some(LinkScope {
                receives: Carries::Everything,
                sends: Carries::Everything,
                names: Box::new(move |name: &Name| {
                    asked.iter().any(|r| name.has_prefix(r))
                        || named.iter().any(|d| name.has_prefix(d))
                }),
                rate: ENROLLMENT_ANSWERS,
                bandwidth: None,
                rated: Vec::new(),
                interests: None,
                answered: None,
                shared: None,
                answers_in: Some(Box::new(move |name: &Name| {
                    answered.iter().any(|r| name.has_prefix(r))
                })),
                interests_in: Some(Box::new(move |name: &Name| {
                    allowed.iter().any(|d| name.has_prefix(d))
                })),
                narrowing: None,
                counts: None,
                explain: format!(
                    "the link to {} was dialled from an introduction code and the party shows no \
                     certificate this device holds: it carries the answers to what this device \
                     asks under {} and only the Interests for this device's own names ({}); it \
                     links fully once the party shows a certificate of a namespace this device \
                     holds",
                    self.label(admitted),
                    list(&routes),
                    if own.is_empty() {
                        "none: this device holds no certificate".to_string()
                    } else {
                        list(&own)
                    }
                ),
            }),
            ..Admission::default()
        })
    }

    /// How this side admits the link: what it tells the peer, what the
    /// link carries as NDN packets (its scope) and whether it carries
    /// channel frames (ndn-link.md §17A).
    pub(crate) fn admission_for(&self, admitted: &Admitted) -> Admission {
        Admission {
            channel: self.channel_policy(admitted),
            ..self.scoped_admission(admitted)
        }
    }

    /// Whether the admitted link carries channel frames, and under which fair
    /// share (ndn-link.md §17A). An own namespace's `admin`, `member` or
    /// `node` on a full link: carried, no quota. A `guest`: not carried (a
    /// guest is no member of a space). A grant link: carried, under its
    /// root's fair share. A relay's strangers (quota links), enrollment,
    /// introduction and departure links, and a peer admitted by its expected
    /// key alone (no identity): not carried, and the link is not closed over
    /// what such a peer sends. A device of a namespace this device serves
    /// without limits, or a relay of another namespace this device follows:
    /// carried as a forwarder, which judges nothing.
    pub(crate) fn channel_policy(&self, admitted: &Admitted) -> ChannelPolicy {
        let no = ChannelPolicy::default();
        if admitted.enrollment.is_some() {
            return no;
        }
        match admitted
            .quota
            .as_ref()
            .and_then(|slot| slot.limits.as_ref())
        {
            Some(limits) => match limits.serving {
                Serving::Granted => ChannelPolicy {
                    carry: true,
                    quota: limits.channel.clone(),
                },
                Serving::Stranger | Serving::Guest => no,
            },
            None => match admitted.identity() {
                Some(id) if id.role != Role::Guest => ChannelPolicy {
                    carry: true,
                    quota: None,
                },
                _ => no,
            },
        }
    }

    /// What the link carries as NDN packets, and what it tells the peer.
    fn scoped_admission(&self, admitted: &Admitted) -> Admission {
        match &admitted.enrollment {
            None => match admitted
                .quota
                .as_ref()
                .and_then(|slot| slot.limits.clone().map(|l| (slot, l)))
            {
                None => self.dialled_admission(admitted).unwrap_or_default(),
                Some((
                    slot,
                    Limits {
                        serving,
                        rate,
                        bandwidth,
                        interests,
                        answered,
                        shared,
                        channel: _,
                    },
                )) => {
                    let own: Vec<Name> = admitted
                        .identities
                        .iter()
                        .map(|id| id.device.clone())
                        .collect();
                    // A grant link's scope is not fixed at admission: the
                    // names it carries, what the peer may push and whether it
                    // has narrowed to a departure are judged at every packet
                    // against the entries live then (§8.7, §8.8). What the
                    // peer pushes toward this device is Interests and the
                    // answers under its own device names (its certificates,
                    // and the seal the owner fetches to wrap a folder's key
                    // for it), and Data under the names of a folder it
                    // *writes* in; Data it pushes under any other name is
                    // dropped.
                    Admission {
                        verdict: LinkVerdict::default(),
                        scope: Some(LinkScope {
                            receives: Carries::Everything,
                            sends: Carries::Everything,
                            names: match &admitted.grant {
                                Some(grant) => self.grant_names(grant.key, own.clone()),
                                None => Box::new(|_: &Name| true),
                            },
                            rate,
                            bandwidth,
                            // The data layer's own asks (`32=grant`) are rated apart
                            // per key, each a task, a fetch back to the member and a
                            // signature at the owner (ndn-link.md §15.3).
                            rated: if serving != Serving::Stranger {
                                vec![RatedInterests {
                                    names: Box::new(is_data_ask),
                                    rate: DATA_ASKS,
                                }]
                            } else {
                                Vec::new()
                            },
                            interests,
                            answered,
                            shared: Some(shared),
                            answers_in: admitted
                                .grant
                                .as_ref()
                                .map(|grant| self.grant_pushes(grant.key, own)),
                            interests_in: None,
                            counts: None,
                            narrowing: admitted.grant.as_ref().map(|grant| {
                                let table = self.grants.clone();
                                let key = grant.key;
                                Narrowing {
                                    when: Box::new(move || {
                                        !table.has_live(&key, SystemTime::now())
                                    }),
                                    receives: Carries::Interests,
                                    sends: Carries::Answers,
                                }
                            }),
                            explain: match &admitted.grant {
                                Some(grant) => format!(
                                    "this device linked {} {}: the names of the folders the person \
                                     is granted (their collections), of the person's own devices, of \
                                     the namespaces' certificates and sync groups, of the \
                                     introduction and of the folder's writers' namespaces cross it, \
                                     and what it pushes is judged at every \
                                     packet by its role in each folder (a reader's entry widens \
                                     nothing; other Data it pushes is dropped); the link's rates bound it \
                                     ({}/s of frames and {} MiB/s from that device, {}/s of Interests \
                                     of any name; what is over is dropped, an Interest with a Nack \
                                     saying Congestion: ask again soon), what this device answers it \
                                     ({} MiB/s: what is over is dropped, and asked again by its timer), \
                                     and its grant asks (<device>/32=grant) {} at once, \
                                     then {}/s (over it is \
                                     dropped without a Nack: ask again later); and an \
                                     entry ends at its date or when \
                                     the inviter revokes it or the folder's members record leaves \
                                     the person out",
                                    admitted.describe(),
                                    grant.describe(),
                                    rate.per_sec,
                                    bandwidth.map_or(0, |b| b.per_sec >> 20),
                                    interests.map_or(0, |i| i.per_sec),
                                    answered.map_or(0, |a| a.per_sec >> 20),
                                    DATA_ASKS.burst,
                                    DATA_ASKS.per_sec
                                ),
                                None if serving == Serving::Guest => format!(
                                    "this device linked {} as a guest of its own namespace {}: a guest is a \
                                     friend's device, so its link carries what an own-namespace link does \
                                     but takes the grant link's rates ({}/s of frames and {} MiB/s from \
                                     that device, {}/s of Interests of any name; what is over is dropped, \
                                     an Interest with a Nack saying Congestion: ask again soon), what \
                                     this device answers it ({} MiB/s), and its grant asks \
                                     ({} at once, then {}/s); it ends when the \
                                     certificate lapses; a member or an \
                                     admin certificate of this namespace links with none of these",
                                    admitted.describe(),
                                    slot.namespace,
                                    rate.per_sec,
                                    bandwidth.map_or(0, |b| b.per_sec >> 20),
                                    interests.map_or(0, |i| i.per_sec),
                                    answered.map_or(0, |a| a.per_sec >> 20),
                                    DATA_ASKS.burst,
                                    DATA_ASKS.per_sec
                                ),
                                None => format!(
                                    "this relay serves {} of {} under its quotas: {}/s from that device, and \
                                     a share of the namespace's limit of all its devices here; to carry more, \
                                     its operator raises the quotas, or the namespace uses another relay",
                                    admitted.describe(),
                                    slot.namespace,
                                    rate.per_sec
                                ),
                            },
                        }),
                        ..Admission::default()
                    }
                }
            },
            Some(Enrollment::Relay(namespaces, introductions)) => {
                let keyring = Arc::clone(self.keyring());
                let scoped = namespaces.clone();
                let introduced = introductions.clone();
                Admission {
                    verdict: LinkVerdict {
                        enrollment_link: Some(namespaces.clone()),
                    },
                    scope: Some(LinkScope {
                        receives: Carries::Interests,
                        sends: Carries::Answers,
                        names: Box::new(move |name: &Name| {
                            in_enrollment(&keyring, &scoped, name, true)
                                || introduced.as_ref().is_some_and(|s| s.0.carries(name))
                        }),
                        rate: ENROLLMENT_INTERESTS,
                        bandwidth: None,
                        rated: Vec::new(),
                        interests: None,
                        answered: None,
                        shared: None,
                        answers_in: None,
                        interests_in: None,
                        counts: None,
                        narrowing: None,
                        explain: format!(
                            "the enrollment link of key {} carries only that device's enrollment in \
                             {} (Interests for its CA, trust context and certificates, and their \
                             answers){}; it links fully once it enrolls",
                            admitted.fingerprint,
                            list(namespaces),
                            if introductions.is_some() {
                                " and the Interests of the introduction an open offer needs"
                            } else {
                                ""
                            }
                        ),
                    }),
                    ..Admission::default()
                }
            }
            Some(Enrollment::Introduction(surface)) => {
                let carried = surface.clone();
                Admission {
                    verdict: LinkVerdict::default(),
                    scope: Some(LinkScope {
                        receives: Carries::Interests,
                        sends: Carries::Answers,
                        names: Box::new(move |name: &Name| carried.0.carries(name)),
                        rate: ENROLLMENT_INTERESTS,
                        bandwidth: None,
                        rated: Vec::new(),
                        interests: None,
                        answered: None,
                        shared: None,
                        answers_in: None,
                        interests_in: None,
                        counts: None,
                        narrowing: None,
                        explain: format!(
                            "the introduction link of key {} carries only the Interests of the \
                             introduction an open offer needs (the offer's record and the ask) \
                             and their answers; it links fully once this device holds the \
                             namespace of the device it reaches",
                            admitted.fingerprint
                        ),
                    }),
                    ..Admission::default()
                }
            }
            Some(Enrollment::Departure(marks)) => {
                let key = admitted.fingerprint;
                let record = marks.first().map(|d| d.record.clone());
                Admission {
                    verdict: LinkVerdict::default(),
                    scope: Some(LinkScope {
                        receives: Carries::Interests,
                        sends: Carries::Answers,
                        names: self.departure_names(key),
                        rate: ENROLLMENT_INTERESTS,
                        bandwidth: None,
                        rated: Vec::new(),
                        interests: None,
                        answered: None,
                        shared: None,
                        answers_in: None,
                        interests_in: None,
                        counts: None,
                        narrowing: None,
                        explain: format!(
                            "the departure link of key {key} carries only the Interests for the \
                             members record {} that lets that person go (its pieces and its cut) \
                             and the key and certificate names that validate it, and their \
                             answers; it closes once the record was carried, or after a short \
                             hold",
                            record.map_or_else(|| "none".to_string(), |r| r.to_string())
                        ),
                    }),
                    ..Admission::default()
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
                        bandwidth: None,
                        rated: Vec::new(),
                        interests: None,
                        answered: None,
                        shared: None,
                        answers_in: None,
                        interests_in: None,
                        counts: None,
                        narrowing: None,
                        explain: format!(
                            "the link to {label} carries only this device's enrollment in {ns} (its \
                             CA, trust context and certificates) until this device enrolls"
                        ),
                    }),
                    ..Admission::default()
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
    // A remembered peer (ndn-link §17C) is a peer entry for the dial this
    // device made and for no link it did not dial: a link that came in is
    // judged as any stranger's, by the serving policy.
    let peer =
        peer.filter(|i| dialed == Some(*i) || !judge.peers.get(*i).is_some_and(|p| p.remembered));
    let config = peer.and_then(|i| judge.peers.get(i));
    // The expected key admits a device that shows no identity, except for a
    // remembered peer, whose key only pins the dial.
    let key_expected = config
        .as_ref()
        .is_some_and(|p| p.key == Some(fingerprint) && !p.remembered);
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
        grant: None,
        follows: Vec::new(),
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
        if p.remembered
            && let Err(why) = &identities
        {
            // Rule 4: a remembered peer is admitted only as an identified
            // device; its key alone admits no one.
            let why = why.detail();
            return Err(Refusal::new(
                CloseReason::Unrecognized,
                LinkDetail::new(
                    code::EXPECTED_DEVICE_UNCONFIRMED,
                    format!(
                        "this device remembers {} by its key and links with it only as an \
                         identified device, and it cannot confirm you are one: {}. A remembered \
                         key admits no one on its own: it links again once this device holds \
                         the namespace of the device and its certificate validates there, and a \
                         device removed from that namespace is not linked",
                        p.label, why.text
                    ),
                )
                .with("key", fingerprint)
                .caused_by(why),
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
                // A remembered peer that first dialled in is judged on the
                // dial this device makes as it was on the link it made: by
                // the serving policy and the grants, which tag the link with
                // its grant, quota and scope (so a grant's end closes it).
                // Any other peer entry admits what it names.
                if config
                    .as_ref()
                    .is_some_and(|p| !(p.remembered && p.linked_in))
                {
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
                            Some(Enrollment::Relay(namespaces, judge.open_introductions())),
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
        Err(why) => {
            // The peer's key is the expected one and it shows no identity. A
            // peer this device dialled from an introduction code
            // (`unidentified_routes`) is a device of the code's namespace only
            // by the code's claim. Once this device holds that namespace its
            // link is made again ([`Judge::relinked`]) so the device shows a
            // certificate of it: a party that still shows none is not that
            // device, and is not admitted again with the introduction's
            // routes.
            if let Some(p) = &config
                && p.unidentified_routes.is_some()
                && peer.is_some_and(|i| judge.relinked.lock().contains(&i))
                && let Some(device) = &p.device
                && let Some(ctx) = judge.keyring().held_for(device)
            {
                let why = why.detail();
                return Err(Refusal::new(
                    CloseReason::Unrecognized,
                    LinkDetail::new(
                        code::EXPECTED_DEVICE_UNCONFIRMED,
                        format!(
                            "this device dialled {device} from an introduction code and holds \
                             {} now, so that device shows a certificate of it; your key \
                             {fingerprint} shows no certificate this device holds ({}), so you \
                             are not {device}. This link is closed and its routes removed: join \
                             again with a new code from the inviter, and check the address and \
                             the code you were given",
                            ctx.namespace(),
                            why.text
                        ),
                    )
                    .with("device", device)
                    .with("namespace", ctx.namespace())
                    .with("key", fingerprint)
                    .caused_by(why),
                ));
            }
            Ok(admitted(Vec::new(), None, None, Vec::new()))
        }
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
    // The identities the policy merely declines to serve, not the ones it
    // refuses for quotas or a name collision: a grant may admit them.
    let mut declined: Vec<Identity> = Vec::new();
    for id in ids {
        match judge.serves(&id) {
            Ok(quota) => served.push((id, quota)),
            Err(refusal) => {
                if [
                    code::NOT_SERVED_OWN,
                    code::NOT_SERVED_UNLISTED,
                    code::NOT_SERVED_UNCERTIFIED,
                ]
                .iter()
                .any(|c| refusal.detail.is(c))
                {
                    declined.push(id.clone());
                }
                refused.get_or_insert((refusal, id.served.is_some()));
            }
        }
    }
    // Only where the policy serves none (a grant never adds to a link the
    // policy already serves): the grant of this key, in its namespaces.
    let mut grant = None;
    if served.is_empty() {
        let (mut refusal, foreign) = refused.expect("an identity was judged");
        if !declined.is_empty() {
            match judge.grant_for(fingerprint, &declined) {
                GrantOutcome::Admitted(ids, granted) => {
                    served = ids.into_iter().map(|(id, slot)| (id, Some(slot))).collect();
                    grant = Some(granted);
                }
                GrantOutcome::Refused(why) => return Err(why),
                GrantOutcome::Departing(marks) => {
                    // No entry stands but a mark of the key does: the narrow
                    // link of §8.7/§8.8, in the enrollment slots, with no
                    // identity recorded, no route and no quota.
                    return Ok(Admitted {
                        fingerprint,
                        identities: Vec::new(),
                        peer,
                        enrollment: Some(Enrollment::Departure(marks)),
                        quota: None,
                        quotas: Vec::new(),
                        grant: None,
                        follows: Vec::new(),
                    });
                }
                GrantOutcome::No(Some(detail)) => {
                    // What the key's holder most needs to read — its grant
                    // ended, or is of other namespaces — comes first: a peer's
                    // words are bounded where they are read, and the refusal
                    // sentence is long.
                    refusal.detail.text = format!("{}. {}", detail.text, refusal.detail.text);
                    refusal.detail.causes.push(detail);
                }
                GrantOutcome::No(None) => {}
            }
        }
        if grant.is_none() {
            // A device of another namespace gets no enrollment link: it
            // proved whom it is, and this relay does not serve it.
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
        grant,
        follows: Vec::new(),
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

/// `…/KEY/<key-id>`, optionally followed by `<issuer>/<version>`, where
/// `components` is the name under a namespace (or device) and `KEY` follows
/// the identity part at once: nothing, `CA` or `<role>/<device>` before it
/// (the shapes of the root, the CA's and a device's key names), none of them
/// a keyword component. A keyword before `KEY` (`32=data`, `32=log`, …)
/// means the name belongs to a collection, whose path may spell `KEY`
/// itself.
pub(crate) fn is_key_or_certificate_name(components: &[ndn_packet::NameComponent]) -> bool {
    let Some(key) = components
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::NAME_COMPONENT && c.value.as_ref() == b"KEY")
    else {
        return false;
    };
    key <= IDENTITY_PART_MAX
        && components[..key]
            .iter()
            .all(|c| c.typ != ndn_packet::tlv_type::KEYWORD)
        && (1..=3).contains(&(components.len() - key - 1))
}

/// The most components an identity (`<role>/<device>`) has before `KEY` in a
/// key or certificate name under its namespace.
const IDENTITY_PART_MAX: usize = 2;

pub(crate) fn list(names: &[Name]) -> String {
    names
        .iter()
        .map(Name::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The most characters of a name a peer sent that a refusal shows.
const RECEIVED_NAME_MAX: usize = 200;

/// A name a peer sent, as a refusal shows it: without control or invisible characters
/// (the peer chose it) and, when long, shortened with `…`.
fn received_name(name: &Name) -> String {
    bounded_text(&clean_text(&name.to_string()), RECEIVED_NAME_MAX)
}

/// A certificate of `ns` that is not named `<ns>/<role>/<device>/KEY/<key-id>/…`
/// identifies no device (`which` is [`code::NOT_DEVICE_CERTIFICATE`], or
/// [`code::FOREIGN_NOT_DEVICE_CERTIFICATE`] with `root`, the root certificate of a
/// namespace this device does not hold). It says the shape expected, the name the
/// certificate had, and what to do (ndn-link.md §7.1).
fn not_a_device_certificate(
    which: &str,
    certificate: &Name,
    ns: &Name,
    root: Option<&Name>,
) -> LinkDetail {
    let received = received_name(certificate);
    let expected = format!("{ns}/<role>/<device>");
    let whose = root.map_or_else(String::new, |root| {
        format!(", the namespace of its root {}", received_name(root))
    });
    let detail = LinkDetail::new(
        which,
        format!(
            "{received} is not a device certificate of {ns}{whose}. The shape expected is \
             /<namespace>/<role>/<device>, here {expected}: a device certificate is named \
             {expected}/KEY/<key-id>/<issuer>/<version>, the role being one component naming \
             what the device does there, such as member. Issue this device's certificate under \
             that shape, for example {ns}/member/<device>"
        ),
    )
    .with("certificate", &received)
    .with("namespace", ns)
    .with("expected", &expected);
    match root {
        Some(root) => detail.with("root", received_name(root)),
        None => detail,
    }
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
    use crate::grants::GrantRole;
    use crate::peer::{PeerSpec, RelaySource, RelayUse};
    use crate::serving::Quotas;
    use ndn_security::{AdvertisedRelay, Ed25519Signer, LinkPolicy, Signer, encode_cert_data};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn keyring_with(ctx: SignedTrustContext) -> Keyring {
        let keyring = Keyring::new();
        keyring.adopt(Arc::new(ctx)).unwrap();
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
            (
                n("/home/member/phone/32=log/home/32=data/diary/KEY/x/seq=3"),
                false,
            ),
            (
                n("/home/member/phone/32=log/home/32=data/diary/KEY/x"),
                false,
            ),
            (n("/home/32=data/KEY/x"), false),
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
        grants: Grants,
        departures: Departures,
        introductions: Option<Arc<dyn Introductions>>,
        relinked: parking_lot::Mutex<std::collections::HashSet<PeerId>>,
        followed_groups: parking_lot::Mutex<Vec<Name>>,
    }

    impl World {
        fn new(trust: Bare, peers: Vec<PeerSpec>, serve: ServePolicy) -> Self {
            Self {
                trust,
                peers: Peers::new(peers),
                serve,
                quotas: QuotaState::default(),
                grants: Grants::default(),
                departures: Departures::default(),
                introductions: None,
                relinked: Default::default(),
                followed_groups: Default::default(),
            }
        }

        fn judge(&self) -> Judge<'_> {
            Judge {
                trust: &self.trust,
                relinked: &self.relinked,
                peers: &self.peers,
                serve: &self.serve,
                quotas: &self.quotas,
                grants: &self.grants,
                departures: &self.departures,
                introductions: self.introductions.clone(),
                followed_groups: &self.followed_groups,
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
        keyring
            .adopt(Arc::new(own.context().with_link_policy(LinkPolicy {
                enrollment_links: false,
                ..LinkPolicy::default()
            })))
            .unwrap();
        for ns in held {
            keyring.adopt(Arc::new(ns.context())).unwrap();
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

    /// A grant in force for `key`, for `namespaces`, for an hour.
    fn granted(key: &PeerKey, namespaces: &[&str], role: GrantRole) -> Grant {
        Grant {
            key: key.fingerprint(),
            namespaces: namespaces.iter().map(|s| n(s)).collect(),
            role,
            folder: n("/a/32=data/notes"),
            until: Some(std::time::SystemTime::now() + std::time::Duration::from_secs(3600)),
        }
    }

    /// Where `own` refuses a device of a held namespace it has no certificate
    /// in, a grant of the device's key serves it in the namespaces the grant
    /// lists — by key and namespace both: another key of the namespace, the
    /// same key presenting another namespace, and a device of a namespace
    /// this device does not hold (served by its own root's certificate) are
    /// refused, whatever the grant lists. Only the granted identities are
    /// admitted, under the default quotas.
    #[tokio::test]
    async fn a_grant_serves_its_key_in_its_namespaces_where_own_refuses_and_no_other() {
        let (a, b, c, d) = (
            namespace("/a", 10).await,
            namespace("/b", 20).await,
            namespace("/c", 30).await,
            namespace("/d", 40).await,
        );
        let world = relay(&a, &[&b, &c], ServePolicy::Own).await;
        let judge = world.judge();
        let (bob, bob_chain) = b.device("member", "phone", 22).await;
        let (carol, carol_chain) = b.device("member", "tablet", 23).await;

        // No grant: refused, and told that an invitation grants a link.
        let refusal = judge
            .decide(&bob, &hello(bob_chain.clone()), &CH, None)
            .await
            .err()
            .unwrap();
        assert!(
            refusal.detail.is(code::NOT_SERVED_UNCERTIFIED),
            "{:?}",
            refusal.detail
        );
        assert!(
            refusal.detail.text.contains("inviting you"),
            "{}",
            refusal.detail.text
        );

        // Granted: served, as the granted namespace's person only, within quotas.
        world.grants.put(granted(&bob, &["/b"], GrantRole::Writer));
        let admitted = judge
            .decide(&bob, &hello(bob_chain.clone()), &CH, None)
            .await
            .unwrap();
        assert_eq!(admitted.identities.len(), 1);
        assert_eq!(admitted.identity().unwrap().device, n("/b/member/phone"));
        assert_eq!(
            admitted.grant.as_ref().map(|g| g.key),
            Some(bob.fingerprint())
        );
        assert!(
            admitted.quota.as_ref().is_some_and(|q| q.limits.is_some()),
            "a grant link is under the default quotas"
        );
        assert!(judge.admission_for(&admitted).scope.is_some());

        // Another key of the same namespace gets nothing from Bob's grant.
        let refusal = judge
            .decide(&carol, &hello(carol_chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        assert!(refusal.detail.is(code::NOT_SERVED_UNCERTIFIED));

        // The grant lists another namespace than the one Bob's certificate is
        // of: refused, and the refusal names the grant.
        world.grants.put(granted(&bob, &["/c"], GrantRole::Writer));
        let refusal = judge
            .decide(&bob, &hello(bob_chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert!(
            refusal
                .detail
                .causes
                .iter()
                .any(|c| c.is(code::GRANT_UNMATCHED)),
            "{:?}",
            refusal.detail
        );

        // A device of a namespace this device does not hold is served by its
        // own root's certificate only; a grant listing the namespace does not
        // serve it.
        let (dan, mut dan_chain) = d.device("member", "phone", 42).await;
        dan_chain.push(d.root.clone());
        world.grants.put(granted(&dan, &["/d"], GrantRole::Writer));
        let refusal = judge
            .decide(&dan, &hello(dan_chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert!(
            refusal.detail.is(code::NOT_SERVED_OWN),
            "{:?}",
            refusal.detail
        );
    }

    /// R12 H1 + M2: a grant link's scope bounds what its member may ask (its own bucket of
    /// Interests below the frames'), the data layer's asks (a class of rated names of their
    /// own) and the bytes this device answers it.
    #[tokio::test]
    async fn a_grant_links_scope_bounds_its_asks_its_interests_and_what_it_is_answered() {
        use crate::policy::{DATA_ASKS, GRANT_ANSWERED, GRANT_INTERESTS};
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let world = relay(&a, &[&b], ServePolicy::Own).await;
        let judge = world.judge();
        let (bob, chain) = b.device("member", "phone", 22).await;
        world.grants.put(granted(&bob, &["/b"], GrantRole::Writer));
        let admitted = judge.decide(&bob, &hello(chain), &CH, None).await.unwrap();
        let scope = judge.admission_for(&admitted).scope.unwrap();
        let same = |got: Option<ndn_face_quic::RateLimit>, want: ndn_face_quic::RateLimit| {
            got.is_some_and(|g| (g.burst, g.per_sec) == (want.burst, want.per_sec))
        };
        assert!(
            same(scope.interests, GRANT_INTERESTS),
            "a grant link's Interests have no bucket of their own below its frames'"
        );
        assert!(
            same(scope.answered, GRANT_ANSWERED),
            "what this device answers a grant link's member is not bounded"
        );
        let rated_for = |name: &str| {
            let name = n(name);
            scope.rated.iter().position(|class| (class.names)(&name))
        };
        let grant_ask = rated_for("/a/member/laptop/32=grant/abc");
        assert!(
            grant_ask.is_some(),
            "grant asks are not rated in a class of their own"
        );
        assert_eq!(
            scope.rated[grant_ask.unwrap()].rate.burst,
            DATA_ASKS.burst,
            "the class takes the data asks' rate"
        );
        assert_eq!(rated_for("/a/member/laptop/32=log/abc"), None);
        assert_eq!(rated_for("/b/member/phone/seal"), None);
    }

    /// Which links carry channel frames (ndn-link.md §17A): an own namespace's
    /// admin, member and node on a full link, with no quota; a guest, a relay's
    /// stranger, an enrollment link and an unidentified peer, not at all; a grant
    /// link under its namespace's fair share, which its links share.
    #[tokio::test]
    async fn admission_for_decides_which_links_carry_channel_frames() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let world = relay(&a, &[&b], ServePolicy::Own).await;
        let judge = world.judge();

        for (role, device, seed) in [
            ("admin", "laptop", 21),
            ("member", "phone", 22),
            ("node", "vps", 24),
        ] {
            let (key, chain) = a.device(role, device, seed).await;
            let admitted = judge.decide(&key, &hello(chain), &CH, None).await.unwrap();
            let channel = judge.admission_for(&admitted).channel;
            assert!(channel.carry, "an own namespace's {role} carries channels");
            assert!(
                channel.quota.is_none(),
                "and takes no quota: the link's congestion control decides"
            );
        }

        let (guest, chain) = a.device("guest", "tablet", 23).await;
        let admitted = judge
            .decide(&guest, &hello(chain), &CH, None)
            .await
            .unwrap();
        let channel = judge.admission_for(&admitted).channel;
        assert!(
            !channel.carry && channel.quota.is_none(),
            "a guest is no space member"
        );

        // Two grant links of one namespace: carried, under one pool.
        let (bob, bob_chain) = b.device("member", "phone", 25).await;
        let (carol, carol_chain) = b.device("member", "tablet", 26).await;
        world.grants.put(granted(&bob, &["/b"], GrantRole::Writer));
        world
            .grants
            .put(granted(&carol, &["/b"], GrantRole::Reader));
        let bob_link = judge
            .decide(&bob, &hello(bob_chain), &CH, None)
            .await
            .unwrap();
        let carol_link = judge
            .decide(&carol, &hello(carol_chain), &CH, None)
            .await
            .unwrap();
        let (bob_channel, carol_channel) = (
            judge.admission_for(&bob_link).channel,
            judge.admission_for(&carol_link).channel,
        );
        assert!(bob_channel.carry && carol_channel.carry);
        let (bob_pool, carol_pool) = (bob_channel.quota.unwrap(), carol_channel.quota.unwrap());
        assert_eq!(bob_pool.capacity(), ndn_face_quic::FAIR_CAPACITY);
        let member = bob_pool.join();
        assert!(member.admit(ndn_face_quic::Flow::Tx, 1).is_ok());
        assert_eq!(
            carol_pool.active(),
            1,
            "the namespace's links count against one pool"
        );

        // A relay's stranger (a device of a namespace it serves under quotas).
        let open = relay(
            &a,
            &[&b],
            ServePolicy::Open {
                quotas: Quotas::default(),
            },
        )
        .await;
        let (stranger, chain) = b.device("member", "watch", 27).await;
        let admitted = open
            .judge()
            .decide(&stranger, &hello(chain), &CH, None)
            .await
            .unwrap();
        assert!(admitted.quota.as_ref().is_some_and(|q| q.limits.is_some()));
        let channel = open.judge().admission_for(&admitted).channel;
        assert!(
            !channel.carry && channel.quota.is_none(),
            "a stranger's quota link carries none"
        );

        // A device with no certificate gets an enrollment link; a key expected
        // alone is unidentified: neither carries.
        let (_, own) = a.device("node", "laptop", 90).await;
        let enrolling = World::new(
            Bare(Arc::new(keyring_with(a.context())), None, own),
            Vec::new(),
            ServePolicy::Own,
        );
        let (newcomer, _) = a.device("member", "new", 28).await;
        let judge = enrolling.judge();
        let admitted = judge
            .decide(&newcomer, &hello(Vec::new()), &CH, None)
            .await
            .unwrap();
        assert!(admitted.enrollment.is_some());
        let channel = judge.admission_for(&admitted).channel;
        assert!(!channel.carry && channel.quota.is_none());
        let unidentified = Admitted {
            fingerprint: newcomer.fingerprint(),
            identities: Vec::new(),
            peer: None,
            enrollment: None,
            quota: None,
            quotas: Vec::new(),
            grant: None,
            follows: Vec::new(),
        };
        assert!(!judge.admission_for(&unidentified).channel.carry);
    }

    /// R12 L2(a): a guest of a namespace this device holds a certificate in is not
    /// "own namespace, never limited": its link takes the grant link's rates and bounds
    /// (frames, bytes, Interests, what it is answered, the ask classes), as a granted
    /// person's does, and carries every name as before; a member's link has none.
    #[tokio::test]
    async fn a_guest_of_an_own_namespace_takes_grant_style_limits_and_a_member_none() {
        use crate::policy::{GRANT_ANSWERED, GRANT_FRAMES, GRANT_INTERESTS};
        let a = namespace("/a", 10).await;
        let world = relay(&a, &[], ServePolicy::Own).await;
        let judge = world.judge();

        let (member, chain) = a.device("member", "phone", 22).await;
        let admitted = judge
            .decide(&member, &hello(chain), &CH, None)
            .await
            .unwrap();
        assert!(admitted.quota.is_none(), "a member's link is never limited");
        assert!(judge.admission_for(&admitted).scope.is_none());

        let (guest, chain) = a.device("guest", "tablet", 23).await;
        let admitted = judge
            .decide(&guest, &hello(chain), &CH, None)
            .await
            .expect("a guest of an own namespace links");
        assert!(
            admitted.quota.as_ref().is_some_and(|q| q.limits.is_some()),
            "a guest's link is under no limit: own namespace, never limited"
        );
        let scope = judge
            .admission_for(&admitted)
            .scope
            .expect("a guest's link has a scope");
        let same = |got: Option<ndn_face_quic::RateLimit>, want: ndn_face_quic::RateLimit| {
            got.is_some_and(|g| (g.burst, g.per_sec) == (want.burst, want.per_sec))
        };
        assert_eq!(
            (scope.rate.burst, scope.rate.per_sec),
            (GRANT_FRAMES.burst, GRANT_FRAMES.per_sec)
        );
        assert!(same(scope.interests, GRANT_INTERESTS));
        assert!(same(scope.answered, GRANT_ANSWERED));
        assert_eq!(scope.rated.len(), 1, "the data asks");
        assert!(scope.shared.is_some() && scope.bandwidth.is_some());
        assert!(
            (scope.names)(&n("/a/member/laptop/32=log/x")) && (scope.names)(&n("/elsewhere/x")),
            "a guest's link carries what an own-namespace link did"
        );
        assert_eq!(
            (scope.receives, scope.sends),
            (Carries::Everything, Carries::Everything)
        );
        assert!(scope.narrowing.is_none() && scope.answers_in.is_none());
    }

    /// R12 L2(b): the certificate of an identity that lapses is found by the pure decision
    /// the timer uses: the earliest NotAfter of the leaf and its issuers, recorded at
    /// admission, and lapsed once the clock is past it.
    #[tokio::test]
    async fn an_identity_records_when_its_chain_first_lapses() {
        use std::time::{Duration, SystemTime};
        let a = namespace("/a", 10).await;
        let world = relay(&a, &[], ServePolicy::Own).await;
        let judge = world.judge();
        let (member, chain) = a.device("member", "phone", 22).await;
        let admitted = judge
            .decide(&member, &hello(chain), &CH, None)
            .await
            .unwrap();
        let id = admitted.identity().unwrap();
        let (cert, at) = id
            .lapses
            .clone()
            .expect("the identity does not say when its certificate lapses");
        let day = Duration::from_secs(24 * 3600);
        let now = SystemTime::now();
        assert!(
            at > now + day - Duration::from_secs(60) && at < now + day + Duration::from_secs(60),
            "the certificates in the test are valid for 24 hours"
        );
        assert!(id.certificates.contains(&cert), "{cert} is in the chain");
        assert!(id.lapse(now).is_none(), "not lapsed while it is valid");
        assert!(id.lapse(at).is_none(), "valid at its NotAfter");
        let lapsed = id.lapse(at + Duration::from_secs(1)).expect("lapsed");
        assert!(
            lapsed.contains(&cert.to_string()) && lapsed.contains("NotAfter"),
            "the reason names the certificate and when it lapsed: {lapsed}"
        );
        let mut none = id.clone();
        none.lapses = None;
        assert!(none.lapse(at + day).is_none(), "no NotAfter, no lapse");
    }

    /// A grant that ended is named in the refusal of the key's next link,
    /// and serves nothing.
    #[tokio::test]
    async fn an_ended_grant_serves_nothing_and_is_named_in_the_refusal() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let world = relay(&a, &[&b], ServePolicy::Own).await;
        let judge = world.judge();
        let (bob, chain) = b.device("member", "phone", 22).await;
        let mut grant = granted(&bob, &["/b"], GrantRole::Writer);
        grant.until = Some(std::time::SystemTime::now() - std::time::Duration::from_secs(1));
        world.grants.put(grant);
        let refusal = judge
            .decide(&bob, &hello(chain), &CH, None)
            .await
            .err()
            .unwrap();
        let ended = refusal
            .detail
            .causes
            .iter()
            .find(|c| c.is(code::GRANT_ENDED))
            .unwrap_or_else(|| panic!("{:?}", refusal.detail));
        assert_eq!(ended.param("ended"), Some("expired"));
        assert!(
            refusal.detail.text.contains("it expired"),
            "{}",
            refusal.detail.text
        );
    }

    /// A served device's hello names the space groups it follows: the
    /// decision carries them, and they route exactly those groups over the
    /// link, beside the group of the namespace the device was served for.
    /// Another space of a followed owner is not routed.
    #[tokio::test]
    async fn a_served_devices_follows_are_carried_and_route_their_groups_only() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let open = relay(
            &a,
            &[&b],
            ServePolicy::Open {
                quotas: Quotas::default(),
            },
        )
        .await;
        let (bob, chain) = b.device("member", "phone", 22).await;
        let mut claim = hello(chain);
        claim.follows = vec![n("/c/32=sync/x"), n("/a/32=sync/y"), n("/c/d/32=sync/x/y")];
        let admitted = open.judge().decide(&bob, &claim, &CH, None).await.unwrap();
        assert_eq!(admitted.follows, claim.follows);
        let routed: Vec<Name> =
            crate::routes::routes_for(&Peers::new(Vec::new()), &admitted, false, None)
                .into_iter()
                .map(|r| r.prefix)
                .collect();
        for group in [
            "/b/32=sync",
            "/c/32=sync/x",
            "/a/32=sync/y",
            "/c/d/32=sync/x/y",
        ] {
            assert!(routed.contains(&n(group)), "{group} in {routed:?}");
        }
        assert!(
            routed
                .iter()
                .all(|p| p.has_prefix(&n("/b")) || claim.follows.iter().any(|g| p == g)),
            "a claim routed more than the groups it names: {routed:?}"
        );
        for whole in ["/a/32=sync", "/c/32=sync", "/c/d/32=sync"] {
            assert!(
                !routed.contains(&n(whole)),
                "the owner's whole group {whole} was routed: {routed:?}"
            );
        }
    }

    /// Under `open` a grant adds nothing: the policy serves the device (under
    /// its quotas) and the link is not the grant's. Under `listed` with
    /// quotas a grant is bound by them: it never serves what they refuse.
    #[tokio::test]
    async fn a_grant_adds_nothing_under_open_and_never_beats_the_quotas() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let open = relay(
            &a,
            &[&b],
            ServePolicy::Open {
                quotas: Quotas::default(),
            },
        )
        .await;
        let (bob, chain) = b.device("member", "phone", 22).await;
        open.grants.put(granted(&bob, &["/b"], GrantRole::Reader));
        let admitted = open
            .judge()
            .decide(&bob, &hello(chain), &CH, None)
            .await
            .unwrap();
        assert!(admitted.grant.is_none(), "open served the device itself");

        let listed = relay(
            &a,
            &[&b],
            ServePolicy::Listed {
                roots: Vec::new(),
                quotas: Some(Quotas {
                    links_per_namespace: 1,
                    ..Quotas::default()
                }),
            },
        )
        .await;
        let judge = listed.judge();
        let (carol, carol_chain) = b.device("member", "tablet", 23).await;
        let (bob, bob_chain) = b.device("member", "phone", 22).await;
        listed.grants.put(granted(&bob, &["/b"], GrantRole::Writer));
        listed
            .grants
            .put(granted(&carol, &["/b"], GrantRole::Writer));
        let first = judge
            .decide(&bob, &hello(bob_chain), &CH, None)
            .await
            .unwrap();
        assert!(first.grant.is_some());
        let refusal = judge
            .decide(&carol, &hello(carol_chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert_eq!(refusal.reason, CloseReason::Busy, "{}", refusal.detail.text);
        assert!(refusal.detail.is(code::QUOTA_NAMESPACE_LINKS));
        drop(first);
    }

    /// An open relay serves a device of a namespace it holds the trust
    /// context of but no certificate in — an inviter holds the namespace of
    /// the person it introduced, whom `own` refuses — checked as any device
    /// of it and under the quotas, the namespace bound to one of the held
    /// context's anchors.
    #[tokio::test]
    async fn open_serves_a_device_of_a_held_namespace_under_quotas() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let serve = ServePolicy::Open {
            quotas: Quotas {
                links_per_namespace: 1,
                ..Quotas::default()
            },
        };
        let world = relay(&a, &[&b], serve).await;
        let judge = world.judge();

        let (key, chain) = b.device("member", "phone", 22).await;
        let first = judge.decide(&key, &hello(chain), &CH, None).await.unwrap();
        let id = first.identity().unwrap();
        assert_eq!((id.device.clone(), id.served), (n("/b/member/phone"), None));
        assert!(first.quota.as_ref().is_some_and(|q| q.limits.is_some()));

        let (key, chain) = b.device("member", "laptop", 23).await;
        let refusal = judge
            .decide(&key, &hello(chain), &CH, None)
            .await
            .err()
            .unwrap();
        assert_eq!(refusal.reason, CloseReason::Busy, "{}", refusal.detail.text);
        assert!(
            refusal.detail.is(code::QUOTA_NAMESPACE_LINKS),
            "{:?}",
            refusal.detail
        );
    }

    /// A link path to a relay routes the namespaces it is used for — a
    /// relay the person added: those this device holds a certificate in; a
    /// relay a namespace advertises: the advertising namespace — then each
    /// namespace this device follows (holds the trust context of without a
    /// certificate in it). Relays are chosen over the certificate
    /// namespaces alone.
    #[tokio::test]
    async fn a_relay_also_routes_the_followed_namespaces() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let keyring = Keyring::new();
        keyring
            .adopt(Arc::new(a.context().with_relays(vec![AdvertisedRelay {
                device: n("/a/node/relay"),
                key: None,
                endpoints: vec!["relay.example:6363".into()],
                preference: 0,
            }])))
            .unwrap();
        keyring.adopt(Arc::new(b.context())).unwrap();
        let (_, chain) = a.device("member", "laptop", 12).await;
        let world = World::new(
            Bare(Arc::new(keyring), None, chain),
            Vec::new(),
            ServePolicy::Own,
        );
        let judge = world.judge();
        assert_eq!(judge.own_namespaces(), [n("/a")]);
        assert_eq!(judge.followed_namespaces(), [n("/b")]);

        let relay = |source| PeerSpec {
            label: "relay".into(),
            device: Some(n("/a/node/relay")),
            relay_use: Some(RelayUse {
                source,
                preference: 0,
            }),
            ..PeerSpec::default()
        };
        let user = relay(RelaySource::User);
        let advertised = relay(RelaySource::Namespace(n("/a")));
        assert_eq!(judge.relay_routed_namespaces(&user), [n("/a"), n("/b")]);
        assert_eq!(
            judge.relay_routed_namespaces(&advertised),
            [n("/a"), n("/b")]
        );
        let own = judge.own_namespaces();
        assert_eq!(judge.relay_namespaces_of(&user, &own), [n("/a")]);
        assert_eq!(judge.relay_namespaces_of(&advertised, &own), [n("/a")]);
        // A relay this device uses is told the space groups the host says it
        // follows, and nothing of the namespaces it holds a context of: with
        // no group given it is told none (and still told, so it knows), for
        // a namespace followed names every space of it. A peer that is no
        // such relay, or one with `routes` of its own (it routes those and no
        // more), is told nothing.
        assert_eq!(judge.told_follows(&user), Some(Vec::new()));
        *world.followed_groups.lock() = vec![n("/b/32=sync/doc")];
        assert_eq!(judge.told_follows(&user), Some(vec![n("/b/32=sync/doc")]));
        assert_eq!(
            judge.told_follows(&advertised),
            Some(vec![n("/b/32=sync/doc")])
        );
        assert_eq!(
            judge.told_follows(&PeerSpec {
                relay_use: None,
                ..user.clone()
            }),
            None
        );
        assert_eq!(
            judge.told_follows(&PeerSpec {
                routes: Some(vec![n("/a")]),
                ..user.clone()
            }),
            None
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
        assert_eq!(
            admitted.enrollment,
            Some(Enrollment::Relay(vec![n("/a")], None))
        );
    }

    fn served(namespace: &str, device: &str, root: KeyFingerprint) -> Identity {
        Identity {
            namespace: n(namespace),
            version: 0,
            device: n(device),
            role: Role::Member,
            certificates: Vec::new(),
            served: Some(root),
            lapses: None,
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
            lapses: None,
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

    /// A remembered peer's entry: its key pins the dial, its device is the
    /// one it proved when it was remembered.
    fn remembered(device: &str) -> PeerSpec {
        PeerSpec {
            remembered: true,
            ..spec(Some(THEIRS), Some(device))
        }
    }

    /// An identity of `/b`, a namespace this device holds.
    fn held_in_b(device: &str) -> Identity {
        Identity {
            served: None,
            lapses: None,
            version: 1,
            ..served("/b", device, THEIRS)
        }
    }

    fn holding_b(peers: Vec<PeerSpec>) -> World {
        World::new(
            Bare(
                Arc::new(keyring_with(
                    SignedTrustContext::hierarchical(n("/b")).with_version(1),
                )),
                None,
                Vec::new(),
            ),
            peers,
            ServePolicy::Own,
        )
    }

    /// Rule 4 (§17C.2): a remembered peer is never admitted by its expected key
    /// alone. The same entry listed by a host is admitted by it (what a
    /// permissive seam would do), so the refusal is the rule's and nothing
    /// else's.
    #[test]
    fn a_remembered_peer_is_never_admitted_by_its_key_alone() {
        let listed = holding_b(vec![PeerSpec {
            remembered: false,
            ..remembered("/b/member/phone")
        }]);
        let by_key = decide_identified(
            &listed.judge(),
            THEIRS,
            Err(Unidentified::NoCertificate),
            Some(PeerId(0)),
            Some(PeerId(0)),
        );
        assert!(
            by_key.is_ok_and(|a| a.identity().is_none()),
            "a host-listed entry is admitted by its expected key: the seam the rule closes"
        );

        let world = holding_b(vec![remembered("/b/member/phone")]);
        for why in [
            Unidentified::NoCertificate,
            Unidentified::Unusable(LinkDetail::new(code::NO_CERTIFICATE, "its chain is broken")),
        ] {
            let refusal = decide_identified(
                &world.judge(),
                THEIRS,
                Err(why),
                Some(PeerId(0)),
                Some(PeerId(0)),
            )
            .err()
            .expect("a remembered peer that shows no identity is refused, not admitted by its key");
            assert_eq!(refusal.reason, CloseReason::Unrecognized);
            assert!(
                refusal.detail.is(code::EXPECTED_DEVICE_UNCONFIRMED),
                "{:?}",
                refusal.detail
            );
            assert!(
                refusal.detail.text.contains("identified device"),
                "{}",
                refusal.detail.text
            );
        }
    }

    #[test]
    fn a_remembered_peer_is_admitted_as_the_identified_device_it_was() {
        let world = holding_b(vec![remembered("/b/member/phone")]);
        let admitted = decide_identified(
            &world.judge(),
            THEIRS,
            Ok(vec![held_in_b("/b/member/phone")]),
            Some(PeerId(0)),
            Some(PeerId(0)),
        )
        .unwrap();
        assert_eq!(admitted.peer, Some(PeerId(0)));
        assert_eq!(admitted.identity().unwrap().device, n("/b/member/phone"));
        assert!(admitted.enrollment.is_none());
    }

    #[test]
    fn a_remembered_peer_proving_another_device_or_another_key_is_refused() {
        let world = holding_b(vec![remembered("/b/member/phone")]);
        let refusal = decide_identified(
            &world.judge(),
            THEIRS,
            Ok(vec![held_in_b("/b/member/laptop")]),
            Some(PeerId(0)),
            Some(PeerId(0)),
        )
        .err()
        .unwrap();
        assert!(
            refusal.detail.is(code::NOT_EXPECTED_DEVICE),
            "{:?}",
            refusal.detail
        );
        let refusal = decide_identified(
            &world.judge(),
            KeyFingerprint([9; 32]),
            Ok(vec![held_in_b("/b/member/phone")]),
            Some(PeerId(0)),
            Some(PeerId(0)),
        )
        .err()
        .unwrap();
        assert!(
            refusal.detail.is(code::NOT_EXPECTED_KEY),
            "{:?}",
            refusal.detail
        );
    }

    /// Rule 3 (§17C.2): an identity only a root this device does not hold
    /// vouches for confirms no remembered peer.
    #[test]
    fn a_remembered_peer_of_a_namespace_no_longer_held_is_refused() {
        let world = holding_b(vec![remembered("/b/member/phone")]);
        let refusal = decide_identified(
            &world.judge(),
            THEIRS,
            Ok(vec![served("/b", "/b/member/phone", THEIRS)]),
            Some(PeerId(0)),
            Some(PeerId(0)),
        )
        .err()
        .expect("served by a root this device does not hold: not a held identity");
        assert!(
            refusal.detail.is(code::EXPECTED_DEVICE_UNCONFIRMED),
            "{:?}",
            refusal.detail
        );
        assert!(
            refusal.detail.text.contains("does not hold"),
            "{}",
            refusal.detail.text
        );
    }

    /// A link that came in is not the dial the remembered entry stands for:
    /// it is judged by the serving policy as any stranger's. Under `own` a
    /// device of a namespace this device holds but is not in is refused,
    /// where a host-listed entry (admitted whoever dials) would take it.
    #[test]
    fn a_remembered_entry_does_not_admit_a_link_that_came_in() {
        let listed = holding_b(vec![PeerSpec {
            remembered: false,
            ..remembered("/b/member/phone")
        }]);
        assert!(
            decide_identified(
                &listed.judge(),
                THEIRS,
                Ok(vec![held_in_b("/b/member/phone")]),
                Some(PeerId(0)),
                None,
            )
            .is_ok(),
            "a host-listed entry admits the device whoever dialled"
        );
        let world = holding_b(vec![remembered("/b/member/phone")]);
        let refusal = decide_identified(
            &world.judge(),
            THEIRS,
            Ok(vec![held_in_b("/b/member/phone")]),
            Some(PeerId(0)),
            None,
        )
        .err()
        .expect("a remembered entry is no reason to serve a link that dialled in");
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );
        // And a remembered key that shows no identity is not admitted by it
        // either way.
        let refusal = decide_identified(
            &world.judge(),
            THEIRS,
            Err(Unidentified::NoCertificate),
            Some(PeerId(0)),
            None,
        )
        .err()
        .unwrap();
        assert_eq!(refusal.reason, CloseReason::Unrecognized);
        assert!(
            refusal.detail.is(code::UNRECOGNIZED_KEY),
            "refused as any stranger: {:?}",
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

    /// A remembered peer's redial is judged on the dial this device makes as
    /// the link it made first was: one that first dialled in is judged by the
    /// serving policy and the grants (refused where a stranger would be, and
    /// admitted under its grant, carrying it, so the grant's end closes the
    /// link); one this device dialled itself is admitted by its entry as
    /// before.
    #[tokio::test]
    async fn a_remembered_peer_that_first_linked_in_is_judged_by_the_grants_as_a_stranger_is() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let (bob, chain) = b.device("member", "phone", 22).await;
        let entry = |linked_in| PeerSpec {
            label: "bob".into(),
            key: Some(bob.fingerprint()),
            device: Some(n("/b/member/phone")),
            remembered: true,
            linked_in,
            ..PeerSpec::default()
        };

        let world = relay(&a, &[&b], ServePolicy::Own).await;
        let id = world.peers.add(entry(true));
        let judge = world.judge();
        let refusal = judge
            .decide(&bob, &hello(chain.clone()), &CH, Some(id))
            .await
            .err()
            .expect("a remembered peer that dialled in was admitted by its entry, with no grant");
        assert_eq!(
            refusal.reason,
            CloseReason::NotServed,
            "{}",
            refusal.detail.text
        );

        world.grants.put(granted(&bob, &["/b"], GrantRole::Writer));
        let admitted = judge
            .decide(&bob, &hello(chain.clone()), &CH, Some(id))
            .await
            .expect("the grant of the remembered key serves the redial");
        assert_eq!(admitted.peer, Some(id));
        assert_eq!(
            admitted.grant.as_ref().map(|g| g.key),
            Some(bob.fingerprint()),
            "the redial's link carries no grant, so the grant's end would not close it"
        );
        assert!(
            admitted.quota.as_ref().is_some_and(|q| q.limits.is_some()),
            "the redial's link is under no quota"
        );
        assert!(judge.admission_for(&admitted).scope.is_some());

        // A peer this device dialled itself: its entry admits it, no grant.
        let world = relay(&a, &[&b], ServePolicy::Own).await;
        let id = world.peers.add(entry(false));
        let admitted = world
            .judge()
            .decide(&bob, &hello(chain), &CH, Some(id))
            .await
            .expect("an entry of a peer this device dialled admits it");
        assert!(admitted.grant.is_none() && admitted.quota.is_none());
    }

    /// What the data layer carries, as a double: the introduction under
    /// `/intro`, the folder's names under the folder.
    struct Surface;

    impl Introductions for Surface {
        fn open(&self) -> bool {
            true
        }

        fn carries(&self, name: &Name) -> bool {
            name.has_prefix(&n("/intro"))
        }

        fn grant_carries(&self, folder: &Name, name: &Name) -> bool {
            name.has_prefix(folder)
        }

        fn departure_carries(&self, record: &Name, name: &Name) -> bool {
            name.has_prefix(record)
        }

        /// `<O>/32=data/<rest>` is grouped as `<O>/32=sync/<rest>`, as the
        /// data layer derives its group.
        fn sync_group(&self, folder: &Name) -> Option<Name> {
            let owner = crate::grants::folder_namespace(folder)?;
            let rest = &folder.components()[owner.len() + 1..];
            Some(Name::from_components(
                ndn_security::sync_group(&owner)
                    .components()
                    .iter()
                    .chain(rest)
                    .cloned(),
            ))
        }
    }

    /// A grant link carries the folder's names, the person's own devices, the
    /// introduction and the namespaces' public names — and no other name this
    /// device serves; a grant that is over carries nothing at all, closed or
    /// not.
    #[tokio::test]
    async fn a_grant_links_names_are_the_folders_the_persons_and_the_public_ones() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let mut world = relay(&a, &[&b], ServePolicy::Own).await;
        world.introductions = Some(Arc::new(Surface));
        let (bob, chain) = b.device("member", "phone", 22).await;
        world.grants.put(granted(&bob, &["/b"], GrantRole::Writer));
        let judge = world.judge();
        let admitted = judge
            .decide(&bob, &hello(chain), &CH, None)
            .await
            .expect("the grant serves bob");
        let scope = judge.admission_for(&admitted).scope.expect("a scope");
        let names = scope.names;

        for carried in [
            // The folder's collections, and the folder itself.
            "/a/32=data/notes",
            "/a/32=data/notes/page/32=log/x",
            // The person's own device.
            "/b/member/phone/32=log/anything",
            // The introduction, which a person may ask again.
            "/intro/ask",
            // Sync groups of the grant's namespace and of the folder (its
            // own group's Sync Interests `<group>/v=N`, not the owner's
            // others), the trust context, keys and certificates.
            "/b/32=sync/probe",
            "/a/32=sync/notes/v=2",
            "/b/32=trust-context/32=metadata",
            "/b/member/phone/KEY/k/issuer/v=1",
            // The ask of a channel, to a device of the folder's owner namespace
            // (`<device>/32=chan/<digest>`), and the session answered under it.
            "/a/member/laptop/32=chan/32=sha256digest",
            "/a/node/relay/32=chan",
        ] {
            assert!(names(&n(carried)), "{carried} did not cross the grant link");
        }
        for refused in [
            // Another folder, another collection of the same namespace, an
            // entry of the inviter's own, another device of the person's
            // namespace, the inviter's namespace's other names.
            "/a/32=data/diary",
            "/a/32=data/notes2",
            "/a/member/laptop/32=log/a/32=data/diary/seq=1",
            "/b/member/tablet/32=log/x",
            "/b/32=data/anything",
            // The sync group of another space of the owner, the group of a
            // space nested in the folder (`notes/f1` is a space of its own, its
            // group's name extends the folder's), a name under the folder's
            // group that is no Sync Interest, and the owner's whole group
            // prefix: a grant link carries the folder's Sync Interests only.
            "/a/32=sync/diary/v=2",
            "/a/32=sync/notes/f1/v=2",
            "/a/32=sync/notes/probe",
            "/a/32=sync/probe",
            // Entries of collections whose path has a literal `KEY` component
            // are no key or certificate names.
            "/a/member/laptop/32=log/a/32=data/diary/KEY/x/seq=3",
            "/b/member/tablet/32=log/b/32=data/diary/KEY/x/seq=3",
            "/somewhere/else",
            // A channel ask names a device of the folder's owner namespace: not
            // the namespace itself, not another namespace's device (the grantee's
            // other devices included), and no other keyword.
            "/a/32=chan/32=sha256digest",
            "/c/member/laptop/32=chan/32=sha256digest",
            "/b/member/tablet/32=chan/32=sha256digest",
            "/a/member/laptop/32=chan2/x",
            "/a/member/laptop/32=log/32=chan/x",
        ] {
            assert!(
                !names(&n(refused)),
                "{refused} crossed the grant link, though the grant does not carry it"
            );
        }

        // The grant ends: nothing crosses, the link closed yet or not.
        let mut over = granted(&bob, &["/b"], GrantRole::Writer);
        over.until = Some(std::time::SystemTime::now() - std::time::Duration::from_secs(1));
        world.grants.put(over);
        for was_carried in [
            "/b/member/phone/32=log/anything",
            "/a/32=data/notes",
            "/intro/ask",
            "/a/member/laptop/32=chan/32=sha256digest",
        ] {
            assert!(
                !names(&n(was_carried)),
                "{was_carried} crossed after the grant ended"
            );
        }
    }

    /// A grant in force for `key` in `namespaces`, in `folder`, for an hour.
    fn granted_in(key: &PeerKey, folder: &str, role: GrantRole) -> Grant {
        Grant {
            folder: n(folder),
            ..granted(key, &["/b"], role)
        }
    }

    /// A key's second entry is added beside its first, not in its place; the
    /// link both admitted carries the names of each folder and what the person
    /// may push is judged at every packet by its role in each: a writer in one
    /// folder and a reader in the other pushes under the first's names only, a
    /// promotion or a demotion shows at the next packet with no new link, and
    /// an entry that ended carries nothing while the other still carries.
    #[tokio::test]
    async fn entries_are_added_not_replaced_and_names_and_pushes_are_judged_per_entry() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let mut world = relay(&a, &[&b], ServePolicy::Own).await;
        world.introductions = Some(Arc::new(Surface));
        let (bob, chain) = b.device("member", "phone", 22).await;
        let key = bob.fingerprint();
        let (notes, diary) = ("/a/32=data/notes", "/a/32=data/diary");
        world.grants.put(granted_in(&bob, notes, GrantRole::Writer));
        world.grants.put(granted_in(&bob, diary, GrantRole::Reader));
        assert_eq!(
            world.grants.live_entries(&key, SystemTime::now()).len(),
            2,
            "the second entry did not replace the first"
        );

        let judge = world.judge();
        let admitted = judge
            .decide(&bob, &hello(chain), &CH, None)
            .await
            .expect("the entries serve bob");
        let scope = judge.admission_for(&admitted).scope.expect("a scope");
        let (names, pushes) = (scope.names, scope.answers_in.expect("pushes are judged"));
        let narrowing = scope.narrowing.expect("a grant link narrows in place");
        assert!(!(narrowing.when)(), "entries stand");

        for carried in [format!("{notes}/page"), format!("{diary}/page")] {
            assert!(names(&n(&carried)), "{carried} did not cross");
        }
        assert!(!names(&n("/a/32=data/other")));
        let mine = "/b/member/phone/32=log/x";
        assert!(pushes(&n(&format!("{notes}/page/32=log/x"))));
        assert!(
            !pushes(&n(&format!("{diary}/page/32=log/x"))),
            "a reader entry widens no push"
        );
        assert!(pushes(&n(mine)), "its own devices' answers pass");
        assert!(
            pushes(&n("/a/32=sync/notes/v=2/probe")),
            "a writer entry carries the folder's own group"
        );
        assert!(
            !pushes(&n("/a/32=sync/diary/v=2/probe"))
                && !pushes(&n("/a/32=sync/notes/f1/v=2/probe"))
                && !pushes(&n("/a/32=sync/probe")),
            "the group of a folder the person only reads, of a space nested in the folder, \
             or the owner's others, was pushed"
        );

        // A promotion shows at the next packet: no new decision, no new link.
        world.grants.put(granted_in(&bob, diary, GrantRole::Writer));
        assert!(pushes(&n(&format!("{diary}/page/32=log/x"))));
        // And a demotion.
        world.grants.put(granted_in(&bob, notes, GrantRole::Reader));
        assert!(!pushes(&n(&format!("{notes}/page/32=log/x"))));
        assert!(pushes(&n(&format!("{diary}/page/32=log/x"))));
        // Both readers: nothing is pushed but under the person's own devices.
        world.grants.put(granted_in(&bob, diary, GrantRole::Reader));
        assert!(
            !pushes(&n("/a/32=sync/notes/v=2/probe")) && !pushes(&n("/a/32=sync/diary/v=2/probe")),
            "no writer entry stands"
        );
        assert!(!pushes(&n(&format!("{diary}/page/32=log/x"))));
        assert!(pushes(&n(mine)));

        // The notes entry ends: it carries nothing, the diary still does.
        assert!(world.grants.take(&key, &n(notes)).is_some());
        assert!(
            !names(&n(&format!("{notes}/page"))),
            "an ended entry carries nothing"
        );
        assert!(names(&n(&format!("{diary}/page"))));
        assert!(!(narrowing.when)(), "one entry stands: not narrowed");
        // The last ends: nothing of the folders, and the link is narrowed.
        assert!(world.grants.take(&key, &n(diary)).is_some());
        assert!(!names(&n(&format!("{diary}/page"))));
        assert!(
            !names(&n(mine)),
            "nothing crosses with no entry and no mark"
        );
        assert!((narrowing.when)(), "no entry stands: narrowed");
        assert_eq!(
            (narrowing.receives, narrowing.sends),
            (Carries::Interests, Carries::Answers)
        );
    }

    /// A key whose last entry ended and that holds a mark of the folder is
    /// admitted on a departure link: Interests toward this device, answers
    /// toward the peer, the record and the keys that validate it and nothing
    /// else, in no quota; only for a key with a mark, in the namespaces the
    /// mark lists, for as many times as the options say, until the mark's
    /// date; and otherwise the refusal says the grant ended.
    #[tokio::test]
    async fn a_mark_admits_a_departure_link_within_its_bounds_and_nothing_else_does() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let mut world = relay(&a, &[&b], ServePolicy::Own).await;
        world.introductions = Some(Arc::new(Surface));
        let (bob, chain) = b.device("member", "phone", 22).await;
        let (carol, carol_chain) = b.device("member", "tablet", 23).await;
        let key = bob.fingerprint();
        let notes = "/a/32=data/notes";
        let record = "/a/member/laptop/32=log/a/32=data/notes/seq=4";
        let hour = SystemTime::now() + std::time::Duration::from_secs(3600);
        let mark = |key: &PeerKey, until| crate::departures::Departure {
            key: key.fingerprint(),
            namespaces: vec![n("/b")],
            folder: n(notes),
            record: n(record),
            until,
        };
        // The entry ended (by a record, said so), and the mark is held.
        world.grants.put(granted_in(&bob, notes, GrantRole::Writer));
        world.grants.take(&key, &n(notes));
        world.departures.put(mark(&bob, hour), SystemTime::now());

        let judge = world.judge();
        let admitted = judge
            .decide(&bob, &hello(chain.clone()), &CH, None)
            .await
            .expect("the mark admits bob on a departure link");
        let Some(Enrollment::Departure(told)) = &admitted.enrollment else {
            panic!("not a departure link: {:?}", admitted.enrollment);
        };
        assert_eq!(told.len(), 1);
        // Registered: that is the first attempt.
        world.departures.count_attempt(&key, told);
        assert!(admitted.quota.is_none() && admitted.grant.is_none());
        assert!(admitted.identities.is_empty(), "no identity is recorded");
        let scope = judge.admission_for(&admitted).scope.expect("a scope");
        assert_eq!(
            (scope.receives, scope.sends),
            (Carries::Interests, Carries::Answers)
        );
        assert!(scope.answers_in.is_none() && scope.narrowing.is_none());
        let names = scope.names;
        assert!(names(&n(record)), "the record");
        assert!(names(&n(&format!("{record}/seg=0"))), "its pieces");
        assert!(names(&n("/a/KEY/k1")), "the key that validates it");
        for refused in [
            notes,
            "/a/32=data/notes/page/32=log/x",
            "/a/32=sync/probe",
            "/intro/ask",
            "/b/member/phone/32=log/x",
            "/a/member/laptop/32=log/a/32=data/notes/seq=5",
            // An entry of another collection whose path has a literal `KEY`
            // component is not a key name.
            "/a/member/laptop/32=log/a/32=data/diary/KEY/x/seq=3",
        ] {
            assert!(!names(&n(refused)), "{refused} crossed the departure link");
        }

        // Another key of the namespace has no mark: the refusal of any other.
        let refusal = judge
            .decide(&carol, &hello(carol_chain), &CH, None)
            .await
            .err()
            .expect("a key with no mark is refused");
        assert!(
            refusal.detail.is(code::NOT_SERVED_UNCERTIFIED)
                && !refusal
                    .detail
                    .causes
                    .iter()
                    .any(|c| c.is(code::GRANT_ENDED)),
            "{:?}",
            refusal.detail
        );

        // The attempts bound: three admissions in all, the fourth is refused
        // and says the grant ended.
        for _ in 0..2 {
            let again = judge
                .decide(&bob, &hello(chain.clone()), &CH, None)
                .await
                .expect("within the attempts");
            // The attempt is counted when the link is registered, not here.
            let Some(Enrollment::Departure(marks)) = &again.enrollment else {
                panic!("not a departure link");
            };
            world.departures.count_attempt(&key, marks);
        }
        let refusal = judge
            .decide(&bob, &hello(chain.clone()), &CH, None)
            .await
            .err()
            .expect("a fourth admission is refused");
        assert!(
            refusal
                .detail
                .causes
                .iter()
                .any(|c| c.is(code::GRANT_ENDED)),
            "{:?}",
            refusal.detail
        );

        // A new record is a new mark with its own attempts; a mark past its
        // date admits no one, with the same refusal.
        world.departures.put(
            crate::departures::Departure {
                record: n("/a/member/laptop/32=log/a/32=data/notes/seq=9"),
                ..mark(&bob, hour)
            },
            SystemTime::now(),
        );
        judge
            .decide(&bob, &hello(chain.clone()), &CH, None)
            .await
            .expect("a new record is a new mark with its own attempts");
        world.departures.put(
            mark(
                &bob,
                SystemTime::now() + std::time::Duration::from_millis(50),
            ),
            SystemTime::now(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let refusal = judge
            .decide(&bob, &hello(chain), &CH, None)
            .await
            .err()
            .expect("the mark expired");
        assert!(
            refusal
                .detail
                .causes
                .iter()
                .any(|c| c.is(code::GRANT_ENDED))
        );
    }

    /// A device certificate whose key is named `key_name` (not necessarily under the device
    /// shape), issued by the CA of `ns`, with the chain a hello carries.
    async fn misnamed(ns: &Namespace, key_name: &str, seed: u8) -> (PeerKey, Vec<Bytes>) {
        let key = Ed25519Signer::from_seed(&[seed; 32], n(key_name));
        let cert = certificate(key.key_name(), key.public_key_bytes(), &ns.ca, "NDNCERT").await;
        let peer =
            PeerKey::from_spki(&ndn_security::spki::wrap_ed25519(&key.public_key_bytes())).unwrap();
        (peer, vec![cert, ns.ca_cert.clone()])
    }

    /// What every refusal "not a device certificate" says: the shape expected, what the
    /// certificate's name was, and what to do.
    fn assert_says_the_shape(why: &LinkDetail, ns: &str, received: &str) {
        for part in [
            "/<namespace>/<role>/<device>".to_owned(),
            format!("{ns}/<role>/<device>/KEY/<key-id>/<issuer>/<version>"),
            "one component naming what the device does there, such as member".to_owned(),
            received.to_owned(),
            format!(
                "Issue this device's certificate under that shape, for example {ns}/member/<device>"
            ),
        ] {
            assert!(
                why.text.contains(&part),
                "{part:?} is not in {:?}",
                why.text
            );
        }
        assert_eq!(
            why.param("expected"),
            Some(format!("{ns}/<role>/<device>").as_str())
        );
        assert_eq!(why.param("namespace"), Some(ns));
        assert!(
            why.param("certificate")
                .is_some_and(|c| c.starts_with(received)),
            "{:?}",
            why.params
        );
    }

    /// A certificate of a held namespace that is not named `<ns>/<role>/<device>/KEY/…`
    /// (here a device named with no role) identifies nobody, and the refusal says the
    /// shape, what the name was and what to do (ndn-link.md §7.1).
    #[tokio::test]
    async fn a_certificate_not_of_the_device_shape_is_refused_with_the_shape_and_what_to_do() {
        let home = namespace("/home", 1).await;
        let (peer, chain) = misnamed(&home, "/home/phone/KEY/k", 20).await;
        let world = World::new(
            Bare(Arc::new(keyring_with(home.context())), None, Vec::new()),
            Vec::new(),
            ServePolicy::Own,
        );
        let proven = world
            .judge()
            .identify(&peer, &hello(chain), &CH)
            .await
            .expect("a certificate of the wrong shape identifies nobody; it does not refuse");
        assert!(proven.identities.is_empty());
        let why = proven.why.detail();
        assert!(why.is(code::NOT_DEVICE_CERTIFICATE), "{why:?}");
        assert_says_the_shape(&why, "/home", "/home/phone/KEY/k");
    }

    /// The same for a device of a namespace this device does not hold, checked against the
    /// root its hello carries.
    #[tokio::test]
    async fn a_foreign_certificate_not_of_the_device_shape_is_refused_with_the_shape_and_what_to_do()
     {
        let mine = namespace("/a", 1).await;
        let theirs = namespace("/b", 5).await;
        let (peer, mut chain) = misnamed(&theirs, "/b/phone/KEY/k", 21).await;
        chain.push(theirs.root.clone());
        let world = World::new(
            Bare(Arc::new(keyring_with(mine.context())), None, Vec::new()),
            Vec::new(),
            ServePolicy::Own,
        );
        let proven = world
            .judge()
            .identify(&peer, &hello(chain), &CH)
            .await
            .expect("a certificate of the wrong shape identifies nobody; it does not refuse");
        assert!(proven.identities.is_empty());
        let why = proven.why.detail();
        assert!(why.is(code::FOREIGN_NOT_DEVICE_CERTIFICATE), "{why:?}");
        assert_says_the_shape(&why, "/b", "/b/phone/KEY/k");
        assert!(why.param("root").is_some(), "{:?}", why.params);
    }

    /// The name of a certificate a hostile peer sent is shown cleaned of control and invisible
    /// characters and shortened, in the text and in the fact.
    #[tokio::test]
    async fn the_received_certificate_name_is_cleaned_and_shortened() {
        let hostile = n("/home/x").append("a\u{202e}b\u{7}c\nd");
        let shown = received_name(&hostile);
        assert!(
            !shown.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{shown:?}"
        );
        assert_eq!(received_name(&n("/home/x/y")), "/home/x/y");

        let long = "y".repeat(400);
        let home = namespace("/home", 1).await;
        let (peer, chain) = misnamed(&home, &format!("/home/phone/{long}/KEY/k"), 22).await;
        let world = World::new(
            Bare(Arc::new(keyring_with(home.context())), None, Vec::new()),
            Vec::new(),
            ServePolicy::Own,
        );
        let proven = world
            .judge()
            .identify(&peer, &hello(chain), &CH)
            .await
            .unwrap();
        let why = proven.why.detail();
        let fact = why.param("certificate").unwrap();
        assert!(why.is(code::NOT_DEVICE_CERTIFICATE), "{why:?}");
        assert!(
            fact.chars().count() <= RECEIVED_NAME_MAX && fact.ends_with('…'),
            "{fact:?}"
        );
        assert!(!why.text.contains(&long), "{:?}", why.text);
        assert!(why.text.contains(fact));
    }

    /// An inviter that also admits enrollment links takes a device with no
    /// certificate (a first contact's hello is empty) as an enrollment link;
    /// while an offer is open that link carries the offer's introduction too,
    /// and still the enrollment's names, and no other.
    #[tokio::test]
    async fn an_enrollment_link_carries_an_open_offers_introduction_too() {
        let a = namespace("/a", 10).await;
        let (_, own) = a.device("node", "laptop", 90).await;
        let mut world = World::new(
            Bare(Arc::new(keyring_with(a.context())), None, own),
            Vec::new(),
            ServePolicy::Own,
        );
        let (key, _) = a.device("member", "phone", 32).await;
        async fn decided(world: &World, key: &PeerKey) -> ndn_face_quic::LinkScope {
            let judge = world.judge();
            let admitted = judge
                .decide(key, &hello(Vec::new()), &CH, None)
                .await
                .expect("a device with no certificate gets a link");
            judge
                .admission_for(&admitted)
                .scope
                .expect("an enrollment link is scoped")
        }
        let scope = decided(&world, &key).await;
        assert!((scope.names)(&n("/a/CA/NEW")), "the enrollment is carried");
        assert!(
            !(scope.names)(&n("/intro/offer")),
            "no offer is open: nothing of an introduction is carried"
        );

        world.introductions = Some(Arc::new(Surface));
        let scope = decided(&world, &key).await;
        assert!(
            (scope.names)(&n("/intro/offer")),
            "the open offer's introduction crosses the enrollment link"
        );
        assert!(
            (scope.names)(&n("/a/CA/NEW")),
            "the enrollment is still carried"
        );
        assert!(
            !(scope.names)(&n("/a/member/phone/album")) && !(scope.names)(&n("/other")),
            "nothing else is"
        );
    }

    /// A peer this device dialled from a code (it has `unidentified_routes`)
    /// is admitted unidentified while its device's namespace is not held
    /// here. Once it is, the link is made again so the device shows a
    /// certificate of it, and a party that still shows none is no device of
    /// it — refused, with why and what to do, not admitted again with the
    /// routes of the introduction.
    #[tokio::test]
    async fn a_dialled_party_still_showing_no_certificate_after_the_relink_is_refused() {
        let a = namespace("/a", 10).await;
        let dialled = |key: Option<KeyFingerprint>, routes: Option<Vec<Name>>| PeerSpec {
            label: "/a/member/laptop".into(),
            key,
            device: Some(n("/a/member/laptop")),
            persistent: false,
            unidentified_routes: routes,
            ..PeerSpec::default()
        };
        let introduction = Some(vec![n("/a/member/laptop/32=held")]);
        // `held`: the namespace is held here; `relinked`: this is the link
        // made again because of it.
        let judged = |held: bool, relinked: bool, peer: PeerSpec| {
            let keyring = if held {
                keyring_with(a.context())
            } else {
                Keyring::new()
            };
            let world = World::new(
                Bare(Arc::new(keyring), None, Vec::new()),
                vec![peer],
                ServePolicy::Own,
            );
            if relinked {
                world.relinked.lock().insert(PeerId(0));
            }
            decide_identified(
                &world.judge(),
                THEIRS,
                Err(Unidentified::NoCertificate),
                Some(PeerId(0)),
                Some(PeerId(0)),
            )
            .map(|admitted| admitted.enrollment)
        };

        let refusal = judged(true, true, dialled(Some(THEIRS), introduction.clone())).expect_err(
            "a held namespace's device shows a certificate of it, or is not that device",
        );
        assert_eq!(refusal.reason, CloseReason::Unrecognized);
        assert!(
            refusal.detail.is(code::EXPECTED_DEVICE_UNCONFIRMED),
            "{:?}",
            refusal.detail
        );
        let said = &refusal.detail.text;
        assert!(
            said.contains("/a/member/laptop") && said.contains("no certificate"),
            "{said}"
        );
        assert!(said.contains("new code"), "it says what to do: {said}");

        // The first link of the dial, whatever is held: the unidentified link
        // of the introduction, which the join judges by the record.
        for held in [false, true] {
            assert_eq!(
                judged(held, false, dialled(Some(THEIRS), introduction.clone())).unwrap(),
                None,
                "held {held}: the first link is admitted unidentified"
            );
        }
        // Made again with the namespace not held (nothing to show yet).
        assert_eq!(
            judged(false, true, dialled(Some(THEIRS), introduction)).unwrap(),
            None
        );
        // A host's own entry for a key (no code's routes) is admitted by its
        // key whatever the namespaces held.
        assert_eq!(
            judged(true, true, dialled(Some(THEIRS), None)).unwrap(),
            None,
            "a host-configured key admits the device"
        );
    }

    /// What an unidentified link to a peer dialled from a code carries: the
    /// answers to what this device asks under the routes it was dialled for,
    /// this device's Interests there, and — of the peer's Interests — only
    /// those under this device's own names (the inviter fetches the joiner's
    /// seal key); the others are dropped, never handed to the forwarder.
    #[tokio::test]
    async fn an_unidentified_dialled_link_carries_only_the_introduction_and_asks_for_own_names() {
        let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
        let (_, own) = b.device("member", "phone", 22).await;
        let routes = vec![
            n("/a/member/laptop/32=held"),
            n("/a/member/laptop/32=intro"),
        ];
        let world = World::new(
            Bare(Arc::new(keyring_with(b.context())), None, own),
            vec![PeerSpec {
                label: "/a/member/laptop".into(),
                key: Some(THEIRS),
                device: Some(n("/a/member/laptop")),
                persistent: false,
                unidentified_routes: Some(routes.clone()),
                ..PeerSpec::default()
            }],
            ServePolicy::Own,
        );
        let _ = &a;
        let judge = world.judge();
        let admitted = decide_identified(
            &judge,
            THEIRS,
            Err(Unidentified::NoCertificate),
            Some(PeerId(0)),
            Some(PeerId(0)),
        )
        .expect("a stranger at a first contact's address is admitted unidentified");
        let scope = judge
            .admission_for(&admitted)
            .scope
            .expect("an unidentified dialled link is scoped");
        let interests = scope.interests_in.expect("the peer's Interests are judged");
        let answers = scope.answers_in.expect("the peer's answers are judged");
        let held = n("/a/member/laptop/32=held/x");
        let own_name = n("/b/member/phone/32=seal/x");
        let other = n("/c/private");
        // The peer's Interests: this device's own names only.
        assert!((scope.names)(&own_name) && interests(&own_name));
        assert!(
            !((scope.names)(&held) && interests(&held)),
            "an Interest for the introduction's names is not the peer's to send"
        );
        assert!(!((scope.names)(&other) && interests(&other)));
        // Its answers: under what this device asked for.
        assert!((scope.names)(&held) && answers(&held));
        assert!(!((scope.names)(&own_name) && answers(&own_name)));
        assert!(!((scope.names)(&other) && answers(&other)));
        // This device's own Interests (names judged alone) go out under the
        // routes, and nowhere else.
        assert!((scope.names)(&held));
        assert!(!(scope.names)(&other));
    }
}
