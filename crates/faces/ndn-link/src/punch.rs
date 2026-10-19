//! The punch: the signed Interest a device sends to another, through
//! whatever path reaches it (normally its relay), to make a direct path,
//! and the signed Data that answers it.
//!
//! Name: `<device>/32=link/32=punch/<session>` (+ ParametersSha256Digest),
//! `<device>` the punched device's name, `<session>` 8 random bytes (a
//! GenericNameComponent). The Interest is an NDN signed Interest
//! (SignatureNonce and SignatureTime) by the sender's link key; its
//! ApplicationParameters and the answer's Content are a punch message:
//!
//! ```text
//! PunchMessage = PunchKey *Candidate [PunchRefusal] *Data *Membership
//! PunchKey     = 0x0460 <the sender's link key as a SubjectPublicKeyInfo>
//! Candidate    = 0x0462 { CandidateKind 0x0464 (1 byte), UdpAddress 0x0466 (6|18 bytes) }
//! PunchRefusal = 0x0468 { RefusalCode 0x046A (NonNegativeInteger), RefusalText 0x046C (UTF-8) }
//! Data         = the sender's certificate, then its issuers (as in LinkHello)
//! Membership   = 0x045C, as in LinkHello: the sender's membership of the
//!                punched device's namespace when its link key is not
//!                certified there, bound to the link key for this punch
//!                ([`punch_binding`])
//! ```
//!
//! An unrecognized TLV-TYPE that is even and above 31 is skipped; any other
//! is malformed.

use std::sync::Arc;

use bytes::Bytes;
use ndn_face_quic::{
    ChannelBinding, LinkKey, MEMBERSHIP, Membership, PathSession, PeerKey, decode_udp_address, encode_udp_address,
};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name, NameComponent};
use ndn_security::{Certificate, Signer, VerifyOutcome, verify_by_sig_type};
use ndn_tlv::{TlvWriter, read_varu64};
use sha2::{Digest, Sha256};

use crate::candidates::{Candidate, CandidateKind};
use crate::policy::{CANDIDATES_MAX, PUNCH_ANSWER_TIMEOUT};

const PUNCH_KEY: u64 = 0x0460;
const CANDIDATE: u64 = 0x0462;
const CANDIDATE_KIND: u64 = 0x0464;
const UDP_ADDRESS: u64 = 0x0466;
const PUNCH_REFUSAL: u64 = 0x0468;
const REFUSAL_CODE: u64 = 0x046A;
const REFUSAL_TEXT: u64 = 0x046C;
const DATA: u64 = 0x06;

/// A punch request or answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PunchMessage {
    /// The sender's link key (SubjectPublicKeyInfo): the key that signs the
    /// message and that its direct path's handshake proves.
    pub(crate) key: Bytes,
    /// Where the sender may be reached directly.
    pub(crate) candidates: Vec<Candidate>,
    /// An answer that refuses: a link close code and why.
    pub(crate) refusal: Option<(u64, String)>,
    /// The sender's certificate and its issuers, nearest first.
    pub(crate) certificates: Vec<Bytes>,
    /// The sender's membership of the punched device's namespace, when its
    /// link key is not certified there.
    pub(crate) memberships: Vec<Membership>,
}

impl PunchMessage {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.write_tlv(PUNCH_KEY, &self.key);
        for c in self.candidates.iter().take(CANDIDATES_MAX) {
            w.write_nested(CANDIDATE, |w| {
                w.write_tlv(CANDIDATE_KIND, &[c.kind.code()]);
                w.write_tlv(UDP_ADDRESS, &encode_udp_address(c.addr));
            });
        }
        if let Some((code, text)) = &self.refusal {
            w.write_nested(PUNCH_REFUSAL, |w| {
                w.write_tlv(REFUSAL_CODE, &nni(*code));
                w.write_tlv(REFUSAL_TEXT, text.as_bytes());
            });
        }
        for cert in &self.certificates {
            w.write_raw(cert);
        }
        for membership in &self.memberships {
            w.write_raw(&membership.encode());
        }
        w.finish().to_vec()
    }

    /// Decode a punch message. Candidates beyond [`CANDIDATES_MAX`], and
    /// ones of a kind this device does not know, are ignored.
    pub(crate) fn decode(mut cur: &[u8]) -> Result<Self, String> {
        let mut msg = Self::default();
        let mut key = None;
        while !cur.is_empty() {
            let (t, value, end) = split(cur)?;
            match t {
                PUNCH_KEY => key = Some(Bytes::copy_from_slice(value)),
                CANDIDATE => {
                    if let Some(c) = decode_candidate(value)?
                        && msg.candidates.len() < CANDIDATES_MAX
                    {
                        msg.candidates.push(c);
                    }
                }
                PUNCH_REFUSAL => msg.refusal = Some(decode_refusal(value)?),
                DATA => msg.certificates.push(Bytes::copy_from_slice(&cur[..end])),
                MEMBERSHIP => msg.memberships.push(Membership::decode(value)?),
                t if skippable(t) => {}
                t => return Err(format!("unknown critical field {t:#x} in the punch message")),
            }
            cur = &cur[end..];
        }
        msg.key = key.ok_or("the punch message names no link key")?;
        Ok(msg)
    }
}

fn decode_candidate(mut cur: &[u8]) -> Result<Option<Candidate>, String> {
    let mut kind = None;
    let mut addr = None;
    while !cur.is_empty() {
        let (t, value, end) = split(cur)?;
        match t {
            CANDIDATE_KIND => match value {
                [k] => kind = Some(*k),
                _ => return Err("a candidate kind is one byte".into()),
            },
            UDP_ADDRESS => addr = Some(decode_udp_address(value)?),
            t if skippable(t) => {}
            t => return Err(format!("unknown critical field {t:#x} in a candidate")),
        }
        cur = &cur[end..];
    }
    let (Some(kind), Some(addr)) = (kind, addr) else {
        return Err("a candidate lacks its kind or address".into());
    };
    Ok(CandidateKind::from_code(kind).map(|kind| Candidate { kind, addr }))
}

fn decode_refusal(mut cur: &[u8]) -> Result<(u64, String), String> {
    let mut code = None;
    let mut text = String::new();
    while !cur.is_empty() {
        let (t, value, end) = split(cur)?;
        match t {
            REFUSAL_CODE => {
                if !matches!(value.len(), 1 | 2 | 4 | 8) {
                    return Err("a refusal code is a NonNegativeInteger".into());
                }
                code = Some(value.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)));
            }
            REFUSAL_TEXT => text = String::from_utf8_lossy(value).into_owned(),
            t if skippable(t) => {}
            t => return Err(format!("unknown critical field {t:#x} in a punch refusal")),
        }
        cur = &cur[end..];
    }
    Ok((code.ok_or("a punch refusal carries no code")?, text))
}

fn nni(n: u64) -> Vec<u8> {
    if n <= 0xFF {
        vec![n as u8]
    } else if n <= 0xFFFF {
        (n as u16).to_be_bytes().to_vec()
    } else if n <= 0xFFFF_FFFF {
        (n as u32).to_be_bytes().to_vec()
    } else {
        n.to_be_bytes().to_vec()
    }
}

fn skippable(t: u64) -> bool {
    t > 31 && t & 1 == 0
}

/// One TLV at the head of `buf`: its type, value, and where it ends.
fn split(buf: &[u8]) -> Result<(u64, &[u8], usize), String> {
    let (t, tn) = read_varu64(buf).map_err(|_| "truncated TLV type".to_string())?;
    let (l, ln) = read_varu64(&buf[tn..]).map_err(|_| "truncated TLV length".to_string())?;
    let start = tn + ln;
    let end = usize::try_from(l)
        .ok()
        .and_then(|l| start.checked_add(l))
        .filter(|&end| end <= buf.len())
        .ok_or_else(|| "truncated TLV value".to_string())?;
    Ok((t, &buf[start..end], end))
}

/// The value a punch's memberships are bound to, in place of a connection's
/// TLS exporter: SHA-256(ASCII `ndn-link/1 punch` ‖ the session). The
/// request and its answer share it; the link keys in their bindings tell
/// them apart.
pub(crate) fn punch_binding(session: &PathSession) -> ChannelBinding {
    let mut hash = Sha256::new();
    hash.update(b"ndn-link/1 punch");
    hash.update(session);
    hash.finalize().into()
}

/// `<device>/32=link/32=punch`: where a device takes punches.
pub(crate) fn punch_prefix(device: &Name) -> Name {
    device
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(b"link")))
        .append_component(NameComponent::keyword(Bytes::from_static(b"punch")))
}

/// The session a punch Interest to `device` names, if `name` is one.
pub(crate) fn session_of(device: &Name, name: &Name) -> Option<PathSession> {
    let prefix = punch_prefix(device);
    if !name.has_prefix(&prefix) {
        return None;
    }
    let rest = &name.components()[prefix.len()..];
    match rest {
        [session, digest]
            if session.typ == ndn_packet::tlv_type::NAME_COMPONENT
                && digest.typ == ndn_packet::tlv_type::PARAMETERS_SHA256 =>
        {
            PathSession::try_from(session.value.as_ref()).ok()
        }
        _ => None,
    }
}

/// The key a punch message is signed with and the KeyLocator it names:
/// the key of the membership it shows (its certificate's name), when it
/// shows one — the punch is named under the namespace of that membership,
/// whose forwarders validate it there — else the link key, with its
/// certificate's name (else its key's).
pub(crate) fn punch_signer(
    key: &LinkKey,
    own_chain: &[Bytes],
    membership: Option<(&Arc<dyn Signer>, &Membership)>,
) -> (Arc<dyn Signer>, Name) {
    let name_of = |certificates: &[Bytes]| {
        certificates
            .first()
            .and_then(|wire| Data::decode(wire.clone()).ok())
            .map(|data| (*data.name).clone())
    };
    if let Some((signer, m)) = membership
        && let Some(locator) = name_of(&m.certificates)
    {
        return (Arc::clone(signer), locator);
    }
    let locator = name_of(own_chain).unwrap_or_else(|| key.key_name().clone());
    (Arc::clone(key.signer()), locator)
}

/// The signed punch Interest to `device`.
pub(crate) async fn request(
    device: &Name,
    session: &PathSession,
    msg: &PunchMessage,
    signer: &dyn Signer,
    locator: &Name,
) -> Bytes {
    InterestBuilder::new(
        punch_prefix(device).append_component(NameComponent::generic(Bytes::copy_from_slice(session))),
    )
    .lifetime(PUNCH_ANSWER_TIMEOUT)
    .must_be_fresh()
    .app_parameters(msg.encode())
    .sign(signer.sig_type(), Some(locator), |region| {
        let region = region.to_vec();
        async move { signer.sign(&region).await.unwrap_or_default() }
    })
    .await
}

/// The signed answer to the punch Interest named `name`.
pub(crate) async fn answer(name: &Name, msg: &PunchMessage, signer: &dyn Signer, locator: &Name) -> Bytes {
    DataBuilder::new(name.clone(), &msg.encode())
        .sign(signer.sig_type(), Some(locator), |region| {
            let region = region.to_vec();
            async move { signer.sign(&region).await.unwrap_or_default() }
        })
        .await
}

/// The key a punch message `msg` must be signed by: its membership's
/// certificate key when it shows one (its binding ties that key to the
/// link key `key`, checked at admission), else the link key.
fn signing_key(msg: &PunchMessage, key: &PeerKey) -> Result<Bytes, String> {
    match msg.memberships.first() {
        Some(m) => m
            .certificates
            .first()
            .and_then(|wire| Data::decode(wire.clone()).ok())
            .and_then(|data| Certificate::decode(&data).ok())
            .map(|cert| cert.public_key)
            .ok_or_else(|| "its membership certificate does not decode".to_string()),
        None => Ok(key.ndn_public_key()),
    }
}

/// Whether `interest` (carrying `msg`) is signed by the key `msg` names —
/// its membership's, else the link key `key` — with SignatureNonce and
/// SignatureTime.
pub(crate) async fn verify_request(interest: &Interest, msg: &PunchMessage, key: &PeerKey) -> Result<(), String> {
    let (Some(info), Some(region), Some(value)) = (interest.sig_info(), interest.signed_region(), interest.sig_value())
    else {
        return Err("the punch Interest is not signed".into());
    };
    if info.sig_nonce.is_none() || info.sig_time.is_none() {
        return Err("the punch Interest lacks SignatureNonce or SignatureTime".into());
    }
    verified(verify_by_sig_type(info.sig_type, &region, value, &signing_key(msg, key)?).await)
}

/// Whether `data` (carrying `msg`) is signed by the key `msg` names.
pub(crate) async fn verify_answer(data: &Data, msg: &PunchMessage, key: &PeerKey) -> Result<(), String> {
    let Some(info) = data.sig_info() else {
        return Err("the punch answer is not signed".into());
    };
    verified(verify_by_sig_type(info.sig_type, data.signed_region(), data.sig_value(), &signing_key(msg, key)?).await)
}

fn verified(outcome: Result<VerifyOutcome, ndn_security::TrustError>) -> Result<(), String> {
    match outcome {
        Ok(VerifyOutcome::Valid) => Ok(()),
        Ok(VerifyOutcome::Invalid) => Err("its signature does not verify under the key it names".into()),
        Err(e) => Err(format!("its signature cannot be verified under the key it names: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(kind: CandidateKind, addr: &str) -> Candidate {
        Candidate {
            kind,
            addr: addr.parse().unwrap(),
        }
    }

    /// A punch message that shows a membership (the sender's link key is not
    /// certified in the punch's namespace) is signed by that membership's
    /// key and names its certificate, so forwarders validating the
    /// namespace accept it; the receiver verifies it under that key, and one
    /// signed by the link key instead does not verify.
    #[tokio::test]
    async fn a_punch_showing_a_membership_is_signed_by_its_key() {
        use ndn_security::{Ed25519Signer, encode_cert_data};
        let link = Arc::new(Ed25519Signer::from_seed(&[1; 32], "/a/member/phone/KEY/k".parse().unwrap()));
        let link_key = LinkKey::from_signer(Arc::clone(&link) as Arc<dyn Signer>).unwrap();
        let c_key: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[2; 32], "/c/member/phone/KEY/k".parse().unwrap()));
        let ca = Ed25519Signer::from_seed(&[3; 32], "/c/CA/KEY/ca".parse().unwrap());
        let cert_name: Name = "/c/member/phone/KEY/k/NDNCERT/v=1".parse().unwrap();
        let pk: [u8; 32] = c_key.public_key().unwrap().as_ref().try_into().unwrap();
        let cert = encode_cert_data(&cert_name, &pk, &ca, 0, u64::MAX / 2).await.unwrap();
        let session = [1; 8];
        let shown = Membership::sign(c_key.as_ref(), &link_key.fingerprint(), &punch_binding(&session), vec![cert])
            .await
            .unwrap();
        let msg = PunchMessage {
            key: link_key.spki().clone(),
            memberships: vec![shown.clone()],
            ..PunchMessage::default()
        };
        let (signer, locator) = punch_signer(&link_key, &[], Some((&c_key, &shown)));
        assert_eq!(locator, cert_name);
        let name: Name = "/c/member/phone/32=link/32=punch/x".parse().unwrap();
        let data = Data::decode(answer(&name, &msg, signer.as_ref(), &locator).await).unwrap();
        let peer = PeerKey::from_spki(link_key.spki()).unwrap();
        verify_answer(&data, &msg, &peer).await.unwrap();
        let by_link = Data::decode(answer(&name, &msg, link.as_ref(), &locator).await).unwrap();
        assert!(verify_answer(&by_link, &msg, &peer).await.is_err());
    }

    #[test]
    fn punch_messages_round_trip_and_ignore_unknown_candidate_kinds() {
        let msg = PunchMessage {
            key: Bytes::from_static(&[0x30, 0x2a]),
            candidates: vec![
                c(CandidateKind::Host, "192.168.1.2:6367"),
                c(CandidateKind::Reflexive, "203.0.113.9:40000"),
            ],
            refusal: None,
            certificates: vec![Bytes::from_static(&[0x06, 0x00])],
            memberships: vec![Membership {
                certificates: vec![Bytes::from_static(&[0x06, 0x01, 0xBB])],
                binding: Bytes::from_static(&[7; 64]),
            }],
        };
        assert_eq!(PunchMessage::decode(&msg.encode()).unwrap(), msg);
        let refusal = PunchMessage {
            refusal: Some((0x18, "direct paths are off".into())),
            candidates: Vec::new(),
            ..msg.clone()
        };
        assert_eq!(PunchMessage::decode(&refusal.encode()).unwrap(), refusal);
        // A candidate of kind 9 is skipped, the rest kept.
        let mut wire = msg.encode();
        let odd = [0xFD, 0x04, 0x62, 0x0F, 0xFD, 0x04, 0x64, 0x01, 0x09, 0xFD, 0x04, 0x66, 0x06, 1, 2, 3, 4, 0, 1];
        // After PunchKey (3 + 1 + 2 bytes).
        wire.splice(6..6, odd);
        assert_eq!(PunchMessage::decode(&wire).unwrap().candidates.len(), 2);
        // No key: malformed. An odd unknown type: malformed.
        assert!(PunchMessage::decode(&[0x06, 0x00]).is_err());
        assert!(PunchMessage::decode(&[0xFD, 0x04, 0x60, 0x00, 0xFD, 0x04, 0x61, 0x00]).is_err());
    }

    #[test]
    fn a_punch_name_carries_its_session_after_link_and_punch_keywords() {
        let device: Name = "/home/member/phone".parse().unwrap();
        let session = [1, 2, 3, 4, 5, 6, 7, 8];
        let name = punch_prefix(&device)
            .append_component(NameComponent::generic(Bytes::copy_from_slice(&session)))
            .append_component(NameComponent::new(ndn_packet::tlv_type::PARAMETERS_SHA256, Bytes::from(vec![0; 32])));
        assert_eq!(session_of(&device, &name), Some(session));
        let other: Name = "/home/member/tab".parse().unwrap();
        assert_eq!(session_of(&other, &name), None);
        assert_eq!(
            punch_prefix(&device),
            "/home/member/phone/32=link/32=punch".parse::<Name>().unwrap()
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The punch vectors of ndn-link.md (§16.14, §16.15).
    #[test]
    fn the_spec_vectors_are_what_this_code_writes() {
        let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        spki.extend_from_slice(&[
            0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72, 0xca,
            0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
        ]);
        let key = Bytes::from(spki);
        let key_hex = "fd04602c302a300506032b65700321008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
        let request = PunchMessage {
            key: key.clone(),
            candidates: vec![
                c(CandidateKind::Reflexive, "203.0.113.9:40000"),
                c(CandidateKind::Host, "192.168.1.2:6367"),
            ],
            refusal: None,
            certificates: Vec::new(),
            memberships: Vec::new(),
        };
        assert_eq!(
            hex(&request.encode()),
            format!(
                "{key_hex}fd04620ffd04640101fd046606cb0071099c40fd04620ffd04640100fd046606c0a8010218df"
            )
        );
        let refusal = PunchMessage {
            key,
            candidates: Vec::new(),
            refusal: Some((0x18, "direct paths are off".into())),
            certificates: Vec::new(),
            memberships: Vec::new(),
        };
        assert_eq!(
            hex(&refusal.encode()),
            format!("{key_hex}fd04681dfd046a0118fd046c1464697265637420706174687320617265206f6666")
        );
        let device: Name = "/home/member/phone".parse().unwrap();
        let name = punch_prefix(&device).append_component(NameComponent::generic(Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8])));
        assert_eq!(
            hex(&name.encode_to_tlv()),
            "072c0804686f6d6508066d656d626572080570686f6e6520046c696e6b200570756e636808080102030405060708"
        );
        // What the memberships of the punch of session 01..08 are bound to.
        assert_eq!(
            hex(&punch_binding(&[1, 2, 3, 4, 5, 6, 7, 8])),
            "b2d0a9d0b6405643f3fba3edebfb5e1b6d777776ba5a3b90377f3635a6f489fa"
        );
    }
}
