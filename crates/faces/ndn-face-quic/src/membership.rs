//! Memberships: the namespaces a device takes part in beyond the one its
//! link key is certified in.
//!
//! A link has one key per device (the TLS key), and its hello's
//! certificates are that key's chain. A device that is also a member of
//! other namespaces, each with a key of its own there, adds a
//! [`Membership`] per such namespace: that key's certificate chain (its
//! certificate, the issuers, the namespace root last) and a *binding*, that
//! key's signature over [`binding_transcript`]: a fixed label, the
//! fingerprint of the TLS key the sender linked with, a value both sides of
//! this one connection share ([`ChannelBinding`]: the TLS exporter of the
//! connection, [`Handshaken::channel_binding`](crate::Handshaken::channel_binding);
//! for a punch message, its session), and the digest of the certificate.
//! The binding proves that whoever holds the namespace key vouches for this
//! link key on this connection: a certificate whose key the sender does not
//! hold cannot be bound, and a binding taken from another connection names
//! another exporter value, so neither verifies ([`Membership::verify`]).
//!
//! Wire: `Membership = 0x045C { Data+, MembershipBinding 0x045E (signature
//! value) }`, an even type above 31: a receiver that predates it skips it.

use bytes::Bytes;
use ndn_security::{Signer, VerifyOutcome, verify_by_sig_type};
use ndn_tlv::TlvWriter;
use sha2::{Digest, Sha256};

use crate::key::{KeyError, KeyFingerprint, LinkKeyAlgorithm};
use crate::message::{DATA, skippable, split_tlv};

/// TLV-TYPE of a [`Membership`] (in a link hello or a punch message).
pub const MEMBERSHIP: u64 = 0x045C;
const MEMBERSHIP_BINDING: u64 = 0x045E;

/// The label a connection's [`ChannelBinding`] is exported with (RFC 8446
/// §7.5), with an empty context.
pub const MEMBERSHIP_EXPORTER_LABEL: &[u8] = b"EXPORTER-ndn-link/1 membership";

/// The fixed label a binding transcript starts with (21 ASCII bytes and a
/// zero byte).
pub const BINDING_LABEL: &[u8] = b"ndn-link/1 membership\0";

/// Most memberships a receiver takes from one hello; the rest are ignored.
pub const MEMBERSHIPS_MAX: usize = 8;

/// A 32-byte value both sides of one connection (or one punch) share and
/// no other has: what a binding is bound to.
pub type ChannelBinding = [u8; 32];

/// One namespace the sender is a member of with a key other than its link
/// key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    /// Certificate Data wires: the sender's certificate in the namespace,
    /// then its issuers nearest first, ending in the namespace's root.
    pub certificates: Vec<Bytes>,
    /// The certificate key's signature over [`binding_transcript`].
    pub binding: Bytes,
}

/// What a membership binding signs: [`BINDING_LABEL`] ‖ the fingerprint of
/// the sender's link key (32 bytes) ‖ `channel` (32 bytes) ‖ SHA-256 of
/// the membership's certificate Data (`leaf`, the whole TLV; 32 bytes).
pub fn binding_transcript(
    link_key: &KeyFingerprint,
    channel: &ChannelBinding,
    leaf: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(BINDING_LABEL.len() + 96);
    out.extend_from_slice(BINDING_LABEL);
    out.extend_from_slice(&link_key.0);
    out.extend_from_slice(channel);
    out.extend_from_slice(&Sha256::digest(leaf));
    out
}

impl Membership {
    /// Bind `certificates` (the chain of `signer`'s key, its certificate
    /// first) to the link key `link_key` on `channel`.
    pub async fn sign(
        signer: &dyn Signer,
        link_key: &KeyFingerprint,
        channel: &ChannelBinding,
        certificates: Vec<Bytes>,
    ) -> Result<Self, KeyError> {
        let Some(leaf) = certificates.first() else {
            return Err(KeyError::Unsupported(format!(
                "the key {} has no certificate to show a membership with",
                signer.key_name()
            )));
        };
        if !matches!(
            signer.sig_type(),
            ndn_packet::SignatureType::SignatureEd25519
                | ndn_packet::SignatureType::SignatureSha256WithEcdsa
        ) {
            return Err(KeyError::Unsupported(format!(
                "the key {} is a {:?} key; a membership is shown with an Ed25519 or P-256 device key",
                signer.key_name(),
                signer.sig_type()
            )));
        }
        let binding = signer
            .sign(&binding_transcript(link_key, channel, leaf))
            .await
            .map_err(|e| {
                KeyError::Unsupported(format!("the key {} cannot sign: {e}", signer.key_name()))
            })?;
        Ok(Self {
            certificates,
            binding,
        })
    }

    /// Whether the binding is the signature of the certificate's key
    /// (`public_key`, as the certificate carries it) for link key
    /// `link_key` on `channel`. `Err`: why not, for the refusal.
    pub async fn verify(
        &self,
        public_key: &[u8],
        link_key: &KeyFingerprint,
        channel: &ChannelBinding,
    ) -> Result<(), String> {
        let leaf = self
            .certificates
            .first()
            .ok_or("the membership carries no certificate")?;
        let algorithm = LinkKeyAlgorithm::of_ndn_key(public_key).ok_or(
            "its certificate's key is neither Ed25519 nor P-256, the two device key types",
        )?;
        let transcript = binding_transcript(link_key, channel, leaf);
        match verify_by_sig_type(algorithm.signature_type(), &transcript, &self.binding, public_key).await {
            Ok(VerifyOutcome::Valid) => Ok(()),
            Ok(VerifyOutcome::Invalid) | Err(_) => Err(
                "its binding is not that certificate's key's signature for this link key on this connection: \
                 the sender does not hold the certificate's key, or the binding was made for another connection"
                    .into(),
            ),
        }
    }

    /// Append this membership's TLV to `w`.
    pub(crate) fn write(&self, w: &mut TlvWriter) {
        w.write_nested(MEMBERSHIP, |w| {
            for cert in &self.certificates {
                w.write_raw(cert);
            }
            w.write_tlv(MEMBERSHIP_BINDING, &self.binding);
        });
    }

    /// The whole `Membership` TLV.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        self.write(&mut w);
        w.finish()
    }

    /// Decode the value of a `Membership` TLV: one or more certificates
    /// and exactly one binding (the last wins when repeated).
    pub fn decode(value: &[u8]) -> Result<Self, String> {
        let mut certificates = Vec::new();
        let mut binding = None;
        let mut cur = value;
        while !cur.is_empty() {
            let (t, start, end) = split_tlv(cur)?;
            match t {
                DATA => certificates.push(Bytes::copy_from_slice(&cur[..end])),
                MEMBERSHIP_BINDING if start < end => {
                    binding = Some(Bytes::copy_from_slice(&cur[start..end]))
                }
                MEMBERSHIP_BINDING => return Err("an empty binding in a membership".into()),
                t if skippable(t) => {}
                t => return Err(format!("unknown critical field {t:#x} in a membership")),
            }
            cur = &cur[end..];
        }
        if certificates.is_empty() {
            return Err("a membership without a certificate".into());
        }
        let binding = binding.ok_or("a membership without its binding")?;
        Ok(Self {
            certificates,
            binding,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::key::LinkKey;
    use ndn_packet::Name;
    use ndn_security::{EcdsaP256Signer, Ed25519Signer, encode_cert_data};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 2026-01-01T00:00:00Z, 2027-…, 2036-… in ns.
    const T2026: u64 = 1_767_225_600_000_000_000;
    const T2027: u64 = 1_798_761_600_000_000_000;
    const T2036: u64 = 2_082_758_400_000_000_000;

    /// The vector of ndn-link.md §19.18: the link key of §19.1 (seed 01),
    /// a membership of `/work` with the device key seed 04, certified by
    /// the `/work` root (seed 03), bound to the exporter value 00..1f.
    async fn vector() -> (KeyFingerprint, ChannelBinding, Ed25519Signer, Vec<Bytes>) {
        let link = LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
            &[1; 32],
            "/home/member/phone/KEY/1112131415161718".parse().unwrap(),
        )))
        .unwrap();
        let root_key: Name = "/work/KEY/2122232425262728".parse().unwrap();
        let root = Ed25519Signer::from_seed(&[3; 32], root_key.clone());
        let root_cert = ndn_security::cert_name::cert_name(&root_key, "self", 1_767_225_600_000);
        let root_cert = encode_cert_data(&root_cert, &root.public_key_bytes(), &root, T2026, T2036)
            .await
            .unwrap();
        let member_key: Name = "/work/member/phone/KEY/3132333435363738".parse().unwrap();
        let member = Ed25519Signer::from_seed(&[4; 32], member_key.clone());
        let leaf = ndn_security::cert_name::cert_name(&member_key, "NDNCERT", 1_767_225_600_000);
        let leaf = encode_cert_data(&leaf, &member.public_key_bytes(), &root, T2026, T2027)
            .await
            .unwrap();
        let channel: ChannelBinding = std::array::from_fn(|i| i as u8);
        (link.fingerprint(), channel, member, vec![leaf, root_cert])
    }

    #[tokio::test]
    async fn the_spec_vectors_are_what_this_code_writes() {
        let (link, channel, member, chain) = vector().await;
        let transcript = binding_transcript(&link, &channel, &chain[0]);
        let membership = Membership::sign(&member, &link, &channel, chain.clone())
            .await
            .unwrap();
        let wire = membership.encode();
        assert_eq!(hex(&chain[0]), LEAF);
        assert_eq!(hex(&chain[1]), ROOT);
        assert_eq!(hex(&transcript), TRANSCRIPT);
        assert_eq!(hex(&membership.binding), BINDING);
        assert_eq!(
            hex(&wire),
            format!("fd045cfd0268{LEAF}{ROOT}fd045e40{BINDING}")
        );
        assert_eq!(Membership::decode(&wire[6..]).unwrap(), membership);
        assert!(
            membership
                .verify(&member.public_key_bytes(), &link, &channel)
                .await
                .is_ok()
        );
    }

    const LEAF: &str = "06fd0117073f0804776f726b08066d656d626572080570686f6e6508034b4559081033313332333333343335333633373338\
08074e444e4345525436080000019b76daa8001414180800000000000000021908000000000036ee80152c302a300506032b6570032100\
ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c164e1b01051c1f071d0804776f726b08034b4559081032\
313232323332343235323632373238fd00fd26fd00fe0f323032363031303154303030303030fd00ff0f32303237303130315430303030\
303017403dc98f25465f7561620a7da039e130d69c5e9607d96aa3ee0d3a04703a1a480c5f9add6f6affc116c0efdd5e36f20629a0f9d0\
5668545bcc4778c33fc9854f0b";
    const ROOT: &str = "06fd0105072d0804776f726b08034b4559081032313232323332343235323632373238080473656c6636080000019b76da\
a8001414180800000000000000021908000000000036ee80152c302a300506032b6570032100ed4928c628d1c2c6eae90338905995612959\
273a5c63f93636c14614ac8737d1164e1b01051c1f071d0804776f726b08034b4559081032313232323332343235323632373238fd00fd26\
fd00fe0f323032363031303154303030303030fd00ff0f3230333630313031543030303030301740841fa024d19bb23a63bf6f9228af413d\
5a6281014f1524362c4ba19f74ac9fea7bc07d14e8de6fa8a6688769860da04fc92c865f2dc6c6bd58e7184487a35601";
    const TRANSCRIPT: &str = "6e646e2d6c696e6b2f31206d656d626572736869700034750f98bd59fcfc946da45aaabe933be154a4b509\
4e1c4abf42866505f3c97e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f14bb26fdde55b6a50683847e00\
cc12f05e7b754b93304b858d9321e68d2691d4";
    const BINDING: &str = "e77a3e5d85e0380c7c409d4b43a779b63c04e133ae3ba1f130dfad0a72042e768c3612fd1077ce641742f08c464a\
49c8e29a5a78c1878bb9f263cec1bf85c700";

    /// A binding verifies only under the certificate's key, for the link
    /// key and connection it was made for: a key that is not the
    /// certificate's (a forgery), another connection's exporter value (a
    /// replay) or another link key all fail. P-256 keys bind too.
    #[tokio::test]
    async fn a_binding_holds_only_for_its_key_link_key_and_connection() {
        let (link, channel, member, chain) = vector().await;
        let forger = Ed25519Signer::from_seed(&[9; 32], "/x/KEY/k".parse().unwrap());
        let forged = Membership::sign(&forger, &link, &channel, chain.clone())
            .await
            .unwrap();
        let key = member.public_key_bytes();
        assert!(forged.verify(&key, &link, &channel).await.is_err());
        let real = Membership::sign(&member, &link, &channel, chain.clone())
            .await
            .unwrap();
        assert!(real.verify(&key, &link, &[0xEE; 32]).await.is_err());
        assert!(
            real.verify(&key, &KeyFingerprint([0; 32]), &channel)
                .await
                .is_err()
        );
        assert!(real.verify(&[0; 5], &link, &channel).await.is_err());

        let ec = EcdsaP256Signer::from_seed(&[5; 32], "/work/member/tab/KEY/k".parse().unwrap())
            .unwrap();
        let ec_key = ec.public_key().unwrap();
        let bound = Membership::sign(&ec, &link, &channel, chain).await.unwrap();
        assert!(bound.verify(&ec_key, &link, &channel).await.is_ok());
        assert!(bound.verify(&ec_key, &link, &[0xEE; 32]).await.is_err());
    }
}
