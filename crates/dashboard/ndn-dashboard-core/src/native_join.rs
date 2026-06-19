//! Native token-join — NDNCERT enrollment for the native app, plus identity
//! persistence. The native analogue of the browser `JoinClient` (dioxus-demo,
//! IndexedDB-backed): drive an [`EnrollmentSession`] through NEW → token
//! CHALLENGE → issued cert, then persist the result.
//!
//! **Transport seam.** Enrollment is driven over a [`CaExchange`] — the three
//! NDNCERT request/response steps at the body level. The native app's impl
//! builds signed NEW/CHALLENGE Interests and rides the Phase-2 IPC seam (a
//! `Connection` to the tunnel's forwarder, which routes to the CA); that impl
//! lands with Phase 4, where it's witnessed against a live forwarder + CA. The
//! protocol driver and persistence here are exercised in-process against a real
//! [`ndn_cert::ca::CaState`] + [`ndn_cert::TokenChallenge`] (see tests).
//!
//! **Persistence has two tiers, keyed on where the private key lives:**
//! - **Software key** — the seed + issued cert persist as an encrypted
//!   `SafeBag` (spec-canonical, `ndnsec`-importable), the same shape as the web
//!   path. Implemented here ([`save_software_safebag`] / [`load_software_safebag`]).
//! - **Enclave key** — an [`EnclaveCustodian`](ndn_security::custodian::EnclaveCustodian)
//!   key's private half never leaves secure hardware, so it **cannot** go into
//!   a SafeBag. It persists as the issued cert plus a reference to the enclave
//!   key handle. That tier lands with Phase 4 (the real Keystore/Enclave key);
//!   `JoinedIdentity` carries the issued cert for either tier.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_cert::EnrollmentSession;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::safebag::{SafeBag, ed25519_seed_to_pkcs8};
use ndn_security::Signer;

/// The NDNCERT token challenge type code, per the CA's offered challenges.
const TOKEN_CHALLENGE: &str = "token";

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("NDNCERT protocol error: {0}")]
    Protocol(String),
    #[error("certificate: {0}")]
    Cert(String),
    #[error("safebag: {0}")]
    SafeBag(String),
    #[error("io: {0}")]
    Io(String),
}

/// The CA-facing transport, as the three NDNCERT steps at the body level. The
/// native impl builds + signs the Interests and rides the IPC seam; an
/// in-process impl over [`ndn_cert::ca::CaState`] backs the tests.
#[async_trait]
pub trait CaExchange: Send + Sync {
    /// `/<ca>/CA/NEW` — send the request body, return the response body.
    async fn new_request(&self, body: &[u8]) -> Result<Bytes, JoinError>;
    /// `/<ca>/CA/CHALLENGE/<request-id>` — send the challenge body, return the
    /// response body. `request_id` is the CA's string key (for an in-process
    /// CA); `request_id_bytes` is the raw 8-byte CHALLENGE Interest name
    /// component (for a wire transport). Each impl uses the form it needs.
    async fn challenge_request(
        &self,
        request_id: &str,
        request_id_bytes: &[u8; 8],
        body: &[u8],
    ) -> Result<Bytes, JoinError>;
    /// Fetch the issued certificate's wire bytes by name.
    async fn fetch_cert(&self, cert_name: &str) -> Result<Bytes, JoinError>;
}

/// A successfully enrolled identity. The issued cert is carried for both
/// persistence tiers; how the *private key* is stored differs (SafeBag for
/// software keys; cert + handle for enclave keys).
#[derive(Debug, Clone)]
pub struct JoinedIdentity {
    pub key_name: Name,
    pub cert_name: Name,
    pub cert_wire: Bytes,
}

/// Drive NDNCERT enrollment through a token challenge: NEW → CHALLENGE(token)
/// → fetch the issued cert. `signer` signs the enrollment (the caller owns the
/// key — software or enclave); `key_name` is its key name.
pub async fn enroll_via_token(
    exchange: &dyn CaExchange,
    key_name: Name,
    signer: Arc<dyn Signer>,
    token: &str,
    validity_secs: u64,
) -> Result<JoinedIdentity, JoinError> {
    let mut session = EnrollmentSession::new(key_name.clone(), signer, validity_secs);

    // NEW.
    let new_body = session
        .new_request_body()
        .await
        .map_err(|e| JoinError::Protocol(format!("NEW body: {e}")))?;
    let new_resp = exchange.new_request(&new_body).await?;
    session
        .handle_new_response(&new_resp)
        .map_err(|e| JoinError::Protocol(format!("NEW response: {e}")))?;

    if !session
        .offered_challenges()
        .iter()
        .any(|c| c == TOKEN_CHALLENGE)
    {
        return Err(JoinError::Protocol(format!(
            "CA did not offer the '{TOKEN_CHALLENGE}' challenge; offered: {:?}",
            session.offered_challenges()
        )));
    }

    // CHALLENGE(token).
    let mut params = serde_json::Map::new();
    params.insert(
        "token".to_string(),
        serde_json::Value::String(token.to_owned()),
    );
    let chal_body = session
        .challenge_request_body(TOKEN_CHALLENGE, params)
        .map_err(|e| JoinError::Protocol(format!("CHALLENGE body: {e}")))?;
    let request_id = session
        .request_id()
        .ok_or_else(|| JoinError::Protocol("no request_id after NEW".into()))?
        .to_string();
    let request_id_bytes = *session
        .request_id_bytes()
        .ok_or_else(|| JoinError::Protocol("no request_id bytes after NEW".into()))?;
    let chal_resp = exchange
        .challenge_request(&request_id, &request_id_bytes, &chal_body)
        .await?;
    session
        .handle_challenge_response(&chal_resp)
        .map_err(|e| JoinError::Protocol(format!("CHALLENGE response: {e}")))?;

    if !session.is_complete() {
        return Err(JoinError::Protocol(format!(
            "CA did not approve the token challenge; status: {:?}",
            session.challenge_status_message()
        )));
    }

    // Fetch the issued cert.
    let cert_name = session
        .issued_cert_name()
        .ok_or_else(|| JoinError::Protocol("no issued cert name on success".into()))?
        .clone();
    let cert_wire = exchange.fetch_cert(&cert_name.to_string()).await?;

    Ok(JoinedIdentity {
        key_name,
        cert_name,
        cert_wire,
    })
}

// ───────────────────────────────────────────────────────────────────────────
// Native transport — signed NDNCERT Interests over a minimal wire port.

/// A minimal duplex port: send one (signed) Interest wire, await the reply Data
/// wire. Kept bytes-only so this crate needn't depend on `ndn-app` — the native
/// app's adapter wraps an `ndn-app` `Connection` over the Phase-2 IPC seam (a
/// `send` + `recv` to the tunnel forwarder, which routes to the CA), mirroring
/// how the `ManagementClient` impls live outside the core.
#[async_trait]
pub trait WireExchange: Send + Sync {
    async fn express(&self, interest_wire: Bytes) -> Result<Bytes, JoinError>;
}

/// A [`CaExchange`] that builds **signed** NDNCERT NEW / CHALLENGE Interests and
/// a cert-fetch Interest, exchanging each over a [`WireExchange`]. This is the
/// native enroll transport — pair it with a `WireExchange` over the IPC seam.
pub struct SignedInterestCaExchange {
    wire: Arc<dyn WireExchange>,
    ca_prefix: Name,
    signer: Arc<dyn Signer>,
}

impl SignedInterestCaExchange {
    pub fn new(wire: Arc<dyn WireExchange>, ca_prefix: Name, signer: Arc<dyn Signer>) -> Self {
        Self {
            wire,
            ca_prefix,
            signer,
        }
    }

    /// Build a signed command Interest (NEW / CHALLENGE) carrying `body` as
    /// ApplicationParameters, signed by the enrolling key.
    async fn signed_interest(&self, name: Name, body: &[u8]) -> Result<Bytes, JoinError> {
        let key_locator = self
            .signer
            .cert_name()
            .cloned()
            .or_else(|| Some(self.signer.key_name().clone()));
        let signer = Arc::clone(&self.signer);
        InterestBuilder::new(name)
            .must_be_fresh()
            .app_parameters(body.to_vec())
            .sign_fallible(self.signer.sig_type(), key_locator.as_ref(), |region| {
                let signer = Arc::clone(&signer);
                let region = Bytes::copy_from_slice(region);
                async move { signer.sign(&region).await }
            })
            .await
            .map_err(|e: ndn_security::TrustError| {
                JoinError::Protocol(format!("sign interest: {e}"))
            })
    }
}

#[async_trait]
impl CaExchange for SignedInterestCaExchange {
    async fn new_request(&self, body: &[u8]) -> Result<Bytes, JoinError> {
        let name = self.ca_prefix.clone().append(b"CA").append(b"NEW");
        let interest = self.signed_interest(name, body).await?;
        data_content(&self.wire.express(interest).await?)
    }

    async fn challenge_request(
        &self,
        _request_id: &str,
        request_id_bytes: &[u8; 8],
        body: &[u8],
    ) -> Result<Bytes, JoinError> {
        let name = self
            .ca_prefix
            .clone()
            .append(b"CA")
            .append(b"CHALLENGE")
            .append_component(NameComponent::generic(Bytes::copy_from_slice(request_id_bytes)));
        let interest = self.signed_interest(name, body).await?;
        data_content(&self.wire.express(interest).await?)
    }

    async fn fetch_cert(&self, cert_name: &str) -> Result<Bytes, JoinError> {
        let name: Name = cert_name
            .parse()
            .map_err(|e| JoinError::Cert(format!("cert name {cert_name}: {e:?}")))?;
        let interest = InterestBuilder::new(name).must_be_fresh().build();
        // The certificate *is* a Data packet — return its wire unchanged.
        self.wire.express(interest).await
    }
}

/// Extract the `Content` from a reply Data wire.
fn data_content(data_wire: &[u8]) -> Result<Bytes, JoinError> {
    let data = Data::decode(Bytes::copy_from_slice(data_wire))
        .map_err(|e| JoinError::Protocol(format!("decode reply Data: {e:?}")))?;
    Ok(data.content().cloned().unwrap_or_default())
}

/// A software identity restored from a SafeBag: the Ed25519 seed (to rebuild
/// the signer) and the issued certificate.
#[derive(Debug, Clone)]
pub struct RestoredIdentity {
    pub seed: [u8; 32],
    pub cert_wire: Bytes,
}

/// Persist a **software** identity as an encrypted `SafeBag` (PKCS#8 of the
/// Ed25519 seed + the issued cert) at `path`. Enclave keys never use this —
/// see the module docs.
pub fn save_software_safebag(
    path: &Path,
    seed: &[u8; 32],
    cert_wire: &Bytes,
    passphrase: &[u8],
) -> Result<(), JoinError> {
    let pkcs8 = ed25519_seed_to_pkcs8(seed).map_err(|e| JoinError::SafeBag(e.to_string()))?;
    let bag = SafeBag::encrypt(cert_wire.clone(), &pkcs8, passphrase)
        .map_err(|e| JoinError::SafeBag(e.to_string()))?;
    std::fs::write(path, bag.encode()).map_err(|e| JoinError::Io(e.to_string()))?;
    Ok(())
}

/// Reload a software identity persisted by [`save_software_safebag`].
pub fn load_software_safebag(path: &Path, passphrase: &[u8]) -> Result<RestoredIdentity, JoinError> {
    let wire = std::fs::read(path).map_err(|e| JoinError::Io(e.to_string()))?;
    let bag = SafeBag::decode(&wire).map_err(|e| JoinError::SafeBag(e.to_string()))?;
    let seed = bag
        .decrypt_ed25519_seed(passphrase)
        .map_err(|e| JoinError::SafeBag(e.to_string()))?;
    Ok(RestoredIdentity {
        seed,
        cert_wire: bag.certificate.clone(),
    })
}

/// An enclave identity persisted **without** a private key: the issued cert
/// plus the platform key-handle naming the enclave key to sign with later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveIdentity {
    /// Opaque platform reference to the enclave key (e.g. the Android Keystore
    /// alias or the Secure-Enclave key tag) — rebound to an
    /// [`EnclaveBackend`](ndn_security::custodian::EnclaveBackend) on load.
    pub key_handle: String,
    pub cert_wire: Bytes,
}

/// Persist an **enclave** identity at `path`. Unlike the software tier there is
/// no SafeBag: the private key never leaves secure hardware, so only the issued
/// cert and a reference to the enclave key handle are stored. On load the
/// handle is rebound to the platform `EnclaveBackend` (Phase 4 wires the real
/// Keystore/Enclave). Framing: `u32-BE handle_len ‖ handle ‖ cert_wire`.
pub fn save_enclave_identity(
    path: &Path,
    key_handle: &str,
    cert_wire: &Bytes,
) -> Result<(), JoinError> {
    let mut buf = Vec::with_capacity(4 + key_handle.len() + cert_wire.len());
    buf.extend_from_slice(&(key_handle.len() as u32).to_be_bytes());
    buf.extend_from_slice(key_handle.as_bytes());
    buf.extend_from_slice(cert_wire);
    std::fs::write(path, buf).map_err(|e| JoinError::Io(e.to_string()))
}

/// Reload an enclave identity persisted by [`save_enclave_identity`].
pub fn load_enclave_identity(path: &Path) -> Result<EnclaveIdentity, JoinError> {
    let buf = std::fs::read(path).map_err(|e| JoinError::Io(e.to_string()))?;
    if buf.len() < 4 {
        return Err(JoinError::Cert("enclave identity file truncated".into()));
    }
    let hl = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + hl {
        return Err(JoinError::Cert("enclave identity handle truncated".into()));
    }
    let key_handle = String::from_utf8(buf[4..4 + hl].to_vec())
        .map_err(|_| JoinError::Cert("enclave key handle is not UTF-8".into()))?;
    Ok(EnclaveIdentity {
        key_handle,
        cert_wire: Bytes::copy_from_slice(&buf[4 + hl..]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_cert::ca::{CaConfig, CaState};
    use ndn_cert::challenge::ChallengeHandler;
    use ndn_cert::policy::HierarchicalPolicy;
    use ndn_cert::{TokenChallenge, TokenStore};
    use ndn_security::{Ed25519Signer, SecurityManager};
    use std::time::Duration;

    /// In-process `CaExchange` over a real `CaState` — body-level, so it needs
    /// no Interest framing or forwarder. The native impl (signed Interests over
    /// the IPC seam) lands with Phase 4.
    struct InProcessCa {
        state: Arc<CaState>,
    }

    #[async_trait]
    impl CaExchange for InProcessCa {
        async fn new_request(&self, body: &[u8]) -> Result<Bytes, JoinError> {
            self.state
                .handle_new(body)
                .await
                .map(Bytes::from)
                .map_err(|e| JoinError::Protocol(e.to_string()))
        }
        async fn challenge_request(
            &self,
            request_id: &str,
            _request_id_bytes: &[u8; 8],
            body: &[u8],
        ) -> Result<Bytes, JoinError> {
            self.state
                .handle_challenge(request_id, body)
                .await
                .map(Bytes::from)
                .map_err(|e| JoinError::Protocol(e.to_string()))
        }
        async fn fetch_cert(&self, cert_name: &str) -> Result<Bytes, JoinError> {
            self.state
                .get_served_cert(cert_name)
                .map(Bytes::from)
                .ok_or_else(|| JoinError::Cert(format!("no served cert {cert_name}")))
        }
    }

    fn make_token_ca(token: &str) -> Arc<CaState> {
        let mgr = Arc::new(SecurityManager::new());
        let ca_key: Name = "/home/bob/CA/KEY/k1/self/v=1".parse().unwrap();
        mgr.generate_ed25519(ca_key.clone()).unwrap();
        let ca_pub = mgr.get_signer_sync(&ca_key).unwrap().public_key().unwrap();
        let ca_cert = mgr
            .issue_self_signed(&ca_key, ca_pub, 365 * 24 * 3600 * 1_000)
            .unwrap();
        mgr.add_trust_anchor(ca_cert);

        let store = TokenStore::new();
        store.add(token);
        let challenges: Vec<Box<dyn ChallengeHandler>> = vec![Box::new(TokenChallenge::new(store))];
        let config = CaConfig::new(
            "/home/bob/CA".parse().unwrap(),
            "native-join test CA".into(),
            Duration::from_secs(86_400),
            Duration::from_secs(7 * 86_400),
            challenges,
            Box::new(HierarchicalPolicy),
        );
        Arc::new(CaState::new(config, mgr))
    }

    #[tokio::test]
    async fn token_join_enrolls_persists_and_reloads() {
        let ca = InProcessCa {
            state: make_token_ca("welcome-1"),
        };

        // Software identity (a fresh Ed25519 seed).
        let seed = [0x2bu8; 32];
        let key_name: Name = "/home/bob/phone/KEY/k1".parse().unwrap();
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone()));

        // Enroll through the token challenge.
        let joined = enroll_via_token(&ca, key_name.clone(), signer, "welcome-1", 86_400)
            .await
            .expect("token enrollment succeeds");
        assert!(
            joined.cert_name.to_string().starts_with("/home/bob/phone"),
            "issued cert is under the requested identity: {}",
            joined.cert_name
        );
        assert!(!joined.cert_wire.is_empty());

        // Persist as a SafeBag and reload.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ndn-native-join-{}.safebag", std::process::id()));
        let pw = b"correct horse battery staple";
        save_software_safebag(&path, &seed, &joined.cert_wire, pw).expect("persist safebag");

        let restored = load_software_safebag(&path, pw).expect("reload safebag");
        assert_eq!(restored.seed, seed, "the seed round-trips through the SafeBag");
        assert_eq!(
            restored.cert_wire, joined.cert_wire,
            "the issued cert round-trips through the SafeBag"
        );

        // The reloaded seed rebuilds the same signing key.
        let restored_signer = Ed25519Signer::from_seed(&restored.seed, key_name.clone());
        assert_eq!(restored_signer.key_name(), &key_name);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wrong_token_is_denied() {
        let ca = InProcessCa {
            state: make_token_ca("the-real-token"),
        };
        let key_name: Name = "/home/bob/phone/KEY/k1".parse().unwrap();
        let signer = Arc::new(Ed25519Signer::from_seed(&[9u8; 32], key_name.clone()));

        let err = enroll_via_token(&ca, key_name, signer, "guessed-wrong", 86_400)
            .await
            .expect_err("a wrong token must not yield a certificate");
        assert!(matches!(err, JoinError::Protocol(_)));
    }

    /// A [`WireExchange`] standing in for the CA reached over the IPC seam: it
    /// decodes the signed Interest the native `SignedInterestCaExchange` builds,
    /// routes NEW / CHALLENGE / cert-fetch to a real `CaState`, and wraps each
    /// reply as a Data wire — exactly what a forwarder + CA would do over the
    /// seam, minus the socket (the socket itself is witnessed by ndn-mgmt's
    /// ipc_seam test).
    struct CaWire {
        ca: InProcessCa,
    }

    #[async_trait]
    impl WireExchange for CaWire {
        async fn express(&self, interest_wire: Bytes) -> Result<Bytes, JoinError> {
            use ndn_packet::Interest;
            use ndn_packet::encode::DataBuilder;

            let interest = Interest::decode(interest_wire)
                .map_err(|e| JoinError::Protocol(format!("CA decode interest: {e:?}")))?;
            let comps = interest.name.components();
            let verb_pos = |v: &[u8]| comps.iter().position(|c| c.value.as_ref() == v);

            if verb_pos(b"NEW").is_some() {
                let body = interest
                    .app_parameters()
                    .ok_or_else(|| JoinError::Protocol("NEW interest has no params".into()))?;
                let resp = self.ca.new_request(body).await?;
                Ok(DataBuilder::new(interest.name.as_ref().clone(), resp.as_ref()).sign_digest_sha256())
            } else if let Some(i) = verb_pos(b"CHALLENGE") {
                // The request-id component follows CHALLENGE (the trailing
                // ParametersSha256Digest the signed-interest encoder appends is
                // after it). `request_id` (the CA's key) is hex of those bytes.
                let rid = comps
                    .get(i + 1)
                    .ok_or_else(|| JoinError::Protocol("CHALLENGE missing request-id".into()))?
                    .value
                    .clone();
                let rid_bytes: [u8; 8] = rid
                    .as_ref()
                    .try_into()
                    .map_err(|_| JoinError::Protocol("request-id not 8 bytes".into()))?;
                let request_id: String = rid_bytes.iter().map(|b| format!("{b:02x}")).collect();
                let body = interest.app_parameters().ok_or_else(|| {
                    JoinError::Protocol("CHALLENGE interest has no params".into())
                })?;
                let resp = self
                    .ca
                    .challenge_request(&request_id, &rid_bytes, body)
                    .await?;
                Ok(DataBuilder::new(interest.name.as_ref().clone(), resp.as_ref()).sign_digest_sha256())
            } else {
                // Cert fetch — the served cert is already a Data wire.
                self.ca.fetch_cert(&interest.name.to_string()).await
            }
        }
    }

    /// Phase-4 fold-in (seam 1): the native enroll transport — signed NEW /
    /// CHALLENGE Interests over a `WireExchange` — drives a full token
    /// enrollment against a real CA and yields a usable certificate.
    #[tokio::test]
    async fn signed_interest_exchange_enrolls_over_the_wire() {
        let ca_prefix: Name = "/home/bob/CA".parse().unwrap();
        let wire = Arc::new(CaWire {
            ca: InProcessCa {
                state: make_token_ca("over-the-wire"),
            },
        });

        let key_name: Name = "/home/bob/phone/KEY/k2".parse().unwrap();
        let signer = Arc::new(Ed25519Signer::from_seed(&[0x77u8; 32], key_name.clone()));
        let exchange =
            SignedInterestCaExchange::new(wire, ca_prefix, Arc::clone(&signer) as Arc<dyn Signer>);

        let joined = enroll_via_token(&exchange, key_name, signer, "over-the-wire", 86_400)
            .await
            .expect("token enrollment over the signed-interest wire transport");
        assert!(joined.cert_name.to_string().starts_with("/home/bob/phone"));
        assert!(!joined.cert_wire.is_empty());
        // The issued cert decodes as a Data packet.
        assert!(ndn_packet::Data::decode(joined.cert_wire.clone()).is_ok());
    }

    /// Enclave persistence tier: cert + key-handle round-trips (no SafeBag — an
    /// enclave key's private half never leaves secure hardware).
    #[test]
    fn enclave_identity_round_trips() {
        let cert = Bytes::from_static(b"\x06\x20issued-cert-data-wire-stand-in...");
        let path = std::env::temp_dir().join(format!("ndn-enclave-id-{}.bin", std::process::id()));

        save_enclave_identity(&path, "android-keystore://ndn-op-key", &cert).expect("save");
        let loaded = load_enclave_identity(&path).expect("load");

        assert_eq!(loaded.key_handle, "android-keystore://ndn-op-key");
        assert_eq!(loaded.cert_wire, cert);
        let _ = std::fs::remove_file(&path);
    }
}
