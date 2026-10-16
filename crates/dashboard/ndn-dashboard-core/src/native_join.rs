//! Native token-join — NDNCERT enrollment for the native app, plus identity
//! persistence. The native analogue of the browser `JoinClient` (dioxus-demo,
//! IndexedDB-backed): run the shared [`ndn_cert::client::enroll`] driver
//! through NEW → token CHALLENGE → issued cert, then persist the result.
//!
//! **Transport seam.** Enrollment is driven over an [`ndn_cert::CaExchange`] —
//! one signed Interest wire out, its reply Data back. The native app's impl
//! rides the Phase-2 IPC seam (a `Connection` to the tunnel's forwarder, which
//! routes to the CA); that impl lands with Phase 4, where it's witnessed
//! against a live forwarder + CA. The enrollment and persistence here are
//! exercised against a real [`ndn_cert::ca::CaState`] +
//! [`ndn_cert::TokenChallenge`] behind an Interest-decoding test exchange.
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

use bytes::Bytes;
use ndn_cert::CaExchange;
use ndn_packet::Name;
use ndn_security::Signer;
use ndn_security::safebag::{SafeBag, ed25519_seed_to_pkcs8};

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

/// A successfully enrolled identity. The issued cert is carried for both
/// persistence tiers; how the *private key* is stored differs (SafeBag for
/// software keys; cert + handle for enclave keys).
#[derive(Debug, Clone)]
pub struct JoinedIdentity {
    pub key_name: Name,
    pub cert_name: Name,
    pub cert_wire: Bytes,
}

/// Enroll through a token challenge against the CA at `ca_prefix`:
/// NEW → CHALLENGE(token) → fetch the issued cert. `signer` signs the
/// enrollment (the caller owns the key — software or enclave).
pub async fn enroll_via_token<E: CaExchange>(
    exchange: &mut E,
    ca_prefix: &Name,
    signer: Arc<dyn Signer>,
    token: &str,
    validity_secs: u64,
) -> Result<JoinedIdentity, JoinError> {
    let key_name = signer.key_name().clone();
    let mut params = serde_json::Map::new();
    params.insert(
        "token".to_string(),
        serde_json::Value::String(token.to_owned()),
    );
    let mut params = Some(params);
    let cert_name = ndn_cert::client::enroll(
        exchange,
        ca_prefix,
        signer,
        validity_secs,
        TOKEN_CHALLENGE,
        |_| std::future::ready(Ok(params.take())),
    )
    .await
    .map_err(|e| JoinError::Protocol(format!("token enrollment: {e}")))?;

    // The certificate *is* a Data packet — keep its wire unchanged.
    let cert_wire = ndn_cert::client::fetch_issued_cert(exchange, &cert_name)
        .await
        .map_err(|e| JoinError::Cert(format!("fetch {cert_name}: {e}")))?
        .raw()
        .clone();

    Ok(JoinedIdentity {
        key_name,
        cert_name,
        cert_wire,
    })
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
pub fn load_software_safebag(
    path: &Path,
    passphrase: &[u8],
) -> Result<RestoredIdentity, JoinError> {
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
    use ndn_cert::CertError;
    use ndn_cert::ca::{CaConfig, CaState};
    use ndn_cert::challenge::ChallengeHandler;
    use ndn_cert::policy::HierarchicalPolicy;
    use ndn_cert::{TokenChallenge, TokenStore};
    use ndn_packet::Data;
    use ndn_security::{Ed25519Signer, SecurityManager};
    use std::time::Duration;

    /// A [`CaExchange`] standing in for the CA reached over the IPC seam: it
    /// decodes the signed Interest the driver builds, routes NEW / CHALLENGE /
    /// cert-fetch to a real `CaState`, and wraps each reply as a Data wire —
    /// exactly what a forwarder + CA would do over the seam, minus the socket
    /// (the socket itself is witnessed by ndn-mgmt's ipc_seam test).
    struct CaWire {
        state: Arc<CaState>,
    }

    impl CaExchange for CaWire {
        async fn express(&mut self, interest_wire: Bytes) -> Result<Data, CertError> {
            use ndn_packet::Interest;
            use ndn_packet::encode::DataBuilder;

            let proto = |m: String| CertError::Transport(m);
            let interest = Interest::decode(interest_wire)
                .map_err(|e| proto(format!("CA decode interest: {e:?}")))?;
            let comps = interest.name.components();
            let verb_pos = |v: &[u8]| comps.iter().position(|c| c.value.as_ref() == v);

            let body = if verb_pos(b"NEW").is_some() {
                let params = interest
                    .app_parameters()
                    .ok_or_else(|| proto("NEW interest has no params".into()))?;
                self.state.handle_new(params).await?
            } else if let Some(i) = verb_pos(b"CHALLENGE") {
                // The request-id component follows CHALLENGE (the trailing
                // ParametersSha256Digest the signed-interest encoder appends is
                // after it). `request_id` (the CA's key) is hex of those bytes.
                let rid = comps
                    .get(i + 1)
                    .ok_or_else(|| proto("CHALLENGE missing request-id".into()))?;
                let request_id: String = rid.value.iter().map(|b| format!("{b:02x}")).collect();
                let params = interest
                    .app_parameters()
                    .ok_or_else(|| proto("CHALLENGE interest has no params".into()))?;
                self.state.handle_challenge(&request_id, params).await?
            } else {
                // Cert fetch — the served cert is already a Data wire.
                let wire = self
                    .state
                    .get_served_cert(&interest.name.to_string())
                    .ok_or_else(|| proto(format!("no served cert {}", interest.name)))?;
                return Data::decode(Bytes::from(wire))
                    .map_err(|e| proto(format!("decode served cert: {e:?}")));
            };
            let reply = DataBuilder::new(interest.name.as_ref().clone(), &body).sign_digest_sha256();
            Data::decode(reply).map_err(|e| proto(format!("decode reply: {e:?}")))
        }
    }

    fn make_token_ca(token: &str) -> CaWire {
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
        CaWire {
            state: Arc::new(CaState::new(config, mgr)),
        }
    }

    fn ca_prefix() -> Name {
        "/home/bob/CA".parse().unwrap()
    }

    #[tokio::test]
    async fn token_join_enrolls_persists_and_reloads() {
        let mut ca = make_token_ca("welcome-1");

        // Software identity (a fresh Ed25519 seed).
        let seed = [0x2bu8; 32];
        let key_name: Name = "/home/bob/phone/KEY/k1".parse().unwrap();
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone()));

        // Enroll through the token challenge.
        let joined = enroll_via_token(&mut ca, &ca_prefix(), signer, "welcome-1", 86_400)
            .await
            .expect("token enrollment succeeds");
        assert!(
            joined.cert_name.to_string().starts_with("/home/bob/phone"),
            "issued cert is under the requested identity: {}",
            joined.cert_name
        );
        // The issued cert decodes as a Data packet.
        assert!(Data::decode(joined.cert_wire.clone()).is_ok());

        // Persist as a SafeBag and reload.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ndn-native-join-{}.safebag", std::process::id()));
        let pw = b"correct horse battery staple";
        save_software_safebag(&path, &seed, &joined.cert_wire, pw).expect("persist safebag");

        let restored = load_software_safebag(&path, pw).expect("reload safebag");
        assert_eq!(
            restored.seed, seed,
            "the seed round-trips through the SafeBag"
        );
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
        let mut ca = make_token_ca("the-real-token");
        let key_name: Name = "/home/bob/phone/KEY/k1".parse().unwrap();
        let signer = Arc::new(Ed25519Signer::from_seed(&[9u8; 32], key_name));

        let err = enroll_via_token(&mut ca, &ca_prefix(), signer, "guessed-wrong", 86_400)
            .await
            .expect_err("a wrong token must not yield a certificate");
        assert!(matches!(err, JoinError::Protocol(_)));
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
