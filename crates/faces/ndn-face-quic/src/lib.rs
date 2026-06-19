//! Raw-QUIC forwarder-to-forwarder face.
//!
//! A [`QuicFace`] is one reliable bidirectional QUIC stream carrying
//! length-delimited NDN TLV (the same `StreamFace` + `TlvCodec` machinery the
//! TCP face uses), over a TLS-1.3-authenticated, migration-capable QUIC
//! connection. Unlike WebTransport this has no HTTP/3 layer (leaner, but does
//! not reach browsers) — it is the authenticated native backbone link.
//!
//! The standout property is **connection migration**: a `quinn` connection
//! keys on a connection ID, not the UDP 4-tuple, so the face — and every route
//! through it — survives the peer's address changing (mobile handoff, NAT
//! rebinding). See [`QuicConnector::rebind`].
//!
//! Crypto is rustls on the **ring** provider (the stack ndn-rs already uses);
//! no new crypto backend. TLS authenticates the link only — NDN signatures
//! authenticate Data, exactly as for the WebTransport face.

#![cfg(not(target_arch = "wasm32"))]

use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tracing::trace;

use ndn_transport::{ClientTls, FaceId, FaceKind, StreamFace, TlvCodec, ip_face_uri};

/// One QUIC face: a `StreamFace` over a quinn bidirectional stream.
pub type QuicFace = StreamFace<quinn::RecvStream, quinn::SendStream, TlvCodec>;

/// ALPN identifier negotiated on the QUIC handshake (both ends must match).
const ALPN_NDN: &[u8] = b"ndn";

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("tls: {0}")]
    Tls(String),
    #[error("connect: {0}")]
    Connect(String),
    #[error("accept: {0}")]
    Accept(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Server-side TLS for a [`QuicListener`].
pub enum QuicServerTls {
    /// Ephemeral self-signed cert; dialers pin its SHA-256
    /// ([`QuicListener::leaf_cert_sha256`]) via [`ClientTls::CertHashes`].
    SelfSigned { hostnames: Vec<String> },
    /// Externally provisioned PEM material (e.g. from ACME) — lets WebPKI
    /// dialers ([`ClientTls::WebPki`]) validate the chain normally.
    Pem {
        cert_chain_pem: Vec<u8>,
        private_key_pem: Vec<u8>,
    },
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// SHA-256 of a DER certificate.
fn cert_sha256(der: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(der));
    out
}

#[derive(Debug)]
struct PinVerifier {
    hashes: Vec<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got = cert_sha256(end_entity.as_ref());
        if self.hashes.contains(&got) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server cert hash not pinned".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// QUIC listener; one accepted connection's first bidi stream → one [`QuicFace`].
pub struct QuicListener {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    leaf_cert_sha256: Option<[u8; 32]>,
}

impl QuicListener {
    pub async fn bind(addr: SocketAddr, tls: QuicServerTls) -> Result<Self, QuicError> {
        let (certs, key, leaf_hash) = match tls {
            QuicServerTls::SelfSigned { hostnames } => {
                let ck = rcgen::generate_simple_self_signed(hostnames)
                    .map_err(|e| QuicError::Tls(format!("self-signed: {e}")))?;
                let cert_der = ck.cert.der().clone();
                let leaf = cert_sha256(cert_der.as_ref());
                let key_der =
                    rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
                (vec![cert_der], key_der, Some(leaf))
            }
            QuicServerTls::Pem {
                cert_chain_pem,
                private_key_pem,
            } => {
                let certs = rustls_pemfile::certs(&mut cert_chain_pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| QuicError::Tls(format!("cert chain: {e}")))?;
                let leaf = certs.first().map(|c| cert_sha256(c.as_ref()));
                let key = rustls_pemfile::private_key(&mut private_key_pem.as_slice())
                    .map_err(|e| QuicError::Tls(format!("private key: {e}")))?
                    .ok_or_else(|| QuicError::Tls("private key: none in PEM".into()))?;
                (certs, key, leaf)
            }
        };

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        server_crypto.alpn_protocols = vec![ALPN_NDN.to_vec()];

        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(qsc));

        let endpoint = quinn::Endpoint::server(server_config, addr)?;
        let local_addr = endpoint.local_addr()?;
        Ok(Self {
            endpoint,
            local_addr,
            leaf_cert_sha256: leaf_hash,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// SHA-256 of the listener's leaf cert, for dialers to pin via
    /// [`ClientTls::CertHashes`].
    pub fn leaf_cert_sha256(&self) -> Option<[u8; 32]> {
        self.leaf_cert_sha256
    }

    /// Accept one inbound connection and its first bidirectional stream,
    /// yielding a face. The stream surfaces once the dialer sends its first
    /// packet, so the face is established on first inbound traffic.
    pub async fn accept(&self, id: FaceId) -> Result<QuicFace, QuicError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| QuicError::Accept("endpoint closed".into()))?;
        let connection = incoming
            .await
            .map_err(|e| QuicError::Accept(format!("handshake: {e}")))?;
        let remote = connection.remote_address();
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| QuicError::Accept(format!("accept_bi: {e}")))?;
        trace!(target: "face.quic", face=%id, peer=%remote, "quic: accepted connection");
        // The Connection is kept alive by its driver while the streams live.
        Ok(StreamFace::new(
            id,
            FaceKind::Quic,
            Some(ip_face_uri("quic", remote)),
            Some(ip_face_uri("quic", self.local_addr)),
            recv,
            send,
            TlvCodec,
        ))
    }
}

/// QUIC dialer. Owns the client endpoint so the same endpoint can dial many
/// peers and, crucially, [`rebind`](Self::rebind) its socket to exercise
/// connection migration.
pub struct QuicConnector {
    endpoint: quinn::Endpoint,
}

impl QuicConnector {
    pub fn new(tls: ClientTls) -> Result<Self, QuicError> {
        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        let mut client_crypto = match tls {
            ClientTls::CertHashes(hashes) => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinVerifier {
                    hashes,
                    provider: provider(),
                }))
                .with_no_client_auth(),
            ClientTls::WebPki => {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder.with_root_certificates(roots).with_no_client_auth()
            }
        };
        client_crypto.alpn_protocols = vec![ALPN_NDN.to_vec()];

        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        let client_config = quinn::ClientConfig::new(Arc::new(qcc));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Dial `addr` (TLS server name `server_name`, e.g. `"localhost"`), open a
    /// bidirectional stream, and wrap it as a face.
    pub async fn connect(
        &self,
        id: FaceId,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicFace, QuicError> {
        let connection = self
            .endpoint
            .connect(addr, server_name)
            .map_err(|e| QuicError::Connect(e.to_string()))?
            .await
            .map_err(|e| QuicError::Connect(format!("handshake: {e}")))?;
        let local = self.endpoint.local_addr()?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| QuicError::Connect(format!("open_bi: {e}")))?;
        trace!(target: "face.quic", face=%id, peer=%addr, "quic: dialed connection");
        Ok(StreamFace::new(
            id,
            FaceKind::Quic,
            Some(ip_face_uri("quic", addr)),
            Some(ip_face_uri("quic", local)),
            recv,
            send,
            TlvCodec,
        ))
    }

    /// Dial a `host:port` authority (resolves DNS; the host is used as the TLS
    /// server name — ignored by the pinning verifier but required by QUIC).
    pub async fn connect_authority(
        &self,
        id: FaceId,
        authority: &str,
    ) -> Result<QuicFace, QuicError> {
        // Host for the TLS server name: strip `[..]` on IPv6, drop the port.
        let server_name = if let Some(rest) = authority.strip_prefix('[') {
            rest.split(']').next().unwrap_or(rest).to_owned()
        } else {
            authority
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(authority)
                .to_owned()
        };
        let addr = tokio::net::lookup_host(authority)
            .await?
            .next()
            .ok_or_else(|| QuicError::Connect(format!("could not resolve {authority}")))?;
        self.connect(id, addr, &server_name).await
    }

    /// Rebind the client endpoint to a new UDP socket — the connection-migration
    /// trigger. Existing connections (and their faces) migrate to the new local
    /// address transparently.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> std::io::Result<()> {
        self.endpoint.rebind(socket)
    }
}
