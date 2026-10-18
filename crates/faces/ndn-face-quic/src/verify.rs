//! TLS 1.3 with RFC 7250 raw public keys on both sides.
//!
//! The handshake proves one thing: the peer holds the private half of the
//! key it presents. Whether that key may link is decided after the
//! handshake, from signed data (the certificates the peer sends as its first
//! link message) or from the expected fingerprint the dialer configured — the
//! only check made here, so a dial to the wrong device fails before any link
//! message is exchanged.

use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, PeerMisbehaved, SignatureScheme};

use crate::key::{KeyFingerprint, LinkKeySource, PeerKey};

const SCHEMES: [SignatureScheme; 2] = [
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

fn check_raw_key(end_entity: &CertificateDer<'_>) -> Result<PeerKey, Error> {
    PeerKey::from_spki(end_entity.as_ref()).map_err(|e| Error::General(e.to_string()))
}

fn verify_signature(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(cert.as_ref()),
        dss,
        &provider.signature_verification_algorithms,
    )
}

/// What a dial saw of the peer's key, for the refusal it reports.
#[derive(Debug, Default)]
pub(crate) struct Presented(Mutex<Option<PeerKey>>);

impl Presented {
    pub(crate) fn get(&self) -> Option<PeerKey> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

/// The dialer's check of the listener: a raw public key of a device key
/// type, equal to the expected fingerprint when one is configured.
#[derive(Debug)]
pub(crate) struct ListenerKeyVerifier {
    pub(crate) expected: Option<KeyFingerprint>,
    pub(crate) presented: Arc<Presented>,
    pub(crate) provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for ListenerKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let key = check_raw_key(end_entity)?;
        let fingerprint = key.fingerprint();
        *self.presented.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(key);
        match self.expected {
            Some(expected) if expected != fingerprint => Err(Error::General(format!(
                "the device presents key {fingerprint}, not the expected fingerprint {expected}"
            ))),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signature(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The listener's check of a dialer: it must present a raw public key of a
/// device key type and sign the handshake with it. Who it is, and whether it
/// may link, is decided after the handshake.
#[derive(Debug)]
pub(crate) struct DialerKeyVerifier {
    pub(crate) provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for DialerKeyVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        check_raw_key(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signature(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Presents this device's current key, on either side of a handshake.
pub(crate) struct KeyResolver(pub(crate) Arc<dyn LinkKeySource>);

impl std::fmt::Debug for KeyResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyResolver")
    }
}

impl KeyResolver {
    fn resolve_key(&self) -> Option<Arc<CertifiedKey>> {
        match self.0.current() {
            Ok(key) => Some(key.certified()),
            Err(e) => {
                tracing::warn!(target: "face.quic", error = %e, "no link key to present");
                None
            }
        }
    }
}

impl rustls::server::ResolvesServerCert for KeyResolver {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_key()
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

impl rustls::client::ResolvesClientCert for KeyResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.resolve_key()
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }

    fn has_certs(&self) -> bool {
        true
    }
}
