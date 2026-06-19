//! Optional body-encryption hook for service-info Data. Decryption
//! failure is local: log and drop the body; the protocol state machine
//! is unaffected. Default [`NoEncryption`] is pass-through.

use bytes::Bytes;

use crate::prefix_announce::ServiceRecord;

#[derive(Debug)]
pub enum EncryptError {
    Internal(String),
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(s) => write!(f, "encrypt error: {s}"),
        }
    }
}

#[derive(Debug)]
pub enum DecryptError {
    Internal(String),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(s) => write!(f, "decrypt error: {s}"),
        }
    }
}

/// `wrap` runs at body publish, `unwrap` at body fetch. The
/// `rendezvous` record carries the stable inputs for key derivation
/// (announced_prefix, node_name, freshness_ms, capabilities).
pub trait EncryptionHook: Send + Sync {
    fn wrap(&self, plaintext: &[u8], rendezvous: &ServiceRecord) -> Result<Bytes, EncryptError>;
    fn unwrap(&self, ciphertext: &[u8], rendezvous: &ServiceRecord) -> Result<Bytes, DecryptError>;
}

pub struct NoEncryption;

impl EncryptionHook for NoEncryption {
    fn wrap(&self, plaintext: &[u8], _rendezvous: &ServiceRecord) -> Result<Bytes, EncryptError> {
        Ok(Bytes::copy_from_slice(plaintext))
    }

    fn unwrap(
        &self,
        ciphertext: &[u8],
        _rendezvous: &ServiceRecord,
    ) -> Result<Bytes, DecryptError> {
        Ok(Bytes::copy_from_slice(ciphertext))
    }
}

#[cfg(test)]
pub(crate) struct XorMaskHook(pub u8);

#[cfg(test)]
impl EncryptionHook for XorMaskHook {
    fn wrap(&self, plaintext: &[u8], _: &ServiceRecord) -> Result<Bytes, EncryptError> {
        Ok(plaintext
            .iter()
            .map(|b| b ^ self.0)
            .collect::<Vec<_>>()
            .into())
    }
    fn unwrap(&self, ciphertext: &[u8], _: &ServiceRecord) -> Result<Bytes, DecryptError> {
        Ok(ciphertext
            .iter()
            .map(|b| b ^ self.0)
            .collect::<Vec<_>>()
            .into())
    }
}

#[cfg(test)]
pub(crate) struct AlwaysFailDecrypt;

#[cfg(test)]
impl EncryptionHook for AlwaysFailDecrypt {
    fn wrap(&self, plaintext: &[u8], _: &ServiceRecord) -> Result<Bytes, EncryptError> {
        Ok(Bytes::copy_from_slice(plaintext))
    }
    fn unwrap(&self, _: &[u8], _: &ServiceRecord) -> Result<Bytes, DecryptError> {
        Err(DecryptError::Internal("always fails".into()))
    }
}
