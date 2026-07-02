//! The NAN service-ID hash.
//!
//! A NAN service name is hashed to a 6-byte **service ID** that keys
//! publish/subscribe matching on the air (the full name is never sent). The
//! algorithm is fixed by the Wi-Fi Aware spec and used identically by Android
//! `WifiAwareManager` and opennan, so getting it byte-exact is what lets our
//! userspace stack interoperate with a stock phone:
//!
//! 1. lower-case the service name (ASCII),
//! 2. take the standard **SHA-256** of the lowercased UTF-8 bytes,
//! 3. the service ID is the **first 6 bytes** of the digest.

use sha2::{Digest, Sha256};

use crate::ServiceId;

/// Compute the 6-byte NAN service ID for `name`.
///
/// The name is lowercased (ASCII) before hashing, matching Android and opennan.
/// `service_id("MyService") == service_id("myservice")`.
pub fn service_id(name: &str) -> ServiceId {
    let mut hasher = Sha256::new();
    // Lowercase ASCII byte-by-byte without allocating. NAN service names are
    // ASCII DNS-style labels; non-ASCII bytes pass through unchanged (matching a
    // simple ASCII-lowercase, which is what the reference stacks do).
    for &b in name.as_bytes() {
        hasher.update([b.to_ascii_lowercase()]);
    }
    let digest = hasher.finalize();
    let mut id = [0u8; 6];
    id.copy_from_slice(&digest[..6]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lowercasing happens before hashing, so case doesn't change the ID.
    #[test]
    fn case_insensitive() {
        assert_eq!(service_id("MyService"), service_id("myservice"));
        assert_eq!(service_id("NDN-AirDrop"), service_id("ndn-airdrop"));
    }

    /// Golden vector: the service ID is the first 6 bytes of SHA-256 of the
    /// lowercased name. Cross-checked against an independent
    /// `printf 'org.ndn.test' | shasum -a 256`
    /// = `8b2dbbaf56ced19145129d4a5b3afe07c98ecb61a42a0d5560f8dca20416dbb3`.
    #[test]
    fn golden_org_ndn_test() {
        assert_eq!(
            service_id("org.ndn.test"),
            [0x8b, 0x2d, 0xbb, 0xaf, 0x56, 0xce]
        );
    }

    /// Distinct names give distinct IDs (collision would be a hash break).
    #[test]
    fn distinct_names_distinct_ids() {
        assert_ne!(service_id("a"), service_id("b"));
    }
}
