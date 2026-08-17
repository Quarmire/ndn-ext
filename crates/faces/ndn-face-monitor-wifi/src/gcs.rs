//! **GCS-in-frame** — re-exported from its shared home in `ndn-radio-cognition` (both the Wi-Fi and
//! LoRa faces reach it there). Kept as a module here only to carry the **agreement test** against this
//! face's own `tier0` Bloom: the shared keyspace (#44) requires both filter structures to admit the
//! same names under the same key, and the two live in different crates now, so the test that pins them
//! together belongs where both are visible.

pub use ndn_radio_cognition::gcs::*;

#[cfg(test)]
mod tests {
    use super::GcsFilter;
    use crate::tier0::PrefixFilter;

    const KEY: [u8; 16] = *b"ndn/gcs-test-key";

    fn deep(depth: usize) -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..depth {
            v.push(b'/');
            v.extend_from_slice(format!("c{i}").as_bytes());
        }
        v
    }

    /// The GCS and the address Blur must admit the **same** prefixes for a name under a key — so a
    /// deployment picks the structure per bearer with no re-registration; only the encoding differs.
    /// This is what guarantees the two crates' copies of the #44 primitives (SipHash, prefix-walk,
    /// clamp, depth cap) have not drifted.
    #[test]
    fn gcs_and_bloom_agree_on_membership() {
        for name_depth in 1..=8usize {
            let name = deep(name_depth);
            let gcs = GcsFilter::from_name(&KEY, &name);
            let mut bloom = PrefixFilter::new();
            bloom.insert_name(&KEY, &name);
            for d in 1..=name_depth {
                let pfx = deep(d);
                let mask = PrefixFilter::mask_for(&KEY, &pfx);
                assert_eq!(
                    gcs.may_match(&KEY, &pfx),
                    bloom.may_match(&mask),
                    "GCS and Bloom disagree — a true prefix (name depth {name_depth}, prefix {d}) \
                     must be admitted by both; a divergence means the #44 primitives drifted between crates"
                );
            }
        }
    }
}
