//! Pipe identity, parameters, and established-pipe state — per the thesis.

use std::time::Duration;

use bytes::Bytes;
use ndn_coding::FecPolicy;
use ndn_packet::Name;

use crate::Confidentiality;

/// A pipe identifier. **Producer-generated** and returned in the SEEK response
/// encrypted with the consumer's public key (only the consumer can decrypt it,
/// so only the consumer can JOIN). In v2 the decrypted id *also* serves as the
/// reflexive name, so the SEEK forward pass installs the reverse route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeId(pub Bytes);

impl PipeId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PipeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Per-pipe policy: how the bulk is coded, the consumer's Promised Use Interval,
/// and the content-connectivity bar a forwarder must clear to carry the SEEK.
#[derive(Clone, Debug)]
pub struct PipeParams {
    /// FEC over the bulk transfer (K-of-N). `None` = uncoded. *(v2 graft — the
    /// thesis had no FEC; the no-ARQ bearer needs it.)*
    pub fec: Option<FecPolicy>,
    /// **Promised Use Interval** — the consumer↔nodes contract to keep the pipe
    /// active; drives the teardown inactivity threshold (per node hop order).
    pub pui: Duration,
    /// CCS bar (`0.0..=1.0`) a node must exceed to forward this pipe's SEEK
    /// (CCLF gating). `0.0` = forward everywhere. *(v2 graft.)*
    pub ccs_threshold: f32,
    /// Bulk read-control (encrypt-then-code). `None` = cleartext. *(v2 graft.)*
    pub confidentiality: Confidentiality,
}

impl Default for PipeParams {
    fn default() -> Self {
        Self {
            fec: FecPolicy::systematic(8, 12),
            pui: Duration::from_secs(10),
            ccs_threshold: 0.0,
            confidentiality: Confidentiality::None,
        }
    }
}

impl PipeParams {
    pub fn uncoded() -> Self {
        Self {
            fec: None,
            ..Self::default()
        }
    }
    pub fn with_fec(mut self, k: u16, n: u16) -> Self {
        self.fec = FecPolicy::systematic(k, n);
        self
    }
    pub fn with_pui(mut self, pui: Duration) -> Self {
        self.pui = pui;
        self
    }
    pub fn with_ccs_threshold(mut self, t: f32) -> Self {
        self.ccs_threshold = t.clamp(0.0, 1.0);
        self
    }
    /// Encrypt the bulk under a pre-shared 32-byte content key (Tier-0 / NAC
    /// baseline, ChaCha20-Poly1305) — encrypt-then-code.
    pub fn with_aead_key(mut self, key: [u8; 32]) -> Self {
        self.confidentiality = Confidentiality::Aead(key);
        self
    }
}

/// An established pipe (after SEEK→JOIN→…→CHECK). `pipe_len` is the hop count
/// (used in the CHECK name); `pui` and the shared pipe key gate teardown.
#[derive(Clone, Debug)]
pub struct Pipe {
    /// The producer namespace this pipe transfers under.
    pub namespace: Name,
    /// The (decrypted) pipe id — also the reflexive name of the reverse route.
    pub id: PipeId,
    /// Number of hops consumer→producer, learned via GHL (names the CHECK).
    pub pipe_len: u32,
    /// The pipe key (a secret sealed to the consumer in the SEEK reply, never
    /// placed in a name). Authenticates TEARDOWN: an on-path relay that saw the
    /// JOIN knows `id` but not this, so it cannot forge a teardown.
    pub teardown_secret: Bytes,
    pub params: PipeParams,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_params_builders() {
        let p = PipeParams::default().with_fec(16, 20).with_pui(Duration::from_secs(30));
        assert_eq!(p.fec.map(|f| (f.k, f.n)), Some((16, 20)));
        assert_eq!(p.pui, Duration::from_secs(30));
        assert!(PipeParams::uncoded().fec.is_none());
    }
}
