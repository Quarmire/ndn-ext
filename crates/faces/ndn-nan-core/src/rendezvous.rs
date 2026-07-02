//! Rendezvous — the medium-access / wake schedule, factored out of the engine.
//!
//! *When* a node transmits and listens is not foundational to a broadcast radio;
//! it is a **mode selected by the power budget.** A NAN node duty-cycles into
//! 16-TU Discovery Windows because it cannot afford to listen continuously; a
//! mains-powered relay or an SDR can listen always. So the schedule is a
//! strategy the engine consults on the cluster-synced clock — the
//! [`DiscoveryWindow`] is one implementation among (always-on, TSCH-by-name,
//! ALOHA), not the foundation. The engine's foundation is `poll(now, heard) ->
//! {tx, wake_at}`; rendezvous is policy plugged into it.

use crate::Usec;

/// A wake / transmit schedule over the **cluster-synced clock** (microseconds
/// since the cluster's time origin — what the engine's software TSF reads). The
/// engine emits one burst per window and re-arms its timer at the next window
/// start. All arithmetic is modular: the TSF wraps at 2^64.
pub trait Rendezvous: Send {
    /// Whether `synced` falls inside a transmit / listen window right now.
    fn in_window(&self, synced: Usec) -> bool;
    /// A monotone index for the window containing `synced`, so the engine emits
    /// exactly one burst per window.
    fn window_index(&self, synced: Usec) -> u64;
    /// The synced-clock time of the next window start after `synced`.
    fn next_window_start(&self, synced: Usec) -> Usec;
}

/// The NAN Discovery Window schedule: the first [`DW_LENGTH_TU`](crate::DW_LENGTH_TU)
/// (16) TU of every [`DW_INTERVAL_TU`](crate::DW_INTERVAL_TU) (512) TU period.
/// The duty-cycled default — what a battery-constrained node uses, and the
/// schedule a stock Wi-Fi Aware peer keeps, so our transmits land in its RX
/// window.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscoveryWindow;

impl Rendezvous for DiscoveryWindow {
    fn in_window(&self, synced: Usec) -> bool {
        let tu = synced / crate::USEC_PER_TU;
        (tu % crate::DW_INTERVAL_TU) < crate::DW_LENGTH_TU
    }
    fn window_index(&self, synced: Usec) -> u64 {
        (synced / crate::USEC_PER_TU) / crate::DW_INTERVAL_TU
    }
    fn next_window_start(&self, synced: Usec) -> Usec {
        let tu = synced / crate::USEC_PER_TU;
        let next_dw_tu = (tu / crate::DW_INTERVAL_TU)
            .wrapping_add(1)
            .wrapping_mul(crate::DW_INTERVAL_TU);
        next_dw_tu.wrapping_mul(crate::USEC_PER_TU)
    }
}

/// An always-listening schedule for a node that can afford continuous RX (mains
/// power, an SDR relay): the window is *always* open and the engine bursts every
/// `burst_interval_usec`, never sleeping. This is the "remove the power
/// constraint and rendezvous collapses to listen-always-speak-on-a-timer"
/// mode — the second, dissimilar implementation that keeps the trait honest.
#[derive(Clone, Copy, Debug)]
pub struct AlwaysOn {
    /// How often to emit a burst. It is always in-window, so this is purely the
    /// transmit cadence, not a wake schedule.
    pub burst_interval_usec: Usec,
}

impl AlwaysOn {
    /// Burst at the NAN sync-beacon cadence (once per DW period) but never sleep.
    pub fn nan_cadence() -> Self {
        Self {
            burst_interval_usec: crate::DW_INTERVAL_TU * crate::USEC_PER_TU,
        }
    }
}

impl Rendezvous for AlwaysOn {
    fn in_window(&self, _synced: Usec) -> bool {
        true
    }
    fn window_index(&self, synced: Usec) -> u64 {
        synced / self.burst_interval_usec.max(1)
    }
    fn next_window_start(&self, synced: Usec) -> Usec {
        let iv = self.burst_interval_usec.max(1);
        (synced / iv).wrapping_add(1).wrapping_mul(iv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TU: Usec = crate::USEC_PER_TU;

    #[test]
    fn discovery_window_is_first_16_of_every_512_tu() {
        let dw = DiscoveryWindow;
        assert!(dw.in_window(0));
        assert!(dw.in_window(15 * TU));
        assert!(!dw.in_window(16 * TU));
        assert!(!dw.in_window(511 * TU));
        assert!(dw.in_window(512 * TU)); // next period's window
        assert_eq!(dw.window_index(0), 0);
        assert_eq!(dw.window_index(512 * TU), 1);
        assert_eq!(dw.next_window_start(0), 512 * TU);
        assert_eq!(dw.next_window_start(10 * TU), 512 * TU);
    }

    #[test]
    fn always_on_never_sleeps_but_paces_bursts() {
        let ao = AlwaysOn { burst_interval_usec: 1000 };
        assert!(ao.in_window(0));
        assert!(ao.in_window(999_999)); // the window is always open
        assert_eq!(ao.window_index(0), 0);
        assert_eq!(ao.window_index(1000), 1);
        assert_eq!(ao.next_window_start(500), 1000);
    }
}
