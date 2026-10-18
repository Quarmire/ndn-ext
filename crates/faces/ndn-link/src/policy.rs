//! The numbers every implementation of the link rules uses, and the dial
//! backoff built on them.

use std::time::Duration;

use ndn_cert::approval::MAX_STATUS_HOLD;
use ndn_face_quic::RateLimit;

/// How long each side has for its hello, and again for its verdict.
pub const MESSAGE_DEADLINE: Duration = Duration::from_secs(10);
/// Cost of a route to a peer reached through its relay; a direct link to it
/// costs 0, so it wins when it is up.
pub const VIA_RELAY_COST: u32 = 10;
/// Redial backoff after a drop or a failure that may pass…
pub const BACKOFF_FIRST: Duration = Duration::from_millis(500);
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// …and after a refusal of the key, which only a change of the trust data
/// or the config lifts.
pub const BACKOFF_REFUSED: Duration = Duration::from_secs(60);
/// Longest certificate chain a link hello is validated through.
pub const MAX_CHAIN: usize = 8;
/// Enrollment links a relay holds at once…
pub const ENROLLMENT_LINKS_MAX: usize = 32;
/// …and from one address (several devices may enroll behind one NAT).
pub const ENROLLMENT_LINKS_PER_SOURCE: usize = 4;
/// An enrollment link that carries nothing this long is closed. Twice the
/// longest a CA holds a STATUS request, so a device waiting for an admin's
/// approval keeps its link.
pub const ENROLLMENT_IDLE: Duration = Duration::from_secs(2 * MAX_STATUS_HOLD.as_secs());
/// What a relay takes from a device on an enrollment link: Interests,
/// which an enrollment sends a handful of.
pub const ENROLLMENT_INTERESTS: RateLimit = RateLimit {
    burst: 32,
    per_sec: 4,
};
/// What a device takes from the relay on its enrollment link: answers, one
/// frame per fragment (a trust context or a certificate chain spans
/// several).
pub const ENROLLMENT_ANSWERS: RateLimit = RateLimit {
    burst: 512,
    per_sec: 128,
};

/// When to dial a peer again: [`BACKOFF_FIRST`] after a link that was up
/// dropped, doubling up to [`BACKOFF_MAX`] while dials fail in ways that may
/// pass, and [`BACKOFF_REFUSED`] after the peer refused this device's key.
#[derive(Clone, Debug)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { next: BACKOFF_FIRST }
    }
}

impl Backoff {
    /// A link came up: the next failure starts over at [`BACKOFF_FIRST`].
    pub fn reset(&mut self) {
        self.next = BACKOFF_FIRST;
    }

    /// The wait after a dial failed: [`BACKOFF_REFUSED`] when the peer
    /// `refused` the key (the doubling is left as it was), else the current
    /// backoff, which doubles for the next failure.
    pub fn after_failure(&mut self, refused: bool) -> Duration {
        if refused {
            return BACKOFF_REFUSED;
        }
        let wait = self.next;
        self.next = (self.next * 2).min(BACKOFF_MAX);
        wait
    }

    /// The wait after a link that was up dropped.
    pub fn after_drop(&self) -> Duration {
        BACKOFF_FIRST
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_its_cap_and_refusals_wait_apart() {
        let mut b = Backoff::default();
        let waits: Vec<_> = (0..9).map(|_| b.after_failure(false).as_millis()).collect();
        assert_eq!(waits, [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
        assert_eq!(b.after_failure(true), BACKOFF_REFUSED);
        assert_eq!(b.after_failure(false), BACKOFF_MAX);
        b.reset();
        assert_eq!(b.after_failure(false), BACKOFF_FIRST);
        assert_eq!(b.after_drop(), BACKOFF_FIRST);
    }
}
