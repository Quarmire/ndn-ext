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

/// How far the SignatureTime of a punch request may be from this device's
/// clock: the NDN signed-Interest grace period. Beyond it the request is
/// refused as replayed, or as signed by a device whose clock is off.
pub const PUNCH_GRACE: Duration = Duration::from_secs(120);
/// How long a punch request waits for its answer (its InterestLifetime).
pub const PUNCH_ANSWER_TIMEOUT: Duration = Duration::from_secs(4);
/// Punch requests whose signature a device checks: a bucket over all
/// requesters, before it knows who asks.
pub const PUNCH_CHECKS: RateLimit = RateLimit {
    burst: 16,
    per_sec: 4,
};
/// Punch requests a device answers from one key: `PUNCH_BURST` at once,
/// then one per `PUNCH_REFILL`.
pub const PUNCH_BURST: u32 = 3;
pub const PUNCH_REFILL: Duration = Duration::from_secs(20);
/// Punches a device runs at once (its own and the ones it answers).
pub const PUNCHES_MAX: usize = 16;
/// Candidates a punch message carries at most; a peer's beyond this are
/// ignored.
pub const CANDIDATES_MAX: usize = 8;
/// A punch probes each candidate of the other device every
/// `PROBE_INTERVAL` for `PROBE_WINDOW`.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(200);
pub const PROBE_WINDOW: Duration = Duration::from_secs(4);
/// The dialling device starts its dial to each next candidate this long
/// after the previous one (the first wins).
pub const DIAL_STAGGER: Duration = Duration::from_millis(250);
/// How long a punch may take, from its answer to the direct path's
/// admission, before it counts as failed.
pub const PUNCH_WINDOW: Duration = Duration::from_secs(10);
/// When to punch again: after a direct path ended, after a punch that may
/// pass failed (doubling to the max), and after a refusal.
pub const DIRECT_RETRY_FIRST: Duration = Duration::from_secs(5);
pub const DIRECT_RETRY_MAX: Duration = Duration::from_secs(300);
pub const DIRECT_RETRY_REFUSED: Duration = Duration::from_secs(600);

/// When to dial (or punch) again: `first` after a link that was up dropped,
/// doubling up to `max` while attempts fail in ways that may pass, and
/// `refused` after the other device refused. [`Backoff::default`] is the
/// dial backoff ([`BACKOFF_FIRST`], [`BACKOFF_MAX`], [`BACKOFF_REFUSED`]);
/// [`Backoff::direct`] the punch backoff.
#[derive(Clone, Debug)]
pub struct Backoff {
    next: Duration,
    first: Duration,
    max: Duration,
    refused: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next: BACKOFF_FIRST,
            first: BACKOFF_FIRST,
            max: BACKOFF_MAX,
            refused: BACKOFF_REFUSED,
        }
    }
}

impl Backoff {
    /// The backoff of direct-path punches ([`DIRECT_RETRY_FIRST`],
    /// [`DIRECT_RETRY_MAX`], [`DIRECT_RETRY_REFUSED`]).
    pub fn direct() -> Self {
        Self {
            next: DIRECT_RETRY_FIRST,
            first: DIRECT_RETRY_FIRST,
            max: DIRECT_RETRY_MAX,
            refused: DIRECT_RETRY_REFUSED,
        }
    }

    /// A link came up: the next failure starts over at the first wait.
    pub fn reset(&mut self) {
        self.next = self.first;
    }

    /// The wait after an attempt failed: the refusal wait when the other
    /// device `refused` (the doubling is left as it was), else the current
    /// backoff, which doubles for the next failure.
    pub fn after_failure(&mut self, refused: bool) -> Duration {
        if refused {
            return self.refused;
        }
        let wait = self.next;
        self.next = (self.next * 2).min(self.max);
        wait
    }

    /// The wait after a link that was up dropped.
    pub fn after_drop(&self) -> Duration {
        self.first
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

    #[test]
    fn punches_back_off_from_five_seconds_to_five_minutes() {
        let mut b = Backoff::direct();
        let waits: Vec<_> = (0..8).map(|_| b.after_failure(false).as_secs()).collect();
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 300, 300]);
        assert_eq!(b.after_failure(true), DIRECT_RETRY_REFUSED);
        b.reset();
        assert_eq!(b.after_failure(false), DIRECT_RETRY_FIRST);
        assert_eq!(b.after_drop(), DIRECT_RETRY_FIRST);
    }
}
