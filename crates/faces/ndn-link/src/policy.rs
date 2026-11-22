//! The numbers every implementation of the link rules uses, and the dial
//! backoff built on them.

use std::time::Duration;

use ndn_cert::approval::MAX_STATUS_HOLD;
use ndn_face_quic::RateLimit;

/// How long each side has for its hello, and again for its verdict.
pub const MESSAGE_DEADLINE: Duration = Duration::from_secs(10);
/// A link already registered for a device is the other half of a
/// simultaneous dial for this long, and no longer: the link dialled by the
/// device with the smaller fingerprint stays (§6.3). An older link that the
/// same device dials past is one it lost (it moved: §17D.3), and the newer
/// link replaces it. A handshake takes at most [`MESSAGE_DEADLINE`] for each of
/// its two messages, so two dials that began together are registered within it.
pub const DIAL_RACE_WINDOW: Duration = MESSAGE_DEADLINE;
/// How often the address watcher reads the interface addresses when the
/// host does not say (§17D.3); on Linux a netlink subscription tells at once
/// and the poll is the backstop.
pub const ADDRESS_POLL: Duration = Duration::from_secs(5);
/// The shortest poll interval the address watcher takes.
pub const ADDRESS_POLL_MIN: Duration = Duration::from_secs(1);
/// A change of the device's addresses is acted on this long after the
/// first notice of it: changes that follow within it are one change.
pub const ADDRESS_COALESCE: Duration = Duration::from_millis(500);
/// Changes of the device's addresses the watcher acts on in a minute at
/// most; the rest merge into the next.
pub const ADDRESS_BURSTS_PER_MINUTE: usize = 6;
/// How long an address of the device must stay gone before the watcher acts
/// on its removal ([`AddressWatch::removal_persists`](crate::AddressWatch)):
/// an address that comes back within it (a VPN flapping, a lifetime renewed,
/// a router advertisement's short-lived prefix) changes nothing.
pub const ADDRESS_REMOVAL_PERSISTS: Duration = Duration::from_secs(3);
/// The lowest port a device rebinds its link socket to at `remember`: a
/// kept port below it (a privileged one, or none) is never a bind target.
pub const LISTEN_PORT_MIN: u16 = 1024;
/// Cost of a route to a peer reached through its relay; a direct link to it
/// costs 0, so it wins when it is up.
pub const VIA_RELAY_COST: u32 = 10;
/// Cost of a route the joiner's link gets toward a namespace of another
/// writer of a folder it joined ([`Links::set_joined_routes`](crate::Links::set_joined_routes)):
/// above every route the link layer makes for a real path (a relay's, a
/// direct path's), so among routes **for the same prefix** a path to the
/// namespace's own devices wins and this route is the way through the inviter
/// only when there is no other. Cost decides only among routes of one prefix:
/// a forwarder takes the longest matching prefix first. What keeps this route
/// from taking a name away from a better route is the device's filter on the
/// names it lists (a name that names itself, and none above or below a
/// namespace it holds), not this cost.
pub const JOINED_ROUTE_COST: u32 = VIA_RELAY_COST + 1000;
/// Distinct namespaces in all that [`Links::set_joined_routes`](crate::Links::set_joined_routes)
/// takes (each is routed with its sync group); a namespace in two folders
/// counts once. The rest are dropped, with a warning.
pub const JOINED_ROUTES_MAX: usize = 64;
/// Folders (entries of the set) that `set_joined_routes` takes; the rest are
/// dropped, with a warning.
pub const JOINED_FOLDERS_MAX: usize = 16;
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

/// What a **grant link's** member may send over its link, in frames: per
/// link, 65,536 at once, then 32,768 a second. A granted member is
/// authenticated by its key, named by a signed grant and revocable (the link
/// closes at the grant's end), so an ordinary transfer must never meet this
/// and the bytes ([`GRANT_BYTES`]) are the bound. What a transfer costs the
/// owner to receive: 1 MiB asked by a member is 256 piece Interests of about
/// 100 bytes, 32 in flight; 1 MiB pushed by a writer is about 1,300 frames
/// (a piece of 4096 bytes fragments to 4 or 5 datagrams of 1,100 bytes or
/// more) and 1.2 MiB. The burst covers 50 such transfers back to back; a
/// second's refill is the frames of 32 MiB at the datagram size, plus the
/// small ones. Small frames are what this bound is for: 32,768 Interests a
/// second is already more than a forwarder answers from a store.
pub const GRANT_FRAMES: RateLimit = RateLimit {
    burst: 65_536,
    per_sec: 32_768,
};
/// What a grant link's member may send over its link, in bytes: 64 MiB at
/// once, then 32 MiB a second (256 Mbit/s), counted on the frames received.
/// This is the bound on a granted member that misbehaves: it can make this
/// device receive no more than that from its key, and a namespace's members
/// no more than [`GRANTS_BYTES`] together; what is over it is dropped (an
/// Interest with a Congestion Nack), and the grant is revocable. It bounds
/// what the member sends; what this device answers it is bounded by
/// [`GRANT_INTERESTS`] (what the member may ask) and [`GRANT_ANSWERED`] (what
/// this device sends back).
pub const GRANT_BYTES: RateLimit = RateLimit {
    burst: 64 << 20,
    per_sec: 32 << 20,
};
/// What a grant link's member may **ask** of this device, in Interests (any
/// name the link carries), per link, beside [`GRANT_FRAMES`] (which counts every
/// frame, a pushed Data fragment too, and was sized for those): 16,384 at once,
/// then 4,096 a second, an Interest over it Nacked Congestion as any Interest
/// dropped for rate is. One member's 1 MiB pull is 256 piece Interests, 32 in
/// flight, and the burst covers 64 of them at once; the refill is 16 such pulls
/// a second, which at the data layer's 4 KiB pieces is 16 MiB a second asked
/// of this device (the 32,768 a second of the frame bucket was 128 MiB a second
/// of 4 KiB Data, 40 to 90 times the amplification of a bound set at the
/// frames of the pieces). What the Interests ask for is bounded again by
/// [`GRANT_ANSWERED`].
pub const GRANT_INTERESTS: RateLimit = RateLimit {
    burst: 16_384,
    per_sec: 4_096,
};
/// What this device may **answer** a grant link's member, in bytes (Data, Nacks
/// and their fragments sent over the link): 64 MiB at once, then 16 MiB a
/// second (128 Mbit/s). One honest 1 MiB pull is 1.2 MiB on the wire, so the
/// burst is some 50 of them back to back and the refill is what
/// [`GRANT_INTERESTS`] asks of 4 KiB pieces; ordinary sync (a few records and
/// their pieces) is a few KiB. A member that asks for more than this device
/// is willing to send it has the answers dropped (silently: a Data has no one to
/// be Nacked to), and asks again when its timer says, so what one key can make
/// this device send is bounded however many Interests it sends, and a
/// namespace's members together by [`GRANTS_BYTES`] on what they send.
pub const GRANT_ANSWERED: RateLimit = RateLimit {
    burst: 64 << 20,
    per_sec: 16 << 20,
};
/// What a grant link's member may send of the data layer's asks (names whose
/// first keyword is `32=grant`, `32=hold` or `32=audit`, followed by the ask:
/// the grants of a folder's epoch keys, the custody leases and their audits),
/// all three together, per link, beside the link's other rates: 256 at once,
/// then 16 a second; over it dropped silently. What one honest member asks: a grant ask per
/// collection and epoch it reads (retried on a backoff of seconds), a hold ask
/// per record it has held (one at a time per asker, the data layer's
/// `HOLDS_PER_ASKER`), and an audit of 16 pieces per holder per round, 32 in flight; and
/// the member's own device never has more than 256 asks in flight (its fetch
/// slots), so the burst covers all it can have outstanding, and a first
/// sync of a few hundred collections or audits of several holders at once are
/// within it. What it must stay under is how fast this device's data layer
/// can drain asks it cannot answer (a fetch back to the asker that
/// times out): about 128 a second, so 16 a second leaves it room for 8
/// such members and for its own work, where the 32,768 a second of the frame
/// bucket left it none.
pub const DATA_ASKS: RateLimit = RateLimit {
    burst: 256,
    per_sec: 16,
};
/// What the grant links of one namespace may send together, in frames: four
/// members' worth (262,144 at once, then 131,072 a second), as the stranger
/// quotas share one namespace among four keys.
pub const GRANTS_FRAMES: RateLimit = RateLimit {
    burst: 262_144,
    per_sec: 131_072,
};
/// The same, in bytes: 256 MiB at once, then 128 MiB a second.
pub const GRANTS_BYTES: RateLimit = RateLimit {
    burst: 256 << 20,
    per_sec: 128 << 20,
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
        assert_eq!(
            waits,
            [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]
        );
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
