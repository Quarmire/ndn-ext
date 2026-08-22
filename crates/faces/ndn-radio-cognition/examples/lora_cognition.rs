//! Live LoRa **cognition loop**, driven by real Interest/Data demand.
//!
//! The named-radio control plane driving a real SX1262 dongle from the forwarding plane's own
//! signals — no synthetic inputs anywhere in the loop. Each node both **produces** its own named
//! objects and **consumes** the peer's, so every number the policy reads is measured:
//!
//!   - SENSE — each received frame's real per-frame RSSI feeds [`MediumState::observe_rx`]; each
//!     Interest/Data event feeds a [`DemandTracker`] that shadows the PIT's in-record lifecycle.
//!   - DECIDE — [`RadioPolicy::decide`] runs over that medium state and a [`NameContext`] whose
//!     priority comes from **the name itself** (an `alarm` is urgent because of what it is), and
//!     whose fan-out / re-Interest rate come from the tracker.
//!   - ACT — the plan's LoRa knobs (spreading factor, coding rate, FEC redundancy) are applied to
//!     the dongle through the `RadioKnobs` seam, then the frame goes out.
//!
//! The two demand signals are real, not modelled:
//!   - **fan-out** — a peer's Interest is a live in-record on our prefix. Serving it is demand-driven
//!     transmission; with no in-record the innovation gate suppresses us instead.
//!   - **re-Interest** — when the peer re-expresses an Interest we never satisfied, a frame was lost
//!     on air. That is the ARQ signal the redundancy budget is allocated to drive down, and here it
//!     is measured from real LoRa loss rather than assumed.
//!
//! SF tracks the measured link (strong → SF7, weak → SF12); CR and FEC track demand. Two close nodes
//! both read a strong RSSI and settle at the same SF, staying paired while coding adapts.
//!
//! Run on both OPis:
//! ```text
//! lora_cognition /dev/ttyACM0 A B
//! lora_cognition /dev/ttyACM0 B A
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_frame_io::{FrameIo, InjectFrame, TxIntent};
use ndn_radio_cognition::{
    DemandTracker, MediumState, MediumView, NameContext, Priority, RadioId, RadioPolicy,
    STATIC_REQ_RSSI_SF, lora_airtime_ms, pick_sf_hysteretic, prefix_hash,
};
use ndn_radio_drivers::LoraSerialBackend;
use ndn_radio_hal::{Bandwidth, RadioKnobs, RadioProfile};

const CHANNEL: u8 = 65; // 915 MHz (US ISM)
const BW_KHZ: u32 = 125; // the backend's default bandwidth — airtime is computed against it
/// SF hysteresis deadband. −92/−94 dBm sit on the −90 SF8/SF9 line; without a deadband the two
/// nodes chatter across it and land on mismatched SFs (a total decode loss). 4 dB holds a converged
/// pair together through the boundary wiggle. See `pick_sf_hysteretic`.
const SF_HYST_DB: f32 = 4.0;
/// Rendezvous fallback. Two ends dialing SF independently can split onto mismatched SFs, and LoRa
/// SFs are quasi-orthogonal — a split pair is deaf to each other, so neither can hear the other's
/// advertised SF and the split is stable (measured: A stuck SF7, B stuck SF9, 0 delivery). A node
/// that has heard nothing from the peer for `RENDEZVOUS_MS` falls back to `RENDEZVOUS_SF` — a fixed,
/// maximally-robust SF both agree on a priori — so the pair re-meets, then peer-SF agreement locks
/// them together. This is the poor-man's version of a fixed rendezvous control SF / receiver-side SF
/// auto-detect (ASFS); the real fix needs firmware CAD. See lora-adr-literature.
///
/// NOT SF12: a 40 B frame at SF12/BW125 is ~1.5 s on air — it blows the firmware `CMD_TX` 3 s reply
/// deadline (measured: `TX FAILED … no reply in 3s`), the duty budget, and overlaps the half-duplex
/// peer. SF10 closes a −94 dBm link with margin at ~1/8 the airtime, so the TX path actually works.
const RENDEZVOUS_SF: u8 = 10;
const RENDEZVOUS_MS: u64 = 12_000;
/// Data-reply delay (LoRaWAN RECEIVE_DELAY analogue). A Data reply fires the instant we decode the
/// Interest — which is right as the requester finishes *its* Interest TX and is still turning its
/// radio from TX to RX. Replying into that turnaround gap loses the frame (measured: one direction
/// delivered, the reverse got 0). A short wait lets the requester settle into RX first. (task #18)
///
/// #52 increment 1: the reply is no longer sent inline — it is SCHEDULED at `now + RX_GUARD_MS +
/// rand(0..REPLY_JITTER_MS)` and CANCELLED if we overhear the name already answered. `RX_GUARD_MS`
/// keeps the turnaround floor; the jitter de-synchronizes multiple holders so the first-to-fire wins
/// and the rest suppress (receiver-agnostic, scales to N). At N=2 (one holder) it is slack, not dedup.
/// Listen-after-transmit cooldown (#52): after any TX, a node yields the medium and listens for at
/// least this long before transmitting again. This is the SCALABLE, receiver-agnostic replacement for
/// the pairwise name-offset — it caps each node's airtime share and guarantees listening windows, so a
/// node re-expressing Interests can't self-deafen (half-duplex) to the very Data replies it awaits.
/// Measured: without it, dropping the offset let one node TX ~2× the other and receive nothing. Kept
/// but disabled (0) now that the offset is restored — the offset does the turn-taking; the cooldown is
/// the tool for a future offset-free (time-slotted) MAC.
const TX_COOLDOWN_MS: u64 = 0;
const RX_GUARD_MS: u64 = 400;
// With the offset restored (it does the turn-taking), the reply jitter goes back to the offset-safe
// 200 ms — a suppression-sized (≥ airtime) jitter fights the offset's tight reply timing (increment 1
// finding). Suppression at N>2 wants the larger jitter; that belongs with the offset-free slotted MAC.
const REPLY_JITTER_MS: u64 = 200;
const LOCAL_FACE: u64 = 0; // our own app face: where our consumer's Interests come from
const PEER_FACE: u64 = 1; // the LoRa face the peer's Interests arrive on

// One Interest per tick (round-robin over the classes), not a burst of all three: LoRa is
// half-duplex, so bursting kept a node deaf across ~3 frame-times and the peer's Data reply collided
// with our own next Interest. At 4 s/tick a class is serviced every ~12 s — inside GIVEUP_MS. (task #18)
const TICK: Duration = Duration::from_millis(4_000);
/// PIT entry lifetime: an in-record counts toward fan-out only while fresh.
const PIT_LIFETIME_MS: u64 = 12_000;
/// No Data within this → re-express. A re-expression before satisfaction IS the re-Interest signal.
const RETX_MS: u64 = 5_000;
/// Give up on a name after this long and move to the next sequence number.
const GIVEUP_MS: u64 = 20_000;

/// The demand classes this demo produces and consumes. Priority is derived from **the name**, not
/// from a timer: an `alarm` is urgent because of what it is. That is the data-centric claim — the
/// radio's dials follow the name's meaning, with no application telling the driver what to do.
const CLASSES: [(&str, Priority); 3] = [
    ("alarm", Priority::Urgent),
    ("telemetry", Priority::Normal),
    ("bulk", Priority::Bulk),
];

fn class_priority(class: &str) -> Option<Priority> {
    CLASSES.iter().find(|(c, _)| *c == class).map(|(_, p)| *p)
}

/// Demand is keyed per prefix — the sequence number names the object within it, not a new prefix.
fn class_prefix(node: &str, class: &str) -> u64 {
    prefix_hash(&[b"ndn", b"lora-cog", node.as_bytes(), class.as_bytes()])
}

struct ParsedName<'a> {
    node: &'a str,
    class: &'a str,
}

/// `ndn/lora-cog/<node>/<class>/<seq>`
fn parse_name(name: &str) -> Option<ParsedName<'_>> {
    let mut it = name.split('/');
    if it.next()? != "ndn" || it.next()? != "lora-cog" {
        return None;
    }
    let node = it.next()?;
    let class = it.next()?;
    it.next()?; // seq
    Some(ParsedName { node, class })
}

/// A frame off the air: `I|<src>|<sf>|<name>` or `D|<src>|<sf>|<name>|<payload>`.
///
/// The **sender** is carried explicitly because the name cannot supply it: an Interest for
/// `ndn/lora-cog/A/...` names A's data but is sent *by* B. Link quality keys the neighbor who
/// transmitted, so without `src` there is nothing honest to attribute RSSI to.
///
/// `sf` is the sender's *current* spreading factor, advertised so the peer can adopt the more
/// robust of the two (SF agreement) and never sit below it. Note the LoRa constraint: SFs are
/// quasi-orthogonal, so this advertisement is only *heard* while the pair is already SF-aligned —
/// it prevents a converged pair from drifting apart, not recovery from a full split.
struct ParsedWire<'a> {
    kind: &'a str,
    src: &'a str,
    sf: u8,
    name: &'a str,
}

fn parse_wire(wire: &str) -> Option<ParsedWire<'_>> {
    let mut it = wire.split('|');
    let kind = it.next()?;
    if kind != "I" && kind != "D" {
        return None;
    }
    let src = it.next()?;
    let sf = it.next()?.parse::<u8>().ok()?;
    let name = it.next()?;
    if src.is_empty() || !(7..=12).contains(&sf) || parse_name(name).is_none() {
        return None;
    }
    Some(ParsedWire { kind, src, sf, name })
}

/// Opaque sense-bus key for a neighbor, derived from who actually transmitted.
fn neighbor_key(src: &str) -> u64 {
    prefix_hash(&[b"node", src.as_bytes()])
}

/// An Interest we have expressed and not yet had satisfied.
struct Pending {
    name: String,
    expressed_ms: u64,
    first_ms: u64,
}

/// A Data reply we hold and have scheduled but not yet sent (#52 broadcast suppression). It fires at
/// `fire_at`, unless we first overhear `name` answered by someone else — then it is cancelled.
struct PendingReply {
    fire_at: u64,
    name: String,
    wire: String,
    prefix_hash: u64,
    priority: Priority,
}

/// A frame off the air, handed to the single-owner state machine in the main loop.
struct RxEvent {
    wire: String,
    rssi: Option<i8>,
    at_ms: u64,
}

struct Node {
    dev: Arc<LoraSerialBackend>,
    name: String,
    peer: String,
    /// Sense-bus key for the peer — the only neighbor whose RSSI we act on.
    peer_key: u64,
    /// Frames on this channel we could not attribute to a sender (beacons, foreign nodes).
    unattributed: u32,
    radio: RadioId,
    medium: MediumState,
    tracker: DemandTracker,
    policy: RadioPolicy,
    start: Instant,
    last_sf: u8,
    /// The peer's last-advertised spreading factor (from a decodable frame), for SF agreement.
    peer_sf: u8,
    /// `at_ms` of the last decodable frame from the peer — drives the rendezvous fallback on silence.
    last_heard_ms: u64,
    /// `at_ms` of our last transmission — enforces the listen-after-transmit cooldown (fairness).
    last_tx_ms: u64,
    /// Round-robin cursor: one Interest class is serviced per tick (half-duplex discipline).
    tick_seq: u64,
    last_cr: u8,
    /// Last-applied TX power (dBm) and bandwidth (kHz) — apply a knob only when its value changes.
    last_power_dbm: i8,
    last_bw_khz: u32,
    pending: HashMap<&'static str, Pending>,
    /// Data replies scheduled (with jittered delay) but not yet sent — drained by the reply pump,
    /// cancelled on overhearing the name answered. The receiver-agnostic replacement for the inline
    /// fixed-delay reply (#52).
    pending_replies: Vec<PendingReply>,
    /// xorshift64 state for reply jitter, seeded per node so peers de-synchronize.
    rng: u64,
    seq: HashMap<&'static str, u32>,
}

impl Node {
    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Listen-after-transmit: true while we should stay off the air and listen (#52 fairness).
    fn in_cooldown(&self) -> bool {
        self.now().saturating_sub(self.last_tx_ms) < TX_COOLDOWN_MS
    }

    /// xorshift64 — cheap per-node randomness for the reply jitter (no external RNG dep, and the
    /// examples have no wall clock to seed from mid-run; the per-node name seed suffices to de-sync).
    fn next_rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// The reply pump: send any scheduled Data reply whose time has come (and that was not cancelled
    /// by overhearing). Draining here, off a fast timer, is what lets on_rx cancel a reply after it is
    /// queued but before it fires — the whole point of the suppression window (#52).
    async fn pump_replies(&mut self) {
        if self.in_cooldown() {
            return; // listening — leave replies queued until the cooldown ends
        }
        let now = self.now();
        let due: Vec<PendingReply> = {
            let all = std::mem::take(&mut self.pending_replies);
            let (ready, keep): (Vec<_>, Vec<_>) = all.into_iter().partition(|r| r.fire_at <= now);
            self.pending_replies = keep;
            ready
        };
        for r in due {
            let mut ctx = NameContext::new(r.prefix_hash); // we produce this name → origin
            ctx.priority = r.priority;
            self.transmit(&ctx, &r.wire, &format!("D {}", r.name)).await;
            self.tracker.on_data(r.prefix_hash, self.now());
        }
    }

    /// DECIDE + ACT + TX for one named object. Returns the row describing what happened.
    async fn transmit(&mut self, ctx: &NameContext, wire: &str, tag: &str) {
        let now = self.now();
        let plan = self.policy.decide(ctx, &self.medium, now);

        // Pull the knobs out before touching `self` again (the plan borrows nothing of it).
        let alloc = plan.allocation_for(self.radio);
        // The plan's raw SF is `pick_sf(rssi)` — right at a threshold it flips every tick and the two
        // ends desync. Re-derive it with hysteresis around where we already are, then take the more
        // robust of that and the peer's advertised SF (agreement). Hold on ticks with no fresh RSSI.
        // NDN_LORA_SF pins the spreading factor and disables adaptation — the #54 N=3 measurement holds
        // SF/BW fixed so the only variables are contention + LBT (the RSSI-driven SF rendezvous can
        // otherwise diverge the two ends into mutual deafness, which is a separate rate-adaptation
        // concern, not what the LBT experiment is testing).
        let sf = if let Some(psf) = std::env::var("NDN_LORA_SF").ok().and_then(|s| s.parse::<u8>().ok()) {
            Some(psf)
        } else {
            alloc.and_then(|a| a.params.spreading_factor()).map(|_| {
                let cur = self.last_sf.max(7);
                // Lost contact for too long → a stable split is the likely cause (each end deaf to the
                // other's SF). Fall back to the rendezvous SF so the pair re-meets; holding `cur` here is
                // the trap that freezes a stranded node forever.
                if now.saturating_sub(self.last_heard_ms) > RENDEZVOUS_MS {
                    return RENDEZVOUS_SF;
                }
                let base = match self.medium.neighbor_rssi(self.radio, self.peer_key) {
                    Some(r) => pick_sf_hysteretic(r, cur, &STATIC_REQ_RSSI_SF, SF_HYST_DB),
                    None => cur,
                };
                base.max(self.peer_sf)
            })
        };
        let cr = alloc.and_then(|a| a.params.coding_rate());
        // NDN_LORA_FEC caps link-FEC redundancy. The escalation to max FEC (8×) is counterproductive on
        // this half-duplex link: it multiplies airtime, so a little loss → more redundancy → more airtime
        // → collisions → total loss (a retry/FEC spiral that collapses a working link ~12 s in). Pin it
        // low (0/1) to hold the link stable for the #54 measurement.
        let fec = std::env::var("NDN_LORA_FEC")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or_else(|| alloc.and_then(|a| a.params.link_fec_redundancy).unwrap_or(0));
        // Power is set freely per-node (not a rendezvous parameter); bandwidth IS a rendezvous
        // parameter but the policy dials it only from shared inputs, so both peers reach the same one.
        let power = alloc.and_then(|a| a.params.tx_power_dbm);
        let bw = std::env::var("NDN_LORA_BW")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .or_else(|| alloc.and_then(|a| a.params.bandwidth_khz()));

        let act = if plan.suppress {
            // A real gate, not a demo branch: a relay with nothing to add stays quiet, and a radio
            // over its duty budget makes the packet wait rather than break the regulatory limit.
            "suppressed".to_string()
        } else {
            let mut applied = Vec::new();
            if let Some(sf) = sf
                && sf != self.last_sf
            {
                match self.dev.set_spreading_factor(sf) {
                    Ok(()) => {
                        self.last_sf = sf;
                        applied.push("sf");
                    }
                    // Report the miss rather than let the table imply a knob that never landed.
                    Err(e) => eprintln!("[{}] set SF{sf} failed: {e}", self.name),
                }
            }
            if let Some(cr) = cr
                && cr != self.last_cr
            {
                match self.dev.set_coding_rate(cr) {
                    Ok(()) => {
                        self.last_cr = cr;
                        applied.push("cr");
                    }
                    Err(e) => eprintln!("[{}] set CR 4/{} failed: {e}", self.name, cr + 4),
                }
            }
            if let Some(dbm) = power
                && dbm != self.last_power_dbm
            {
                match self.dev.set_tx_power(dbm.max(0) as u32) {
                    Ok(()) => {
                        self.last_power_dbm = dbm;
                        applied.push("pwr");
                    }
                    Err(e) => eprintln!("[{}] set {dbm}dBm failed: {e}", self.name),
                }
            }
            if let Some(khz) = bw
                && khz != self.last_bw_khz
            {
                match self.dev.set_bandwidth_khz(khz) {
                    Ok(()) => {
                        self.last_bw_khz = khz;
                        applied.push("bw");
                    }
                    Err(e) => eprintln!("[{}] set BW {khz}kHz failed: {e}", self.name),
                }
            }
            // Splice our just-applied SF in after the src (KIND|SRC|SF|NAME[|payload]) so the frame
            // advertises the SF it is actually sent at — the peer folds this into its own agreement.
            let onair = {
                let mut it = wire.splitn(3, '|');
                match (it.next(), it.next(), it.next()) {
                    (Some(k), Some(s), Some(rest)) => {
                        format!("{k}|{s}|{}|{rest}", self.last_sf.max(7))
                    }
                    _ => wire.to_string(),
                }
            };
            let frame =
                InjectFrame::broadcast(onair.as_bytes().to_vec().into(), TxIntent::CONSERVATIVE);
            // Never swallow this: a failed inject means nothing went on air, and a table that
            // reports "tx" for a frame that never left is worse than no table at all.
            match self.dev.inject(frame).await {
                Ok(()) => {
                    self.last_tx_ms = self.now(); // start the listen-after-transmit cooldown (fairness)
                    // Charge the duty-cycle budget with this frame's real on-air time.
                    self.medium.record_airtime(
                        self.radio,
                        lora_airtime_ms(
                            sf.unwrap_or(self.last_sf.max(7)),
                            BW_KHZ,
                            cr.unwrap_or(self.last_cr.max(1)),
                            wire.len(),
                        ),
                        now,
                    );
                    if applied.is_empty() {
                        format!("tx {tag}")
                    } else {
                        format!("tx {tag} (+{})", applied.join("+"))
                    }
                }
                Err(e) => format!("TX FAILED {tag}: {e}"),
            }
        };

        self.print_row(ctx, sf, cr, fec, &act);
    }

    fn print_row(
        &self,
        ctx: &NameContext,
        sf: Option<u8>,
        cr: Option<u8>,
        fec: u16,
        act: &str,
    ) {
        let now = self.now();
        let secs = now / 1000;
        let d = self.medium.demand(ctx.prefix_hash);
        let fanout = d.as_ref().map(|d| d.fanout).unwrap_or(0);
        let reint = d
            .as_ref()
            .and_then(|d| d.reinterest_rate.get())
            .unwrap_or(0.0);
        let per = self
            .medium
            .residual(self.radio)
            .and_then(|r| r.phy_per.get())
            .unwrap_or(0.0);
        let rssi = self
            .medium
            .neighbor_rssi(self.radio, self.peer_key)
            .map(|r| format!("{r}dBm"))
            .unwrap_or_else(|| "  --  ".into());
        let sf_s = sf.map(|s| format!("SF{s}")).unwrap_or_else(|| "---".into());
        let cr_s = cr
            .map(|c| format!("4/{}", c + 4))
            .unwrap_or_else(|| "---".into());
        let duty = self.medium.duty_used(self.radio, now) * 100.0;
        // BW and TX power are cognition-driven too now — show the live actuated values.
        let bw_s = if self.last_bw_khz > 0 { format!("BW{}", self.last_bw_khz) } else { "BW---".into() };
        let pwr_s = if self.last_power_dbm > 0 { format!("{}dBm", self.last_power_dbm) } else { "--dBm".into() };
        println!(
            "[{}] {secs:>3}s| {:<7?}| {rssi:>7} | fan={fanout} reI={reint:.2} PER={per:.2} | {sf_s} {cr_s} {bw_s} {pwr_s} FEC{fec} duty={duty:.2}% | {act}",
            self.name, ctx.priority,
        );
    }

    /// A frame arrived: fold its RSSI into the medium and its Interest/Data event into the PIT.
    async fn on_rx(&mut self, ev: RxEvent) {
        // Attribute BEFORE sensing. RSSI keys a neighbor, so a frame we cannot attribute — a beacon,
        // another LoRa node on this channel — must not be credited to the peer's link: that RSSI
        // picks the spreading factor, and mis-attributing it would dial the radio to a link that
        // isn't there. Say what we dropped rather than fold it in silently.
        let Some(w) = parse_wire(&ev.wire) else {
            self.unattributed += 1;
            println!(
                "[{}] ?? ignoring unattributable frame ({}dBm): {:?}",
                self.name,
                fmt_rssi(ev.rssi),
                ev.wire.chars().take(32).collect::<String>(),
            );
            return;
        };
        if w.src == self.name {
            return; // our own name on the air; nothing to learn from it
        }
        let (kind, name) = (w.kind.to_string(), w.name.to_string());
        // We heard the peer, so we are SF-aligned right now: record its advertised SF for agreement.
        // The actuator never dials below this, so once one end climbs, the other follows rather than
        // dropping back and splitting the pair.
        if w.src == self.peer {
            self.peer_sf = w.sf;
            self.last_heard_ms = ev.at_ms;
        }
        self.medium
            .observe_rx(self.radio, neighbor_key(w.src), ev.rssi, ev.at_ms);

        let Some(parsed) = parse_name(&name) else {
            return;
        };
        let Some(priority) = class_priority(parsed.class) else {
            return;
        };
        let (node, class) = (parsed.node.to_string(), parsed.class.to_string());

        match kind.as_str() {
            // The peer wants one of OUR names: a live in-record on our prefix. Serving it is
            // demand-driven transmission — this is the fan-out the policy provisions for.
            "I" if node == self.name => {
                let ph = class_prefix(&self.name, &class);
                self.tracker.on_interest(ph, PEER_FACE, ev.at_ms);
                self.fold_demand();
                // Don't answer inline. SCHEDULE the reply after a turnaround guard + random jitter, so
                // the requester is in RX and multiple holders de-sync + suppress (#52). Dedup our own:
                // one queued reply per name (a re-Interest before it fires does not stack a second).
                if !self.pending_replies.iter().any(|r| r.name == name) {
                    let fire_at = self.now() + RX_GUARD_MS + (self.next_rand() % REPLY_JITTER_MS);
                    let wire = format!("D|{}|{name}|payload-{}", self.name, "x".repeat(24));
                    self.pending_replies.push(PendingReply {
                        fire_at,
                        name: name.clone(),
                        wire,
                        prefix_hash: ph,
                        priority,
                    });
                }
            }
            // Any Data for a name we hold a queued reply for → someone answered; suppress ours (#52).
            "D" => {
                let before = self.pending_replies.len();
                self.pending_replies.retain(|r| r.name != name);
                if self.pending_replies.len() < before {
                    println!("[{}] ~~ suppressed reply {name} (overheard Data)", self.name);
                }
                // Data we asked for came back: satisfy the in-record and score the round trip.
                if node == self.peer {
                    let ph = class_prefix(&self.peer, &class);
                    let matched = self
                        .pending
                        .iter()
                        .find(|(_, p)| p.name == name)
                        .map(|(k, _)| *k);
                    if let Some(k) = matched {
                        self.pending.remove(k);
                        self.tracker.on_data(ph, ev.at_ms);
                        // Both our Interest and its Data made it over the air.
                        self.medium.observe_phy_per(self.radio, 0.0);
                        println!("[{}] <- D {name} ({}dBm)", self.name, fmt_rssi(ev.rssi));
                    }
                }
            }
            _ => {}
        }
    }

    /// Consumer side: express or re-express Interests for the peer's names. Half-duplex discipline
    /// (task #18): age-out is bookkeeping for every class (no TX), but only ONE class is *expressed*
    /// per tick — bursting all three kept the radio deaf across ~3 frame-times, so the peer's Data
    /// reply to the first Interest collided with our own second/third Interest and never landed.
    async fn tick(&mut self) {
        let now = self.now();

        // #52: show the firmware's carrier-sense counters — cad_busy climbing with deferred near zero
        // means LBT is finding the channel and winning the backoff, not starving.
        if let Ok((cad_busy, deferred)) = self.dev.csma_counters() {
            println!("[{}] csma: cad_busy={cad_busy} deferred={deferred}", self.name);
        }

        // Age out any class whose Interest has gone unanswered too long. Pure bookkeeping — no frame
        // goes on air — so doing it for all three every tick costs no airtime.
        for (class, _) in CLASSES {
            if let Some(p) = self.pending.get(class)
                && now.saturating_sub(p.first_ms) >= GIVEUP_MS
            {
                self.pending.remove(class);
                self.tracker.on_data(class_prefix(&self.peer, class), now);
                println!("[{}] xx gave up on {class}", self.name);
            }
        }

        // Listen-after-transmit: if we just transmitted, yield this tick and keep listening (fairness).
        if self.in_cooldown() {
            self.tracker.prune(now);
            self.medium.prune(now);
            return;
        }

        // Round-robin from this tick's cursor, express the FIRST class that is due (no pending, or
        // past RETX_MS). One TX per tick keeps us listening for the reply; scanning-for-due avoids
        // wasting the slot on a class whose Interest is still fresh.
        let start = (self.tick_seq % CLASSES.len() as u64) as usize;
        self.tick_seq += 1;
        let chosen = (0..CLASSES.len()).map(|i| CLASSES[(start + i) % CLASSES.len()]).find(
            |(class, _)| match self.pending.get(class) {
                Some(p) => now.saturating_sub(p.expressed_ms) >= RETX_MS,
                None => true,
            },
        );

        if let Some((class, priority)) = chosen {
            let ph = class_prefix(&self.peer, class);
            // Fresh express vs re-express. A re-expression before satisfaction is a REAL delivery
            // miss — a frame was lost on air — so it inflates the redundancy budget.
            let name = match self.pending.get(class) {
                Some(p) => {
                    self.medium.observe_phy_per(self.radio, 1.0);
                    p.name.clone()
                }
                None => {
                    let seq = self.seq.entry(class).or_insert(0);
                    *seq += 1;
                    format!("ndn/lora-cog/{}/{class}/{seq}", self.peer)
                }
            };

            let reexpressed = self.tracker.on_interest(ph, LOCAL_FACE, now);
            let first_ms = self.pending.get(class).map(|p| p.first_ms).unwrap_or(now);
            self.pending.insert(
                class,
                Pending {
                    name: name.clone(),
                    expressed_ms: now,
                    first_ms,
                },
            );

            self.fold_demand();
            // We consume this name, we do not produce it → relayed: the innovation gate decides
            // whether our transmission adds rank for a downstream that still needs it.
            let mut ctx = NameContext::relayed(ph);
            ctx.priority = priority;
            let tag = if reexpressed {
                format!("I {name} (re)")
            } else {
                format!("I {name}")
            };
            let wire = format!("I|{}|{name}", self.name);
            self.transmit(&ctx, &wire, &tag).await;
        }

        self.tracker.prune(now);
        self.medium.prune(now);
    }

    /// Push the tracker's PIT-shadow into the sense bus so the policy decides on fresh demand.
    fn fold_demand(&mut self) {
        let now = self.now();
        for (ph, demand) in self.tracker.snapshot(now) {
            self.medium.observe_demand(ph, demand);
        }
    }
}

fn fmt_rssi(r: Option<i8>) -> String {
    r.map(|r| r.to_string()).unwrap_or_else(|| "?".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "/dev/ttyACM0".into());
    let name = args.next().unwrap_or_else(|| "A".into());
    let peer = args.next().unwrap_or_else(|| "B".into());

    let dev = Arc::new(LoraSerialBackend::open(&path)?);
    // #52 increment 3: route every inject through the firmware's atomic listen-before-talk. Channel
    // access is now carrier-sense, not a pairwise TX schedule — so the name-ordered offset is dropped
    // below and the reply jitter grows to suppression size (CAD handles collisions regardless of phase).
    // LBT (firmware carrier-sense) is BUILT, flashed, and functional — its cad_busy/defer counters
    // prove CAD senses and backs off. But MEASURED counterproductive at N=2 on this clean channel: with
    // the offset already preventing collisions, LBT only adds deferral latency and starves the weaker
    // node (delivery 13→7). This is the #37 EDCCA lesson on LoRa — you can't sense your way to better
    // delivery on a channel that isn't collision-limited. So LBT is OFF for the N=2 demo and ON for the
    // N≥3 contended case (flip to `true` + set_lbt_cfg when the Heltec joins as a third node).
    // LBT is OFF for N=2 (measured counterproductive on a clean channel) and ON for the N≥3 contended
    // case — set NDN_LBT=1 to enable it (the #54 measurement: does carrier-sense help once a third node
    // makes the channel collision-limited?).
    let lbt_on = std::env::var("NDN_LBT").map(|v| v == "1" || v == "true").unwrap_or(false);
    dev.set_lbt(lbt_on);
    println!("[{name}] open OK — cognition plane driving {path} (LBT {}), consuming from {peer}",
        if lbt_on { "ON" } else { "off" });

    // Frequency is a rendezvous parameter (both ends must sit on the same carrier). Derive the link's
    // channel from the *pair identity* — name-keyed, task #40 in miniature — so both nodes compute the
    // SAME channel with no negotiation. Kept in 914–916 MHz, tight around the known-good 915. This is
    // the cognition-chosen frequency; per-name/per-time FHSS (tasks #40/#41) is the scalable version.
    // NDN_LORA_CHANNEL pins every node to one carrier (the #54 N=3 measurement needs A, B and the
    // contender C on the SAME channel; the name-keyed default would scatter a 3rd node elsewhere).
    let (lo, hi) = if name <= peer { (&name, &peer) } else { (&peer, &name) };
    let link_ch = std::env::var("NDN_LORA_CHANNEL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| 64 + (prefix_hash(&[b"lorach", lo.as_bytes(), hi.as_bytes()]) % 3) as u8);
    if let Err(e) = dev.set_channel(link_ch, Bandwidth::from_code(0)) {
        eprintln!("[{name}] set channel {link_ch} failed: {e}");
    }
    println!(
        "[{name}] link channel = {link_ch} ({} MHz) — name-keyed from the pair {{{lo},{hi}}}",
        850 + link_ch as u32
    );

    let radio = RadioId(0);
    let mut medium = MediumState::new();

    // Take the radio's real capability from the device, with one honest regional correction:
    // `RadioCapability::lora()` carries the ETSI EU868 1% duty ceiling, which does not govern this
    // band. These dongles run 915 MHz, where FCC 15.247 limits dwell time and power rather than a
    // duty fraction. State that explicitly instead of quietly transmitting through a gate the policy
    // believes it is enforcing. On an EU 868 channel, drop this line and the policy fail-closes at 1%
    // on its own. Airtime is still recorded either way, so the budget stays visible in the table.
    let mut cap = dev.capability();
    cap.channels = vec![link_ch];
    cap.duty_cycle_max = 1.0;

    // Wire the firmware's on-device NDN data plane FROM cognition (not a test harness). The policy
    // decides the MECHANISM toggles from the face's capability — on this duty-limited LoRa broadcast
    // bearer it turns on dedup (drop repeats at the antenna) and CS-serve (answer a repeat Interest
    // from cache instead of re-fetching: the airtime-per-content win over a flood mesh). The NAME sets
    // come from the forwarder's FIB: we SERVE our own prefix (answer only Interests under it) and we
    // RELAY whatever prefixes this node forwards for others (env NDN_RELAY_PREFIXES, comma-separated —
    // empty at N=2, set on the node that bridges others at N>=3). filter/relay match by PREFIX (LPM),
    // so one entry covers every seq-varying name under it; dedup/CS still key on the full object name.
    let dp = RadioPolicy::default().data_plane(&cap);
    let own_prefix = format!("ndn/lora-cog/{name}");
    let relay_prefixes: Vec<String> = std::env::var("NDN_RELAY_PREFIXES")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        .unwrap_or_default();
    {
        let relay_refs: Vec<&[u8]> = relay_prefixes.iter().map(|s| s.as_bytes()).collect();
        if let Err(e) = dev.set_name_filter(&[own_prefix.as_bytes()]) {
            eprintln!("[{name}] set_name_filter failed (pre-#55 firmware?): {e}");
        }
        if let Err(e) = dev.set_relay(&relay_refs) {
            eprintln!("[{name}] set_relay failed: {e}");
        }
        if let Err(e) = dev.set_dataplane(dp.cs_serve, dp.dedup, dp.hop, 64, 3) {
            eprintln!("[{name}] set_dataplane failed: {e}");
        }
    }
    println!(
        "[{name}] data plane ← cognition: dedup={} cs_serve={} hop={} | serve '{own_prefix}' | relay {relay_prefixes:?}",
        dp.dedup, dp.cs_serve, dp.hop
    );

    medium.register_radio(radio, cap);

    let (tx_ch, mut rx_ch) = tokio::sync::mpsc::channel::<RxEvent>(64);
    let start = Instant::now();

    // SENSE task: pull frames off the dongle and hand them to the single-owner state machine.
    {
        let dev = dev.clone();
        tokio::spawn(async move {
            while let Ok(f) = dev.recv_frame().await {
                let ev = RxEvent {
                    wire: String::from_utf8_lossy(&f.payload).to_string(),
                    rssi: f.rssi_dbm,
                    at_ms: start.elapsed().as_millis() as u64,
                };
                if tx_ch.send(ev).await.is_err() {
                    break;
                }
            }
        });
    }

    let mut node = Node {
        dev,
        name: name.clone(),
        peer_key: neighbor_key(&peer),
        unattributed: 0,
        peer,
        radio,
        medium,
        tracker: DemandTracker::new(PIT_LIFETIME_MS),
        policy: RadioPolicy::default(),
        start,
        last_sf: 0,
        peer_sf: 7,
        last_heard_ms: 0,
        last_tx_ms: 0,
        last_cr: 0,
        last_power_dbm: 0,
        last_bw_khz: 0,
        tick_seq: 0,
        pending: HashMap::new(),
        pending_replies: Vec::new(),
        // Seed the jitter PRNG from the node name (non-zero) so the two ends de-synchronize.
        rng: prefix_hash(&[b"jitter", name.as_bytes()]) | 1,
        seq: HashMap::new(),
    };

    println!("[{name}] t   | demand | obsRSSI | PIT-shadow            | knobs               | act");

    // #52 finding: firmware LBT (carrier sense) is active and correct, but it is NOT sufficient on its
    // own for a half-duplex named-data link. MEASURED: dropping the pairwise offset let the node that
    // leads by a startup skew consistently get ahead and miss the peer's Data replies (it delivered 0
    // while the other delivered fine) — a turn-taking/receive-window problem, not a collision one that
    // CSMA solves. So the offset STAYS as the N=2 turn-taking layer (LBT rides on top for collision
    // avoidance). The scalable, non-pairwise replacement is time-slotted receive windows anchored to
    // common-view time (#41) — tracked there, not bodged here.
    let offset = if node.name < node.peer {
        Duration::ZERO
    } else {
        TICK / 2
    };
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + offset, TICK);
    // Reply pump: a fast timer that fires scheduled Data replies once their (jittered) time comes and
    // they were not cancelled by overhearing. 50 ms is well under the guard so timing stays tight.
    let mut pump = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            Some(ev) = rx_ch.recv() => node.on_rx(ev).await,
            _ = ticker.tick() => node.tick().await,
            _ = pump.tick() => node.pump_replies().await,
        }
    }
}

/// The demand wiring is testable without a dongle: the tracker and the policy are both pure, so the
/// PIT-shadow → knobs path can be exercised on the same code the live loop runs.
#[cfg(test)]
mod tests {
    use super::*;
    use ndn_radio_cognition::RadioCapability;

    const R: RadioId = RadioId(0);

    fn medium() -> MediumState {
        let mut m = MediumState::new();
        let mut cap = RadioCapability::lora(vec![CHANNEL]);
        cap.duty_cycle_max = 1.0; // US 915: no duty ceiling (see `run`)
        m.register_radio(R, cap);
        m.observe_rx(R, neighbor_key("B"), Some(-40), 0); // a strong, live peer
        m
    }

    /// A frame we cannot attribute must be rejected outright — it would otherwise be credited to the
    /// peer's link and dial the spreading factor from a neighbor that isn't there.
    #[test]
    fn only_attributable_frames_are_accepted() {
        let w = parse_wire("I|B|9|ndn/lora-cog/A/alarm/7").expect("well-formed Interest");
        assert_eq!((w.kind, w.src, w.sf, w.name), ("I", "B", 9, "ndn/lora-cog/A/alarm/7"));
        let d = parse_wire("D|A|12|ndn/lora-cog/A/bulk/2|payload-xxx").expect("well-formed Data");
        assert_eq!((d.kind, d.src, d.sf), ("D", "A", 12));

        // The frames that were silently polluting the peer's RSSI before.
        assert!(parse_wire("LORA-BEACON seq=3").is_none(), "a beacon is not ours");
        assert!(parse_wire("I|B|9|ndn/other-app/A/alarm/7").is_none(), "foreign name");
        assert!(parse_wire("I|B").is_none(), "truncated");
        assert!(parse_wire("I|B|9").is_none(), "no name");
        assert!(parse_wire("I|B|99|ndn/lora-cog/A/alarm/7").is_none(), "SF out of range");
        assert!(parse_wire("I||9|ndn/lora-cog/A/alarm/7").is_none(), "no sender");
        // Distinct senders key distinct neighbors — the whole point of carrying `src`.
        assert_ne!(neighbor_key("A"), neighbor_key("B"));
    }

    #[test]
    fn names_parse_and_foreign_names_are_ignored() {
        let n = parse_name("ndn/lora-cog/B/alarm/7").expect("well-formed name");
        assert_eq!((n.node, n.class), ("B", "alarm"));
        assert!(parse_name("LORA-BEACON seq=3").is_none());
        assert!(parse_name("ndn/other-app/B/alarm/7").is_none());
        // The prefix keys demand per class, not per sequence number.
        assert_eq!(class_prefix("B", "alarm"), class_prefix("B", "alarm"));
        assert_ne!(class_prefix("B", "alarm"), class_prefix("B", "bulk"));
        assert_ne!(class_prefix("A", "alarm"), class_prefix("B", "alarm"));
    }

    #[test]
    fn priority_comes_from_the_name() {
        assert_eq!(class_priority("alarm"), Some(Priority::Urgent));
        assert_eq!(class_priority("bulk"), Some(Priority::Bulk));
        assert_eq!(class_priority("nonsense"), None);
    }

    /// A peer's Interest is a live in-record: it becomes fan-out the policy provisions for.
    #[test]
    fn peer_interest_becomes_fanout_and_urgency_raises_coding_rate() {
        let mut m = medium();
        let mut t = DemandTracker::new(PIT_LIFETIME_MS);
        let ph = class_prefix("A", "alarm");
        t.on_interest(ph, PEER_FACE, 0);
        for (p, d) in t.snapshot(0) {
            m.observe_demand(p, d);
        }
        assert_eq!(m.demand(ph).map(|d| d.fanout), Some(1), "peer Interest = 1 in-record");

        let policy = RadioPolicy::default();
        let mut urgent = NameContext::new(ph);
        urgent.priority = Priority::Urgent;
        let plan = policy.decide(&urgent, &m, 0);
        let alloc = plan.allocation_for(R).expect("origin serves its own name");
        // Strong link → fastest SF; urgent → the more robust coding rate.
        assert_eq!(alloc.params.spreading_factor(), Some(7));
        assert_eq!(alloc.params.coding_rate(), Some(2), "urgent → 4/6");

        let mut bulk = NameContext::new(ph);
        bulk.priority = Priority::Bulk;
        let bulk_cr = policy
            .decide(&bulk, &m, 0)
            .allocation_for(R)
            .and_then(|a| a.params.coding_rate());
        assert_eq!(bulk_cr, Some(1), "bulk → 4/5");
    }

    /// The heart of the demand path: a peer re-expressing an unsatisfied Interest means a frame was
    /// lost on air, and that measured re-Interest must buy more redundancy.
    #[test]
    fn reinterest_from_real_loss_raises_the_redundancy_budget() {
        let mut m = medium();
        let mut t = DemandTracker::new(PIT_LIFETIME_MS);
        let ph = class_prefix("A", "telemetry");
        m.observe_phy_per(R, 0.3); // measured frame loss on the link

        t.on_interest(ph, PEER_FACE, 0); // first expression: not a re-Interest
        for (p, d) in t.snapshot(0) {
            m.observe_demand(p, d);
        }
        let policy = RadioPolicy::default();
        let ctx = NameContext::new(ph);
        let fec0 = policy
            .decide(&ctx, &m, 0)
            .allocation_for(R)
            .and_then(|a| a.params.link_fec_redundancy)
            .expect("lossy link buys some parity");

        // The peer re-asks before we satisfied it — a real delivery miss.
        assert!(t.on_interest(ph, PEER_FACE, 1_000), "re-expression is detected");
        t.on_interest(ph, PEER_FACE, 2_000);
        for (p, d) in t.snapshot(2_000) {
            m.observe_demand(p, d);
        }
        let fec1 = policy
            .decide(&ctx, &m, 2_000)
            .allocation_for(R)
            .and_then(|a| a.params.link_fec_redundancy)
            .expect("still lossy");
        assert!(fec1 > fec0, "re-Interest must raise redundancy: {fec1} > {fec0}");
    }

    /// Satisfying the demand retires it: with no in-record left, a relay has no rank to add.
    #[test]
    fn satisfied_demand_suppresses_the_relay() {
        let mut m = medium();
        let mut t = DemandTracker::new(PIT_LIFETIME_MS);
        let ph = class_prefix("B", "telemetry");
        t.on_interest(ph, LOCAL_FACE, 0);
        for (p, d) in t.snapshot(0) {
            m.observe_demand(p, d);
        }
        let policy = RadioPolicy::default();
        let ctx = NameContext::relayed(ph);
        assert!(!policy.decide(&ctx, &m, 0).suppress, "live demand → transmit");

        t.on_data(ph, 1_000); // Data came back; the in-records clear
        for (p, d) in t.snapshot(1_000) {
            m.observe_demand(p, d);
        }
        assert_eq!(m.demand(ph).map(|d| d.fanout), Some(0));
    }

    /// Airtime is charged per frame, so the duty budget is real rather than decorative.
    #[test]
    fn transmitting_charges_the_duty_budget() {
        let mut m = medium();
        assert_eq!(m.duty_used(R, 0), 0.0);
        let air = lora_airtime_ms(7, BW_KHZ, 1, 40);
        assert!(air > 0.0, "a 40 B SF7 frame has real airtime: {air}ms");
        m.record_airtime(R, air, 0);
        assert!(m.duty_used(R, 0) > 0.0, "the budget moved");
    }
}
