//! Reachability while asleep, on a relay: holding the Interests of a device
//! whose link ended, and waking it.
//!
//! A device asks on its link (a `Reachability` message on the control
//! stream): hold my Interests while I am not linked, and/or here is a wake
//! token. When that link ends — the device closed it to sleep, the host went
//! to the background, or the path broke — and the device is linked over no
//! other path, this relay counts it as **asleep** for at most
//! [`RelayService::asleep_max`]: the routes its link had lead to the waiting
//! face, where
//!
//! - its Interests are held, when it asked and this relay holds Interests
//!   ([`RelayService::hold`]): each until its lifetime ends or
//!   [`HoldLimits::max_hold`], whichever is sooner, at most
//!   [`HoldLimits::per_device`] for it and [`HoldLimits::total`] for all;
//!   beyond them an Interest is Nacked (Congestion) at once;
//! - its wake notifier is invoked, when it registered a token and this relay
//!   has one ([`RelayService::wake`]): at most once per [`WAKE_INTERVAL`]
//!   while Interests keep arriving for it, and never while it is linked;
//!
//! and when it links again, its held Interests still within their lifetime
//! are sent to it over the new link. A device that does not come back
//! within `asleep_max` is forgotten (its held Interests are Nacked).
//!
//! What a notifier receives is the device's name, its key and its token —
//! never the names of the Interests that wait. The library defines the
//! interface; the host provides the notifier (an external command, a
//! webhook, a platform push service).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;

use ndn_face_quic::{CloseReason, KeyFingerprint, LinkError, Reachability};
use ndn_packet::Name;
use ndn_packet::nack::NackReason;

use crate::links::Links;
use crate::serving::ServePolicy;
use crate::status::AsleepStatus;
use crate::table::Ended;
use crate::waiting::{Verdict, WaitFor};

/// A device is woken at most once per this long while Interests for it
/// keep arriving.
pub const WAKE_INTERVAL: Duration = Duration::from_secs(30);

/// What this device offers the devices it relays for. Whom it serves is
/// its serving policy; the rest is offered only to devices that ask.
#[derive(Clone)]
pub struct RelayService {
    pub serve: ServePolicy,
    /// `Some`: hold the Interests of devices asleep here that ask, within
    /// these bounds. `None`: hold none (Interests for a sleeping device are
    /// Nacked, after its wake when it registered one).
    pub hold: Option<HoldLimits>,
    /// Invoked for a device asleep here that registered a wake token, when
    /// an Interest arrives for it.
    pub wake: Option<Arc<dyn WakeNotifier>>,
    /// How long a device whose link ended counts as asleep (its Interests
    /// held, its wakes sent) before it is forgotten.
    pub asleep_max: Duration,
}

impl Default for RelayService {
    /// Own namespaces only; no holding, no wakes.
    fn default() -> Self {
        Self {
            serve: ServePolicy::Own,
            hold: None,
            wake: None,
            asleep_max: Duration::from_secs(24 * 3600),
        }
    }
}

/// Bounds on the Interests a relay holds for sleeping devices.
#[derive(Clone, Copy, Debug)]
pub struct HoldLimits {
    /// Interests held for one device at once.
    pub per_device: usize,
    /// Interests held for all devices at once.
    pub total: usize,
    /// The longest an Interest is held (less when its lifetime ends
    /// sooner).
    pub max_hold: Duration,
}

impl Default for HoldLimits {
    fn default() -> Self {
        Self {
            per_device: 64,
            total: 4096,
            max_hold: Duration::from_secs(60),
        }
    }
}

/// Wakes a device asleep at this relay: the host's hook (an external
/// command, a webhook, a platform push service). Called on the runtime's
/// thread; it must not block (spawn the work).
pub trait WakeNotifier: Send + Sync + 'static {
    fn wake(&self, request: WakeRequest);
}

/// One wake.
#[derive(Clone, Debug)]
pub struct WakeRequest {
    /// The device's name, from its certificate (`None` for a device linked
    /// by its expected fingerprint alone).
    pub device: Option<Name>,
    pub key: KeyFingerprint,
    /// The opaque token it registered (e.g. a platform push token).
    pub token: Bytes,
    /// Interests held for it now.
    pub held: usize,
}

/// A device asleep here.
struct Sleeper {
    device: Option<Name>,
    since: Instant,
    until: Instant,
    hold: bool,
    token: Option<Bytes>,
    last_wake: Option<Instant>,
    wakes: u64,
}

#[derive(Default)]
pub(crate) struct Sleepers {
    map: Mutex<HashMap<KeyFingerprint, Sleeper>>,
    pub(crate) wakes_sent: AtomicU64,
}

impl Links {
    /// A link path to the device with key `fingerprint` ended (`why`):
    /// count it as asleep here if it asked to be reachable while asleep and
    /// this relay offers what it asked for.
    pub(crate) fn maybe_asleep(
        self: &Arc<Self>,
        fingerprint: KeyFingerprint,
        ended: &Ended,
        reach: Option<Reachability>,
        why: &LinkError,
    ) {
        let Some(reach) = reach else { return };
        if !ended.last || ended.enrolling || ended.routes.is_empty() {
            return;
        }
        if matches!(
            why,
            LinkError::Refused {
                reason: Some(CloseReason::Released | CloseReason::Revoked),
                ..
            }
        ) {
            return;
        }
        // A revoked device sleeps nowhere (a membership revoked while it
        // was linked is already gone from the link, with its routes).
        if ended.identities.iter().any(|id| {
            let ctx = self.trust.keyring().context_for(&id.device);
            id.certificates.iter().any(|c| ctx.is_revoked(c))
        }) {
            return;
        }
        let hold = reach.hold && self.service.hold.is_some();
        let token = reach.wake_token.filter(|_| self.service.wake.is_some());
        if !hold && token.is_none() {
            return;
        }
        let device = ended.identities.first().map(|id| id.device.clone());
        let label = device
            .as_ref()
            .map_or_else(|| format!("key {fingerprint}"), ToString::to_string);
        let now = Instant::now();
        self.sleepers.map.lock().insert(
            fingerprint,
            Sleeper {
                device,
                since: now,
                until: now + self.service.asleep_max,
                hold,
                token: token.clone(),
                last_wake: None,
                wakes: 0,
            },
        );
        let prefixes = ended.routes.iter().map(|r| r.prefix.clone()).collect();
        self.waiting()
            .route(self, WaitFor::Asleep(fingerprint), prefixes);
        tracing::info!(
            target: "face.quic",
            peer = %label,
            hold,
            wake = token.is_some(),
            "{label} is asleep here ({why}): {}{}",
            if hold { "its Interests are held" } else { "its Interests are not held" },
            if token.is_some() { "; an Interest for it wakes it" } else { "" }
        );
        let weak = Arc::downgrade(self);
        let max = self.service.asleep_max;
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = tokio::time::sleep(max) => {
                    if let Some(links) = weak.upgrade() {
                        links.forget_sleeper(fingerprint, now).await;
                    }
                }
            }
        });
    }

    /// The device with key `fingerprint` asleep since `since` did not come
    /// back within `asleep_max`: forget it.
    async fn forget_sleeper(&self, fingerprint: KeyFingerprint, since: Instant) {
        let gone = {
            let mut map = self.sleepers.map.lock();
            match map.get(&fingerprint) {
                Some(s) if s.since == since => map.remove(&fingerprint),
                _ => None,
            }
        };
        let Some(sleeper) = gone else { return };
        let target = WaitFor::Asleep(fingerprint);
        self.waiting().unroute(self, &target);
        self.waiting().drop_all(&target, NackReason::NoRoute).await;
        tracing::info!(
            target: "face.quic",
            key = %fingerprint,
            "{} did not link again within {} s of falling asleep; it is no longer held for or woken",
            sleeper.device.map_or_else(|| format!("key {fingerprint}"), |d| d.to_string()),
            self.service.asleep_max.as_secs()
        );
    }

    /// The device with key `fingerprint` linked again: it is awake. Its
    /// held Interests go to it over the new link.
    pub(crate) async fn awake(&self, fingerprint: KeyFingerprint) {
        let woke = self.sleepers.map.lock().remove(&fingerprint);
        let target = WaitFor::Asleep(fingerprint);
        if woke.is_some() {
            self.waiting().unroute(self, &target);
        }
        self.flush_if_linked(&target).await;
    }

    /// What to do with an Interest for the device asleep with key
    /// `fingerprint`: hold it, and wake the device.
    pub(crate) fn asleep_interest(&self, fingerprint: KeyFingerprint, name: &Name) -> Verdict {
        if self.table.is_linked(&fingerprint) {
            // It linked again while this Interest was on its way.
            return Verdict::Hold {
                per_target: usize::MAX,
                total: usize::MAX,
                max_hold: None,
            };
        }
        let now = Instant::now();
        let mut map = self.sleepers.map.lock();
        let Some(sleeper) = map.get_mut(&fingerprint) else {
            return Verdict::Nack(
                NackReason::NoRoute,
                format!("the device {name} was for is no longer asleep here"),
            );
        };
        if let (Some(token), Some(notifier)) = (&sleeper.token, &self.service.wake)
            && sleeper
                .last_wake
                .is_none_or(|at| now.duration_since(at) >= WAKE_INTERVAL)
        {
            sleeper.last_wake = Some(now);
            sleeper.wakes += 1;
            self.sleepers.wakes_sent.fetch_add(1, Ordering::Relaxed);
            let held = self
                .waiting
                .get()
                .map_or(0, |w| w.count(&WaitFor::Asleep(fingerprint)));
            tracing::info!(
                target: "face.quic",
                key = %fingerprint,
                "waking {}: an Interest arrived for it while it is asleep here",
                sleeper
                    .device
                    .as_ref()
                    .map_or_else(|| format!("key {fingerprint}"), ToString::to_string)
            );
            notifier.wake(WakeRequest {
                device: sleeper.device.clone(),
                key: fingerprint,
                token: token.clone(),
                held,
            });
        }
        match (sleeper.hold, self.service.hold) {
            (true, Some(limits)) => Verdict::Hold {
                per_target: limits.per_device,
                total: limits.total,
                max_hold: Some(limits.max_hold),
            },
            _ => Verdict::Nack(
                NackReason::NoRoute,
                format!(
                    "the device {name} is for is asleep here and its Interests are not held{}",
                    if sleeper.token.is_some() {
                        " (it was woken)"
                    } else {
                        ""
                    }
                ),
            ),
        }
    }

    /// The device with key `fingerprint`, if asleep here.
    pub(crate) fn asleep_status(&self, fingerprint: &KeyFingerprint) -> Option<AsleepStatus> {
        let map = self.sleepers.map.lock();
        let s = map.get(fingerprint)?;
        Some(AsleepStatus {
            since: s.since.elapsed(),
            held: self
                .waiting
                .get()
                .map_or(0, |w| w.count(&WaitFor::Asleep(*fingerprint))),
            hold: s.hold,
            wake: s.token.is_some(),
            wakes: s.wakes,
        })
    }

    /// The devices asleep here: key, device, and until when.
    pub(crate) fn sleepers(&self) -> Vec<(KeyFingerprint, Option<Name>)> {
        let now = Instant::now();
        self.sleepers
            .map
            .lock()
            .iter()
            .filter(|(_, s)| s.until > now)
            .map(|(fp, s)| (*fp, s.device.clone()))
            .collect()
    }
}
