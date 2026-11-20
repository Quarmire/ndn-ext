//! The device's own addresses, watched (`ndn-rs/docs/specs/ndn-link.md`
//! §17D.3): when an address of this device appears or goes, [`Links`] does what
//! [`Links::network_changed`] does, so a host with no platform callback (a
//! desktop program) polls nothing itself.
//!
//! The watcher reads a set, never the network: [`AddressSource::addresses`],
//! by default the interfaces' addresses, loopback, link-local and interfaces
//! that are down excluded as the host candidates of a direct path are, and on
//! Linux the **deprecated and temporary** IPv6 addresses too (privacy
//! addresses that rotate, prefixes whose lifetime runs out: addresses nothing
//! lasting is bound to). On Linux a netlink subscription (`NETLINK_ROUTE`,
//! `RTMGRP_IPV4_IFADDR` and `RTMGRP_IPV6_IFADDR`) says at once that something
//! changed, read by the runtime (no thread that cannot be stopped); every
//! platform also reads the set every [`AddressWatch::poll`] (a second at
//! least, five by default), which is how a change is found where there is no
//! subscription and the backstop where there is one. The notices are
//! throttled: the interfaces are read once per [`ADDRESS_COALESCE`] however
//! many notices came, so a flood of them (a router advertisement storm) costs
//! a read a window and no more. A subscription that breaks is said so, with
//! why, and opened again at a poll; the poll reads meanwhile. A read of the
//! set that fails is said so and tried again at the next poll: the watcher
//! never stops of its own.
//!
//! A change is acted on [`ADDRESS_COALESCE`] after it was noticed (changes
//! that follow are the same change), at most [`ADDRESS_BURSTS_PER_MINUTE`] times
//! in a minute (the rest merge into the next), and not at all while the device
//! is offline (it notes the set; going online redials anyway). An address that
//! **went** is acted on only once it has stayed gone for
//! [`AddressWatch::removal_persists`]: one that comes back before is no change
//! (a flap, a lifetime renewed). Acting on removed addresses closes the links
//! this device accepted at **those addresses** and no others (a link accepted
//! at an address that stays is not touched), and every change redials every
//! peer and punches again, as [`Links::network_changed`] does. The watcher
//! only reads the interface list: it makes no network I/O, and never blocks
//! the links.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::links::Links;
use crate::policy::{
    ADDRESS_BURSTS_PER_MINUTE, ADDRESS_COALESCE, ADDRESS_POLL, ADDRESS_POLL_MIN,
    ADDRESS_REMOVAL_PERSISTS,
};
use crate::table::Gone;

/// How [`Links`] watches this device's own addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressWatch {
    /// How often the addresses are read (at least [`ADDRESS_POLL_MIN`], a
    /// second); on Linux a netlink subscription tells sooner. Five seconds by
    /// default.
    pub poll: Duration,
    /// Watch at all. On by default; off, a host calls
    /// [`Links::network_changed`] itself.
    pub enabled: bool,
    /// How long an address must stay gone before its removal is acted on
    /// (the links accepted at it closed): one that is back within it changes
    /// nothing. Three seconds by default; zero acts at the first read that
    /// finds it gone.
    pub removal_persists: Duration,
}

impl Default for AddressWatch {
    fn default() -> Self {
        Self {
            poll: ADDRESS_POLL,
            enabled: true,
            removal_persists: ADDRESS_REMOVAL_PERSISTS,
        }
    }
}

/// Where the watcher reads this device's addresses: a set it compares with the
/// one it last acted on. Reading must not need the network.
pub trait AddressSource: Send + Sync + 'static {
    /// The addresses this device has now that another device could reach it
    /// at: not loopback, not link-local, and none that is about to go (a
    /// deprecated or temporary one) where the host can tell.
    fn addresses(&self) -> Vec<IpAddr>;
}

/// The addresses of this device's interfaces that are up, loopback and
/// link-local ones excluded: the default [`AddressSource`]. On Linux the IPv6
/// addresses the kernel marks deprecated (preferred lifetime over), temporary
/// (privacy addresses), tentative or whose duplicate check failed are left
/// out as well (`/proc/net/if_inet6`); where the platform tells no such flag
/// every address is in, and the watcher's persistence window is what keeps an
/// address that comes and goes from acting.
#[derive(Clone, Copy, Debug, Default)]
pub struct InterfaceAddresses;

impl AddressSource for InterfaceAddresses {
    fn addresses(&self) -> Vec<IpAddr> {
        let unsettled = unsettled_v6();
        crate::candidates::interfaces()
            .into_iter()
            .map(|i| i.addr.to_canonical())
            .filter(|ip| !crate::candidates::is_local(*ip))
            .filter(|ip| match ip {
                IpAddr::V6(v6) => !unsettled.contains(v6),
                IpAddr::V4(_) => true,
            })
            .collect()
    }
}

/// The IPv6 addresses of the interfaces that are deprecated, temporary,
/// tentative or failed their duplicate check, from the kernel's list.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unsettled_v6() -> std::collections::HashSet<std::net::Ipv6Addr> {
    std::fs::read_to_string("/proc/net/if_inet6")
        .map(|text| parse_unsettled_v6(&text))
        .unwrap_or_default()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn unsettled_v6() -> std::collections::HashSet<std::net::Ipv6Addr> {
    std::collections::HashSet::new()
}

/// The addresses of `/proc/net/if_inet6` (`<32 hex digits> <ifindex> <prefix
/// length> <scope> <flags> <name>`, numbers in hex) whose `IFA_F_*` flags say
/// they are temporary (`0x01`), failed their duplicate check (`0x08`),
/// deprecated (`0x20`) or tentative (`0x40`).
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_unsettled_v6(text: &str) -> std::collections::HashSet<std::net::Ipv6Addr> {
    const TEMPORARY: u32 = 0x01;
    const DAD_FAILED: u32 = 0x08;
    const DEPRECATED: u32 = 0x20;
    const TENTATIVE: u32 = 0x40;
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let addr = u128::from_str_radix(fields.next()?, 16).ok()?;
            let flags = u32::from_str_radix(fields.nth(3)?, 16).ok()?;
            (flags & (TEMPORARY | DAD_FAILED | DEPRECATED | TENTATIVE) != 0)
                .then_some(std::net::Ipv6Addr::from(addr))
        })
        .collect()
}

/// What the watcher compares: the addresses as a set.
type AddressSet = BTreeSet<IpAddr>;

/// What the watcher believes this device has, and what it saw go and has not
/// yet acted on.
struct Tracker {
    /// The set last acted on, with the addresses that have gone but not yet
    /// for long enough.
    applied: AddressSet,
    /// When each address of `applied` that is missing from the set read now
    /// was first found missing.
    absent: BTreeMap<IpAddr, Instant>,
    persists: Duration,
}

/// What is due: addresses that appeared, and addresses that went and stayed
/// gone for the persistence window.
#[derive(Debug, Default, PartialEq, Eq)]
struct Due {
    added: AddressSet,
    removed: AddressSet,
}

impl Due {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

impl Tracker {
    fn new(applied: AddressSet, persists: Duration) -> Self {
        Self {
            applied,
            absent: BTreeMap::new(),
            persists,
        }
    }

    /// Compare the set read at `at` (`now`) with the one acted on: what is
    /// due, and when the next removal that is not yet due becomes due. An
    /// address that is back is no longer missing.
    fn observe(&mut self, now: &AddressSet, at: Instant) -> (Due, Option<Instant>) {
        self.absent
            .retain(|ip, _| self.applied.contains(ip) && !now.contains(ip));
        for ip in self.applied.difference(now) {
            self.absent.entry(*ip).or_insert(at);
        }
        let mut due = Due {
            added: now.difference(&self.applied).copied().collect(),
            removed: AddressSet::new(),
        };
        let mut next: Option<Instant> = None;
        for (ip, since) in &self.absent {
            let due_at = *since + self.persists;
            if at >= due_at {
                due.removed.insert(*ip);
            } else {
                next = Some(next.map_or(due_at, |n| n.min(due_at)));
            }
        }
        (due, next)
    }

    /// `due` was acted on (or noted, while offline).
    fn apply(&mut self, due: &Due) {
        for ip in &due.removed {
            self.applied.remove(ip);
            self.absent.remove(ip);
        }
        self.applied.extend(due.added.iter().copied());
    }
}

/// The times the watcher acted in the last minute.
#[derive(Default)]
struct Bursts(VecDeque<Instant>);

impl Bursts {
    const WINDOW: Duration = Duration::from_secs(60);

    /// How long until the watcher may act again at `now`: nothing while it
    /// acted fewer than [`ADDRESS_BURSTS_PER_MINUTE`] times in the minute
    /// before.
    fn wait(&mut self, now: Instant) -> Duration {
        while self
            .0
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= Self::WINDOW)
        {
            self.0.pop_front();
        }
        if self.0.len() < ADDRESS_BURSTS_PER_MINUTE {
            return Duration::ZERO;
        }
        self.0.front().map_or(Duration::ZERO, |oldest| {
            Self::WINDOW.saturating_sub(now.saturating_duration_since(*oldest))
        })
    }

    fn acted(&mut self, now: Instant) {
        self.0.push_back(now);
    }
}

impl Links {
    /// Watch this device's own addresses as `watch` says, reading the
    /// interfaces ([`InterfaceAddresses`]); it replaces the watch that runs.
    /// [`Links::start`] starts one with the defaults ([`AddressWatch::default`]),
    /// so a host does nothing for a change of address; a host with a platform
    /// callback keeps calling [`Links::network_changed`] (a change both see is
    /// one change: the second notice inside [`ADDRESS_COALESCE`] is merged).
    pub fn watch_addresses(self: &Arc<Self>, watch: AddressWatch) {
        self.watch_addresses_from(watch, Arc::new(InterfaceAddresses));
    }

    /// [`watch_addresses`](Self::watch_addresses) reading `source`: a host
    /// that knows its addresses better than the interface list (a phone's
    /// network callback, a test's controlled set).
    pub fn watch_addresses_from(
        self: &Arc<Self>,
        watch: AddressWatch,
        source: Arc<dyn AddressSource>,
    ) {
        let stop = self.cancel.child_token();
        if let Some(running) = self.address_watch.lock().replace(stop.clone()) {
            running.cancel();
        }
        if !watch.enabled {
            stop.cancel();
            return;
        }
        let poll = watch.poll.max(ADDRESS_POLL_MIN);
        tokio::spawn(address_loop(
            Arc::downgrade(self),
            poll,
            watch.removal_persists,
            source,
            stop,
        ));
    }

    /// This device's addresses changed (`removed` went and stayed gone): what
    /// a change of network does ([`Links::network_changed`], with no socket to
    /// move), except that the links this device accepted are closed only when
    /// they were accepted at one of the addresses that went (an address only
    /// added, or one that went that no link was accepted at, breaks no link).
    fn address_changed(self: &Arc<Self>, removed: &AddressSet) {
        tracing::info!(
            target: "face.quic",
            removed = ?removed,
            "this device's addresses changed: links are dialled and punched again"
        );
        self.moved(None, (!removed.is_empty()).then_some(Gone::At(removed)));
    }
}

/// Reads the source, no more often than once per [`ADDRESS_COALESCE`].
struct Reader {
    source: Arc<dyn AddressSource>,
    last: Option<Instant>,
}

enum Read {
    Stopped,
    Failed,
    Set(AddressSet),
}

impl Reader {
    /// Wait out the rest of the window since the last read (the notices that
    /// came meanwhile are thrown away: this read answers them), then read.
    async fn read(&mut self, notices: &Notices, stop: &CancellationToken) -> Read {
        if let Some(last) = self.last {
            let wait = ADDRESS_COALESCE.saturating_sub(last.elapsed());
            if !wait.is_zero() {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return Read::Stopped,
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
        notices.drain();
        self.last = Some(Instant::now());
        let source = Arc::clone(&self.source);
        match tokio::task::spawn_blocking(move || source.addresses().into_iter().collect()).await {
            Ok(set) => Read::Set(set),
            Err(e) => {
                tracing::warn!(
                    target: "face.quic",
                    "reading this device's addresses failed ({e}): the watcher reads them again \
                     at the next poll"
                );
                Read::Failed
            }
        }
    }
}

/// A notice from the system that an address changed: netlink on Linux, never
/// on another platform.
struct Notices {
    #[cfg(target_os = "linux")]
    netlink: Option<netlink::Subscription>,
    /// The subscription broke or could not be opened, and this is said once.
    #[cfg(target_os = "linux")]
    said: bool,
}

impl Notices {
    fn open() -> Self {
        #[cfg(target_os = "linux")]
        {
            match netlink::Subscription::open() {
                Ok(netlink) => Self {
                    netlink: Some(netlink),
                    said: false,
                },
                Err(e) => {
                    tracing::info!(
                        target: "face.quic",
                        "no address subscription ({e}): this device's addresses are read at every \
                         poll"
                    );
                    Self {
                        netlink: None,
                        said: true,
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        Self {}
    }

    /// Wait for a notice; pending for ever where there is no subscription.
    /// `Err` when the subscription broke (the poll goes on alone).
    async fn notice(&self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(netlink) = &self.netlink {
            return netlink.notice().await;
        }
        std::future::pending().await
    }

    /// Throw away what queued up while the watcher waited.
    fn drain(&self) {
        #[cfg(target_os = "linux")]
        if let Some(netlink) = &self.netlink {
            netlink.drain();
        }
    }

    /// The subscription broke: it is closed (the poll reads alone) until
    /// [`reopen`](Self::reopen) opens it again.
    fn close(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.netlink = None;
            self.said = true;
        }
    }

    /// Open the subscription again if it is closed; says why when it cannot,
    /// once.
    fn reopen(&mut self) {
        #[cfg(target_os = "linux")]
        if self.netlink.is_none() {
            match netlink::Subscription::open() {
                Ok(netlink) => {
                    tracing::info!(
                        target: "face.quic",
                        "the address subscription is open again"
                    );
                    self.netlink = Some(netlink);
                    self.said = false;
                }
                Err(e) if !self.said => {
                    tracing::warn!(
                        target: "face.quic",
                        "the address subscription cannot be opened again ({e}): this device's \
                         addresses are read at every poll"
                    );
                    self.said = true;
                }
                Err(_) => {}
            }
        }
    }
}

enum Woke {
    Stop,
    Notice,
    Broken(std::io::Error),
    Poll,
}

/// Sleep until `at`; never when there is none.
async fn until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

async fn address_loop(
    links: Weak<Links>,
    poll: Duration,
    persists: Duration,
    source: Arc<dyn AddressSource>,
    stop: CancellationToken,
) {
    let mut notices = Notices::open();
    let mut reader = Reader { source, last: None };
    let mut bursts = Bursts::default();
    let mut tracker = loop {
        match reader.read(&notices, &stop).await {
            Read::Stopped => return,
            Read::Set(set) => break Tracker::new(set, persists),
            Read::Failed => tokio::select! {
                biased;
                () = stop.cancelled() => return,
                () = tokio::time::sleep(poll) => {}
            },
        }
    };
    // When the next removal that has not yet stayed gone long enough does.
    let mut due_at: Option<Instant> = None;
    loop {
        let woke = tokio::select! {
            biased;
            () = stop.cancelled() => Woke::Stop,
            notice = notices.notice() => match notice {
                Ok(()) => Woke::Notice,
                Err(e) => Woke::Broken(e),
            },
            () = tokio::time::sleep(poll) => Woke::Poll,
            () = until(due_at) => Woke::Poll,
        };
        match woke {
            Woke::Stop => return,
            Woke::Broken(why) => {
                tracing::warn!(
                    target: "face.quic",
                    "the address subscription broke ({why}): this device's addresses are read \
                     every {} s, and the subscription is opened again at a poll",
                    poll.as_secs_f32()
                );
                notices.close();
                continue;
            }
            Woke::Poll => notices.reopen(),
            Woke::Notice => {}
        }
        let now = match reader.read(&notices, &stop).await {
            Read::Stopped => return,
            Read::Failed => continue,
            Read::Set(now) => now,
        };
        let (due, next) = tracker.observe(&now, Instant::now());
        due_at = next;
        if due.is_empty() {
            continue;
        }
        // Changes that follow this notice are the same change.
        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            () = tokio::time::sleep(ADDRESS_COALESCE) => {}
        }
        // At most a few bursts a minute; what changes meanwhile is merged
        // into the one that follows.
        loop {
            let wait = bursts.wait(Instant::now());
            if wait.is_zero() {
                break;
            }
            tokio::select! {
                biased;
                () = stop.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
        let now = match reader.read(&notices, &stop).await {
            Read::Stopped => return,
            Read::Failed => continue,
            Read::Set(now) => now,
        };
        let (due, next) = tracker.observe(&now, Instant::now());
        due_at = next;
        if due.is_empty() {
            continue;
        }
        tracker.apply(&due);
        let Some(links) = links.upgrade() else { return };
        if !links.is_online() {
            // Noted: going online redials from where this device is then.
            continue;
        }
        bursts.acted(Instant::now());
        links.address_changed(&due.removed);
    }
}

#[cfg(target_os = "linux")]
mod netlink {
    //! `NETLINK_ROUTE` address notices, read by the runtime.

    use std::io;
    use std::os::fd::{AsRawFd, OwnedFd};

    use nix::sys::socket::{
        AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, socket,
    };
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;

    pub(super) struct Subscription {
        fd: AsyncFd<OwnedFd>,
    }

    impl Subscription {
        /// Subscribe to IPv4 and IPv6 address changes; `Err` says why where
        /// the system does not allow it (the poll goes on alone).
        pub(super) fn open() -> io::Result<Self> {
            let fd = socket(
                AddressFamily::Netlink,
                SockType::Raw,
                SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
                SockProtocol::NetlinkRoute,
            )
            .map_err(io::Error::from)?;
            let groups = (nix::libc::RTMGRP_IPV4_IFADDR | nix::libc::RTMGRP_IPV6_IFADDR) as u32;
            bind(fd.as_raw_fd(), &NetlinkAddr::new(0, groups)).map_err(io::Error::from)?;
            let fd = AsyncFd::with_interest(fd, Interest::READABLE)?;
            Ok(Self { fd })
        }

        /// Wait until the kernel sent a notice; what else queued is read by
        /// [`drain`](Self::drain). A notice lost to a full buffer is a
        /// notice.
        pub(super) async fn notice(&self) -> io::Result<()> {
            loop {
                let mut ready = self.fd.readable().await?;
                let read = ready.try_io(|fd| {
                    let mut buffer = [0u8; 4096];
                    recv(fd.as_raw_fd(), &mut buffer, MsgFlags::MSG_DONTWAIT)
                        .map_err(io::Error::from)
                });
                match read {
                    Ok(Ok(_)) => return Ok(()),
                    Ok(Err(e)) if e.raw_os_error() == Some(nix::libc::ENOBUFS) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => {}
                }
            }
        }

        /// Read what is queued, to the end.
        pub(super) fn drain(&self) {
            let mut buffer = [0u8; 4096];
            while recv(self.fd.as_raw_fd(), &mut buffer, MsgFlags::MSG_DONTWAIT).is_ok() {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(addrs: &[&str]) -> AddressSet {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    fn ip(a: &str) -> IpAddr {
        a.parse().unwrap()
    }

    #[test]
    fn an_address_added_is_due_at_once_and_one_removed_only_after_it_stayed_gone() {
        let start = Instant::now();
        let mut tracker = Tracker::new(set(&["10.1.0.1", "2001:db8::1"]), Duration::from_secs(3));
        let (due, next) = tracker.observe(&set(&["10.1.0.1", "2001:db8::1"]), start);
        assert!(due.is_empty() && next.is_none(), "nothing changed");

        let (due, next) = tracker.observe(&set(&["10.1.0.1", "2001:db8::1", "10.2.0.1"]), start);
        assert_eq!(due.added, set(&["10.2.0.1"]), "an address added is due");
        assert!(due.removed.is_empty() && next.is_none());
        tracker.apply(&due);

        // 10.1.0.1 goes: not due until it has stayed gone for the window.
        let gone = set(&["2001:db8::1", "10.2.0.1"]);
        let (due, next) = tracker.observe(&gone, start);
        assert!(due.is_empty(), "{due:?}");
        assert_eq!(next, Some(start + Duration::from_secs(3)));
        let (due, next) = tracker.observe(&gone, start + Duration::from_secs(2));
        assert!(due.is_empty());
        assert_eq!(
            next,
            Some(start + Duration::from_secs(3)),
            "the window runs from when it was first found gone"
        );
        let (due, next) = tracker.observe(&gone, start + Duration::from_secs(3));
        assert_eq!(due.removed, set(&["10.1.0.1"]));
        assert!(next.is_none());
        tracker.apply(&due);
        let (due, _) = tracker.observe(&gone, start + Duration::from_secs(4));
        assert!(due.is_empty(), "acted on once");
    }

    #[test]
    fn an_address_that_is_back_within_the_window_was_never_gone() {
        let start = Instant::now();
        let mut tracker = Tracker::new(set(&["10.1.0.1", "10.2.0.1"]), Duration::from_secs(3));
        let (due, _) = tracker.observe(&set(&["10.2.0.1"]), start);
        assert!(due.is_empty());
        // Back after two seconds: nothing was ever due.
        let (due, next) = tracker.observe(
            &set(&["10.1.0.1", "10.2.0.1"]),
            start + Duration::from_secs(2),
        );
        assert!(due.is_empty() && next.is_none(), "{due:?} {next:?}");
        // Gone again: the window starts over.
        let (due, next) = tracker.observe(&set(&["10.2.0.1"]), start + Duration::from_secs(4));
        assert!(due.is_empty());
        assert_eq!(next, Some(start + Duration::from_secs(7)));
        let (due, _) = tracker.observe(&set(&["10.2.0.1"]), start + Duration::from_secs(5));
        assert!(due.is_empty(), "one second after it went again");
    }

    #[test]
    fn a_window_of_zero_acts_on_the_first_read_that_finds_the_address_gone() {
        let start = Instant::now();
        let mut tracker = Tracker::new(set(&["10.1.0.1"]), Duration::ZERO);
        let (due, next) = tracker.observe(&AddressSet::new(), start);
        assert_eq!(
            due,
            Due {
                added: AddressSet::new(),
                removed: set(&["10.1.0.1"])
            }
        );
        assert!(next.is_none());
    }

    #[test]
    fn an_added_address_is_acted_on_while_a_removal_still_waits() {
        let start = Instant::now();
        let mut tracker = Tracker::new(set(&["10.1.0.1"]), Duration::from_secs(3));
        let (due, next) = tracker.observe(&set(&["10.2.0.1"]), start);
        assert_eq!(due.added, set(&["10.2.0.1"]));
        assert!(due.removed.is_empty());
        assert_eq!(next, Some(start + Duration::from_secs(3)));
        tracker.apply(&due);
        let (due, _) = tracker.observe(&set(&["10.2.0.1"]), start + Duration::from_secs(3));
        assert_eq!(due.removed, set(&["10.1.0.1"]), "the removal still comes");
    }

    #[test]
    fn at_most_six_bursts_a_minute_and_the_wait_is_until_the_oldest_leaves_the_minute() {
        let start = Instant::now();
        let mut bursts = Bursts::default();
        for i in 0..ADDRESS_BURSTS_PER_MINUTE {
            let at = start + Duration::from_secs(i as u64);
            assert_eq!(bursts.wait(at), Duration::ZERO, "burst {i} is allowed");
            bursts.acted(at);
        }
        let at = start + Duration::from_secs(10);
        assert_eq!(
            bursts.wait(at),
            Duration::from_secs(50),
            "the seventh waits until the first is a minute old"
        );
        assert_eq!(
            bursts.wait(start + Duration::from_secs(60)),
            Duration::ZERO,
            "the first left the minute"
        );
        bursts.acted(start + Duration::from_secs(60));
        assert_eq!(
            bursts.wait(start + Duration::from_secs(60)),
            Duration::from_secs(1),
            "five of the old ones and the new one: the second leaves in a second"
        );
    }

    #[test]
    fn the_poll_is_a_second_at_least() {
        let watch = AddressWatch {
            poll: Duration::from_millis(10),
            ..AddressWatch::default()
        };
        assert_eq!(watch.poll.max(ADDRESS_POLL_MIN), ADDRESS_POLL_MIN);
        assert_eq!(AddressWatch::default().poll, Duration::from_secs(5));
        assert!(AddressWatch::default().enabled);
        assert_eq!(
            AddressWatch::default().removal_persists,
            Duration::from_secs(3)
        );
    }

    #[test]
    fn the_default_source_names_no_loopback_or_link_local_address() {
        for ip in InterfaceAddresses.addresses() {
            assert!(!crate::candidates::is_local(ip), "{ip}");
        }
    }

    /// The lines of `/proc/net/if_inet6` that name addresses not to rely on:
    /// temporary, deprecated, tentative, or a failed duplicate check; not a
    /// permanent one or a managed one.
    #[test]
    fn the_kernels_flags_say_which_ipv6_addresses_are_not_to_rely_on() {
        let text = "\
20010db8000000000000000000000001 02 40 00 80   eth0
20010db8000000000000000000000002 02 40 00 01   eth0
20010db8000000000000000000000003 02 40 00 20   eth0
20010db8000000000000000000000004 02 40 00 40   eth0
20010db8000000000000000000000005 02 40 00 08   eth0
20010db8000000000000000000000006 02 40 00 c0   eth0
20010db8000000000000000000000007 02 40 00 a1   eth0
not a line
";
        let unsettled = parse_unsettled_v6(text);
        let listed: BTreeSet<IpAddr> = unsettled.into_iter().map(IpAddr::V6).collect();
        assert_eq!(
            listed,
            BTreeSet::from([
                ip("2001:db8::2"),
                ip("2001:db8::3"),
                ip("2001:db8::4"),
                ip("2001:db8::5"),
                ip("2001:db8::6"),
                ip("2001:db8::7"),
            ])
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn netlink_is_subscribed_without_privilege() {
        assert!(
            netlink::Subscription::open().is_ok(),
            "a NETLINK_ROUTE socket in the address groups opens for any user"
        );
    }
}
