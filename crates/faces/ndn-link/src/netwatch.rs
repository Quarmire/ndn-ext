//! The device's own addresses, watched (`ndn-rs/docs/specs/ndn-link.md`
//! §17D.3): when an address of this device appears or goes, [`Links`] does what
//! [`Links::network_changed`] does, so a host with no platform callback (a
//! desktop program) polls nothing itself.
//!
//! The watcher reads a set, never the network: [`AddressSource::addresses`],
//! by default the interfaces' addresses, loopback, link-local and interfaces
//! that are down excluded as the host candidates of a direct path are. On
//! Linux a netlink subscription (`NETLINK_ROUTE`, `RTMGRP_IPV4_IFADDR` and
//! `RTMGRP_IPV6_IFADDR`) says at once that something changed, read by the
//! runtime (no thread that cannot be stopped); every platform also reads the
//! set every [`AddressWatch::poll`] (a second at least, five by default), which
//! is how a change is found where there is no subscription and the backstop
//! where there is one.
//!
//! A change is acted on [`ADDRESS_COALESCE`] after it was noticed (changes
//! that follow are the same change), at most [`ADDRESS_BURSTS_PER_MINUTE`] times
//! in a minute (the rest merge into the next), and not at all while the device
//! is offline (it notes the set; going online redials anyway). The watcher
//! only reads the interface list: it makes no network I/O, and never blocks
//! the links.

use std::collections::{BTreeSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::links::Links;
use crate::policy::{ADDRESS_BURSTS_PER_MINUTE, ADDRESS_COALESCE, ADDRESS_POLL, ADDRESS_POLL_MIN};

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
}

impl Default for AddressWatch {
    fn default() -> Self {
        Self {
            poll: ADDRESS_POLL,
            enabled: true,
        }
    }
}

/// Where the watcher reads this device's addresses: a set it compares with the
/// one it last acted on. Reading must not need the network.
pub trait AddressSource: Send + Sync + 'static {
    /// The addresses this device has now that another device could reach it
    /// at: not loopback, not link-local.
    fn addresses(&self) -> Vec<IpAddr>;
}

/// The addresses of this device's interfaces that are up, loopback and
/// link-local ones excluded: the default [`AddressSource`].
#[derive(Clone, Copy, Debug, Default)]
pub struct InterfaceAddresses;

impl AddressSource for InterfaceAddresses {
    fn addresses(&self) -> Vec<IpAddr> {
        crate::candidates::interfaces()
            .into_iter()
            .map(|i| i.addr.to_canonical())
            .filter(|ip| !crate::candidates::is_local(*ip))
            .collect()
    }
}

/// What the watcher compares: the addresses as a set.
type AddressSet = BTreeSet<IpAddr>;

/// What changed between the set acted on and the set now: `None` when
/// nothing; else whether an address went (a link that used it is lost, a
/// link accepted at it included), not only one added.
fn change(applied: &AddressSet, now: &AddressSet) -> Option<Change> {
    if applied == now {
        return None;
    }
    Some(Change {
        removed: applied.difference(now).next().is_some(),
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Change {
    removed: bool,
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
        tokio::spawn(address_loop(Arc::downgrade(self), poll, source, stop));
    }

    /// This device's addresses changed: what a change of network does
    /// ([`Links::network_changed`], with no socket to move); the links this
    /// device accepted are closed only when an address went (one only added
    /// breaks no link).
    fn address_changed(self: &Arc<Self>, removed: bool) {
        tracing::info!(
            target: "face.quic",
            removed,
            "this device's addresses changed: links are dialled and punched again"
        );
        self.moved(None, removed);
    }
}

async fn read(source: &Arc<dyn AddressSource>) -> Option<AddressSet> {
    let source = Arc::clone(source);
    tokio::task::spawn_blocking(move || source.addresses().into_iter().collect())
        .await
        .ok()
}

/// A notice from the system that an address changed: netlink on Linux, never
/// on another platform.
struct Notices {
    #[cfg(target_os = "linux")]
    netlink: Option<netlink::Subscription>,
}

impl Notices {
    fn open() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            netlink: netlink::Subscription::open(),
        }
    }

    /// Wait for a notice; pending for ever where there is no subscription.
    /// `false` when the subscription broke (the poll goes on alone).
    async fn notice(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(netlink) = &self.netlink {
            return netlink.notice().await.is_ok();
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

    fn close(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.netlink = None;
        }
    }
}

enum Woke {
    Stop,
    Notice,
    Broken,
    Poll,
}

async fn address_loop(
    links: Weak<Links>,
    poll: Duration,
    source: Arc<dyn AddressSource>,
    stop: CancellationToken,
) {
    let Some(mut applied) = read(&source).await else {
        return;
    };
    let mut notices = Notices::open();
    let mut bursts = Bursts::default();
    loop {
        let woke = tokio::select! {
            () = stop.cancelled() => Woke::Stop,
            ok = notices.notice() => if ok { Woke::Notice } else { Woke::Broken },
            () = tokio::time::sleep(poll) => Woke::Poll,
        };
        match woke {
            Woke::Stop => return,
            Woke::Broken => {
                tracing::warn!(
                    target: "face.quic",
                    "the address subscription broke: this device's addresses are read every {} s \
                     from now on",
                    poll.as_secs_f32()
                );
                notices.close();
                continue;
            }
            Woke::Notice | Woke::Poll => {}
        }
        let Some(now) = read(&source).await else {
            return;
        };
        if change(&applied, &now).is_none() {
            continue;
        }
        // Changes that follow this notice are the same change.
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(ADDRESS_COALESCE) => {}
        }
        notices.drain();
        // At most a few bursts a minute; what changes meanwhile is merged
        // into the one that follows.
        loop {
            let wait = bursts.wait(Instant::now());
            if wait.is_zero() {
                break;
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
        notices.drain();
        let Some(now) = read(&source).await else {
            return;
        };
        let Some(changed) = change(&applied, &now) else {
            continue;
        };
        applied = now;
        let Some(links) = links.upgrade() else { return };
        if !links.is_online() {
            // Noted: going online redials from where this device is then.
            continue;
        }
        bursts.acted(Instant::now());
        links.address_changed(changed.removed);
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
        /// Subscribe to IPv4 and IPv6 address changes; `None` where the
        /// system does not allow it (the poll goes on alone).
        pub(super) fn open() -> Option<Self> {
            let fd = socket(
                AddressFamily::Netlink,
                SockType::Raw,
                SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
                SockProtocol::NetlinkRoute,
            )
            .ok()?;
            let groups = (nix::libc::RTMGRP_IPV4_IFADDR | nix::libc::RTMGRP_IPV6_IFADDR) as u32;
            bind(fd.as_raw_fd(), &NetlinkAddr::new(0, groups)).ok()?;
            let fd = AsyncFd::with_interest(fd, Interest::READABLE).ok()?;
            Some(Self { fd })
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

    #[test]
    fn a_change_is_an_address_added_or_removed_and_says_which() {
        let before = set(&["10.1.0.1", "2001:db8::1"]);
        assert_eq!(change(&before, &before.clone()), None);
        assert_eq!(
            change(&before, &set(&["10.1.0.1", "2001:db8::1", "10.2.0.1"])),
            Some(Change { removed: false }),
            "an address added breaks no link"
        );
        assert_eq!(
            change(&before, &set(&["10.2.0.1", "2001:db8::1"])),
            Some(Change { removed: true }),
            "10.1.0.1 went, 10.2.0.1 came"
        );
        assert_eq!(
            change(&before, &AddressSet::new()),
            Some(Change { removed: true })
        );
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
            enabled: true,
        };
        assert_eq!(watch.poll.max(ADDRESS_POLL_MIN), ADDRESS_POLL_MIN);
        assert_eq!(AddressWatch::default().poll, Duration::from_secs(5));
        assert!(AddressWatch::default().enabled);
    }

    #[test]
    fn the_default_source_names_no_loopback_or_link_local_address() {
        for ip in InterfaceAddresses.addresses() {
            assert!(!crate::candidates::is_local(ip), "{ip}");
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn netlink_is_subscribed_without_privilege() {
        assert!(
            netlink::Subscription::open().is_some(),
            "a NETLINK_ROUTE socket in the address groups opens for any user"
        );
    }
}
