//! Offline and online (`ndn-rs/docs/specs/ndn-link.md` §17D.1): a device that
//! went offline is not a participant. Its links and direct paths are closed
//! and none is made; the endpoints take no inbound attempt (each is dropped
//! unanswered, before its handshake); every loop that would dial, redial,
//! punch or answer a punch waits on the flag and sends nothing. Going online
//! wakes every loop at once, staggered by the link memory's
//! [`MemoryOptions::dials_at_once`](crate::MemoryOptions::dials_at_once).
//!
//! The state lives here, in [`Links`], so a host keeps nothing around them: no
//! stop-and-start of its links to be offline.

use std::sync::Arc;

use ndn_face_quic::{CloseReason, LinkEndpoint};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::links::Links;

/// What a link closed for going offline says, to the device that closed it
/// and to the one it was linked with.
pub(crate) const WENT_OFFLINE: &str = "this device went offline; it links again when it is back";

/// The reason a device that is offline gives for every link it does not make.
pub(crate) fn offline_detail() -> LinkDetail {
    LinkDetail::new(code::OFFLINE, WENT_OFFLINE)
}

/// Whether the device is online: true until the host says otherwise.
pub(crate) struct Online {
    flag: watch::Sender<bool>,
    /// Held for a whole [`Online::switch`]: the flag and the steps that
    /// follow it (the endpoints' accepting flag, the closes), set one after
    /// the other, are never done by two calls at once. Interleaved, they
    /// could leave an offline device answering handshakes.
    transition: parking_lot::Mutex<()>,
}

impl Default for Online {
    fn default() -> Self {
        Self {
            flag: watch::channel(true).0,
            transition: parking_lot::Mutex::new(()),
        }
    }
}

impl Online {
    pub(crate) fn get(&self) -> bool {
        *self.flag.borrow()
    }

    /// Set the flag; whether it changed.
    fn set(&self, online: bool) -> bool {
        self.flag.send_if_modified(|now| {
            let changed = *now != online;
            *now = online;
            changed
        })
    }

    /// Set the flag and, when it changed, run `then` (what follows from it),
    /// with no other switch between the two: `then` of one call is over before
    /// the next call sets the flag. Whether it changed.
    fn switch(&self, online: bool, then: impl FnOnce()) -> bool {
        let _one_at_a_time = self.transition.lock();
        let changed = self.set(online);
        if changed {
            then();
        }
        changed
    }

    /// A receiver for [`wait_online`].
    pub(crate) fn subscribe(&self) -> watch::Receiver<bool> {
        self.flag.subscribe()
    }
}

/// Wait until the device is online; `false` when `cancel` ended the wait or
/// the links are gone.
pub(crate) async fn wait_online(
    mut online: watch::Receiver<bool>,
    cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        () = cancel.cancelled() => false,
        reached = online.wait_for(|up| *up) => reached.is_ok(),
    }
}

impl Links {
    /// `false`: close every link and direct path now (the close says "this
    /// device went offline; it links again when it is back", so the other
    /// device sees `link-closed-by-peer` and not a grant that ended), take no
    /// inbound attempt (each is dropped before its handshake and unanswered),
    /// and dial, redial, punch and answer a punch no more: no packet leaves
    /// this device for a link. [`Links::watch`] shows every peer down with
    /// [`Next::WhenOnline`](crate::Next::WhenOnline) and the `offline` code.
    /// `true`: link the remembered and the configured peers again (every loop
    /// wakes at once; the dials are staggered by the memory's
    /// `dials_at_once`) and gather this device's candidates again. The state
    /// is held here; the default is online. Calling it with the state it
    /// already has does nothing.
    pub fn set_online(self: &Arc<Self>, online: bool) {
        self.online.switch(online, || {
            for endpoint in self.link_endpoints() {
                endpoint.set_accepting(online);
            }
            if online {
                tracing::info!(target: "face.quic", "this device is online: links are dialled again");
                self.redial_all();
            } else {
                tracing::info!(target: "face.quic", "{WENT_OFFLINE}");
                self.table.close_all(CloseReason::Shutdown, WENT_OFFLINE);
                self.watch_offline();
            }
        });
    }

    /// Whether this device is online ([`Links::set_online`]).
    pub fn is_online(&self) -> bool {
        self.online.get()
    }

    /// Every endpoint of these links: the host's link socket and the
    /// dial-only sockets made so far.
    pub(crate) fn link_endpoints(&self) -> Vec<Arc<LinkEndpoint>> {
        let dialers = self.dialers.lock();
        self.socket
            .iter()
            .chain(dialers.values())
            .cloned()
            .collect()
    }

    /// Dial every peer again now, each loop skipping the rest of its backoff
    /// and taking its turn at the memory's `dials_at_once`; punch again now.
    /// What going online and a change of address both do.
    pub(crate) fn redial_all(&self) {
        for (id, _) in self.peers.iter() {
            let ctl = self.ctl(id);
            ctl.stagger();
            ctl.kick();
        }
        self.direct.kick();
        if let Some(memory) = self.memory.get() {
            memory.kick_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_starts_online_and_says_whether_it_changed() {
        let online = Online::default();
        assert!(online.get());
        assert!(!online.set(true), "already online");
        assert!(online.set(false));
        assert!(!online.get());
        assert!(!online.set(false), "already offline");
        assert!(online.set(true));
    }

    /// What follows a switch is over before the next switch sets the flag: the
    /// flag and the endpoints' accepting flag cannot end up different.
    #[test]
    fn what_follows_a_switch_is_over_before_the_next_switch_begins() {
        use std::sync::mpsc;
        use std::time::Duration;
        let online = Arc::new(Online::default());
        online.set(false);
        let events = Arc::new(parking_lot::Mutex::new(Vec::<&'static str>::new()));
        let (inside_tx, inside_rx) = mpsc::channel::<()>();
        let first = {
            let (online, events) = (Arc::clone(&online), Arc::clone(&events));
            std::thread::spawn(move || {
                online.switch(true, || {
                    events.lock().push("first begins");
                    inside_tx.send(()).unwrap();
                    // Long enough for the second call to reach the switch.
                    std::thread::sleep(Duration::from_millis(300));
                    events.lock().push("first ends");
                });
            })
        };
        inside_rx.recv().unwrap();
        let second = {
            let (online, events) = (Arc::clone(&online), Arc::clone(&events));
            std::thread::spawn(move || {
                online.switch(false, || {
                    events.lock().push("second begins");
                    events.lock().push("second ends");
                });
            })
        };
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(
            *events.lock(),
            ["first begins", "first ends", "second begins", "second ends"],
            "the second switch ran inside the first"
        );
        assert!(!online.get(), "the second call was the last");
    }

    #[tokio::test]
    async fn a_waiter_goes_on_when_online_and_stops_at_cancel() {
        let online = Online::default();
        online.set(false);
        let cancel = CancellationToken::new();
        let waiting = tokio::spawn({
            let rx = online.subscribe();
            let cancel = cancel.clone();
            async move { wait_online(rx, &cancel).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        online.set(true);
        assert!(waiting.await.unwrap());

        online.set(false);
        let waiting = tokio::spawn({
            let rx = online.subscribe();
            let cancel = cancel.clone();
            async move { wait_online(rx, &cancel).await }
        });
        cancel.cancel();
        assert!(!waiting.await.unwrap(), "cancelled while offline");
    }
}
