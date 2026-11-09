//! A subscriber's coalescing queue: the newest signal per (sender, address) not
//! yet read, in the order each pair first became unread. A slow reader gets the
//! newest per address, never a backlog.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use bytes::Bytes;
use ndn_foundation_types::Name;
use tokio::sync::Notify;

use super::Signal;
use super::state::LATEST_MAX;

type Key = (Name, Bytes);

#[derive(Default)]
struct Unread {
    order: VecDeque<Key>,
    newest: HashMap<Key, Signal>,
    closed: bool,
}

/// One subscriber's queue. One reader; any number of writers.
#[derive(Default)]
pub(crate) struct Queue {
    unread: Mutex<Unread>,
    wake: Notify,
}

impl Queue {
    /// Hand `signal` to the reader: it replaces an unread older one of its pair.
    pub(crate) fn push(&self, signal: Signal) {
        let mut u = self.unread.lock().expect("signal queue lock");
        if u.closed {
            return;
        }
        let key = (signal.sender.clone(), signal.address.clone());
        match u.newest.get_mut(&key) {
            Some(held) => {
                if signal.seq > held.seq {
                    *held = signal;
                }
            }
            None => {
                if u.newest.len() >= LATEST_MAX
                    && let Some(old) = u.order.pop_front()
                {
                    u.newest.remove(&old);
                }
                u.order.push_back(key.clone());
                u.newest.insert(key, signal);
            }
        }
        drop(u);
        self.wake.notify_one();
    }

    /// No more signals: the reader drains what is unread, then ends.
    pub(crate) fn close(&self) {
        self.unread.lock().expect("signal queue lock").closed = true;
        self.wake.notify_one();
    }

    fn pop(&self) -> Result<Signal, bool> {
        let mut u = self.unread.lock().expect("signal queue lock");
        while let Some(key) = u.order.pop_front() {
            if let Some(s) = u.newest.remove(&key) {
                return Ok(s);
            }
        }
        Err(u.closed)
    }

    /// The next unread signal; `None` once closed and drained.
    pub(crate) async fn next(&self) -> Option<Signal> {
        loop {
            match self.pop() {
                Ok(s) => return Some(s),
                Err(true) => return None,
                // `notify_one` keeps a permit when no one waits, so a push
                // between `pop` and here is not missed.
                Err(false) => self.wake.notified().await,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn unread(&self) -> usize {
        self.unread.lock().expect("signal queue lock").newest.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::RunId;
    use super::*;

    fn signal(sender: &str, address: &'static [u8], seq: u64) -> Signal {
        Signal {
            scope: "/alice/32=data/board".parse().unwrap(),
            sender: sender.parse().unwrap(),
            run: RunId([0; 16]),
            seq,
            address: Bytes::from_static(address),
            payload: Bytes::from(seq.to_be_bytes().to_vec()),
            expires: 0,
            local: false,
        }
    }

    #[tokio::test]
    async fn a_slow_reader_gets_the_newest_per_sender_and_address_and_no_backlog() {
        let q = Queue::default();
        for seq in 0..100 {
            q.push(signal("/alice/laptop/KEY/1", b"cursor", seq));
            q.push(signal("/bob/phone/KEY/1", b"cursor", seq));
        }
        q.push(signal("/alice/laptop/KEY/1", b"presence", 1));
        q.push(signal("/alice/laptop/KEY/1", b"cursor", 50));
        assert_eq!(q.unread(), 3, "one per (sender, address)");
        let a = q.next().await.unwrap();
        assert_eq!(
            (a.sender.to_string().as_str(), a.address.as_ref(), a.seq),
            ("/alice/laptop/KEY/1", &b"cursor"[..], 99)
        );
        let b = q.next().await.unwrap();
        assert_eq!((b.address.as_ref(), b.seq), (&b"cursor"[..], 99));
        assert_eq!(b.sender.to_string(), "/bob/phone/KEY/1");
        assert_eq!(q.next().await.unwrap().address.as_ref(), b"presence");
        q.push(signal("/alice/laptop/KEY/1", b"cursor", 100));
        q.close();
        assert_eq!(q.next().await.unwrap().seq, 100, "drained after close");
        assert!(q.next().await.is_none());
        q.push(signal("/alice/laptop/KEY/1", b"cursor", 101));
        assert!(q.next().await.is_none(), "nothing after close");
    }
}
