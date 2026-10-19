//! How many enrollment links a relay holds, in total and from one address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;

use ndn_face_quic::CloseReason;
use ndn_mgmt_wire::{LinkDetail, link_code as code};

use crate::admission::Refusal;
use crate::policy::{ENROLLMENT_LINKS_MAX, ENROLLMENT_LINKS_PER_SOURCE};

#[derive(Default)]
struct Counts {
    total: usize,
    by_source: HashMap<IpAddr, usize>,
}

/// Enrollment links this relay holds.
#[derive(Default)]
pub(crate) struct EnrollmentSlots(Arc<Mutex<Counts>>);

/// One enrollment link's place among [`EnrollmentSlots`], given back when
/// it is dropped (the link ended).
pub(crate) struct EnrollmentSlot {
    counts: Weak<Mutex<Counts>>,
    source: IpAddr,
}

impl EnrollmentSlots {
    /// Take a place for an enrollment link from `source`, or refuse it when
    /// this relay holds as many as it takes.
    pub(crate) fn reserve(&self, source: IpAddr) -> Result<EnrollmentSlot, Refusal> {
        let mut slots = self.0.lock();
        let from_source = slots.by_source.get(&source).copied().unwrap_or(0);
        if slots.total >= ENROLLMENT_LINKS_MAX || from_source >= ENROLLMENT_LINKS_PER_SOURCE {
            return Err(Refusal::new(
                CloseReason::Busy,
                LinkDetail::new(
                    code::ENROLLMENT_LINKS_FULL,
                    format!(
                        "this relay holds {} enrollment links ({from_source} from your address; it \
                         takes {ENROLLMENT_LINKS_MAX}, {ENROLLMENT_LINKS_PER_SOURCE} from one address); \
                         your device dials again by itself — or enroll it over another path",
                        slots.total
                    ),
                )
                .with("links", slots.total)
                .with("from_source", from_source)
                .with("max", ENROLLMENT_LINKS_MAX)
                .with("max_per_source", ENROLLMENT_LINKS_PER_SOURCE),
            ));
        }
        slots.total += 1;
        *slots.by_source.entry(source).or_default() += 1;
        Ok(EnrollmentSlot {
            counts: Arc::downgrade(&self.0),
            source,
        })
    }
}

impl Drop for EnrollmentSlot {
    fn drop(&mut self) {
        let Some(counts) = self.counts.upgrade() else {
            return;
        };
        let mut slots = counts.lock();
        slots.total = slots.total.saturating_sub(1);
        if let Some(n) = slots.by_source.get_mut(&self.source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                slots.by_source.remove(&self.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_bounded_in_total_and_per_source_and_given_back() {
        let slots = EnrollmentSlots::default();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..ENROLLMENT_LINKS_PER_SOURCE)
            .map(|_| slots.reserve(a).ok().unwrap())
            .collect();
        assert_eq!(slots.reserve(a).err().unwrap().reason, CloseReason::Busy);
        drop(held);
        let mut held: Vec<_> = (0..ENROLLMENT_LINKS_MAX)
            .map(|i| {
                slots
                    .reserve(IpAddr::from([10, 0, (i / 250) as u8, (i % 250) as u8]))
                    .ok()
                    .unwrap()
            })
            .collect();
        assert_eq!(slots.reserve(a).err().unwrap().reason, CloseReason::Busy);
        held.pop();
        assert!(slots.reserve(a).is_ok());
    }
}
