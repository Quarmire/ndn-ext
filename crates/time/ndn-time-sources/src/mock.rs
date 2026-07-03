//! A scripted time source for tests and for driving the discipline loop with no
//! hardware.

use crate::{Reading, TimeSource};

/// A source that returns a caller-set [`Reading`] on every poll (a steady clock,
/// unlike the event-driven GNSS source). Use [`Self::set`] to script a sequence.
pub struct MockSource {
    reading: Option<Reading>,
    label: &'static str,
}

impl MockSource {
    /// A mock that always yields `reading`.
    pub fn new(reading: Reading) -> Self {
        Self {
            reading: Some(reading),
            label: "mock",
        }
    }

    /// A mock with nothing to report yet.
    pub fn empty() -> Self {
        Self {
            reading: None,
            label: "mock",
        }
    }

    /// Replace the reading returned by subsequent polls.
    pub fn set(&mut self, reading: Reading) {
        self.reading = Some(reading);
    }
}

impl TimeSource for MockSource {
    fn poll(&mut self) -> Option<Reading> {
        self.reading
    }

    fn label(&self) -> &'static str {
        self.label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_time::{ClockCapability, TimeInterval};

    #[test]
    fn mock_yields_the_scripted_reading_steadily() {
        let r = Reading {
            wall: TimeInterval::new(1_700_000_000_000_000_000, 1_000),
            cap: ClockCapability::oscillator_tcxo(),
            captured_mono_ns: 5,
        };
        let mut m = MockSource::new(r);
        assert_eq!(m.poll(), Some(r));
        assert_eq!(m.poll(), Some(r), "steady, not consumed");

        let mut e = MockSource::empty();
        assert!(e.poll().is_none());
        e.set(r);
        assert_eq!(e.poll(), Some(r));
    }
}
