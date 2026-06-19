//! Layer: extension — reusable **signal sources** with pluggable backends.
//!
//! A *source* turns raw driver readings into typed [`ndn_signals_core`] signals
//! and pushes them into a [`SignalStore`]; a *backend* is the actual hardware /
//! browser API / mock. The two are decoupled so the same source logic serves a
//! LoRa radio, a Wi-Fi NIC, or a test mock — and so a source written once is
//! reusable by *any* strategy, not just one.
//!
//! Sources are **push, not pull**: the driver loop (the engine's signal-source
//! task on native, a timer/promise callback in the browser) calls
//! [`SignalSource::poll`] on a cadence; strategies read the cached latest value
//! through the [`SignalView`](ndn_signals_core::SignalView) on their context.
//! Nothing here blocks the forwarding hot path.
//!
//! Generic over the face-id type `F` so the same sources work with the native
//! `FaceId` and the embedded `u8`.

use core::marker::PhantomData;
use core::time::Duration;

use ndn_signals_core::{GeoPos, LinkSignals, NodeSignals, SignalStore};

// The `SignalSource` trait moved to `ndn-signals-core` (the core taxonomy) so the
// spec engine depends only on it, not on this extension framework. Re-exported
// here so concrete sources below — and downstream callers — are unaffected.
pub use ndn_signals_core::SignalSource;

/// A driver that yields per-face link readings (RSSI/SNR/…). Implement this for
/// a concrete radio (LoRa, Wi-Fi) or a mock; `read` returns one pending reading
/// or `None` when the backend has nothing new.
pub trait RadioBackend<F: Copy + Eq>: Send + 'static {
    fn read(&mut self) -> Option<(F, LinkSignals)>;
}

/// Source that publishes per-face [`LinkSignals`] from a [`RadioBackend`].
pub struct RadioMetricsSource<F, B> {
    backend: B,
    interval: Duration,
    _f: PhantomData<fn() -> F>,
}

impl<F: Copy + Eq, B: RadioBackend<F>> RadioMetricsSource<F, B> {
    pub fn new(backend: B, interval: Duration) -> Self {
        Self {
            backend,
            interval,
            _f: PhantomData,
        }
    }
}

impl<F: Copy + Eq + Send + 'static, B: RadioBackend<F>> SignalSource<F>
    for RadioMetricsSource<F, B>
{
    fn name(&self) -> &str {
        "radio-metrics"
    }
    fn interval(&self) -> Duration {
        self.interval
    }
    fn poll(&mut self, store: &dyn SignalStore<F>, now_ms: u32) {
        while let Some((face, mut signals)) = self.backend.read() {
            signals.updated_ms = now_ms;
            store.set_link(face, signals);
        }
    }
}

/// A driver that yields this node's latest [`NodeSignals`] (position, heading,
/// …). Implement for a GPS module, the browser geolocation API, a fixed
/// coordinate, or a mock.
pub trait LocationBackend: Send + 'static {
    fn read(&mut self) -> Option<NodeSignals>;
}

/// Source that publishes this node's [`NodeSignals`] from a [`LocationBackend`].
pub struct LocationSource<B> {
    backend: B,
    interval: Duration,
}

impl<B: LocationBackend> LocationSource<B> {
    pub fn new(backend: B, interval: Duration) -> Self {
        Self { backend, interval }
    }
}

impl<F: Copy + Eq + Send + 'static, B: LocationBackend> SignalSource<F> for LocationSource<B> {
    fn name(&self) -> &str {
        "location"
    }
    fn interval(&self) -> Duration {
        self.interval
    }
    fn poll(&mut self, store: &dyn SignalStore<F>, now_ms: u32) {
        if let Some(mut node) = self.backend.read() {
            node.updated_ms = now_ms;
            store.set_node(node);
        }
    }
}

// Mock backends are always compiled in; the witnesses depend on them.

/// A radio backend that replays a scripted sequence of readings — for tests
/// and `--features`-free demos. Each `read` pops one queued reading.
pub struct MockRadioBackend<F> {
    queue: std::collections::VecDeque<(F, LinkSignals)>,
}

impl<F: Copy + Eq> MockRadioBackend<F> {
    pub fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
        }
    }
    /// Queue a reading to be emitted on a later `read`/`poll`.
    pub fn push(&mut self, face: F, signals: LinkSignals) {
        self.queue.push_back((face, signals));
    }
}

impl<F: Copy + Eq> Default for MockRadioBackend<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Copy + Eq + Send + 'static> RadioBackend<F> for MockRadioBackend<F> {
    fn read(&mut self) -> Option<(F, LinkSignals)> {
        self.queue.pop_front()
    }
}

/// A location backend that replays a scripted sequence of node readings.
pub struct MockLocationBackend {
    queue: std::collections::VecDeque<NodeSignals>,
}

impl MockLocationBackend {
    pub fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
        }
    }
    pub fn push(&mut self, node: NodeSignals) {
        self.queue.push_back(node);
    }
}

impl Default for MockLocationBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LocationBackend for MockLocationBackend {
    fn read(&mut self) -> Option<NodeSignals> {
        self.queue.pop_front()
    }
}

/// A stationary node's position — the "gps-fixed" backend. Re-emits the same
/// reading on every poll, so the published position is continuously re-stamped
/// (never goes stale). For a node that knows where it is and does not move.
pub struct FixedLocationBackend {
    node: NodeSignals,
}

impl FixedLocationBackend {
    /// Fix at `position` only.
    pub fn new(position: GeoPos) -> Self {
        Self {
            node: NodeSignals {
                position: Some(position),
                ..Default::default()
            },
        }
    }
    /// Fix at a full node reading (position + heading/battery/…).
    pub fn with_node(node: NodeSignals) -> Self {
        Self { node }
    }
}

impl LocationBackend for FixedLocationBackend {
    fn read(&mut self) -> Option<NodeSignals> {
        Some(self.node)
    }
}

/// A push handle for [`SharedLocationBackend`] — `Clone`, `Send`, `Sync`, so an
/// async task or a JS callback can publish positions into it.
#[derive(Clone)]
pub struct LocationHandle(std::sync::Arc<std::sync::Mutex<Option<NodeSignals>>>);

impl LocationHandle {
    /// Publish the latest reading; the paired backend emits it on its next poll.
    pub fn set(&self, node: NodeSignals) {
        *self.0.lock().unwrap() = Some(node);
    }
}

/// Position fed asynchronously through a [`LocationHandle`]. This is the
/// browser-geolocation path: the browser's `navigator.geolocation` watch is
/// async and permissioned, so the app's JS/wasm glue calls
/// [`LocationHandle::set`] from the position callback and this backend drains
/// the latest value on each poll. Keeping the web-platform glue in the app
/// keeps `web-sys` out of this crate.
pub struct SharedLocationBackend(std::sync::Arc<std::sync::Mutex<Option<NodeSignals>>>);

impl SharedLocationBackend {
    /// Create the backend and its push handle.
    pub fn new() -> (Self, LocationHandle) {
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        (Self(slot.clone()), LocationHandle(slot))
    }
}

impl LocationBackend for SharedLocationBackend {
    fn read(&mut self) -> Option<NodeSignals> {
        self.0.lock().unwrap().take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use ndn_signals_core::{GeoPos, SignalView};
    use std::collections::HashMap;

    /// Minimal single-threaded store for testing the sources in isolation.
    #[derive(Default)]
    struct TestStore {
        link: RefCell<HashMap<u32, LinkSignals>>,
        node: RefCell<NodeSignals>,
    }
    impl SignalView<u32> for TestStore {
        fn link(&self, f: u32) -> Option<LinkSignals> {
            self.link.borrow().get(&f).copied()
        }
        fn node(&self) -> NodeSignals {
            *self.node.borrow()
        }
        fn neighbor(&self, _f: u32) -> Option<NodeSignals> {
            None
        }
    }
    impl SignalStore<u32> for TestStore {
        fn set_link(&self, f: u32, s: LinkSignals) {
            self.link.borrow_mut().insert(f, s);
        }
        fn set_node(&self, s: NodeSignals) {
            *self.node.borrow_mut() = s;
        }
        fn set_neighbor(&self, _f: u32, _s: NodeSignals) {}
    }

    #[test]
    fn radio_source_pushes_and_stamps() {
        let mut backend = MockRadioBackend::<u32>::new();
        backend.push(
            7,
            LinkSignals {
                rssi_dbm: Some(-61),
                ..Default::default()
            },
        );
        let mut src = RadioMetricsSource::new(backend, Duration::from_millis(500));

        let store = TestStore::default();
        assert_eq!(store.link(7), None);
        src.poll(&store, 1234);

        let got = store.link(7).expect("pushed");
        assert_eq!(got.rssi_dbm, Some(-61));
        assert_eq!(got.updated_ms, 1234, "source stamps the reading");
    }

    #[test]
    fn fixed_location_backend_publishes_position_each_poll() {
        let pos = GeoPos {
            lat_e7: 377_749_000,
            lon_e7: -1_224_194_000,
            alt_cm: 5000,
        };
        let mut src: LocationSource<_> =
            LocationSource::new(FixedLocationBackend::new(pos), Duration::from_secs(1));
        let store = TestStore::default();

        SignalSource::<u32>::poll(&mut src, &store, 10);
        assert_eq!(store.node().position, Some(pos));
        assert_eq!(store.node().updated_ms, 10);
        // Re-stamped on the next poll (position never goes stale).
        SignalSource::<u32>::poll(&mut src, &store, 1010);
        assert_eq!(store.node().updated_ms, 1010);
    }

    #[test]
    fn shared_location_backend_drains_pushed_position() {
        let (backend, handle) = SharedLocationBackend::new();
        let mut src: LocationSource<_> = LocationSource::new(backend, Duration::from_secs(1));
        let store = TestStore::default();

        // Nothing pushed yet -> node stays default.
        SignalSource::<u32>::poll(&mut src, &store, 1);
        assert_eq!(store.node().position, None);

        // A JS/async callback pushes a position; the next poll publishes it.
        handle.set(NodeSignals {
            position: Some(GeoPos {
                lat_e7: 1,
                lon_e7: 2,
                alt_cm: 3,
            }),
            ..Default::default()
        });
        SignalSource::<u32>::poll(&mut src, &store, 2);
        assert_eq!(
            store.node().position,
            Some(GeoPos {
                lat_e7: 1,
                lon_e7: 2,
                alt_cm: 3
            })
        );
    }

    #[test]
    fn location_source_pushes_node_position() {
        let mut backend = MockLocationBackend::new();
        backend.push(NodeSignals {
            position: Some(GeoPos {
                lat_e7: 377_749_000,
                lon_e7: -1_224_194_000,
                alt_cm: 1000,
            }),
            ..Default::default()
        });
        let mut src: LocationSource<_> = LocationSource::new(backend, Duration::from_secs(1));

        let store = TestStore::default();
        SignalSource::<u32>::poll(&mut src, &store, 99);
        assert_eq!(store.node().position.unwrap().alt_cm, 1000);
        assert_eq!(store.node().updated_ms, 99);
    }
}
