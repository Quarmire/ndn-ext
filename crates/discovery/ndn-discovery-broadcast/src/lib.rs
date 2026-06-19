//! Origin-scoped engine discovery via the browser
//! [`BroadcastChannel`](https://developer.mozilla.org/en-US/docs/Web/API/BroadcastChannel)
//! API. Every `tick_interval` (default 5s) posts a JSON hello
//! `{ "router", "prefixes", "ts" }`; received hellos populate an
//! internal peer table inspected via [`BroadcastDiscovery::peers`].
//!
//! This is a hint, not a face: receiving a hello does not produce a
//! [`Face`](ndn_transport::Face). The application opens an inter-context
//! transport (SharedWorker, MessageChannel, etc.) on demand using the
//! hello as a hint. Cross-origin discovery goes through the signaling
//! layer (WebRTC, NDNCERT).
//!
//! On non-wasm targets this compiles to an inert stub.

#![deny(rust_2018_idioms)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ndn_discovery_core::{DiscoveryContext, DiscoveryProtocol, InboundMeta, ProtocolId};
use ndn_packet::Name;
use ndn_transport::FaceId;
use serde::{Deserialize, Serialize};
use web_time::Instant;

#[derive(Clone, Debug)]
pub struct BroadcastDiscoveryConfig {
    /// Default `"ndn-rs-discovery"`. Every context joining the same
    /// name + origin sees one another.
    pub channel_name: String,
    pub router_name: Name,
    pub advertise: Vec<Name>,
    /// Default 5s.
    pub hello_period: Duration,
    /// Default `3 * hello_period`.
    pub stale_after: Duration,
}

impl BroadcastDiscoveryConfig {
    pub fn new(router_name: Name) -> Self {
        Self {
            channel_name: "ndn-rs-discovery".into(),
            router_name,
            advertise: Vec::new(),
            hello_period: Duration::from_secs(5),
            stale_after: Duration::from_secs(15),
        }
    }

    pub fn advertise(mut self, prefix: Name) -> Self {
        self.advertise.push(prefix);
        self
    }

    pub fn channel_name(mut self, name: impl Into<String>) -> Self {
        self.channel_name = name.into();
        self
    }

    pub fn hello_period(mut self, period: Duration) -> Self {
        self.hello_period = period;
        self
    }
}

#[derive(Serialize, Deserialize)]
struct HelloMsg {
    router: String,
    prefixes: Vec<String>,
    ts: u64,
}

#[derive(Clone, Debug)]
pub struct BroadcastPeer {
    pub router_name: Name,
    pub prefixes: Vec<Name>,
    pub last_seen: Instant,
}

const PROTOCOL_ID: ProtocolId = ProtocolId("broadcast-discovery");

/// Shared between [`on_tick`](DiscoveryProtocol::on_tick) and the
/// receive-pump task that owns the JS-side `BroadcastChannel`.
struct Shared {
    config: BroadcastDiscoveryConfig,
    peers: Mutex<Vec<BroadcastPeer>>,
    last_hello: Mutex<Option<Instant>>,
}

pub struct BroadcastDiscovery {
    shared: Arc<Shared>,
}

impl BroadcastDiscovery {
    pub fn new(config: BroadcastDiscoveryConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                peers: Mutex::new(Vec::new()),
                last_hello: Mutex::new(None),
            }),
        }
    }

    /// Stale entries (older than
    /// [`BroadcastDiscoveryConfig::stale_after`]) are filtered on read;
    /// the underlying table is pruned by `on_tick`.
    pub fn peers(&self) -> Vec<BroadcastPeer> {
        let now = Instant::now();
        let stale = self.shared.config.stale_after;
        self.shared
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter(|p| now.duration_since(p.last_seen) < stale)
            .cloned()
            .collect()
    }

    /// No-op on non-wasm.
    pub fn start(self: &Arc<Self>) -> Result<(), BroadcastError> {
        #[cfg(target_arch = "wasm32")]
        {
            wasm::install_receiver(Arc::clone(self))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = self;
            Ok(())
        }
    }
}

impl DiscoveryProtocol for BroadcastDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL_ID
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.shared.config.advertise
    }

    /// Discovery is not face-bound: face state is orthogonal to
    /// broadcasting.
    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_face_down(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    /// Hellos arrive out-of-band on `BroadcastChannel`; never claim a
    /// wire packet.
    fn on_inbound(
        &self,
        _raw: &bytes::Bytes,
        _incoming_face: FaceId,
        _meta: &InboundMeta,
        _ctx: &dyn DiscoveryContext,
    ) -> bool {
        false
    }

    fn on_tick(&self, now: std::time::Instant, _ctx: &dyn DiscoveryContext) {
        let stale = self.shared.config.stale_after;
        let wt_now = Instant::now();
        self.shared
            .peers
            .lock()
            .unwrap()
            .retain(|p| wt_now.duration_since(p.last_seen) < stale);

        // Track our own cadence in `web_time` to keep the wasm path
        // single-clock; `now` is the engine clock and unused here.
        let _ = now;
        let send_now = match *self.shared.last_hello.lock().unwrap() {
            Some(last) => wt_now.duration_since(last) >= self.shared.config.hello_period,
            None => true,
        };
        if !send_now {
            return;
        }
        *self.shared.last_hello.lock().unwrap() = Some(wt_now);

        let cfg = &self.shared.config;
        let ts_ms = web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let msg = HelloMsg {
            router: cfg.router_name.to_string(),
            prefixes: cfg.advertise.iter().map(|n| n.to_string()).collect(),
            ts: ts_ms,
        };
        let json = match serde_json::to_string(&msg) {
            Ok(j) => j,
            Err(_) => return,
        };
        #[cfg(target_arch = "wasm32")]
        wasm::post_hello(&cfg.channel_name, &json);
        #[cfg(not(target_arch = "wasm32"))]
        {
            tracing::trace!(target: "discovery.broadcast", channel = %cfg.channel_name, %json, "(native stub) would post hello");
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
    #[error("BroadcastChannel({channel}) unavailable: {detail}")]
    Unavailable { channel: String, detail: String },
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::{Arc, BroadcastDiscovery, BroadcastError, BroadcastPeer, HelloMsg};
    use ndn_packet::Name;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::JsValue;
    use wasm_bindgen::closure::Closure;
    use web_sys::{BroadcastChannel, MessageEvent};

    /// Open the channel, install `onmessage`, leak channel + closure
    /// for the page lifetime. Received messages flow into
    /// `discovery.shared.peers` until the page unloads.
    pub fn install_receiver(discovery: Arc<BroadcastDiscovery>) -> Result<(), BroadcastError> {
        let channel_name = discovery.shared.config.channel_name.clone();
        let bc = BroadcastChannel::new(&channel_name).map_err(|e| BroadcastError::Unavailable {
            channel: channel_name.clone(),
            detail: format!("{e:?}"),
        })?;

        let discovery_for_cb = Arc::clone(&discovery);
        let cb: Closure<dyn FnMut(JsValue)> = Closure::wrap(Box::new(move |ev: JsValue| {
            let event: MessageEvent = ev.unchecked_into();
            let Some(text) = event.data().as_string() else {
                return;
            };
            let msg: HelloMsg = match serde_json::from_str(&text) {
                Ok(m) => m,
                Err(_) => return,
            };
            if msg.router == discovery_for_cb.shared.config.router_name.to_string() {
                return;
            }
            let router_name: Name = match msg.router.parse() {
                Ok(n) => n,
                Err(_) => return,
            };
            let prefixes: Vec<Name> = msg.prefixes.iter().filter_map(|p| p.parse().ok()).collect();
            let peer = BroadcastPeer {
                router_name: router_name.clone(),
                prefixes,
                last_seen: web_time::Instant::now(),
            };
            let mut table = discovery_for_cb.shared.peers.lock().unwrap();
            if let Some(slot) = table.iter_mut().find(|p| p.router_name == router_name) {
                *slot = peer;
            } else {
                table.push(peer);
            }
        }));
        bc.set_onmessage(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
        Box::leak(Box::new(bc));
        Ok(())
    }

    /// Channels are cheap to open and synchronously deliver to every
    /// subscriber in the origin. Open per-post to avoid pinning a
    /// `!Send` `BroadcastChannel` into the engine's `on_tick` path.
    pub fn post_hello(channel_name: &str, json: &str) {
        if let Ok(bc) = BroadcastChannel::new(channel_name) {
            let _ = bc.post_message(&JsValue::from_str(json));
            bc.close();
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn config_builder_round_trips() {
        let cfg = BroadcastDiscoveryConfig::new("/r1".parse().unwrap())
            .channel_name("test")
            .advertise("/a".parse().unwrap())
            .advertise("/b".parse().unwrap())
            .hello_period(Duration::from_secs(2));
        assert_eq!(cfg.channel_name, "test");
        assert_eq!(cfg.advertise.len(), 2);
        assert_eq!(cfg.hello_period, Duration::from_secs(2));
    }

    #[test]
    fn protocol_id_is_broadcast_discovery() {
        let d = BroadcastDiscovery::new(BroadcastDiscoveryConfig::new("/r1".parse().unwrap()));
        assert_eq!(d.protocol_id().0, "broadcast-discovery");
    }

    #[test]
    fn claimed_prefixes_surface_through_trait() {
        let cfg = BroadcastDiscoveryConfig::new("/r1".parse().unwrap())
            .advertise("/foo".parse().unwrap());
        let d = BroadcastDiscovery::new(cfg);
        assert_eq!(d.claimed_prefixes().len(), 1);
        assert_eq!(d.claimed_prefixes()[0].to_string(), "/foo");
    }

    #[test]
    fn empty_peer_list_on_fresh_construction() {
        let d = BroadcastDiscovery::new(BroadcastDiscoveryConfig::new("/r1".parse().unwrap()));
        assert!(d.peers().is_empty());
    }
}
