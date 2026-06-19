//! Browser-side Web Bluetooth **central** `Face`.
//!
//! Lets an ndn-rs engine running inside a browser tab (compiled to
//! `wasm32-unknown-unknown`) connect to an NDN-over-BLE GATT *peripheral* and
//! exchange Interest/Data over it. The peripheral side already ships in this
//! workspace:
//!
//! - native — [`ndn_face::l2::BleFace`] (Linux `bluer`, macOS `CBPeripheralManager`)
//! - embedded — `ndn-embedded` (ESP32, trouble-host)
//!
//! All of those speak the NDNts `@ndn/web-bluetooth-transport` GATT profile,
//! which is exactly what the browser's `navigator.bluetooth` expects, so this
//! central is wire-compatible with them out of the box.
//!
//! | Role | Detail |
//! |------|--------|
//! | GATT role | Central (browser dials a peripheral) |
//! | Service UUID | `099577e3-0788-412a-8824-395084d97391` |
//! | CS (client→server) | `cc5abb89-…` — we **write** Interests here (Write Without Response) |
//! | SC (server→client) | `972f9527-…` — we **subscribe** to notifications for Data |
//!
//! Framing is NDNLPv2 (same code path as UDP/Ethernet/WebTransport): each ATT
//! write carries one `LpPacket`, and the engine pipeline's `ReassemblyBuffer`
//! reassembles fragments. We do not invent a BLE-specific framing.
//!
//! ## Browser constraints (by design, not omission)
//!
//! - **Central only.** The Web Bluetooth API exposes no peripheral/advertising
//!   role, so a browser cannot be the NDN-BLE *server*. Browser↔browser BLE is
//!   impossible; the browser is always a consumer dialing a native/embedded
//!   peripheral.
//! - **User gesture required.** [`WebBleFace::connect`] calls
//!   `requestDevice()`, which pops the browser's device chooser. It must be
//!   invoked from a click/tap handler — it cannot scan or auto-reconnect
//!   silently or in the background.
//! - **Chromium only.** Firefox and Safari/iOS do not ship Web Bluetooth.
//!
//! ## JS-handle bridging
//!
//! The Web Bluetooth handles (`BluetoothRemoteGattCharacteristic`, the
//! `characteristicvaluechanged` listener closure) are `!Send + !Sync`. The
//! `Face` trait requires `Send + Sync + 'static`. We bridge with two `mpsc`
//! channels and a single pump task spawned via [`ndn_runtime::Runtime`]; the
//! JS handles live inside the pump, never crossing a thread boundary.

#![deny(rust_2018_idioms)]

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tracing::trace;

use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

mod framing;
pub use framing::{BleFraming, NdntsReassembler};

// `Arc`/`Runtime` are only named by the `connect` stubs below, which are
// cfg'd out when the real wasm backend is active.
#[cfg(not(all(target_arch = "wasm32", web_sys_unstable_apis)))]
use {ndn_runtime::Runtime, std::sync::Arc};

/// Canonical NDN-over-BLE GATT profile (NDNts `@ndn/web-bluetooth-transport`).
///
/// These MUST match the peripheral side in
/// `crates/ndn-face-native/src/l2/bluetooth` and esp8266ndn. They are redefined
/// here rather than imported because `ndn-face-native` pulls `bluer`/`objc2`, which
/// do not build for `wasm32-unknown-unknown`. The witness test below pins them.
pub const BLE_SERVICE_UUID: &str = "099577e3-0788-412a-8824-395084d97391";
/// Client→server characteristic: we write Interests here (Write Without Response).
pub const BLE_CS_CHAR_UUID: &str = "cc5abb89-a541-46d8-a351-2f95a6a81f49";
/// Server→client characteristic: we subscribe for Data notifications.
pub const BLE_SC_CHAR_UUID: &str = "972f9527-0d83-4261-b95d-b1b2fc73bde4";
/// ndn-rs capability characteristic (read-only): present ⇒ the peer speaks
/// NDNLPv2; absent ⇒ a stock NDNts/esp8266ndn peer. Must match
/// `ndn_face::l2::bluetooth::BLE_FRAMING_CHAR_UUID`.
pub const BLE_FRAMING_CHAR_UUID: &str = "099577e3-0788-412a-8824-395084d97392";

// Only the wasm central backend builds channels; the native stub never does.
#[cfg(target_arch = "wasm32")]
const CHAN_DEPTH: usize = 64;

/// Errors surfaced while constructing a [`WebBleFace`].
#[derive(Debug, Error)]
pub enum WebBleError {
    /// Web Bluetooth is not available (non-wasm target, or wasm built without
    /// `--cfg=web_sys_unstable_apis`, or a browser without the API).
    #[error("web bluetooth unavailable in this environment")]
    Unsupported,
    /// `navigator.bluetooth.requestDevice()` rejected or was cancelled.
    #[error("requestDevice: {0}")]
    RequestDevice(String),
    /// GATT server connect failed.
    #[error("gatt connect: {0}")]
    Connect(String),
    /// Service/characteristic discovery or notification setup failed.
    #[error("gatt discovery: {0}")]
    Discovery(String),
}

/// Browser-side Web Bluetooth central face.
///
/// Construct with [`WebBleFace::connect`] from inside a user-gesture handler.
pub struct WebBleFace {
    id: FaceId,
    remote_uri: String,
    tx_out: mpsc::Sender<Bytes>,
    rx_in: Mutex<mpsc::Receiver<Bytes>>,
    /// Wire framing for this peer (chosen at connect via the capability char).
    framing: BleFraming,
    /// Fragmentation sequence base, bumped once per fragmented packet.
    frag_seq: std::sync::atomic::AtomicU64,
}

/// Web Bluetooth doesn't expose the negotiated ATT MTU, so we fragment writes
/// at a conservative payload that fits the >=185-byte MTU modern stacks
/// negotiate — matching `ndn_face::l2::bluetooth::central`.
const BLE_WRITE_MTU: usize = 244;

impl Transport for WebBleFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Bluetooth
    }

    fn remote_uri(&self) -> Option<String> {
        Some(self.remote_uri.clone())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx_in.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        // Frame per the peer's framing (chosen at connect). Each fragment is one
        // ATT write to the CS characteristic.
        let mut seq = self.frag_seq.load(std::sync::atomic::Ordering::Relaxed);
        let frags = self.framing.frame(&pkt, BLE_WRITE_MTU, &mut seq);
        self.frag_seq
            .store(seq, std::sync::atomic::Ordering::Relaxed);
        for frag in frags {
            trace!(target: "face.webble", face = %self.id, len = frag.len(), "webble: write CS");
            self.tx_out
                .send(frag)
                .await
                .map_err(|_| FaceError::Closed)?;
        }
        Ok(())
    }
}

// Native stub: there is no central role off-wasm; `connect` reports `Unsupported` so the
// crate stays in `default-members` and the host toolchain builds it. The
// framing path and profile constants remain exercised by the witness tests.
#[cfg(not(target_arch = "wasm32"))]
impl WebBleFace {
    /// Always `Err(WebBleError::Unsupported)` off-wasm — Web Bluetooth is a
    /// browser-only API. `framing` forces a wire framing; `None` auto-selects
    /// via the capability characteristic.
    pub async fn connect(
        _id: FaceId,
        _runtime: Arc<dyn Runtime>,
        _framing: Option<BleFraming>,
    ) -> Result<Self, WebBleError> {
        Err(WebBleError::Unsupported)
    }
}

// Browser backend: Web Bluetooth types only exist when web-sys is built with the
// `web_sys_unstable_apis` cfg. Without it we fall back to the same `Unsupported`
// stub so a plain `wasm32` build still compiles.
#[cfg(all(target_arch = "wasm32", web_sys_unstable_apis))]
mod wasm;

#[cfg(all(target_arch = "wasm32", not(web_sys_unstable_apis)))]
impl WebBleFace {
    /// Stub: this wasm build lacks `--cfg=web_sys_unstable_apis`, so the
    /// Web Bluetooth bindings are absent.
    pub async fn connect(
        _id: FaceId,
        _runtime: Arc<dyn Runtime>,
        _framing: Option<BleFraming>,
    ) -> Result<Self, WebBleError> {
        Err(WebBleError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Off-wire if these drift; verbatim from NDNts / esp8266ndn and the
    // ndn-face-native peripheral side.
    #[test]
    fn gatt_uuids_match_profile() {
        assert_eq!(BLE_SERVICE_UUID, "099577e3-0788-412a-8824-395084d97391");
        assert_eq!(BLE_CS_CHAR_UUID, "cc5abb89-a541-46d8-a351-2f95a6a81f49");
        assert_eq!(BLE_SC_CHAR_UUID, "972f9527-0d83-4261-b95d-b1b2fc73bde4");
    }

    #[test]
    fn send_wraps_in_lp_envelope() {
        use ndn_packet::lp::LpPacket;

        let payload: Vec<u8> = (0..50).map(|i| i as u8).collect();
        let wire = ndn_packet::lp::encode_lp_packet(&payload);
        let lp = LpPacket::decode(wire).expect("decode LpPacket");
        assert!(!lp.is_fragmented());
        assert_eq!(lp.fragment.as_deref(), Some(&payload[..]));
    }
}
