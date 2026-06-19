//! Web Bluetooth central backend (wasm32 + `web_sys_unstable_apis`).
//!
//! NOTE: Web Bluetooth is one of web-sys's `unstable_apis`, and its exact
//! method shapes (builder setters vs `set_*`, `*_with_str` suffixes) move
//! between web-sys releases. This module is gated off the host toolchain, so
//! the workspace `cargo build`/`clippy` cannot catch a signature drift here —
//! reconcile against the pinned web-sys version at the first
//! `wasm32-unknown-unknown` build (`RUSTFLAGS=--cfg=web_sys_unstable_apis`).

use std::sync::Arc;

use bytes::Bytes;
use js_sys::JsString;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    BluetoothDevice, BluetoothLeScanFilterInit, BluetoothRemoteGattCharacteristic,
    BluetoothRemoteGattServer, BluetoothRemoteGattService, Event, RequestDeviceOptions,
};

use ndn_runtime::Runtime;
use ndn_transport::FaceId;

use super::{
    BLE_CS_CHAR_UUID, BLE_FRAMING_CHAR_UUID, BLE_SC_CHAR_UUID, BLE_SERVICE_UUID, BleFraming,
    CHAN_DEPTH, NdntsReassembler, WebBleError, WebBleFace,
};

fn js_err(e: JsValue) -> String {
    format!("{e:?}")
}

/// Read the optional capability characteristic to choose a framing: present ⇒
/// its advertised framing (NDNLPv2 for ndn-rs peers); absent or unreadable ⇒
/// [`BleFraming::Ndnts`] (a stock NDNts/esp8266ndn peer).
async fn read_framing_capability(service: &BluetoothRemoteGattService) -> BleFraming {
    let cap: BluetoothRemoteGattCharacteristic =
        match JsFuture::from(service.get_characteristic_with_str(BLE_FRAMING_CHAR_UUID)).await {
            Ok(c) => c,
            Err(_) => return BleFraming::Ndnts,
        };
    let dv: js_sys::DataView = match JsFuture::from(cap.read_value()).await {
        Ok(v) => v,
        // Present but unreadable — it's an ndn-rs peer, default to NDNLPv2.
        Err(_) => return BleFraming::Ndnlpv2,
    };
    if dv.byte_length() >= 1 {
        BleFraming::from_capability_byte(dv.get_uint8(0))
    } else {
        BleFraming::Ndnlpv2
    }
}

impl WebBleFace {
    /// Open a Web Bluetooth central connection to an NDN-BLE peripheral.
    ///
    /// MUST be called from a user-gesture handler (click/tap): `requestDevice`
    /// pops the browser's device chooser filtered to the NDN service UUID.
    /// Subscribes to SC notifications (inbound Data) and returns a `Face` whose
    /// `send_bytes` writes Interests to the CS characteristic. `framing` forces
    /// a wire framing; `None` auto-selects via the capability characteristic.
    pub async fn connect(
        id: FaceId,
        runtime: Arc<dyn Runtime>,
        framing_override: Option<BleFraming>,
    ) -> Result<Self, WebBleError> {
        let window = web_sys::window().ok_or(WebBleError::Unsupported)?;
        let bluetooth = window
            .navigator()
            .bluetooth()
            .ok_or(WebBleError::Unsupported)?;

        // Filter the chooser to peripherals advertising the NDN service.
        let services = [JsString::from(BLE_SERVICE_UUID)];
        let filter = BluetoothLeScanFilterInit::new();
        filter.set_services(&services);
        let filters = [filter];
        let opts = RequestDeviceOptions::new();
        opts.set_filters(&filters);

        // web-sys 0.3.91 exposes typed `Promise<T>`, so each `JsFuture` awaits
        // straight to the concrete type — no `JsValue` downcast needed.
        let device: BluetoothDevice = JsFuture::from(bluetooth.request_device(&opts))
            .await
            .map_err(|e| WebBleError::RequestDevice(js_err(e)))?;
        let name = device.name().unwrap_or_else(|| device.id());

        let gatt = device
            .gatt()
            .ok_or_else(|| WebBleError::Connect("no GATT".into()))?;
        let server: BluetoothRemoteGattServer = JsFuture::from(gatt.connect())
            .await
            .map_err(|e| WebBleError::Connect(js_err(e)))?;

        let service: BluetoothRemoteGattService =
            JsFuture::from(server.get_primary_service_with_str(BLE_SERVICE_UUID))
                .await
                .map_err(|e| WebBleError::Discovery(js_err(e)))?;

        let cs_char: BluetoothRemoteGattCharacteristic =
            JsFuture::from(service.get_characteristic_with_str(BLE_CS_CHAR_UUID))
                .await
                .map_err(|e| WebBleError::Discovery(js_err(e)))?;
        let sc_char: BluetoothRemoteGattCharacteristic =
            JsFuture::from(service.get_characteristic_with_str(BLE_SC_CHAR_UUID))
                .await
                .map_err(|e| WebBleError::Discovery(js_err(e)))?;

        // Framing: explicit override, else read the capability characteristic
        // (present ⇒ NDNLPv2; absent / unreadable ⇒ stock NDNts peer).
        let framing = match framing_override {
            Some(f) => f,
            None => read_framing_capability(&service).await,
        };

        let (tx_out, rx_out) = mpsc::channel::<Bytes>(CHAN_DEPTH);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(CHAN_DEPTH);

        // Inbound Data arrives as `characteristicvaluechanged` events on the SC
        // characteristic — event-driven, not future-driven, so we bridge into
        // `tx_in` from a sync closure. NDNLPv2 passes raw (pipeline reassembles);
        // NDNts is reassembled here.
        let mut reasm = NdntsReassembler::new();
        let on_change = Closure::<dyn FnMut(Event)>::new(move |ev: Event| {
            let Some(target) = ev.target() else { return };
            let chr: BluetoothRemoteGattCharacteristic = target.unchecked_into();
            let Some(dv) = chr.value() else { return };
            let buf = dv.buffer();
            let arr = js_sys::Uint8Array::new_with_byte_offset_and_length(
                &buf,
                dv.byte_offset() as u32,
                dv.byte_length() as u32,
            );
            let raw = arr.to_vec();
            let deliver = match framing {
                BleFraming::Ndnlpv2 => Some(Bytes::from(raw)),
                BleFraming::Ndnts => reasm.feed(&raw),
            };
            if let Some(pkt) = deliver
                && tx_in.try_send(pkt).is_err()
            {
                warn!(target: "face.webble", "webble: inbound queue full or closed; dropping notification");
            }
        });
        sc_char
            .add_event_listener_with_callback(
                "characteristicvaluechanged",
                on_change.as_ref().unchecked_ref(),
            )
            .map_err(|e| WebBleError::Discovery(js_err(e)))?;
        JsFuture::from(sc_char.start_notifications())
            .await
            .map_err(|e| WebBleError::Discovery(js_err(e)))?;

        // The pump owns the !Send JS handles (cs_char, the listener closure,
        // sc_char) for the life of the face; dropping the face closes `tx_out`
        // and the pump exits, releasing them.
        runtime.spawn(Box::pin(pump(cs_char, sc_char, on_change, rx_out)));

        Ok(Self {
            id,
            remote_uri: format!("ble://{name}"),
            tx_out,
            rx_in: Mutex::new(rx_in),
            framing,
            frag_seq: std::sync::atomic::AtomicU64::new(0),
        })
    }
}

async fn pump(
    cs_char: BluetoothRemoteGattCharacteristic,
    _sc_char: BluetoothRemoteGattCharacteristic,
    _on_change: Closure<dyn FnMut(Event)>,
    mut rx_out: mpsc::Receiver<Bytes>,
) {
    while let Some(bytes) = rx_out.recv().await {
        let mut data = bytes.to_vec();
        let promise = match cs_char.write_value_without_response_with_u8_slice(&mut data) {
            Ok(p) => p,
            Err(e) => {
                warn!(target: "face.webble", error = ?e, "webble: CS write rejected; closing pump");
                break;
            }
        };
        if let Err(e) = JsFuture::from(promise).await {
            warn!(target: "face.webble", error = ?e, "webble: CS write failed; closing pump");
            break;
        }
    }
}
