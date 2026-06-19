//! Port wire framing: one NDN packet TLV per `postMessage`, transferred as a
//! [`Uint8Array`]. No length prefix or RPC envelope.
//!
//! These helpers are the only place that touches JS array buffers so the rest
//! of the crate works in [`Bytes`] terms. `wasm32`-only because [`Uint8Array`]
//! is `!Send`.

#[cfg(target_arch = "wasm32")]
use bytes::Bytes;
#[cfg(target_arch = "wasm32")]
use js_sys::{ArrayBuffer, Uint8Array};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

/// Wrap an outbound NDN packet in a fresh [`Uint8Array`] for `postMessage`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn encode_outbound(pkt: &Bytes) -> Uint8Array {
    let array = Uint8Array::new_with_length(pkt.len() as u32);
    array.copy_from(pkt);
    array
}

/// Decode a `MessageEvent.data` payload into [`Bytes`]. Accepts an
/// [`ArrayBuffer`] (transferred) or [`Uint8Array`] (copied); returns `None`
/// for anything else so a misbehaving peer can't crash the pump.
#[cfg(target_arch = "wasm32")]
pub(crate) fn decode_inbound(data: JsValue) -> Option<Bytes> {
    if let Ok(buf) = data.clone().dyn_into::<ArrayBuffer>() {
        let view = Uint8Array::new(&buf);
        let mut out = vec![0u8; view.length() as usize];
        view.copy_to(&mut out);
        return Some(Bytes::from(out));
    }
    if let Ok(view) = data.dyn_into::<Uint8Array>() {
        let mut out = vec![0u8; view.length() as usize];
        view.copy_to(&mut out);
        return Some(Bytes::from(out));
    }
    None
}
