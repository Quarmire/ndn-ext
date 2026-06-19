//! BLE wire framing for the Web Bluetooth central.
//!
//! The codec lives in the shared, wasm-buildable [`ndn_ble_framing`] crate.
//! See that crate for the NDNLPv2-vs-NDNts framing distinction and reassembly.

pub use ndn_ble_framing::{BleFraming, NdntsReassembler};
