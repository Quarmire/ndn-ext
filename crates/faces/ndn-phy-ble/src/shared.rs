//! **Shared-mux BLE backend** — a BLE [`AdvBackend`] backed by a *shared* `SerialRadioBackend` (the unified
//! ESP32-C5 firmware's one port/reader), so a single host connection carries **both** bearers of the named
//! radio: the Wi-Fi `FrameIo` and this BLE advertiser/scanner. The `SerialRadioBackend` reader demuxes
//! `T_RX_TS` (Wi-Fi) and `T_BLE_RX` (BLE) off the same stream; this wrapper just exposes its BLE side as an
//! `AdvBackend` for [`BlePhy`](crate::BlePhy).
//!
//! Get the shared handle from the Wi-Fi view — `Esp32SerialBackend::shared_mux()` — so both views ride one
//! serial link (the alternative, opening the port twice, is what the old `Esp32BleBackend::open` did and it
//! can't coexist with a Wi-Fi backend on the same device):
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use ndn_phy_ble::{SharedBleBackend, BlePhy};
//! # fn demo(wifi: &ndn_radio_drivers::Esp32SerialBackend) -> Result<(), ndn_transport::FaceError> {
//! let mux = wifi.shared_mux();                 // the Arc<SerialRadioBackend> behind the Wi-Fi FrameIo
//! let ble = Arc::new(SharedBleBackend::new(mux.clone()));
//! let face = BlePhy::new(ndn_transport::FaceId(0), ble);
//! // The BLE<->Wi-Fi airtime split is cognition-driven, not a constant:
//! mux.clone().spawn_demand_coex(std::time::Duration::from_secs(1), 0.15, 0.9, 256);
//! # let _ = face; Ok(()) }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_radio_drivers::SerialRadioBackend;
use ndn_transport::FaceError;

use crate::{AdvBackend, ScannedFrame};

/// A BLE [`AdvBackend`] over a shared [`SerialRadioBackend`] mux (see module docs). Broadcast and scan go
/// through the mux's BLE methods; the coex split (`set_ble_share` / `spawn_demand_coex`) lives on the mux
/// itself, since it governs *both* bearers.
pub struct SharedBleBackend {
    mux: Arc<SerialRadioBackend>,
}

impl SharedBleBackend {
    /// Wrap the shared mux (from `Esp32SerialBackend::shared_mux()`) as a BLE `AdvBackend`.
    pub fn new(mux: Arc<SerialRadioBackend>) -> Self {
        Self { mux }
    }

    /// The underlying shared mux — for driving the coex split (`set_ble_share`/`spawn_demand_coex`) that
    /// allocates radio time between this BLE bearer and the Wi-Fi bearer on the same port.
    pub fn mux(&self) -> &Arc<SerialRadioBackend> {
        &self.mux
    }
}

#[async_trait]
impl AdvBackend for SharedBleBackend {
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError> {
        self.mux.ble_broadcast(&frame)
    }

    async fn next_scanned(&self) -> Result<ScannedFrame, FaceError> {
        let (rssi, addr, frame) = self.mux.ble_next_scanned().await?;
        Ok(ScannedFrame {
            frame,
            addr: Some(addr),
            rssi_dbm: Some(rssi),
        })
    }
}
