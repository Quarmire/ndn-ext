//! **The Mac's own Bluetooth as a named-radio BLE PHY** (CoreBluetooth via `btleplug`).
//!
//! Host-radio analog of [`Esp32BleBackend`](crate::Esp32BleBackend): instead of a serial bridge to an
//! ESP32's controller, this drives the Mac's built-in Bluetooth as an [`AdvBackend`]. It **scans** for
//! our connectionless named adverts — the manufacturer-specific AD with company id `0x4E44` ("ND") that
//! every ND BLE firmware emits — and surfaces each as a [`ScannedFrame`], so a
//! [`BlePhy`](crate::BlePhy) over it receives named data straight off Apple's BLE stack. The same
//! backend works on Windows (WinRT) and Linux (BlueZ) since `btleplug` is cross-platform; it is named
//! `MacBleBackend` because the one-way limitation below is a macOS/CoreBluetooth property.
//!
//! ## Receive-only on the adv bearer, by OS design
//! CoreBluetooth's advertising API (`CBPeripheralManager`) accepts only a local name + service UUIDs and
//! silently drops `CBAdvertisementDataManufacturerDataKey`. So the Mac **cannot broadcast** our
//! manufacturer-AD frames: [`broadcast`](MacBleBackend::broadcast) returns an error rather than pretend.
//! The Mac BLE PHY is receive-only on the connectionless adv bearer; a TX path would need a different
//! bearer (a GATT service — that is what `ndn-face-bluetooth` is for). This is Apple's stack, not a stub.
//!
//! ## Iteration points (deliberately v1)
//! - **RSSI** is not on `btleplug`'s manufacturer-data event; wiring it needs the `DeviceUpdated` →
//!   `peripheral.properties().rssi` path. `rssi_dbm` is `None` for now (per-neighbour measurement TODO).
//! - **Sender address**: macOS hides the BD_ADDR behind a CoreBluetooth UUID, so we synthesize a stable
//!   6-byte id from that UUID (enough for dedup / NDNts per-sender reassembly; not a real MAC).
//! - **Extended vs coded PHY**: CoreBluetooth scans the 1M primary transparently; long-range (coded) or
//!   large ext-adv payloads may need scan-PHY tuning — an on-hardware iteration, not a code gap.
use std::hash::{Hash, Hasher};

use async_trait::async_trait;
use btleplug::api::{Central, CentralEvent, Manager as _, ScanFilter};
use btleplug::platform::{Adapter, Manager, PeripheralId};
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tracing::{debug, warn};

use crate::{AdvBackend, ScannedFrame};
use ndn_transport::FaceError;

/// BLE manufacturer company identifier the ND firmware advertises under (`0x4E44` = "ND", LE on air).
/// `btleplug` parses the 2-byte company prefix, so the map value is the inner named payload directly.
const COMPANY_ID_ND: u16 = 0x4E44;

fn io_err(msg: String) -> FaceError {
    FaceError::Io(std::io::Error::other(msg))
}

/// The Mac's built-in Bluetooth as a receive-capable named-radio BLE PHY.
pub struct MacBleBackend {
    rx: AsyncMutex<mpsc::UnboundedReceiver<ScannedFrame>>,
    /// Hold the scanning adapter alive for the lifetime of the backend — dropping it stops the scan and
    /// ends the event stream the reader task is draining.
    _adapter: Adapter,
}

impl MacBleBackend {
    /// Open the first BLE adapter and start scanning for ND named adverts.
    pub async fn open() -> Result<Self, FaceError> {
        Self::open_adapter(None).await
    }

    /// Open a specific adapter (matched by an `adapter_info()` substring, e.g. a Windows/Linux host with
    /// several radios); `None` picks the first. Starts a passive scan and spawns the reader task that
    /// turns company-`0x4E44` manufacturer-data adverts into [`ScannedFrame`]s.
    pub async fn open_adapter(select: Option<&str>) -> Result<Self, FaceError> {
        let manager = Manager::new()
            .await
            .map_err(|e| io_err(format!("ble manager: {e}")))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| io_err(format!("ble adapters: {e}")))?;
        let adapter = match select {
            Some(want) => {
                let mut chosen = None;
                for a in adapters {
                    if a.adapter_info().await.is_ok_and(|i| i.contains(want)) {
                        chosen = Some(a);
                        break;
                    }
                }
                chosen.ok_or_else(|| io_err(format!("no BLE adapter matching {want:?}")))?
            }
            None => adapters
                .into_iter()
                .next()
                .ok_or_else(|| io_err("no BLE adapter found".into()))?,
        };

        // Empty filter: our firmware advertises manufacturer data with no service UUID, so a service
        // filter would exclude it. We filter to company 0x4E44 ourselves in the reader.
        adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(|e| io_err(format!("ble start_scan: {e}")))?;
        let mut events = adapter
            .events()
            .await
            .map_err(|e| io_err(format!("ble events: {e}")))?;

        let (tx, rxch) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(ev) = events.next().await {
                if let CentralEvent::ManufacturerDataAdvertisement {
                    id,
                    manufacturer_data,
                } = ev
                {
                    let Some(payload) = manufacturer_data.get(&COMPANY_ID_ND) else {
                        continue;
                    };
                    if payload.is_empty() {
                        continue;
                    }
                    let frame = Bytes::copy_from_slice(payload);
                    debug!(bytes = frame.len(), "mac-ble: ND advert");
                    if tx
                        .send(ScannedFrame {
                            frame,
                            addr: Some(synth_addr(&id)),
                            rssi_dbm: None,
                        })
                        .is_err()
                    {
                        break; // face dropped
                    }
                }
            }
            warn!("mac-ble: scan event stream ended");
        });

        Ok(Self {
            rx: AsyncMutex::new(rxch),
            _adapter: adapter,
        })
    }
}

#[async_trait]
impl AdvBackend for MacBleBackend {
    async fn broadcast(&self, _frame: Bytes) -> Result<(), FaceError> {
        Err(io_err(
            "CoreBluetooth cannot advertise manufacturer-specific data (Apple drops \
             CBAdvertisementDataManufacturerDataKey); the Mac BLE PHY is receive-only on the \
             connectionless adv bearer — use a GATT bearer (ndn-face-bluetooth) to transmit"
                .into(),
        ))
    }

    async fn next_scanned(&self) -> Result<ScannedFrame, FaceError> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }
}

/// macOS hides the BD_ADDR behind a per-peripheral CoreBluetooth UUID; derive a stable 6-byte link id
/// from it so dedup / per-sender reassembly have a consistent key. FNV-1a over the id's string form.
fn synth_addr(id: &PeripheralId) -> [u8; 6] {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    id.to_string().hash(&mut h);
    let b = h.finish().to_le_bytes();
    [b[0], b[1], b[2], b[3], b[4], b[5]]
}
