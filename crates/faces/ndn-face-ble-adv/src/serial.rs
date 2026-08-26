//! Serial-bridged BLE backend — the **ESP32-C5 running the unified `firmware/esp32c5-ndn`** (one image that
//! serves *all* the named-radio bearers: raw 802.11 AND NimBLE BLE 5 extended advertising + scanning),
//! driven over its native USB-Serial-JTAG with the `[4E 44 type len payload]` "ND" wire protocol. This is
//! the crate's first *real* [`AdvBackend`] — named data rides in BLE extended advertisements (a
//! manufacturer-specific AD with the `0x4E44` "ND" company magic, filtered on the device so the serial
//! pipe is not swamped by ambient beacons). The Wi-Fi bearer of the same firmware is `Esp32SerialBackend`
//! (a `FrameIo`); this is its BLE peer, using distinct `T_BLE_*` message types on the shared protocol.
//!
//! ```no_run
//! # use ndn_face_ble_adv::{Esp32BleBackend, BleAdvFace};
//! # use std::sync::Arc;
//! let backend = Arc::new(Esp32BleBackend::open("/dev/cu.usbmodem1101")?);
//! let face = BleAdvFace::new(ndn_transport::FaceId(0), backend);
//! # Ok::<(), ndn_transport::FaceError>(())
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::FaceError;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::{AdvBackend, ScannedFrame};

const SYNC0: u8 = 0x4E;
const SYNC1: u8 = 0x44;
// BLE-bearer message types in the UNIFIED C5 firmware (esp32c5-ndn serves Wi-Fi + BLE from one image, so
// BLE needs its own types distinct from the Wi-Fi T_INJECT(0x01)/T_RX_TS(0x82)).
const T_BLE_ADV: u8 = 0x30; // host->device: advertise this payload
const T_COEX: u8 = 0x31; // host->device: [scan_window_le16][scan_itvl_le16] — the BLE<->Wi-Fi radio-time split
const T_BLE_RX: u8 = 0x88; // device->host: [rssi_i8][addr6][payload] — a scanned advertisement

/// BLE-scan interval base for [`Esp32BleBackend::set_ble_share`], in 0.625 ms units (256 = 160 ms).
const COEX_ITVL: u16 = 256;

/// An ESP32-C5 BLE bearer reached over its USB-serial port (see module docs).
pub struct Esp32BleBackend {
    tx: Arc<Mutex<Box<dyn serialport::SerialPort>>>,
    rx: AsyncMutex<mpsc::UnboundedReceiver<ScannedFrame>>,
}

impl Esp32BleBackend {
    /// Open the C5 BLE firmware at `path` and spawn the RX reader. **Never** asserts RTS/DTR — on the
    /// C5's native USB-Serial-JTAG RTS maps to EN (chip reset), so touching it would hold the chip halted
    /// (the trap the Wi-Fi backend documents). The board free-runs the firmware it booted on power-up.
    pub fn open(path: &str) -> Result<Self, FaceError> {
        let mut port = serialport::new(path, 115_200)
            .timeout(Duration::from_millis(50))
            .open()
            .map_err(|e| io_err(format!("ble open {path}: {e}")))?;
        let _ = port.write_request_to_send(false);
        let _ = port.write_data_terminal_ready(false);
        let _ = port.clear(serialport::ClearBuffer::Input);
        let reader = port.try_clone().map_err(|e| io_err(format!("ble clone: {e}")))?;
        let (txch, rxch) = mpsc::unbounded_channel();
        std::thread::spawn(move || reader_loop(reader, txch));
        Ok(Self {
            tx: Arc::new(Mutex::new(port)),
            rx: AsyncMutex::new(rxch),
        })
    }

    /// Set this radio's **BLE share** of airtime — `fraction` (0.0–1.0) of the scan interval spent scanning
    /// for BLE, the rest left to the concurrent promiscuous Wi-Fi RX (the two bearers share one radio via
    /// coex). This is the NDR way to handle the split: **not** a firmware constant but a lever cognition
    /// drives from measured per-bearer demand — raise it when BLE has named traffic, lower it when Wi-Fi
    /// does. `1.0` = full BLE scan (starves Wi-Fi RX); the firmware boot fallback is ~0.12.
    pub fn set_ble_share(&self, fraction: f32) -> Result<(), FaceError> {
        let window = ((fraction.clamp(0.0, 1.0) * COEX_ITVL as f32) as u16).clamp(4, COEX_ITVL);
        let mut p = window.to_le_bytes().to_vec();
        p.extend_from_slice(&COEX_ITVL.to_le_bytes());
        self.send_framed(T_COEX, &p)
    }

    fn send_framed(&self, ty: u8, payload: &[u8]) -> Result<(), FaceError> {
        use std::io::Write;
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.extend_from_slice(&[SYNC0, SYNC1, ty, (payload.len() & 0xff) as u8, (payload.len() >> 8) as u8]);
        buf.extend_from_slice(payload);
        let mut port = self.tx.lock().map_err(|_| io_err("ble tx lock poisoned".into()))?;
        port.write_all(&buf).map_err(|e| io_err(format!("ble write: {e}")))?;
        let _ = port.flush();
        Ok(())
    }
}

#[async_trait]
impl AdvBackend for Esp32BleBackend {
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError> {
        // The device wraps this in the ND manufacturer AD and burst-advertises it (fire-and-forget).
        self.send_framed(T_BLE_ADV, &frame)
    }

    async fn next_scanned(&self) -> Result<ScannedFrame, FaceError> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }
}

fn reader_loop(mut port: Box<dyn serialport::SerialPort>, tx: mpsc::UnboundedSender<ScannedFrame>) {
    use std::io::Read;
    let mut acc: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        match port.read(&mut tmp) {
            Ok(n) if n > 0 => {
                acc.extend_from_slice(&tmp[..n]);
                loop {
                    let Some(pos) = acc.windows(2).position(|w| w == [SYNC0, SYNC1]) else {
                        break;
                    };
                    if acc.len() < pos + 5 {
                        break;
                    }
                    let ty = acc[pos + 2];
                    let len = (acc[pos + 3] as usize) | ((acc[pos + 4] as usize) << 8);
                    if acc.len() < pos + 5 + len {
                        break;
                    }
                    if ty == T_BLE_RX && len >= 7 {
                        let p = &acc[pos + 5..pos + 5 + len];
                        let rssi = p[0] as i8;
                        let mut addr = [0u8; 6];
                        addr.copy_from_slice(&p[1..7]);
                        let frame = Bytes::copy_from_slice(&p[7..]);
                        if tx
                            .send(ScannedFrame { frame, addr: Some(addr), rssi_dbm: Some(rssi) })
                            .is_err()
                        {
                            return; // face dropped
                        }
                    }
                    acc.drain(..pos + 5 + len);
                }
                if acc.len() > 8192 {
                    acc.clear();
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
        }
    }
}

fn io_err(msg: String) -> FaceError {
    FaceError::Io(std::io::Error::other(msg))
}
