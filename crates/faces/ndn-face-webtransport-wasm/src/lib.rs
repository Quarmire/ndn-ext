//! Browser-side WebTransport client `Face`.
//!
//! Produces a `Face` impl that an ndn-rs engine running inside a browser tab
//! (compiled to `wasm32-unknown-unknown`) can use to dial out to a server-side
//! WT listener. Also compiles natively via [`xwt_wtransport`] so unit tests
//! can drive the same code path without a real browser.
//!
//! Outbound only: the W3C WebTransport API does not expose an "accept inbound
//! session" surface in the browser.
//!
//! Each NDN packet is wrapped in NDNLPv2 and sent over QUIC datagrams; a packet
//! larger than the negotiated `max_datagram_size` is split into NDNLPv2
//! fragments (one per datagram) and reassembled by the peer's decode stage.
//! This matches NDNts' `H3Transport` + `LpService` (datagram transport,
//! fragment/reassemble at `maxDatagramSize`), so the two interoperate.
//!
//! `xwt_web::Session` holds JS handles (`!Send + !Sync`). The `Face` trait
//! requires `Send + Sync + 'static`. We bridge with two `mpsc` channels and a
//! single pump task spawned via [`ndn_runtime::Runtime`]; the session lives
//! inside the pump.

#![deny(rust_2018_idioms)]

use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tracing::{trace, warn};

use ndn_runtime::Runtime;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

/// Conservative QUIC-datagram floor used when the session cannot report a
/// negotiated `max_datagram_size` (≈ the QUIC minimum).
const WT_DATAGRAM_FLOOR: usize = 1200;

#[cfg(not(target_arch = "wasm32"))]
mod backend {
    pub use xwt_wtransport::{Endpoint, Session};
}

/// Errors surfaced while constructing a [`BrowserWebTransportFace`].
#[derive(Debug, Error)]
pub enum WtClientError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("handshake: {0}")]
    Handshake(String),
}

/// Outbound WebTransport client face.
///
/// Construct via [`BrowserWebTransportFace::connect`] or, for an
/// already-established `xwt` session, [`BrowserWebTransportFace::from_session`].
pub struct BrowserWebTransportFace {
    id: FaceId,
    remote_uri: String,
    tx_out: mpsc::Sender<Bytes>,
    rx_in: Mutex<mpsc::Receiver<Bytes>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl BrowserWebTransportFace {
    /// Bridge a live xwt session into a `Face`.
    ///
    /// Spawns one pump task on `runtime` that owns the session; dropping
    /// the face closes the outbound channel and the pump exits.
    pub fn from_session(
        id: FaceId,
        remote_uri: impl Into<String>,
        runtime: Arc<dyn Runtime>,
        session: backend::Session,
    ) -> Self {
        let (tx_out, rx_out) = mpsc::channel::<Bytes>(64);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(64);

        runtime.spawn(Box::pin(pump(session, rx_out, tx_in)));

        Self {
            id,
            remote_uri: remote_uri.into(),
            tx_out,
            rx_in: Mutex::new(rx_in),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl BrowserWebTransportFace {
    /// Open a WebTransport session to `url` from a browser tab.
    ///
    /// `url` is `https://host:port[/path]`. `cert_hashes` is forwarded as
    /// `serverCertificateHashes` for self-signed loopback / demo deployments;
    /// pass `&[]` to defer to the browser's WebPKI trust store.
    /// Drives `web_wt_sys::WebTransport` directly (rather than going through
    /// `xwt_web::Session`) so the datagram reader is a **default** reader.
    /// Firefox's WebTransport `datagrams.readable` is not a byte stream and
    /// rejects the BYOB reader `xwt_web` acquires at session construction;
    /// `xwt_web` is used here only to build the options object.
    pub async fn connect(
        id: FaceId,
        url: &str,
        cert_hashes: &[[u8; 32]],
        runtime: Arc<dyn Runtime>,
    ) -> Result<Self, WtClientError> {
        let options = xwt_web::WebTransportOptions {
            server_certificate_hashes: cert_hashes
                .iter()
                .map(|h| xwt_web::CertificateHash {
                    algorithm: xwt_web::HashAlgorithm::Sha256,
                    value: h.to_vec(),
                })
                .collect(),
            ..Default::default()
        };
        let transport = web_wt_sys::WebTransport::new_with_options(url, &options.to_js())
            .map_err(|e| WtClientError::Connect(format!("{e:?}")))?;
        transport
            .ready()
            .await
            .map_err(|e| WtClientError::Handshake(format!("{e:?}")))?;

        let (tx_out, rx_out) = mpsc::channel::<Bytes>(64);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(64);
        runtime.spawn(Box::pin(pump_wasm(transport, rx_out, tx_in)));

        Ok(Self {
            id,
            remote_uri: url.to_owned(),
            tx_out,
            rx_in: Mutex::new(rx_in),
        })
    }
}

/// Browser datagram pump: hold **one default datagram reader** for the
/// connection's lifetime and `read()` per datagram (never re-`getReader()` —
/// that's what Firefox rejects), plus a writer for egress. Mirrors the native
/// pump's NDNLPv2 fragment-on-send / reassemble-on-decode behaviour.
#[cfg(target_arch = "wasm32")]
async fn pump_wasm(
    transport: web_wt_sys::WebTransport,
    mut rx_out: mpsc::Receiver<Bytes>,
    tx_in: mpsc::Sender<Bytes>,
) {
    use futures::FutureExt;
    use wasm_bindgen_futures::JsFuture;

    let datagrams = transport.datagrams();
    let max_dg = match datagrams.max_datagram_size() as usize {
        0 => WT_DATAGRAM_FLOOR,
        n => n,
    };
    let reader = web_sys_stream_utils::get_reader(datagrams.readable());
    let writer = web_sys_stream_utils::get_writer(datagrams.writable());
    let mut frag_seq: u64 = 0;

    let mut inbound = Box::pin(web_sys_stream_utils::read(&reader));
    loop {
        futures::select_biased! {
            outgoing = rx_out.recv().fuse() => {
                let Some(wire) = outgoing else { break };
                let frames = if wire.len() > max_dg {
                    let seq = frag_seq;
                    frag_seq = frag_seq.wrapping_add(1);
                    ndn_packet::fragment::fragment_packet(&wire, max_dg, seq)
                } else {
                    vec![wire]
                };
                let mut failed = false;
                for frame in frames {
                    trace!(target: "face.wt-wasm", len=frame.len(), "wt: send datagram");
                    let chunk = js_sys::Uint8Array::from(frame.as_ref());
                    if JsFuture::from(writer.write_with_chunk(chunk.as_ref())).await.is_err() {
                        warn!(target: "face.wt-wasm", "wt: datagram write failed; closing pump");
                        failed = true;
                        break;
                    }
                }
                if failed {
                    break;
                }
            }
            incoming = (&mut inbound).fuse() => {
                match incoming {
                    Ok(Some(bytes)) => {
                        if tx_in.send(Bytes::from(bytes)).await.is_err() {
                            break;
                        }
                        inbound = Box::pin(web_sys_stream_utils::read(&reader));
                    }
                    // `None` = datagrams stream closed cleanly.
                    Ok(None) => break,
                    Err(e) => {
                        warn!(target: "face.wt-wasm", error=?format!("{e:?}"), "wt: datagram read failed; closing pump");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl BrowserWebTransportFace {
    /// Open a WebTransport session natively via xwt-wtransport.
    ///
    /// The caller supplies a fully-built `wtransport::ClientConfig` and owns
    /// cert validation policy. Wire framing matches the browser path.
    pub async fn connect(
        id: FaceId,
        url: &str,
        client_config: wtransport::ClientConfig,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Self, WtClientError> {
        use xwt_core::prelude::*;

        let endpoint = wtransport::Endpoint::client(client_config)
            .map_err(|e| WtClientError::Connect(e.to_string()))?;
        let endpoint = backend::Endpoint(endpoint);
        let connecting = endpoint
            .connect(url)
            .await
            .map_err(|e| WtClientError::Connect(format!("{e:?}")))?;
        let session = connecting
            .wait_connect()
            .await
            .map_err(|e| WtClientError::Handshake(format!("{e:?}")))?;
        Ok(Self::from_session(id, url, runtime, session))
    }
}

impl Transport for BrowserWebTransportFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::WebTransport
    }
    fn remote_uri(&self) -> Option<String> {
        Some(self.remote_uri.clone())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx_in.lock().await;
        match rx.recv().await {
            Some(b) => {
                trace!(target: "face.wt-wasm", face=%self.id, len=b.len(), "wt: recv datagram");
                Ok(b)
            }
            None => Err(FaceError::Closed),
        }
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        // The pump owns the session (and its negotiated datagram size) and
        // fragments oversized packets; here we just hand it the LP wire.
        let wire = ndn_packet::lp::encode_lp_packet(&pkt);
        trace!(target: "face.wt-wasm", face=%self.id, len=wire.len(), "wt: enqueue send");
        self.tx_out.send(wire).await.map_err(|_| FaceError::Closed)
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn pump(
    session: backend::Session,
    mut rx_out: mpsc::Receiver<Bytes>,
    tx_in: mpsc::Sender<Bytes>,
) {
    use futures::FutureExt;
    use xwt_core::prelude::*;

    let max_dg = session.max_datagram_size().unwrap_or(WT_DATAGRAM_FLOOR);
    let mut frag_seq: u64 = 0;

    // One Box-pinned receive future, re-armed after each delivery.
    let mut inbound_dg = Box::pin(session.receive_datagram());

    loop {
        futures::select_biased! {
            outgoing = rx_out.recv().fuse() => {
                let Some(wire) = outgoing else { break };
                // Fragment oversized packets to the datagram size; the peer's
                // NDNLPv2 reassembler (ndn-rs decode / NDNts LpService) restores
                // them.
                let frames = if wire.len() > max_dg {
                    let seq = frag_seq;
                    frag_seq = frag_seq.wrapping_add(1);
                    ndn_packet::fragment::fragment_packet(&wire, max_dg, seq)
                } else {
                    vec![wire]
                };
                let mut failed = false;
                for frame in frames {
                    trace!(target: "face.wt-wasm", len=frame.len(), "wt: send datagram");
                    if let Err(e) = session.send_datagram(frame).await {
                        warn!(target: "face.wt-wasm", error=?e, "wt: send_datagram failed; closing pump");
                        failed = true;
                        break;
                    }
                }
                if failed {
                    break;
                }
            }
            incoming = (&mut inbound_dg).fuse() => {
                match incoming {
                    Ok(dg) => {
                        let bytes = Bytes::copy_from_slice(dg.as_ref());
                        if tx_in.send(bytes).await.is_err() {
                            break;
                        }
                        inbound_dg = Box::pin(session.receive_datagram());
                    }
                    Err(e) => {
                        warn!(target: "face.wt-wasm", error=?e, "wt: receive_datagram failed; closing pump");
                        break;
                    }
                }
            }
        }
    }
}
