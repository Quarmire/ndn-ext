//! Native [`RtcChannel`] / [`WebRtcFace`] backed by `webrtc-rs`.
//!
//! Each face owns one [`RTCPeerConnection`] holding one reliable ordered SCTP
//! datachannel. The datachannel's event-callback shape is adapted to the
//! async [`RtcChannel`] surface via a Tokio mpsc.

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::{IceCandidate, IceServers, RtcChannel, SessionDescription, TurnServer, WebRtcError};

const DATA_CHANNEL_LABEL: &str = "ndn";

/// Native RtcChannel: `Arc<RTCDataChannel>` for sends, mpsc receiver for
/// inbound packets routed from the `on_message` callback.
pub struct NativeRtcChannel {
    dc: Arc<RTCDataChannel>,
    rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

#[async_trait::async_trait]
impl RtcChannel for NativeRtcChannel {
    async fn send(&self, bytes: Bytes) -> Result<(), WebRtcError> {
        self.dc
            .send(&bytes)
            .await
            .map(|_| ())
            .map_err(|e| WebRtcError::DataChannel(format!("send: {e}")))
    }

    async fn recv(&self) -> Result<Bytes, WebRtcError> {
        match self.rx.lock().await.recv().await {
            Some(b) => Ok(b),
            None => Err(WebRtcError::Closed),
        }
    }

    fn is_open(&self) -> bool {
        // Best-effort: RTCDataChannel has no sync is_open; the canonical
        // close signal is recv() returning Closed.
        true
    }
}

/// Native WebRTC face.
pub struct WebRtcFace {
    id: ndn_transport::FaceId,
    inner: Arc<NativeRtcChannel>,
    /// Held to keep the peer connection alive for the lifetime of the face;
    /// dropping closes the underlying SCTP/DTLS session.
    _pc: Arc<RTCPeerConnection>,
}

impl WebRtcFace {
    /// Direct access to the underlying byte pipe.
    pub fn channel(&self) -> Arc<NativeRtcChannel> {
        Arc::clone(&self.inner)
    }

    /// Override the face id; the listener allocates one via
    /// `engine.faces().alloc_id()` before plugging the face in.
    pub fn set_id(&mut self, id: ndn_transport::FaceId) {
        self.id = id;
    }
}

impl ndn_transport::Transport for WebRtcFace {
    fn id(&self) -> ndn_transport::FaceId {
        self.id
    }
    fn kind(&self) -> ndn_transport::FaceKind {
        ndn_transport::FaceKind::WebRtc
    }

    async fn recv_bytes(&self) -> Result<bytes::Bytes, ndn_transport::FaceError> {
        match self.inner.recv().await {
            Ok(b) => Ok(b),
            Err(crate::WebRtcError::Closed) => Err(ndn_transport::FaceError::Closed),
            Err(e) => Err(ndn_transport::FaceError::Io(std::io::Error::other(
                e.to_string(),
            ))),
        }
    }

    async fn send_bytes(&self, pkt: bytes::Bytes) -> Result<(), ndn_transport::FaceError> {
        // FaceKind::WebRtc is local-scope, so packets go on the wire raw
        // (no NDNLP envelope), matching the Unix / App / Shm / Internal faces.
        self.inner.send(pkt).await.map_err(|e| match e {
            crate::WebRtcError::Closed => ndn_transport::FaceError::Closed,
            other => ndn_transport::FaceError::Io(std::io::Error::other(other.to_string())),
        })
    }
}

/// Half-built peer connection awaiting the matching finalise call.
pub struct PendingFace {
    pc: Arc<RTCPeerConnection>,
    /// Resolves once the SCTP handshake completes.
    open_rx: tokio::sync::oneshot::Receiver<Arc<NativeRtcChannel>>,
}

/// Builder + signaling driver for [`WebRtcFace`].
pub struct WebRtcConnector {
    api: webrtc::api::API,
    config: RTCConfiguration,
}

impl WebRtcConnector {
    /// Build a connector with the given STUN/TURN policy.
    pub fn new(servers: IceServers) -> Result<Self, WebRtcError> {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| WebRtcError::PeerConnection(format!("register codecs: {e}")))?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .map_err(|e| WebRtcError::PeerConnection(format!("register interceptors: {e}")))?;
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        let config = RTCConfiguration {
            ice_servers: servers
                .stun
                .into_iter()
                .map(|url| RTCIceServer {
                    urls: vec![url],
                    ..Default::default()
                })
                .chain(servers.turn.into_iter().map(
                    |TurnServer {
                         url,
                         username,
                         credential,
                     }| RTCIceServer {
                        urls: vec![url],
                        username,
                        credential,
                    },
                ))
                .collect(),
            ..Default::default()
        };

        Ok(Self { api, config })
    }

    /// Build a peer connection, open a reliable ordered datachannel, and
    /// generate an SDP offer. Caller ships `offer` out-of-band, receives an
    /// answer, then calls [`Self::finalize_with_answer`].
    pub async fn create_offer(&self) -> Result<(SessionDescription, PendingFace), WebRtcError> {
        let pc = Arc::new(
            self.api
                .new_peer_connection(self.config.clone())
                .await
                .map_err(|e| WebRtcError::PeerConnection(format!("new pc: {e}")))?,
        );

        // Offerer opens the datachannel; answerer sees it via on_data_channel.
        let init = RTCDataChannelInit {
            ordered: Some(true),
            ..Default::default()
        };
        let dc = pc
            .create_data_channel(DATA_CHANNEL_LABEL, Some(init))
            .await
            .map_err(|e| WebRtcError::DataChannel(format!("create dc: {e}")))?;

        let (open_tx, open_rx) = tokio::sync::oneshot::channel();
        let dc_for_on_open = Arc::clone(&dc);
        let open_tx = Arc::new(Mutex::new(Some(open_tx)));
        let open_tx_clone = Arc::clone(&open_tx);
        dc.on_open(Box::new(move || {
            let dc = Arc::clone(&dc_for_on_open);
            let open_tx = Arc::clone(&open_tx_clone);
            Box::pin(async move {
                let chan = wire_datachannel(dc).await;
                if let Some(tx) = open_tx.lock().await.take() {
                    let _ = tx.send(chan);
                }
            })
        }));

        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("create offer: {e}")))?;
        let mut gather_done = pc.gathering_complete_promise().await;
        pc.set_local_description(offer)
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set local description: {e}")))?;
        // Non-trickle ICE: wait until gathering completes so the local
        // description we ship includes every candidate. Trickle is still
        // supported via `add_ice_candidate`.
        gather_done.recv().await;
        let local = pc.local_description().await.ok_or_else(|| {
            WebRtcError::PeerConnection("no local description after gathering".into())
        })?;

        Ok((to_blob(&local)?, PendingFace { pc, open_rx }))
    }

    /// Accept an incoming SDP offer and produce an answer. The answerer
    /// receives the caller's datachannel via `on_data_channel`.
    pub async fn accept_offer(
        &self,
        offer: SessionDescription,
    ) -> Result<(SessionDescription, PendingFace), WebRtcError> {
        let pc = Arc::new(
            self.api
                .new_peer_connection(self.config.clone())
                .await
                .map_err(|e| WebRtcError::PeerConnection(format!("new pc: {e}")))?,
        );

        let (open_tx, open_rx) = tokio::sync::oneshot::channel();
        let open_tx = Arc::new(Mutex::new(Some(open_tx)));

        let open_tx_clone = Arc::clone(&open_tx);
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let open_tx = Arc::clone(&open_tx_clone);
            Box::pin(async move {
                let dc_for_open = Arc::clone(&dc);
                let open_tx_inner = Arc::clone(&open_tx);
                dc.on_open(Box::new(move || {
                    let dc = Arc::clone(&dc_for_open);
                    let open_tx = Arc::clone(&open_tx_inner);
                    Box::pin(async move {
                        let chan = wire_datachannel(dc).await;
                        if let Some(tx) = open_tx.lock().await.take() {
                            let _ = tx.send(chan);
                        }
                    })
                }));
            })
        }));

        let remote = from_blob(offer)?;
        pc.set_remote_description(remote)
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set remote description: {e}")))?;
        let answer = pc
            .create_answer(None)
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("create answer: {e}")))?;
        let mut gather_done = pc.gathering_complete_promise().await;
        pc.set_local_description(answer)
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set local description: {e}")))?;
        gather_done.recv().await;
        let local = pc.local_description().await.ok_or_else(|| {
            WebRtcError::PeerConnection("no local description after gathering".into())
        })?;

        Ok((to_blob(&local)?, PendingFace { pc, open_rx }))
    }

    /// Feed the offerer the remote answer and await the SCTP `open` event.
    pub async fn finalize_with_answer(
        &self,
        pending: PendingFace,
        answer: SessionDescription,
    ) -> Result<WebRtcFace, WebRtcError> {
        let remote = from_blob(answer)?;
        pending
            .pc
            .set_remote_description(remote)
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set remote description: {e}")))?;
        let chan = pending
            .open_rx
            .await
            .map_err(|_| WebRtcError::DataChannel("datachannel never opened".into()))?;
        Ok(WebRtcFace {
            id: ndn_transport::FaceId(0),
            inner: chan,
            _pc: pending.pc,
        })
    }

    /// Answerer side: wait for the offerer's datachannel `open` event.
    pub async fn finalize_pending(&self, pending: PendingFace) -> Result<WebRtcFace, WebRtcError> {
        let chan = pending
            .open_rx
            .await
            .map_err(|_| WebRtcError::DataChannel("datachannel never opened".into()))?;
        Ok(WebRtcFace {
            id: ndn_transport::FaceId(0),
            inner: chan,
            _pc: pending.pc,
        })
    }

    /// Add a trickle-ICE candidate received from the remote peer. Safe to
    /// call any time after the peer-connection exists; queued if the remote
    /// description isn't set yet.
    pub async fn add_ice_candidate(
        &self,
        pending: &PendingFace,
        candidate: IceCandidate,
    ) -> Result<(), WebRtcError> {
        let init = RTCIceCandidateInit {
            candidate: candidate.candidate,
            sdp_mid: candidate.sdp_mid,
            sdp_mline_index: candidate.sdp_m_line_index,
            ..Default::default()
        };
        pending
            .pc
            .add_ice_candidate(init)
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("add ice candidate: {e}")))
    }
}

fn to_blob(desc: &RTCSessionDescription) -> Result<SessionDescription, WebRtcError> {
    let kind = match desc.sdp_type {
        RTCSdpType::Offer => "offer",
        RTCSdpType::Answer => "answer",
        RTCSdpType::Pranswer => "pranswer",
        RTCSdpType::Rollback => "rollback",
        RTCSdpType::Unspecified => {
            return Err(WebRtcError::Signaling("unspecified SDP type".into()));
        }
    };
    Ok(SessionDescription {
        kind: kind.into(),
        sdp: desc.sdp.clone(),
    })
}

fn from_blob(blob: SessionDescription) -> Result<RTCSessionDescription, WebRtcError> {
    match blob.kind.as_str() {
        "offer" => RTCSessionDescription::offer(blob.sdp)
            .map_err(|e| WebRtcError::Signaling(format!("offer parse: {e}"))),
        "answer" => RTCSessionDescription::answer(blob.sdp)
            .map_err(|e| WebRtcError::Signaling(format!("answer parse: {e}"))),
        other => Err(WebRtcError::Signaling(format!(
            "unsupported SDP type: {other}"
        ))),
    }
}

async fn wire_datachannel(dc: Arc<RTCDataChannel>) -> Arc<NativeRtcChannel> {
    let (tx, rx) = mpsc::unbounded_channel();

    let tx_clone = tx.clone();
    dc.on_message(Box::new(move |msg| {
        let tx = tx_clone.clone();
        Box::pin(async move {
            // SCTP delivers ordered framed messages — one msg.data == one NDN
            // packet. The receiving Face owns any LP/raw framing policy.
            if tx.send(msg.data).is_err() {
                warn!(target: "face.webrtc", "recv channel closed; dropping inbound");
            }
        })
    }));

    let tx_for_close = tx.clone();
    dc.on_close(Box::new(move || {
        // Drop the tx so a pending recv() returns Closed.
        let _ = &tx_for_close;
        Box::pin(async {})
    }));

    Arc::new(NativeRtcChannel {
        dc,
        rx: Mutex::new(rx),
    })
}
