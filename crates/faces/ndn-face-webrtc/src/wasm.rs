//! Wasm [`RtcChannel`] / [`WebRtcFace`] backed by `web_sys::RtcPeerConnection`.
//!
//! Mirrors the native flow: `WebRtcConnector` drives the offer/answer/finalize
//! handshake; the resulting [`WebRtcFace`] exposes a [`WasmRtcChannel`] with
//! `send` / `recv`. JS callbacks are bridged to the async surface via Tokio
//! mpsc + oneshot.
//!
//! `wasm32-unknown-unknown` is single-threaded and every `web_sys` type is
//! `!Send`, so the `RtcChannel` trait drops its `Send + Sync` bound here.

use std::cell::RefCell;
use std::rc::Rc;

use bytes::Bytes;
use js_sys::Uint8Array;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelEvent, RtcDataChannelInit,
    RtcIceCandidate, RtcIceCandidateInit, RtcPeerConnection, RtcPeerConnectionIceEvent, RtcSdpType,
    RtcSessionDescriptionInit,
};

use crate::{IceCandidate, IceServers, RtcChannel, SessionDescription, WebRtcError};

const DATA_CHANNEL_LABEL: &str = "ndn";

/// Wasm-side `RtcChannel`: [`RtcDataChannel`] for sends + mpsc receiver wired
/// from the `onmessage` callback.
pub struct WasmRtcChannel {
    dc: RtcDataChannel,
    rx: RefCell<mpsc::UnboundedReceiver<Bytes>>,
    /// Held to keep the JS-side closures alive for the channel's lifetime.
    _closures: ClosureBag,
}

#[async_trait::async_trait(?Send)]
impl RtcChannel for WasmRtcChannel {
    async fn send(&self, bytes: Bytes) -> Result<(), WebRtcError> {
        // Binary send path; the text path would UTF-8-encode the bytes.
        let array = Uint8Array::new_with_length(bytes.len() as u32);
        array.copy_from(&bytes);
        self.dc
            .send_with_array_buffer_view(&array)
            .map_err(|e| WebRtcError::DataChannel(format!("send: {e:?}")))
    }

    // Holding the RefMut across the await is sound: wasm32 is single-threaded
    // and the Face contract guarantees recv is single-consumer.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn recv(&self) -> Result<Bytes, WebRtcError> {
        match self.rx.borrow_mut().recv().await {
            Some(b) => Ok(b),
            None => Err(WebRtcError::Closed),
        }
    }

    fn is_open(&self) -> bool {
        matches!(self.dc.ready_state(), web_sys::RtcDataChannelState::Open)
    }
}

/// Public face wrapper. Holds the peer connection for the channel's lifetime;
/// dropping it tears down the SCTP/DTLS session via JS GC.
pub struct WebRtcFace {
    inner: Rc<WasmRtcChannel>,
    _pc: RtcPeerConnection,
}

impl WebRtcFace {
    pub fn channel(&self) -> Rc<WasmRtcChannel> {
        Rc::clone(&self.inner)
    }
}

/// Half-built peer connection between offer/answer creation and finalise.
pub struct PendingFace {
    pc: RtcPeerConnection,
    open_rx: oneshot::Receiver<Rc<WasmRtcChannel>>,
    /// Keeps `ondatachannel` / `onicecandidate` closures alive during handshake.
    _setup_closures: ClosureBag,
}

/// Builder + signaling driver for the wasm [`WebRtcFace`].
pub struct WebRtcConnector {
    config: RtcConfiguration,
}

impl WebRtcConnector {
    /// Build a connector with the given STUN/TURN policy.
    pub fn new(servers: IceServers) -> Result<Self, WebRtcError> {
        let ice_servers = js_sys::Array::new();
        for url in &servers.stun {
            let entry = js_sys::Object::new();
            js_sys::Reflect::set(&entry, &"urls".into(), &JsValue::from_str(url))
                .map_err(|e| WebRtcError::PeerConnection(format!("ice cfg: {e:?}")))?;
            ice_servers.push(&entry);
        }
        for turn in &servers.turn {
            let entry = js_sys::Object::new();
            js_sys::Reflect::set(&entry, &"urls".into(), &JsValue::from_str(&turn.url))
                .map_err(|e| WebRtcError::PeerConnection(format!("ice cfg: {e:?}")))?;
            js_sys::Reflect::set(
                &entry,
                &"username".into(),
                &JsValue::from_str(&turn.username),
            )
            .map_err(|e| WebRtcError::PeerConnection(format!("ice cfg: {e:?}")))?;
            js_sys::Reflect::set(
                &entry,
                &"credential".into(),
                &JsValue::from_str(&turn.credential),
            )
            .map_err(|e| WebRtcError::PeerConnection(format!("ice cfg: {e:?}")))?;
            ice_servers.push(&entry);
        }
        let config = RtcConfiguration::new();
        config.set_ice_servers(&ice_servers);
        Ok(Self { config })
    }

    /// Create an SDP offer and a half-built [`PendingFace`].
    pub async fn create_offer(&self) -> Result<(SessionDescription, PendingFace), WebRtcError> {
        let pc = RtcPeerConnection::new_with_configuration(&self.config)
            .map_err(|e| WebRtcError::PeerConnection(format!("new pc: {e:?}")))?;

        let dc_init = RtcDataChannelInit::new();
        dc_init.set_ordered(true);
        let dc = pc.create_data_channel_with_data_channel_dict(DATA_CHANNEL_LABEL, &dc_init);

        let mut closures = ClosureBag::default();
        let (open_tx, open_rx) = oneshot::channel();
        wire_local_datachannel(dc, &mut closures, open_tx);

        // Non-trickle: wait until ICE gathering completes so the SDP we ship
        // bundles every candidate (matches the native path).
        let offer_js = JsFuture::from(pc.create_offer())
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("create offer: {e:?}")))?;
        let sdp_str = js_sys::Reflect::get(&offer_js, &"sdp".into())
            .map_err(|e| WebRtcError::Signaling(format!("read sdp: {e:?}")))?
            .as_string()
            .ok_or_else(|| WebRtcError::Signaling("offer.sdp not a string".into()))?;
        let init = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        init.set_sdp(&sdp_str);
        JsFuture::from(pc.set_local_description(&init))
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set local: {e:?}")))?;
        wait_for_gathering(&pc).await;
        let local_sdp = pc
            .local_description()
            .ok_or_else(|| WebRtcError::PeerConnection("no local description".into()))?;

        let blob = SessionDescription {
            kind: sdp_type_str(local_sdp.type_()).to_string(),
            sdp: local_sdp.sdp(),
        };
        Ok((
            blob,
            PendingFace {
                pc,
                open_rx,
                _setup_closures: closures,
            },
        ))
    }

    /// Accept an incoming SDP offer and produce a bundled answer.
    pub async fn accept_offer(
        &self,
        offer: SessionDescription,
    ) -> Result<(SessionDescription, PendingFace), WebRtcError> {
        let pc = RtcPeerConnection::new_with_configuration(&self.config)
            .map_err(|e| WebRtcError::PeerConnection(format!("new pc: {e:?}")))?;

        let mut closures = ClosureBag::default();
        let (open_tx, open_rx) = oneshot::channel();
        wire_remote_datachannel(&pc, &mut closures, open_tx);

        let remote_init = RtcSessionDescriptionInit::new(parse_sdp_type(&offer.kind)?);
        remote_init.set_sdp(&offer.sdp);
        JsFuture::from(pc.set_remote_description(&remote_init))
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set remote: {e:?}")))?;

        let answer_js = JsFuture::from(pc.create_answer())
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("create answer: {e:?}")))?;
        let sdp_str = js_sys::Reflect::get(&answer_js, &"sdp".into())
            .map_err(|e| WebRtcError::Signaling(format!("read sdp: {e:?}")))?
            .as_string()
            .ok_or_else(|| WebRtcError::Signaling("answer.sdp not a string".into()))?;
        let local_init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        local_init.set_sdp(&sdp_str);
        JsFuture::from(pc.set_local_description(&local_init))
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set local: {e:?}")))?;
        wait_for_gathering(&pc).await;
        let local_sdp = pc
            .local_description()
            .ok_or_else(|| WebRtcError::PeerConnection("no local description".into()))?;

        let blob = SessionDescription {
            kind: sdp_type_str(local_sdp.type_()).to_string(),
            sdp: local_sdp.sdp(),
        };
        Ok((
            blob,
            PendingFace {
                pc,
                open_rx,
                _setup_closures: closures,
            },
        ))
    }

    pub async fn finalize_with_answer(
        &self,
        pending: PendingFace,
        answer: SessionDescription,
    ) -> Result<WebRtcFace, WebRtcError> {
        let init = RtcSessionDescriptionInit::new(parse_sdp_type(&answer.kind)?);
        init.set_sdp(&answer.sdp);
        JsFuture::from(pending.pc.set_remote_description(&init))
            .await
            .map_err(|e| WebRtcError::PeerConnection(format!("set remote: {e:?}")))?;
        let chan = pending
            .open_rx
            .await
            .map_err(|_| WebRtcError::DataChannel("datachannel never opened".into()))?;
        Ok(WebRtcFace {
            inner: chan,
            _pc: pending.pc,
        })
    }

    pub async fn finalize_pending(&self, pending: PendingFace) -> Result<WebRtcFace, WebRtcError> {
        let chan = pending
            .open_rx
            .await
            .map_err(|_| WebRtcError::DataChannel("datachannel never opened".into()))?;
        Ok(WebRtcFace {
            inner: chan,
            _pc: pending.pc,
        })
    }

    pub async fn add_ice_candidate(
        &self,
        pending: &PendingFace,
        candidate: IceCandidate,
    ) -> Result<(), WebRtcError> {
        let init = RtcIceCandidateInit::new(&candidate.candidate);
        if let Some(mid) = candidate.sdp_mid.as_ref() {
            init.set_sdp_mid(Some(mid));
        }
        if let Some(idx) = candidate.sdp_m_line_index {
            init.set_sdp_m_line_index(Some(idx));
        }
        let cand = RtcIceCandidate::new(&init)
            .map_err(|e| WebRtcError::Signaling(format!("ice candidate ctor: {e:?}")))?;
        JsFuture::from(
            pending
                .pc
                .add_ice_candidate_with_opt_rtc_ice_candidate(Some(&cand)),
        )
        .await
        .map_err(|e| WebRtcError::PeerConnection(format!("add ice: {e:?}")))?;
        Ok(())
    }
}

/// Tracks JS closures so they live exactly as long as the peer connection /
/// data channel that holds the listener — `forget()` would leak past EOL,
/// dropping them while JS still holds the reference would dangle.
#[derive(Default)]
struct ClosureBag {
    items: Vec<JsClosure>,
}

type JsClosure = Closure<dyn FnMut(JsValue)>;

impl ClosureBag {
    fn push<F>(&mut self, f: F) -> &JsClosure
    where
        F: FnMut(JsValue) + 'static,
    {
        let c: JsClosure = Closure::wrap(Box::new(f) as Box<dyn FnMut(JsValue)>);
        self.items.push(c);
        self.items.last().unwrap()
    }
}

fn wire_local_datachannel(
    dc: RtcDataChannel,
    closures: &mut ClosureBag,
    open_tx: oneshot::Sender<Rc<WasmRtcChannel>>,
) {
    // Offerer side: install on_open so we get notified once SCTP completes.
    let dc_for_open = dc.clone();
    let open_tx = Rc::new(RefCell::new(Some(open_tx)));
    let open_tx_clone = Rc::clone(&open_tx);
    let on_open = closures.push(move |_| {
        let dc = dc_for_open.clone();
        if let Some(tx) = open_tx_clone.borrow_mut().take() {
            let chan = wire_recv(dc);
            let _ = tx.send(chan);
        }
    });
    dc.set_onopen(Some(on_open.as_ref().unchecked_ref()));
}

fn wire_remote_datachannel(
    pc: &RtcPeerConnection,
    closures: &mut ClosureBag,
    open_tx: oneshot::Sender<Rc<WasmRtcChannel>>,
) {
    // Answerer side: the datachannel arrives via the ondatachannel event.
    let open_tx = Rc::new(RefCell::new(Some(open_tx)));
    let on_data_channel = closures.push(move |ev: JsValue| {
        let event: RtcDataChannelEvent = ev.unchecked_into();
        let dc = event.channel();
        let dc_for_open = dc.clone();
        let open_tx = Rc::clone(&open_tx);
        // Forget this inner closure: it must outlive the outer one but the
        // peer-connection lifecycle is short, so the leak is bounded.
        let on_open: Closure<dyn FnMut(JsValue)> = Closure::wrap(Box::new(move |_| {
            let dc = dc_for_open.clone();
            if let Some(tx) = open_tx.borrow_mut().take() {
                let chan = wire_recv(dc);
                let _ = tx.send(chan);
            }
        }));
        dc.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        on_open.forget();
    });
    pc.set_ondatachannel(Some(on_data_channel.as_ref().unchecked_ref()));
}

fn wire_recv(dc: RtcDataChannel) -> Rc<WasmRtcChannel> {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut bag = ClosureBag::default();

    // Force binary frames so on_message receives an ArrayBuffer (not a Blob,
    // which would require an async read).
    dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);

    let tx_msg = tx.clone();
    let on_message = bag.push(move |ev: JsValue| {
        let event: MessageEvent = ev.unchecked_into();
        let data = event.data();
        if let Ok(buf) = data.dyn_into::<js_sys::ArrayBuffer>() {
            let view = Uint8Array::new(&buf);
            let mut out = vec![0u8; view.length() as usize];
            view.copy_to(&mut out);
            if tx_msg.send(Bytes::from(out)).is_err() {
                warn!(target: "face.webrtc.wasm", "recv channel closed; dropping inbound");
            }
        }
    });
    dc.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let tx_close = tx;
    let on_close = bag.push(move |_| {
        // Drop sender → recv() returns Closed.
        let _ = &tx_close;
    });
    dc.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    Rc::new(WasmRtcChannel {
        dc,
        rx: RefCell::new(rx),
        _closures: bag,
    })
}

async fn wait_for_gathering(pc: &RtcPeerConnection) {
    use web_sys::RtcIceGatheringState::Complete;
    if pc.ice_gathering_state() == Complete {
        return;
    }
    let (tx, rx) = oneshot::channel();
    let tx = Rc::new(RefCell::new(Some(tx)));
    let pc_clone = pc.clone();
    let tx_clone = Rc::clone(&tx);
    let cb: Closure<dyn FnMut()> = Closure::wrap(Box::new(move || {
        if pc_clone.ice_gathering_state() == Complete
            && let Some(tx) = tx_clone.borrow_mut().take()
        {
            let _ = tx.send(());
        }
    }));
    pc.set_onicegatheringstatechange(Some(cb.as_ref().unchecked_ref()));
    let _ = rx.await;
    pc.set_onicegatheringstatechange(None);
    drop(cb);
}

fn sdp_type_str(t: RtcSdpType) -> &'static str {
    match t {
        RtcSdpType::Offer => "offer",
        RtcSdpType::Answer => "answer",
        RtcSdpType::Pranswer => "pranswer",
        RtcSdpType::Rollback => "rollback",
        _ => "offer",
    }
}

fn parse_sdp_type(s: &str) -> Result<RtcSdpType, WebRtcError> {
    match s {
        "offer" => Ok(RtcSdpType::Offer),
        "answer" => Ok(RtcSdpType::Answer),
        "pranswer" => Ok(RtcSdpType::Pranswer),
        "rollback" => Ok(RtcSdpType::Rollback),
        other => Err(WebRtcError::Signaling(format!(
            "unsupported SDP type: {other}"
        ))),
    }
}
