//! The link library's own face to the host's forwarder: it sends punch
//! Interests and takes their answers, and takes the punches other devices
//! send to this one (`<device>/32=link/32=punch`). Punches are plain NDN
//! packets, so they reach the other device through whatever routes reach
//! it — normally its relay.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::oneshot;

use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Interest, Name};
use ndn_transport::{Face, FaceId};

use crate::host::Route;
use crate::links::Links;
use crate::punch::punch_prefix;

/// What answered a punch Interest.
pub(crate) enum Answer {
    Data(Data),
    /// A Nack, with its reason, and whether this device's own forwarder
    /// refused (a local refusal, e.g. Data it cannot validate).
    Nack { why: String, refused: bool },
}

pub(crate) struct Signal {
    handle: InProcHandle,
    face: FaceId,
    pending: Mutex<HashMap<Name, oneshot::Sender<Answer>>>,
    routed: Mutex<HashSet<Name>>,
}

/// Packets queued between the face and the forwarder.
const QUEUE: usize = 64;

impl Signal {
    /// The face, added to the host's forwarder; it lives until `links` is
    /// cancelled.
    pub(crate) fn start(links: &Arc<Links>) -> Arc<Self> {
        let faces = links.faces();
        let id = faces.alloc_face_id();
        let (face, handle) = InProcFace::new(id, QUEUE);
        let kind = ndn_transport::Transport::kind(&face);
        faces.add_face(
            Face::from_parts(Arc::new(face), ndn_transport::default_link_service_for_kind(kind)),
            links.cancel_token().child_token(),
        );
        let signal = Arc::new(Self {
            handle,
            face: id,
            pending: Mutex::new(HashMap::new()),
            routed: Mutex::new(HashSet::new()),
        });
        tokio::spawn(receive(Arc::downgrade(links), Arc::clone(&signal)));
        signal
    }

    /// Route the punches to `device` (this device's name) to this face.
    pub(crate) fn take_punches_for(&self, links: &Links, device: &Name) {
        let prefix = punch_prefix(device);
        if self.routed.lock().insert(prefix.clone()) {
            links.faces().add_routes(self.face, &[Route { prefix, cost: 0 }]);
        }
    }

    /// Send the punch Interest `wire` and wait (up to `within`) for its
    /// answer.
    pub(crate) async fn express(&self, wire: Bytes, within: Duration) -> Result<Answer, String> {
        let name = Interest::decode(wire.clone())
            .map_err(|e| format!("the punch Interest does not decode: {e}"))?
            .name;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert((*name).clone(), tx);
        let sent = self.handle.send(wire).await;
        let answer = match sent {
            Ok(()) => tokio::time::timeout(within, rx).await,
            Err(_) => {
                self.pending.lock().remove(&*name);
                return Err("this device's forwarder took no punch Interest (it is stopping)".into());
            }
        };
        self.pending.lock().remove(&*name);
        match answer {
            Ok(Ok(answer)) => Ok(answer),
            _ => Err(format!("no answer within {} s", within.as_secs())),
        }
    }

    /// Send an answer (Data) to the forwarder.
    pub(crate) async fn send(&self, wire: Bytes) {
        let _ = self.handle.send(wire).await;
    }

    fn answered(&self, name: &Name, answer: Answer) {
        if let Some(tx) = self.pending.lock().remove(name) {
            let _ = tx.send(answer);
        }
    }
}

/// Take what the forwarder hands the face: answers to this device's
/// punches, and punches for it.
async fn receive(links: Weak<Links>, signal: Arc<Signal>) {
    while let Some(wire) = signal.handle.recv().await {
        let (wire, nack) = if is_lp_packet(&wire) {
            match LpPacket::decode(wire) {
                Ok(LpPacket {
                    fragment: Some(fragment),
                    nack,
                    ..
                }) => (fragment, nack),
                _ => continue,
            }
        } else {
            (wire, None)
        };
        match wire.first() {
            Some(0x05) => {
                let Ok(interest) = Interest::decode(wire) else { continue };
                if let Some(nack) = nack {
                    let (why, refused) = match nack.reason {
                        Some(reason) => (format!("Nack {reason:?} ({})", reason.code()), reason.refusal().is_some()),
                        None => ("a Nack".into(), false),
                    };
                    signal.answered(&interest.name, Answer::Nack { why, refused });
                    continue;
                }
                let Some(links) = links.upgrade() else { return };
                tokio::spawn(async move { links.answer_punch(interest).await });
            }
            Some(0x06) => {
                if let Ok(data) = Data::decode(wire) {
                    let name = (*data.name).clone();
                    signal.answered(&name, Answer::Data(data));
                }
            }
            _ => {}
        }
    }
}
