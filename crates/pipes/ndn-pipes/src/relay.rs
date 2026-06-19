//! Relay side: a node *between* consumer and producer that participates in pipe
//! formation on the COMMON control band, while the engine forwards the data
//! plane toward the producer.
//!
//! Faithful to the thesis's coordinator-free addressing: the relay derives its
//! own hop index from `GHL − remaining HopLimit` — no configuration, no central
//! assignment — and answers CONTEXT/LINK/PIPE for its hop. The full per-hop
//! bundle (LINK) and pipe-key handoff (PIPE) carry the same hop today; the key
//! exchange and PUI-driven teardown land in a later slice.

use ndn_app::{AppError, Producer};
use ndn_packet::encode::DataBuilder;

use crate::message::{GHL, MessageKind, classify, hop_index};

/// A pipe relay: serves the COMMON control channel for one node on the path.
/// Its [`Producer`] must be registered on the relay engine for [`COMMON_PREFIX`]
/// (`/COMMON`); non-control names are left to the engine to forward onward.
///
/// [`COMMON_PREFIX`]: crate::message::COMMON_PREFIX
pub struct PipeRelay {
    producer: Producer,
}

impl PipeRelay {
    pub fn new(producer: Producer) -> Self {
        Self { producer }
    }

    /// Serve the COMMON control band. On CONTEXT/LINK/PIPE the relay reports the
    /// hop index it derived locally from the Interest's remaining HopLimit — the
    /// witnessable proof of coordinator-free addressing. Anything else is left
    /// unanswered (it isn't ours to control).
    pub async fn serve(self) -> Result<(), AppError> {
        self.producer
            .serve(move |interest, responder| async move {
                let name = (*interest.name).clone();
                let remaining = interest.hop_limit().unwrap_or(GHL);
                let hop = hop_index(GHL, remaining);
                match classify(&name) {
                    Some(MessageKind::Context | MessageKind::Link | MessageKind::Pipe) => {
                        let d = DataBuilder::new(name, &[hop]).build();
                        responder.respond_bytes(d).await.ok();
                    }
                    _ => drop(responder),
                }
            })
            .await
    }
}
