//! The PIPE-handshake **client** (G3 relay slice 1): fetch the pipe key from an
//! adjacent upstream node that holds it, so an on-path relay obtains the credential
//! that authenticates teardown. The thesis's Table 8 PIPE exchange, request side.
//!
//! Pairs with the upstream **serve** side (`PipeProducer`'s and `PipeRelay`'s PIPE
//! handlers), which seal `pipe_key ‖ PUI` to the requester's session public key. Only
//! the requester (holding the session private half) can open it — a relay learns the
//! key without it ever appearing on the wire in the clear.

use std::time::Duration;

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_packet::encode::InterestBuilder;

use crate::crypto::ConsumerSession;
use crate::message::{decode_pipe_bundle, pipe_name};

/// Fetch the pipe key + PUI for `pipe_id` from the adjacent upstream node, addressed
/// by `upstream_hop` (this node's hop index + 1). Generates an ephemeral session,
/// advertises its public key in the PIPE Interest, and opens the sealed reply.
/// `None` if no holder answered or the reply couldn't be opened/parsed.
pub async fn fetch_pipe_key(
    consumer: &mut Consumer,
    pipe_id: &[u8],
    upstream_hop: u32,
    timeout: Duration,
) -> Option<(Bytes, Duration)> {
    let session = ConsumerSession::generate()?;
    let wire = InterestBuilder::new(pipe_name(pipe_id, upstream_hop))
        .app_parameters(session.public.to_vec())
        .lifetime(timeout)
        .build();
    let data = consumer.fetch_wire(wire, timeout).await.ok()?;
    let sealed = data.content()?;
    let plain = session.open(sealed.as_ref())?;
    decode_pipe_bundle(&plain)
}
