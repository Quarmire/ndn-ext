//! **NDN-Pipes v2** — two-band named-data transport on ndn-rs.
//!
//! The published NDN-Pipes thesis protocol (Le 2025) — a shared **common
//! channel** carries lightweight `SEEK` coordination to find a producer, then a
//! dedicated **pipe** carries the bulk — re-architected on ndn-rs as a
//! *best-of-both*: faithful to the thesis message set and crypto, over a modern
//! substrate (reflexive forwarding for the reverse route, `ndn-coding` FEC for
//! the no-ARQ bearer, `ndn-signals-core` for adaptation, name-group MAC
//! couplings). See `.claude/notes/named-radio/ndn-pipes-v2-best-of-both-*.md`.
//!
//! The message set (Tables 3–10): SEEK / HIDE / JOIN / CONTEXT / LINK / PIPE /
//! CHECK / TEARDOWN. This crate currently lands the **foundation** — the
//! message-name contract ([`message`]) and pipe state ([`pipe`]); the
//! consumer/producer state machine, relay participation, teardown, and the
//! `PIPES` mgmt module are built on top witness-first over emulated faces.

mod confidentiality;
mod consumer;
mod crypto;
pub mod message;
mod mgmt;
pub mod pipe;
mod producer;
mod registry;
mod relay;

pub use confidentiality::Confidentiality;
pub use consumer::PipeConsumer;
/// Derive a producer's Ed25519 trust anchor (public key) from its signing key,
/// for [`PipeConsumer::with_trust_anchor`] / [`PipeProducer::with_identity`].
pub use crypto::ed25519_public;
pub use message::{
    COMMON_PREFIX, GHL, JOIN_PREFIX, MessageKind, SEEK_PREFIX, check_name, classify, context_name,
    decode_seek_reply, encode_seek_reply, hop_index, join_name, link_name, pipe_name, seek_name,
    teardown_name,
};
pub use mgmt::{PipesModule, render_list};
pub use pipe::{Pipe, PipeId, PipeParams};
pub use producer::PipeProducer;
pub use registry::{PipeInfo, PipeRegistry};
pub use relay::PipeRelay;

/// Errors from pipe setup and transfer.
#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    /// No producer answered the SEEK before its lifetime elapsed.
    #[error("no producer answered SEEK for {0}")]
    NoProducer(String),
    /// An application-layer fetch/serve error (Interest expression, timeout).
    #[error(transparent)]
    App(#[from] ndn_app::AppError),
    /// A coding (segment/recover) error from the K-of-N transfer.
    #[error("coding: {0}")]
    Coding(String),
    /// The producer/consumer crypto handshake failed (bad pipe id / nonce).
    #[error("pipe crypto: {0}")]
    Crypto(String),
}
