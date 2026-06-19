//! ndn-dv distance-vector routing per `ndnd/dv/SPEC.md`.
//!
//! Reference impl: `ndnd/dv/` (Go).
//! Paper: Patil et al., *Poster: Distance Vector Routing for Named Data
//! Networking*, CoNEXT '24 (DOI `10.1145/3680121.3699885`).
//!
//! ndn-rs divergences from ndnd:
//! - LP reliability default OFF (NDN-LP Ack/TxSequence rejected by ndnd).
//! - Adv/Pfx Data content is bare entries (no outer 0xC9/0x12D wrapper),
//!   matching ndnd's `client.Produce`.

pub mod fib;
pub mod pfx_sync;
pub mod prefix;
pub mod protocol;
pub mod rib;
pub mod signing;
pub mod sync;
pub mod tlv;

pub use protocol::{DvConfig, DvProtocol};
