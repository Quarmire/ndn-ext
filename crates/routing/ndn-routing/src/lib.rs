//! NDN routing protocol implementations.
//!
//! Pluggable routing algorithms for the NDN forwarder:
//!
//! - [`StaticProtocol`] — fixed routes installed at startup.
//! - [`NlsrProtocol`] — NLSR link-state, interop with the C++ NLSR reference.
//! - [`protocols::dv`] — ndn-dv distance-vector per `ndnd/dv/SPEC.md`.
//!
//! Register a protocol with `EngineBuilder::register_routing_protocol`.

pub mod protocols;

pub use protocols::nlsr::protocol::NeighborConfig;
pub mod nlsr {
    pub use crate::protocols::nlsr::{NlsrConfig, NlsrIo, NlsrProtocol};
}
pub use protocols::nlsr::{NlsrConfig, NlsrIo, NlsrProtocol};
pub use protocols::r#static::{StaticProtocol, StaticRoute};
