//! Routing protocol implementations.
//!
//! Each sub-module contains one algorithm implementing
//! [`RoutingProtocol`](ndn_engine::RoutingProtocol); some also implement
//! [`DiscoveryProtocol`](ndn_discovery::DiscoveryProtocol) for protocols
//! that need direct packet I/O.

pub mod dv;
pub mod nlsr;
pub mod r#static;

pub use nlsr::NlsrProtocol;
pub use r#static::{StaticProtocol, StaticRoute};
