//! NLSR — Named-data Link State Routing.
//!
//! C++ reference: `NLSR/src/` (named-data/NLSR).

pub mod hello;
pub mod lsa;
pub mod lsdb;
pub mod name_prefix_table;
pub mod protocol;
pub mod routing_table;
pub mod sync;

pub use protocol::{NlsrConfig, NlsrIo, NlsrProtocol};

#[derive(Debug)]
pub enum NlsrError {
    Codec(String),
    LsaNotFound,
    StaleSequence,
}

impl std::fmt::Display for NlsrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlsrError::Codec(msg) => write!(f, "NLSR codec error: {msg}"),
            NlsrError::LsaNotFound => write!(f, "LSA not found"),
            NlsrError::StaleSequence => write!(f, "stale LSA sequence number"),
        }
    }
}

impl std::error::Error for NlsrError {}

impl From<crate::protocols::nlsr::lsa::LsaCodecError> for NlsrError {
    fn from(e: crate::protocols::nlsr::lsa::LsaCodecError) -> Self {
        NlsrError::Codec(e.to_string())
    }
}
