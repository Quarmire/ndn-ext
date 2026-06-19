//! AF_XDP kernel-bypass Ethernet face for ndn-rs (Linux only).
//!
//! An **extension** transport: a faster I/O backend for the EtherType-`0x8624`
//! Ethernet face, selected via `[[face]] kind="ether" io="afxdp"`. Builds on
//! `ndn-face`'s Ethernet framing + interface helpers. Empty on non-Linux.

#![allow(missing_docs)]

#[cfg(target_os = "linux")]
mod af_xdp;
#[cfg(target_os = "linux")]
pub use af_xdp::AfXdpFace;
