//! NDN face transport over serial (UART) links for embedded and IoT, with
//! COBS framing. [`SerialFace`] is a `StreamFace` alias; open via
//! [`serial_face_open`].
//!
//! An **extension** transport — serial faces have no NFD/ndnd analogue.

#![allow(missing_docs)]

pub mod cobs;
mod serial;

pub use cobs::CobsCodec;
pub use serial::{SerialFace, serial_face_open};
