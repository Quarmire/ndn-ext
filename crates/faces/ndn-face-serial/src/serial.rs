use ndn_transport::{FaceId, FaceKind};

use crate::cobs::CobsCodec;

/// NDN face over a serial port with COBS framing. `0x00` never appears in the
/// encoded payload, so resync is at most one frame away after line noise.
pub type SerialFace = ndn_transport::StreamFace<
    tokio::io::ReadHalf<tokio_serial::SerialStream>,
    tokio::io::WriteHalf<tokio_serial::SerialStream>,
    CobsCodec,
>;

pub fn serial_face_open(
    id: FaceId,
    port: impl Into<String>,
    baud: u32,
) -> std::io::Result<SerialFace> {
    let port = port.into();
    let builder = tokio_serial::new(&port, baud);
    let stream = tokio_serial::SerialStream::open(&builder)?;
    let (r, w) = tokio::io::split(stream);
    let uri = format!("serial://{}", port);
    Ok(ndn_transport::StreamFace::new(
        id,
        FaceKind::Serial,
        Some(uri.clone()),
        Some(uri),
        r,
        w,
        CobsCodec::new(),
    ))
}
