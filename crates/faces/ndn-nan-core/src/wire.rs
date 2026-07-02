//! Little-endian read/write primitives over byte buffers.
//!
//! NAN is little-endian on the wire. The [`Reader`] is a bounds-checked cursor
//! (every accessor returns [`WireError::Truncated`] rather than panicking on a
//! short buffer — frames come off a lossy radio and may be malformed). Writing
//! is plain `push_*` onto an [`alloc::vec::Vec<u8>`] via the [`WriteExt`] trait,
//! so the typed builders read as a transcription of the byte layout.

use alloc::vec::Vec;

/// A decode error. Frames arrive from a lossy/hostile medium, so decoding never
/// panics — it returns one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Ran off the end of the buffer (a field's bytes are not all present).
    Truncated,
    /// A field held a value outside the set this decoder accepts (e.g. a
    /// declared attribute length that overruns the buffer, or a frame whose
    /// fixed tag bytes don't match NAN).
    Invalid,
}

/// A bounds-checked little-endian cursor over a byte slice.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True once every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The not-yet-consumed tail, without advancing.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Take `n` raw bytes, advancing past them.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Take a fixed `N`-byte array (e.g. a 6-byte MAC / service ID).
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// Take one byte.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    /// Take a little-endian `u16`.
    pub fn le16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Take a little-endian `u32`.
    pub fn le32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Take a little-endian `u64`.
    pub fn le64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

/// Little-endian append helpers for building frames into a `Vec<u8>`.
pub trait WriteExt {
    fn put_u8(&mut self, v: u8);
    fn put_le16(&mut self, v: u16);
    fn put_le32(&mut self, v: u32);
    fn put_le64(&mut self, v: u64);
    fn put_bytes(&mut self, v: &[u8]);
}

impl WriteExt for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }
    fn put_le16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_le32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_le64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_bytes(&mut self, v: &[u8]) {
        self.extend_from_slice(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_scalars() {
        let mut b = Vec::new();
        b.put_u8(0xA5);
        b.put_le16(0x1234);
        b.put_le32(0xDEAD_BEEF);
        b.put_le64(0x0102_0304_0506_0708);
        b.put_bytes(&[1, 2, 3]);
        // little-endian on the wire
        assert_eq!(&b[0..1], &[0xA5]);
        assert_eq!(&b[1..3], &[0x34, 0x12]);
        assert_eq!(&b[3..7], &[0xEF, 0xBE, 0xAD, 0xDE]);

        let mut r = Reader::new(&b);
        assert_eq!(r.u8().unwrap(), 0xA5);
        assert_eq!(r.le16().unwrap(), 0x1234);
        assert_eq!(r.le32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.le64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.take(3).unwrap(), &[1, 2, 3]);
        assert!(r.is_empty());
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        let mut r = Reader::new(&[0x01, 0x02]);
        assert_eq!(r.le16().unwrap(), 0x0201);
        assert_eq!(r.u8(), Err(WireError::Truncated));
        assert_eq!(r.le32(), Err(WireError::Truncated));
    }

    #[test]
    fn take_array_extracts_mac() {
        let mut r = Reader::new(&[0x50, 0x6F, 0x9A, 0x01, 0x02, 0x03, 0xFF]);
        let mac: [u8; 6] = r.take_array().unwrap();
        assert_eq!(mac, [0x50, 0x6F, 0x9A, 0x01, 0x02, 0x03]);
        assert_eq!(r.remaining(), 1);
    }
}
