//! **Onion / oblivious forwarding for NDN** (G5) — *draft, non-standard.*
//!
//! ANDaNA-style (Anonymous NDN, DiBenedetto et al.) consumer unlinkability: a request is
//! wrapped in one encryption layer per anonymizing relay on a *circuit*, so no single
//! relay sees both who is asking and what is being asked. Each relay peels exactly one
//! layer — learning only the next hop and an opaque inner blob — and forwards it; the exit
//! relay recovers the real Interest and forwards it to the producer. Returning Data is
//! re-wrapped a layer at each relay on the way back, and the consumer (who holds every
//! hop key) peels them all.
//!
//! This is the layer the NDF privacy tiers can't reach: hiding the *network path* is the
//! forwarder's job. Name/content confidentiality (encrypted-suffix naming, PIR) is NDF's.
//!
//! ## Scope of this crate
//!
//! The **symmetric data-plane onion**: layered ChaCha20-Poly1305 over a circuit of per-hop
//! keys (repeatable — every Interest on the circuit re-uses the hop keys). This is the
//! novel forwarding-anonymity mechanism, and it is transport-agnostic (addresses are
//! opaque bytes the face layer resolves to forwarding-hints).
//!
//! **Out of scope here (the circuit *setup*):** how the consumer establishes a shared
//! [`HopKey`] with each relay — a per-circuit key agreement against the relay's long-lived
//! onion key (an asymmetric handshake, like Tor's). The data-plane below is independent of
//! that; wire the keys in via [`Circuit`] however setup produces them.
//!
//! ## Non-standard
//!
//! ANDaNA is research, not an NDN community spec; mark any user-facing surface that exposes
//! this as a **draft extension**.

use bytes::Bytes;
use ndn_crypto_core::{open_in_place, seal_in_place};

/// AEAD additional-authenticated-data: domain separation for onion layers.
const ONION_AAD: &[u8] = b"ndn-onion/v0";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// A 32-byte symmetric key shared with one relay for one circuit.
pub type HopKey = [u8; 32];

/// An opaque relay address — whatever the face layer resolves to a forwarding-hint
/// (a Name URI, an endpoint id, …). The onion core never interprets it.
pub type RelayAddr = Bytes;

/// What peeling one forward layer yields at a relay.
#[derive(Clone, Debug)]
pub struct Peeled {
    /// `Some(addr)` ⇒ forward `inner` (the next layer) to that relay; `None` ⇒ this is the
    /// **exit**, and `inner` is the real Interest to forward to the producer.
    pub next: Option<RelayAddr>,
    pub inner: Bytes,
}

/// Onion errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OnionError {
    #[error("empty circuit")]
    EmptyCircuit,
    #[error("layer too short")]
    Truncated,
    #[error("authentication failed (wrong key or tampered layer)")]
    AuthFailed,
    #[error("RNG failure")]
    Rng,
}

/// One hop of a circuit: where to send + the key shared with that relay.
#[derive(Clone)]
pub struct Hop {
    pub addr: RelayAddr,
    pub key: HopKey,
}

/// A consumer's circuit: ordered hops, `hops[0]` the entry, the last the exit.
#[derive(Clone)]
pub struct Circuit {
    hops: Vec<Hop>,
}

impl Circuit {
    pub fn new(hops: Vec<Hop>) -> Self {
        Self { hops }
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Wrap `inner` (a real Interest wire) into nested layers for this circuit. Returns
    /// the entry relay's address and the outermost onion to send there.
    pub fn wrap_forward(&self, inner: &[u8]) -> Result<(RelayAddr, Bytes), OnionError> {
        if self.hops.is_empty() {
            return Err(OnionError::EmptyCircuit);
        }
        // Build innermost (exit) first, wrapping outward to the entry.
        let mut payload = inner.to_vec();
        for i in (0..self.hops.len()).rev() {
            let next_addr: &[u8] = if i + 1 < self.hops.len() {
                self.hops[i + 1].addr.as_ref()
            } else {
                &[] // exit: no next hop
            };
            let plaintext = encode_inner(next_addr, &payload);
            payload = seal_layer(&self.hops[i].key, &plaintext)?;
        }
        Ok((self.hops[0].addr.clone(), Bytes::from(payload)))
    }

    /// Peel every return layer the relays added on the way back (entry's outermost first,
    /// exit's innermost last), recovering the producer's Data.
    pub fn unwrap_return(&self, onion: &[u8]) -> Result<Bytes, OnionError> {
        if self.hops.is_empty() {
            return Err(OnionError::EmptyCircuit);
        }
        let mut payload = onion.to_vec();
        for hop in &self.hops {
            payload = open_layer(&hop.key, &payload)?;
        }
        Ok(Bytes::from(payload))
    }
}

/// Relay side: peel one forward layer with `hop_key`. Returns the next hop + inner blob,
/// or an auth error if the layer wasn't sealed for this relay (or was tampered).
pub fn peel(hop_key: &HopKey, layer: &[u8]) -> Result<Peeled, OnionError> {
    let plaintext = open_layer(hop_key, layer)?;
    let (next_addr, inner) = decode_inner(&plaintext)?;
    Ok(Peeled {
        next: (!next_addr.is_empty()).then(|| Bytes::copy_from_slice(next_addr)),
        inner: Bytes::copy_from_slice(inner),
    })
}

/// Relay side: add this relay's return layer to a returning `data` blob on the way back to
/// the consumer.
pub fn wrap_return(hop_key: &HopKey, data: &[u8]) -> Result<Bytes, OnionError> {
    Ok(Bytes::from(seal_layer(hop_key, data)?))
}

// ---- layer codec --------------------------------------------------------------

/// `nonce(12) ‖ tag(16) ‖ ciphertext`.
fn seal_layer(key: &HopKey, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| OnionError::Rng)?;
    let mut buf = plaintext.to_vec();
    let tag = seal_in_place(key, &nonce, ONION_AAD, &mut buf).ok_or(OnionError::AuthFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + TAG_LEN + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buf);
    Ok(out)
}

fn open_layer(key: &HopKey, layer: &[u8]) -> Result<Vec<u8>, OnionError> {
    if layer.len() < NONCE_LEN + TAG_LEN {
        return Err(OnionError::Truncated);
    }
    let nonce: [u8; NONCE_LEN] = layer[..NONCE_LEN].try_into().unwrap();
    let tag: [u8; TAG_LEN] = layer[NONCE_LEN..NONCE_LEN + TAG_LEN].try_into().unwrap();
    let mut buf = layer[NONCE_LEN + TAG_LEN..].to_vec();
    if open_in_place(key, &nonce, ONION_AAD, &mut buf, &tag) {
        Ok(buf)
    } else {
        Err(OnionError::AuthFailed)
    }
}

/// Layer plaintext: `addr_len(u16 BE) ‖ addr ‖ inner`. `addr_len == 0` marks the exit.
fn encode_inner(addr: &[u8], inner: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + addr.len() + inner.len());
    v.extend_from_slice(&(addr.len() as u16).to_be_bytes());
    v.extend_from_slice(addr);
    v.extend_from_slice(inner);
    v
}

fn decode_inner(plaintext: &[u8]) -> Result<(&[u8], &[u8]), OnionError> {
    if plaintext.len() < 2 {
        return Err(OnionError::Truncated);
    }
    let addr_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    let rest = &plaintext[2..];
    if rest.len() < addr_len {
        return Err(OnionError::Truncated);
    }
    Ok((&rest[..addr_len], &rest[addr_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(addr: &str, k: u8) -> Hop {
        Hop {
            addr: Bytes::from(addr.to_owned()),
            key: [k; 32],
        }
    }

    /// A 3-relay circuit: the Interest is peeled hop-by-hop to the exit, and the Data is
    /// re-wrapped hop-by-hop back to the consumer — no relay ever sees both ends in clear.
    #[test]
    fn three_hop_forward_and_return_round_trip() {
        let circuit = Circuit::new(vec![hop("/r/a", 1), hop("/r/b", 2), hop("/r/c", 3)]);
        let interest = b"/secret/document/v=42 (the real interest wire)";

        // Forward: consumer wraps; each relay peels exactly one layer.
        let (entry, mut onion) = circuit.wrap_forward(interest).unwrap();
        assert_eq!(entry.as_ref(), b"/r/a", "send to the entry relay");

        // Hop A peels → next is B, inner is opaque (B's layer).
        let a = peel(&[1; 32], &onion).unwrap();
        assert_eq!(a.next.as_deref(), Some(b"/r/b".as_ref()));
        assert_ne!(a.inner.as_ref(), interest, "A cannot see the real interest");
        onion = a.inner.to_vec().into();

        let b = peel(&[2; 32], &onion).unwrap();
        assert_eq!(b.next.as_deref(), Some(b"/r/c".as_ref()));
        onion = b.inner.to_vec().into();

        // Exit C peels → no next hop; inner IS the real interest.
        let c = peel(&[3; 32], &onion).unwrap();
        assert_eq!(c.next, None, "exit relay");
        assert_eq!(c.inner.as_ref(), interest, "exit recovers the real interest");

        // Return: producer's Data, re-wrapped exit→entry, peeled by the consumer.
        let data = b"<the producer's Data wire>";
        let mut ret = wrap_return(&[3; 32], data).unwrap(); // exit (innermost)
        ret = wrap_return(&[2; 32], &ret).unwrap();
        ret = wrap_return(&[1; 32], &ret).unwrap(); // entry (outermost)
        let recovered = circuit.unwrap_return(&ret).unwrap();
        assert_eq!(recovered.as_ref(), data, "consumer recovers the Data");
    }

    #[test]
    fn wrong_key_or_tamper_fails_closed() {
        let circuit = Circuit::new(vec![hop("/r/a", 1), hop("/r/b", 2)]);
        let (_, onion) = circuit.wrap_forward(b"x").unwrap();
        // A relay with the wrong key can't peel.
        assert_eq!(peel(&[9; 32], &onion).unwrap_err(), OnionError::AuthFailed);
        // A flipped byte fails authentication.
        let mut tampered = onion.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert_eq!(peel(&[1; 32], &tampered).unwrap_err(), OnionError::AuthFailed);
    }

    #[test]
    fn single_hop_is_a_degenerate_circuit() {
        let circuit = Circuit::new(vec![hop("/r/only", 7)]);
        let (entry, onion) = circuit.wrap_forward(b"hello").unwrap();
        assert_eq!(entry.as_ref(), b"/r/only");
        let p = peel(&[7; 32], &onion).unwrap();
        assert_eq!(p.next, None);
        assert_eq!(p.inner.as_ref(), b"hello");

        let ret = wrap_return(&[7; 32], b"data").unwrap();
        assert_eq!(circuit.unwrap_return(&ret).unwrap().as_ref(), b"data");
    }

    #[test]
    fn empty_circuit_errors() {
        assert_eq!(Circuit::new(vec![]).wrap_forward(b"x").unwrap_err(), OnionError::EmptyCircuit);
    }
}
