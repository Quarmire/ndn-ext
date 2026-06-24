//! **Onion / oblivious forwarding for NDN** (G5) — *draft, non-standard.*
//!
//! ANDaNA-style (Anonymous NDN, DiBenedetto et al.) consumer unlinkability: a request is
//! wrapped in one encryption layer per anonymizing relay on a *circuit*, so no single
//! relay sees both who is asking and what is being asked. Each relay peels exactly one
//! layer — learning only the next hop and an opaque inner blob — and forwards it; the exit
//! relay recovers the real Interest and forwards it to the producer. Returning Data is
//! re-wrapped a layer at each relay on the way back, and the consumer (who holds every hop
//! key) peels them all.
//!
//! This is the layer the NDF privacy tiers can't reach: hiding the *network path* is the
//! forwarder's job. Name/content confidentiality (encrypted-suffix naming, PIR) is NDF's.
//!
//! ## Circuit setup is built in (no separate handshake round)
//!
//! Each relay has a long-lived **static X25519 onion key** ([`RelayOnionKey`]); the
//! consumer knows the public half of every relay on the circuit. To wrap a layer for relay
//! *i*, the consumer mints a fresh **ephemeral** key, derives the hop key
//! `HopKey_i = HKDF(ephemeral_i × relay_i_static)`, and prefixes the layer with the
//! ephemeral public key. Relay *i* reconstructs the same `HopKey_i` from its static secret
//! and that ephemeral key, then decrypts. So the per-circuit key agreement rides inside the
//! onion itself — no telescoping setup, just a directory of relay onion pubkeys. (A relay
//! re-uses its static key across every Interest, which is why this needs static-key X25519,
//! not ring's one-shot ephemeral agreement.) The return path is then symmetric under those
//! hop keys.
//!
//! ## Non-standard
//!
//! ANDaNA is research, not an NDN community spec; mark any user-facing surface as a
//! **draft extension**.

use std::collections::HashMap;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_crypto_core::{open_in_place, seal_in_place};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// AEAD additional-authenticated-data: domain separation for onion layers.
const ONION_AAD: &[u8] = b"ndn-onion/v0";
/// HKDF info string for deriving a hop key from a DH shared secret.
const HOP_KDF_INFO: &[u8] = b"ndn-onion/hop-key/v0";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const EPH_LEN: usize = 32;

/// A 32-byte symmetric key shared with one relay for one circuit (HKDF of the hop's DH).
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
    /// The hop key derived for this relay — keep it (keyed by the inner request) to
    /// [`wrap_return`] the matching Data on the way back.
    pub hop_key: HopKey,
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

/// A relay's long-lived static X25519 onion key. Its [`public`](Self::public) half goes in
/// the circuit directory; the secret peels forward layers + derives the hop key.
pub struct RelayOnionKey {
    secret: StaticSecret,
}

impl RelayOnionKey {
    /// Generate a fresh onion key.
    pub fn generate() -> Result<Self, OnionError> {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).map_err(|_| OnionError::Rng)?;
        Ok(Self {
            secret: StaticSecret::from(b),
        })
    }

    /// Construct from raw secret bytes (e.g. loaded from a keystore).
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(secret),
        }
    }

    /// The 32-byte public onion key to advertise.
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// Peel one forward layer addressed to this relay.
    pub fn peel(&self, layer: &[u8]) -> Result<Peeled, OnionError> {
        if layer.len() < EPH_LEN {
            return Err(OnionError::Truncated);
        }
        let eph_pub: [u8; 32] = layer[..EPH_LEN].try_into().unwrap();
        let hop_key = derive_hop_key(&self.secret.diffie_hellman(&PublicKey::from(eph_pub)));
        let plaintext = open_sym(&hop_key, &layer[EPH_LEN..])?;
        let (next_addr, inner) = decode_inner(&plaintext)?;
        Ok(Peeled {
            next: (!next_addr.is_empty()).then(|| Bytes::copy_from_slice(next_addr)),
            inner: Bytes::copy_from_slice(inner),
            hop_key,
        })
    }
}

/// One hop of a circuit: where to send + that relay's static onion public key.
#[derive(Clone)]
pub struct Hop {
    pub addr: RelayAddr,
    pub onion_pub: [u8; 32],
}

/// A wrapped request ready to send: the entry relay, the onion, and the per-hop keys the
/// consumer must keep to [`unwrap_return`] the matching Data.
#[derive(Debug)]
pub struct Wrapped {
    pub entry: RelayAddr,
    pub onion: Bytes,
    pub return_keys: Vec<HopKey>,
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

    /// Wrap `inner` (a real Interest wire) for this circuit, deriving a fresh hop key per
    /// relay. Returns the entry address, the onion, and the hop keys (hop order) for the
    /// return path.
    pub fn wrap_forward(&self, inner: &[u8]) -> Result<Wrapped, OnionError> {
        if self.hops.is_empty() {
            return Err(OnionError::EmptyCircuit);
        }
        let mut payload = inner.to_vec();
        let mut return_keys = vec![[0u8; 32]; self.hops.len()];
        // Build innermost (exit) first, wrapping outward to the entry.
        for i in (0..self.hops.len()).rev() {
            let next_addr: &[u8] = if i + 1 < self.hops.len() {
                self.hops[i + 1].addr.as_ref()
            } else {
                &[] // exit: no next hop
            };
            let plaintext = encode_inner(next_addr, &payload);
            let (layer, hop_key) = seal_forward_layer(&self.hops[i].onion_pub, &plaintext)?;
            return_keys[i] = hop_key;
            payload = layer;
        }
        Ok(Wrapped {
            entry: self.hops[0].addr.clone(),
            onion: Bytes::from(payload),
            return_keys,
        })
    }
}

/// Relay side: add this relay's return layer to a returning `data` blob (symmetric under
/// the hop key derived during [`RelayOnionKey::peel`]).
pub fn wrap_return(hop_key: &HopKey, data: &[u8]) -> Result<Bytes, OnionError> {
    Ok(Bytes::from(seal_sym(hop_key, data)?))
}

/// Consumer side: peel every return layer (entry's outermost first, exit's innermost
/// last) with the `return_keys` from [`Circuit::wrap_forward`], recovering the Data.
pub fn unwrap_return(return_keys: &[HopKey], onion: &[u8]) -> Result<Bytes, OnionError> {
    if return_keys.is_empty() {
        return Err(OnionError::EmptyCircuit);
    }
    let mut payload = onion.to_vec();
    for key in return_keys {
        payload = open_sym(key, &payload)?;
    }
    Ok(Bytes::from(payload))
}

/// Consumer-side driver: wraps outgoing requests over a [`Circuit`] and keeps each
/// request's return keys (by an opaque token) so the matching returned onion can be
/// unwrapped. A face plugs its transport around this (`wrap` → send to `entry`; on the
/// reply → `unwrap`).
pub struct OnionConsumer {
    circuit: Circuit,
    pending: HashMap<u64, Vec<HopKey>>,
    next_token: u64,
}

impl OnionConsumer {
    pub fn new(circuit: Circuit) -> Self {
        Self {
            circuit,
            pending: HashMap::new(),
            next_token: 0,
        }
    }

    /// Wrap `inner`; returns `(token, entry_addr, onion)`. Send `onion` to `entry_addr`;
    /// pass the reply onion + `token` to [`unwrap`](Self::unwrap).
    pub fn wrap(&mut self, inner: &[u8]) -> Result<(u64, RelayAddr, Bytes), OnionError> {
        let w = self.circuit.wrap_forward(inner)?;
        let token = self.next_token;
        self.next_token += 1;
        self.pending.insert(token, w.return_keys);
        Ok((token, w.entry, w.onion))
    }

    /// Unwrap the reply onion for `token`, freeing the request's state.
    pub fn unwrap(&mut self, token: u64, onion: &[u8]) -> Result<Bytes, OnionError> {
        let keys = self.pending.remove(&token).ok_or(OnionError::EmptyCircuit)?;
        unwrap_return(&keys, onion)
    }
}

/// Relay-side driver: peels forward layers with this relay's onion key and remembers each
/// derived hop key by a caller-supplied **correlation** (the inner request's identity — its
/// name, which the face extracts from `Peeled::inner`), so the matching returning Data can
/// be re-wrapped. A face plugs its transport + PIT around this: on a forward onion call
/// [`forward`](Self::forward) then [`remember`](Self::remember) the inner interest's name;
/// on the matching Data call [`wrap_return`](Self::wrap_return) and send the result back the
/// way the onion came.
pub struct OnionRelay {
    key: RelayOnionKey,
    pending: HashMap<Vec<u8>, HopKey>,
}

impl OnionRelay {
    pub fn new(key: RelayOnionKey) -> Self {
        Self {
            key,
            pending: HashMap::new(),
        }
    }

    /// This relay's public onion key (for the directory).
    pub fn public(&self) -> [u8; 32] {
        self.key.public()
    }

    /// Peel one forward layer. The caller extracts a correlation key from `Peeled::inner`
    /// (the inner Interest's name) and calls [`remember`](Self::remember) with it +
    /// `Peeled::hop_key` before forwarding the inner onward.
    pub fn forward(&self, layer: &[u8]) -> Result<Peeled, OnionError> {
        self.key.peel(layer)
    }

    /// Record the hop key for a forwarded request, keyed by its `correlation` (inner
    /// interest name bytes), so the return path can find it.
    pub fn remember(&mut self, correlation: Vec<u8>, hop_key: HopKey) {
        self.pending.insert(correlation, hop_key);
    }

    /// Re-wrap returning `data` with the hop key stored for `correlation` (consuming it).
    /// `None` if no forward request is outstanding for that correlation.
    pub fn wrap_return(&mut self, correlation: &[u8], data: &[u8]) -> Option<Bytes> {
        let hop_key = self.pending.remove(correlation)?;
        wrap_return(&hop_key, data).ok()
    }
}

// ---- crypto + codec -----------------------------------------------------------

fn derive_hop_key(shared: &x25519_dalek::SharedSecret) -> HopKey {
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(HOP_KDF_INFO, &mut okm)
        .expect("32 is a valid HKDF-SHA256 length");
    okm
}

/// Forward layer: `eph_pub(32) ‖ nonce(12) ‖ tag(16) ‖ ciphertext`. Returns the layer +
/// the derived hop key (kept by the consumer for the return path).
fn seal_forward_layer(relay_pub: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, HopKey), OnionError> {
    let mut eph_bytes = [0u8; 32];
    getrandom::getrandom(&mut eph_bytes).map_err(|_| OnionError::Rng)?;
    let eph = StaticSecret::from(eph_bytes);
    let eph_pub = PublicKey::from(&eph);
    let hop_key = derive_hop_key(&eph.diffie_hellman(&PublicKey::from(*relay_pub)));
    let body = seal_sym(&hop_key, plaintext)?;
    let mut layer = Vec::with_capacity(EPH_LEN + body.len());
    layer.extend_from_slice(eph_pub.as_bytes());
    layer.extend_from_slice(&body);
    Ok((layer, hop_key))
}

/// Symmetric layer: `nonce(12) ‖ tag(16) ‖ ciphertext`.
fn seal_sym(key: &HopKey, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
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

fn open_sym(key: &HopKey, blob: &[u8]) -> Result<Vec<u8>, OnionError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(OnionError::Truncated);
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN].try_into().unwrap();
    let tag: [u8; TAG_LEN] = blob[NONCE_LEN..NONCE_LEN + TAG_LEN].try_into().unwrap();
    let mut buf = blob[NONCE_LEN + TAG_LEN..].to_vec();
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

    /// Stands in for a forwarder running a relay: its onion key + its address.
    struct Relay {
        addr: &'static str,
        key: RelayOnionKey,
    }

    impl Relay {
        fn new(addr: &'static str) -> Self {
            Self {
                addr,
                key: RelayOnionKey::generate().unwrap(),
            }
        }
        fn hop(&self) -> Hop {
            Hop {
                addr: Bytes::from(self.addr),
                onion_pub: self.key.public(),
            }
        }
    }

    /// Full circuit: the consumer knows only the relays' public onion keys, derives a hop
    /// key per relay via DH inside the onion, and round-trips a request + reply through a
    /// 3-relay chain — every relay seeing only ciphertext until the exit.
    #[test]
    fn three_hop_circuit_setup_and_round_trip() {
        let relays = [Relay::new("/r/a"), Relay::new("/r/b"), Relay::new("/r/c")];
        let circuit = Circuit::new(relays.iter().map(Relay::hop).collect());
        let interest = b"/secret/document/v=42 (the real interest wire)";

        let w = circuit.wrap_forward(interest).unwrap();
        assert_eq!(w.entry.as_ref(), b"/r/a");

        // Forward: each relay peels one layer with its OWN static key; collect hop keys.
        let mut layer = w.onion.clone();
        let mut idx = 0usize;
        let mut hop_keys = Vec::new();
        let real = loop {
            let p = relays[idx].key.peel(&layer).unwrap();
            hop_keys.push(p.hop_key);
            match p.next {
                Some(next) => {
                    assert_ne!(p.inner.as_ref(), interest, "relay sees only ciphertext");
                    idx += 1;
                    assert_eq!(relays[idx].addr.as_bytes(), next.as_ref(), "routed to next hop");
                    layer = p.inner;
                }
                None => break p.inner, // exit
            }
        };
        assert_eq!(idx, 2, "reached the exit (3rd relay)");
        assert_eq!(real.as_ref(), interest, "exit recovers the real interest");
        // Each side derived the same hop keys via DH.
        assert_eq!(hop_keys, w.return_keys, "relay-derived hop keys match the consumer's");

        // Return: producer Data, re-wrapped exit→entry, peeled by the consumer.
        let data = b"<the producer's Data wire>";
        let mut ret = Bytes::from_static(data);
        for key in hop_keys.iter().rev() {
            ret = wrap_return(key, &ret).unwrap();
        }
        let recovered = unwrap_return(&w.return_keys, &ret).unwrap();
        assert_eq!(recovered.as_ref(), data, "consumer recovers the Data");
    }

    /// The `OnionConsumer` driver (the face-facing API) ties wrap↔unwrap by token.
    #[test]
    fn consumer_driver_tracks_return_keys_by_token() {
        let relays = [Relay::new("/r/x"), Relay::new("/r/y")];
        let circuit = Circuit::new(relays.iter().map(Relay::hop).collect());
        let mut consumer = OnionConsumer::new(circuit);

        let (token, entry, onion) = consumer.wrap(b"/data/obj").unwrap();
        assert_eq!(entry.as_ref(), b"/r/x");

        // Drive the chain.
        let mut layer = onion;
        let mut hop_keys = Vec::new();
        let mut i = 0;
        let real = loop {
            let p = relays[i].key.peel(&layer).unwrap();
            hop_keys.push(p.hop_key);
            match p.next {
                Some(_) => {
                    i += 1;
                    layer = p.inner;
                }
                None => break p.inner,
            }
        };
        assert_eq!(real.as_ref(), b"/data/obj");

        let mut ret = Bytes::from_static(b"reply");
        for key in hop_keys.iter().rev() {
            ret = wrap_return(key, &ret).unwrap();
        }
        assert_eq!(consumer.unwrap(token, &ret).unwrap().as_ref(), b"reply");
        // Token consumed.
        assert!(consumer.unwrap(token, &ret).is_err());
    }

    /// Both drivers composed: the consumer wraps + tracks return keys by token; each
    /// relay peels, remembers its hop key by the inner it forwarded, and re-wraps the
    /// matching reply — a full onion fetch with only the driver APIs.
    #[test]
    fn consumer_and_relay_drivers_compose_end_to_end() {
        let mut relays: Vec<OnionRelay> = (0..3)
            .map(|_| OnionRelay::new(RelayOnionKey::generate().unwrap()))
            .collect();
        let addrs = ["/r/0", "/r/1", "/r/2"];
        let circuit = Circuit::new(
            addrs
                .iter()
                .zip(&relays)
                .map(|(a, r)| Hop {
                    addr: Bytes::from(*a),
                    onion_pub: r.public(),
                })
                .collect(),
        );
        let mut consumer = OnionConsumer::new(circuit);

        let interest = b"/app/data/v=1";
        let (token, entry, onion) = consumer.wrap(interest).unwrap();
        assert_eq!(entry.as_ref(), b"/r/0");

        // Forward: each relay forwards an inner blob and remembers its hop key keyed by it
        // (the face's correlation = the inner interest's name; here the opaque inner bytes).
        let mut layer = onion;
        let mut forwarded: Vec<Bytes> = Vec::new();
        let mut i = 0;
        let real = loop {
            let p = relays[i].forward(&layer).unwrap();
            relays[i].remember(p.inner.to_vec(), p.hop_key);
            forwarded.push(p.inner.clone());
            match p.next {
                Some(_) => {
                    i += 1;
                    layer = p.inner;
                }
                None => break p.inner,
            }
        };
        assert_eq!(real.as_ref(), interest, "exit recovered the interest");

        // Return: producer Data, re-wrapped exit→entry, each relay keyed by the inner it
        // forwarded.
        let data = b"the reply";
        let mut ret = Bytes::from_static(data);
        for idx in (0..relays.len()).rev() {
            ret = relays[idx]
                .wrap_return(&forwarded[idx], &ret)
                .expect("relay remembered this request");
        }
        assert_eq!(consumer.unwrap(token, &ret).unwrap().as_ref(), data);
    }

    #[test]
    fn wrong_relay_key_and_tamper_fail_closed() {
        let relays = [Relay::new("/r/a"), Relay::new("/r/b")];
        let circuit = Circuit::new(relays.iter().map(Relay::hop).collect());
        let w = circuit.wrap_forward(b"x").unwrap();
        // A relay with a different onion key derives a different hop key → can't open.
        let stranger = RelayOnionKey::generate().unwrap();
        assert_eq!(stranger.peel(&w.onion).unwrap_err(), OnionError::AuthFailed);
        // Flip a ciphertext byte → auth fails.
        let mut t = w.onion.to_vec();
        let last = t.len() - 1;
        t[last] ^= 0xFF;
        assert_eq!(relays[0].key.peel(&t).unwrap_err(), OnionError::AuthFailed);
    }

    #[test]
    fn empty_circuit_errors() {
        assert_eq!(
            Circuit::new(vec![]).wrap_forward(b"x").unwrap_err(),
            OnionError::EmptyCircuit
        );
    }
}
