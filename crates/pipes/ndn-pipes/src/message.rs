//! The NDN-Pipes message-name contract, faithful to the thesis (Tables 3–10):
//! the exact names for SEEK / JOIN / CONTEXT / LINK / PIPE / CHECK and the GHL
//! (Global Hop Limit) hop-ordering math.
//!
//! Names (`{pipe_id}` is the producer-generated id; in v2 it doubles as the
//! reflexive name that installs the reverse route):
//! ```text
//! SEEK     /NPD/SEEK/{namespace}
//! JOIN     /NPD/JOIN/{namespace}/{pipe_id}
//! CONTEXT  /COMMON/{pipe_id}/{hop}/CONTEXT      (hop = adjacent downstream = my_hop-1)
//! LINK     /COMMON/{pipe_id}/{hop}/LINK         (hop = adjacent downstream)
//! PIPE     /COMMON/{pipe_id}/{hop}/PIPE         (hop = adjacent upstream = my_hop+1)
//! CHECK    /{pipe_id}/{pipe_length}/CHECK
//! ```
//! FIB after JOIN installs `/NPD/JOIN/{namespace}` (data, multicast) and
//! `/COMMON/{pipe_id}` (control, best-route).

use bytes::Bytes;
use ndn_packet::Name;

/// The **Global Hop Limit**: a protocol-wide reference every node uses to derive
/// its own hop index as `GHL − remaining_hop_limit`, with no coordination
/// (thesis Fig. 12). Pipe-formation Interests carry `HopLimit = GHL`; each
/// forwarder decrements it, so a node's distance from the consumer falls out of
/// the wire. 64 is ample for any pipe we form and never underflows in practice.
pub const GHL: u8 = 64;

/// Common-channel SEEK namespace (the producer-search band).
pub const SEEK_PREFIX: &str = "/NPD/SEEK";
/// JOIN namespace (commit, carrying the decrypted pipe id).
pub const JOIN_PREFIX: &str = "/NPD/JOIN";
/// Per-pipe control namespace on the common channel.
pub const COMMON_PREFIX: &str = "/COMMON";

/// The eight protocol messages (Tables 3–10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Seek,
    Hide,
    Join,
    Context,
    Link,
    Pipe,
    Check,
    Teardown,
}

fn extend(mut n: Name, suffix: &Name) -> Name {
    for c in suffix.components() {
        n = n.append_component(c.clone());
    }
    n
}

/// `/NPD/SEEK/{namespace}` — the multicast producer search.
pub fn seek_name(namespace: &Name) -> Name {
    extend(Name::from(SEEK_PREFIX), namespace)
}

/// `/NPD/JOIN/{namespace}/{pipe_id}` — only the consumer (who decrypted the
/// pipe id) can form this, so only it can JOIN.
pub fn join_name(namespace: &Name, pipe_id: &[u8]) -> Name {
    extend(Name::from(JOIN_PREFIX), namespace).append(pipe_id)
}

/// `/COMMON/{pipe_id}/{hop}/CONTEXT`.
pub fn context_name(pipe_id: &[u8], hop: u32) -> Name {
    Name::from(COMMON_PREFIX)
        .append(pipe_id)
        .append(hop.to_string())
        .append("CONTEXT")
}

/// `/COMMON/{pipe_id}/{hop}/LINK`.
pub fn link_name(pipe_id: &[u8], hop: u32) -> Name {
    Name::from(COMMON_PREFIX)
        .append(pipe_id)
        .append(hop.to_string())
        .append("LINK")
}

/// `/COMMON/{pipe_id}/{hop}/PIPE`.
pub fn pipe_name(pipe_id: &[u8], hop: u32) -> Name {
    Name::from(COMMON_PREFIX)
        .append(pipe_id)
        .append(hop.to_string())
        .append("PIPE")
}

/// `/COMMON/{pipe_id}/TEARDOWN` — pipe-wide teardown. Authenticated by the pipe
/// private key in the real protocol; the crypto-stub treats the pipe id itself
/// as the capability (only consumer + producer + on-path relays hold it).
pub fn teardown_name(pipe_id: &[u8]) -> Name {
    Name::from(COMMON_PREFIX).append(pipe_id).append("TEARDOWN")
}

/// `/{pipe_id}/{pipe_length}/CHECK` — the consumer's final liveness gate.
pub fn check_name(pipe_id: &[u8], pipe_length: u32) -> Name {
    Name::root()
        .append(pipe_id)
        .append(pipe_length.to_string())
        .append("CHECK")
}

/// Classify an Interest by its name into a [`MessageKind`] — the producer/relay
/// dispatch. SEEK/JOIN key on the first two components; CONTEXT/LINK/PIPE/CHECK
/// on the trailing verb.
pub fn classify(name: &Name) -> Option<MessageKind> {
    let comps = name.components();
    let at = |i: usize| comps.get(i).and_then(|c| std::str::from_utf8(&c.value).ok());
    if let (Some("NPD"), Some("SEEK")) = (at(0), at(1)) {
        return Some(MessageKind::Seek);
    }
    if let (Some("NPD"), Some("JOIN")) = (at(0), at(1)) {
        return Some(MessageKind::Join);
    }
    // The verb is the last *generic* component: an Interest carrying
    // ApplicationParameters (SEEK pubkey, TEARDOWN pipe key) has a trailing
    // ParametersSha256Digest component appended by the builder — skip it.
    match comps
        .iter()
        .rev()
        .find(|c| c.typ != ndn_packet::tlv_type::PARAMETERS_SHA256)
        .and_then(|c| std::str::from_utf8(&c.value).ok())
    {
        Some("CONTEXT") => Some(MessageKind::Context),
        Some("LINK") => Some(MessageKind::Link),
        Some("PIPE") => Some(MessageKind::Pipe),
        Some("CHECK") => Some(MessageKind::Check),
        Some("TEARDOWN") => Some(MessageKind::Teardown),
        _ => None,
    }
}

/// Encode a SEEK reply body: the GHL-derived pipe length (cleartext, for the
/// CHECK name) followed by the sealed handshake blob — `seal(consumer_pubkey,
/// pipe_id ‖ pipe_key)`, opaque to anyone but the consumer.
pub fn encode_seek_reply(sealed: &[u8], pipe_len: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + sealed.len());
    v.push(pipe_len);
    v.extend_from_slice(sealed);
    v
}

/// Parse a SEEK reply body into `(sealed_blob, pipe_len)`.
pub fn decode_seek_reply(content: &[u8]) -> Option<(Bytes, u8)> {
    let (&pipe_len, sealed) = content.split_first()?;
    if sealed.is_empty() {
        return None;
    }
    Some((Bytes::copy_from_slice(sealed), pipe_len))
}

/// GHL hop ordering: a node's hop index is the **globally-set** hop limit minus
/// the Interest's remaining hop limit — coordinator-free distributed addressing
/// (thesis Fig. 12). The adjacent-downstream hop is `idx - 1`, upstream `idx + 1`.
pub fn hop_index(global_hop_limit: u8, remaining_hop_limit: u8) -> u8 {
    global_hop_limit.saturating_sub(remaining_hop_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_names_match_the_thesis_tables() {
        let ns = Name::from("/sensors/temp");
        let pid = b"\x9a\x12\xff\x03"; // a producer-generated pipe id

        assert_eq!(seek_name(&ns).to_string(), "/NPD/SEEK/sensors/temp");
        assert_eq!(
            join_name(&ns, pid).to_string(),
            "/NPD/JOIN/sensors/temp/%9A%12%FF%03"
        );
        assert_eq!(
            context_name(pid, 2).to_string(),
            "/COMMON/%9A%12%FF%03/2/CONTEXT"
        );
        assert_eq!(link_name(pid, 2).to_string(), "/COMMON/%9A%12%FF%03/2/LINK");
        assert_eq!(pipe_name(pid, 4).to_string(), "/COMMON/%9A%12%FF%03/4/PIPE");
        assert_eq!(check_name(pid, 5).to_string(), "/%9A%12%FF%03/5/CHECK");
    }

    #[test]
    fn classify_dispatches_each_message() {
        assert_eq!(classify(&seek_name(&Name::from("/a"))), Some(MessageKind::Seek));
        assert_eq!(classify(&join_name(&Name::from("/a"), b"p")), Some(MessageKind::Join));
        assert_eq!(classify(&context_name(b"p", 1)), Some(MessageKind::Context));
        assert_eq!(classify(&link_name(b"p", 1)), Some(MessageKind::Link));
        assert_eq!(classify(&pipe_name(b"p", 1)), Some(MessageKind::Pipe));
        assert_eq!(classify(&check_name(b"p", 3)), Some(MessageKind::Check));
        assert_eq!(classify(&teardown_name(b"p")), Some(MessageKind::Teardown));
        assert_eq!(classify(&Name::from("/random/data")), None);
    }

    #[test]
    fn seek_reply_codec_round_trips() {
        let pid = b"\x9a\x12\xff\x03";
        let body = encode_seek_reply(pid, 3);
        let (got_id, got_len) = decode_seek_reply(&body).expect("parses");
        assert_eq!(got_id.as_ref(), pid);
        assert_eq!(got_len, 3);
        // A body with no pipe id is rejected; an empty body too.
        assert!(decode_seek_reply(&[7]).is_none());
        assert!(decode_seek_reply(&[]).is_none());
    }

    #[test]
    fn ghl_hop_index_is_subtraction() {
        // GHL = 64; a node whose Interest arrives with remaining 62 is hop 2.
        assert_eq!(hop_index(64, 64), 0); // the originator (consumer)
        assert_eq!(hop_index(64, 62), 2);
        assert_eq!(hop_index(64, 61), 3);
        assert_eq!(hop_index(64, 70), 0); // saturating: never underflows
    }
}
