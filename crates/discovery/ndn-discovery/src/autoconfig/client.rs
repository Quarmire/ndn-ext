//! NDN AutoConfig hub-discovery client.
//!
//! 1. **Multicast** — `/localhop/ndn-autoconf/hub` on every face that
//!    comes up. Ref: `NFD/tools/ndn-autoconfig/multicast-discovery.cpp:131-133`.
//! 2. **NDN-FCH** — HTTP GET; response body is the hub hostname. Spawns
//!    one tokio task to keep `on_tick` non-blocking. Ref:
//!    `NFD/tools/ndn-autoconfig/ndn-fch-discovery.cpp:141-196`.
//!
//! Hub URI is published on a `watch` channel. The engine reads it and
//! creates the face — `DiscoveryContext` does not expose URI-based face
//! creation.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_tlv::{TlvReader, TlvWriter};
use ndn_transport::FaceId;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::context::DiscoveryContext;
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};
use crate::scope::localhop_autoconf_hub;
use crate::wire::parse_raw_data;

const PROTOCOL: ProtocolId = ProtocolId("ndn-autoconfig");

// Ref: NFD multicast-discovery.cpp:41.
const HUB_DISCOVERY_INTEREST_LIFETIME: Duration = Duration::from_secs(4);

const RETRY_INTERVAL: Duration = Duration::from_secs(30);

// nfd::Uri TLV type — ndn-cxx/encoding/tlv-nfd.hpp.
const TLV_NFD_URI: u64 = 0x72;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Searching,
    Found,
}

struct State {
    known_faces: Vec<FaceId>,
    phase: Phase,
    last_attempt: Option<Instant>,
    fch_spawned: bool,
}

/// Add to a [`CompositeDiscovery`](crate::CompositeDiscovery); read the
/// discovered hub URI via [`hub_uri_rx`](Self::hub_uri_rx).
pub struct AutoConfigDiscovery {
    claimed: Vec<Name>,
    state: Mutex<State>,
    hub_tx: Arc<watch::Sender<Option<String>>>,
    hub_rx: watch::Receiver<Option<String>>,
    /// When set, FCH HTTP fallback is attempted after multicast.
    ndnfch_url: Option<String>,
}

impl AutoConfigDiscovery {
    pub fn new() -> Self {
        Self::with_fch(None)
    }

    pub fn with_fch(ndnfch_url: Option<String>) -> Self {
        let (hub_tx, hub_rx) = watch::channel(None);
        Self {
            claimed: vec![localhop_autoconf_hub().clone()],
            state: Mutex::new(State {
                known_faces: Vec::new(),
                phase: Phase::Searching,
                last_attempt: None,
                fch_spawned: false,
            }),
            hub_tx: Arc::new(hub_tx),
            hub_rx,
            ndnfch_url,
        }
    }

    /// `None` until a hub is found.
    pub fn hub_uri_rx(&self) -> watch::Receiver<Option<String>> {
        self.hub_rx.clone()
    }

    fn send_hub_discovery(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let pkt = InterestBuilder::new(localhop_autoconf_hub().clone())
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(HUB_DISCOVERY_INTEREST_LIFETIME)
            .build();
        ctx.send_on(face_id, pkt);
        debug!("autoconfig: sent hub discovery Interest on face {face_id:?}");
    }

    fn publish_hub(&self, uri: String) {
        info!(hub_uri = %uri, "autoconfig: hub discovered");
        let _ = self.hub_tx.send(Some(uri));
        self.state.lock().unwrap().phase = Phase::Found;
    }

    fn spawn_fch(&self, url: String) {
        let tx = Arc::clone(&self.hub_tx);
        tokio::spawn(async move {
            match fetch_fch_hub(&url).await {
                Ok(hub_uri) => {
                    info!(hub_uri = %hub_uri, "autoconfig: hub from NDN-FCH");
                    let _ = tx.send(Some(hub_uri));
                }
                Err(e) => {
                    warn!("autoconfig: NDN-FCH failed: {e}");
                }
            }
        });
    }
}

impl Default for AutoConfigDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryProtocol for AutoConfigDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let mut st = self.state.lock().unwrap();
        if st.phase == Phase::Found {
            return;
        }
        st.known_faces.push(face_id);
        st.last_attempt = Some(ctx.now());
        drop(st);
        self.send_hub_discovery(face_id, ctx);
    }

    fn on_face_down(&self, face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        self.state
            .lock()
            .unwrap()
            .known_faces
            .retain(|&f| f != face_id);
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        _incoming_face: FaceId,
        _meta: &InboundMeta,
        _ctx: &dyn DiscoveryContext,
    ) -> bool {
        if raw.first() != Some(&0x06) {
            return false;
        }
        let parsed = match parse_raw_data(raw) {
            Some(d) => d,
            None => return false,
        };
        if !parsed.name.has_prefix(localhop_autoconf_hub()) {
            return false;
        }
        // Hub URI content: TLV { 0x72, <uri> }. Ref: NFD
        // ndn-autoconfig-server/program.cpp:56.
        let content = match parsed.content {
            Some(c) => c,
            None => {
                warn!("autoconfig: hub Data has no content");
                return true;
            }
        };
        if let Some(uri) = parse_hub_uri(&content) {
            self.publish_hub(uri);
        } else {
            warn!("autoconfig: hub Data content missing nfd::Uri element (0x72)");
        }
        true
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let mut st = self.state.lock().unwrap();
        if st.phase == Phase::Found {
            return;
        }
        let should_retry = st
            .last_attempt
            .map(|t| now.duration_since(t) >= RETRY_INTERVAL)
            .unwrap_or(true);

        if should_retry && !st.known_faces.is_empty() {
            st.last_attempt = Some(now);
            let faces: Vec<FaceId> = st.known_faces.clone();
            drop(st);
            for face_id in faces {
                self.send_hub_discovery(face_id, ctx);
            }
            let mut st2 = self.state.lock().unwrap();
            if let Some(url) = self.ndnfch_url.clone().filter(|_| !st2.fch_spawned) {
                st2.fch_spawned = true;
                drop(st2);
                self.spawn_fch(url);
            }
        }
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_secs(5)
    }
}

/// Content: TLV { 0x72 (nfd::Uri), <UTF-8 FaceUri> }. Ref: NFD
/// `ndn-autoconfig-server/program.cpp:56`.
fn parse_hub_uri(content: &Bytes) -> Option<String> {
    let mut r = TlvReader::new(content.clone());
    while !r.is_empty() {
        let (typ, val) = r.read_tlv().ok()?;
        if typ == TLV_NFD_URI {
            return String::from_utf8(val.to_vec()).ok();
        }
    }
    None
}

/// Wire: Interest `/localhop/ndn-autoconf/hub` + CanBePrefix + MustBeFresh.
/// Ref: NFD `multicast-discovery.cpp:131-133`.
pub fn build_hub_discovery_interest() -> Bytes {
    InterestBuilder::new(localhop_autoconf_hub().clone())
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(HUB_DISCOVERY_INTEREST_LIFETIME)
        .build()
}

/// Encode the FaceUri in a nfd::Uri TLV (0x72). Ref: NFD
/// `ndn-autoconfig-server/program.cpp:53-56`.
pub fn build_hub_data(hub_uri: &str) -> Bytes {
    use ndn_packet::encode::DataBuilder;
    use std::time::Duration;

    let name = localhop_autoconf_hub().clone().append_version(0);

    let mut w = TlvWriter::new();
    w.write_tlv(TLV_NFD_URI, hub_uri.as_bytes());
    let content = w.finish();

    DataBuilder::new(name, &content)
        .freshness(Duration::from_secs(3600))
        .sign_digest_sha256()
}

/// Returns `udp://<hub-host>`. Ref: NFD
/// `ndn-autoconfig/ndn-fch-discovery.cpp:141-196`.
async fn fetch_fch_hub(url: &str) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let (host, port, path) = parse_http_url(url)?;
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("connect to {addr}: {e}"))?;

    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\nAccept: */*\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| e.to_string())?;

    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no HTTP header separator")?
        + 4;
    let body = std::str::from_utf8(&response[body_start..])
        .map_err(|e| e.to_string())?
        .trim();
    if body.is_empty() {
        return Err("NDN-FCH returned empty body".into());
    }
    Ok(format!("udp://{body}"))
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let url = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// supported, got: {url}"))?;
    let (authority, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{path}");
    let (host, port_str) = authority.split_once(':').unwrap_or((authority, "80"));
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port: {port_str}"))?;
    Ok((host.to_string(), port, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::parse_raw_interest;

    #[test]
    fn parse_hub_uri_extracts_faceuri() {
        let uri = "udp://192.168.1.1:6363";
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_NFD_URI, uri.as_bytes());
        let content = w.finish();

        let result = parse_hub_uri(&content);
        assert_eq!(result.as_deref(), Some(uri));
    }

    #[test]
    fn parse_hub_uri_missing_element_returns_none() {
        let content = Bytes::from_static(b"\x01\x01\xFF");
        assert!(parse_hub_uri(&content).is_none());
    }

    #[test]
    fn build_hub_data_round_trips_uri() {
        let uri = "udp://hub.example.com:6363";
        let wire = build_hub_data(uri);
        // Verify it's parseable as a Data packet.
        let parsed = parse_raw_data(&wire).expect("should parse as Data");
        assert!(parsed.name.has_prefix(localhop_autoconf_hub()));
        let content = parsed.content.expect("should have content");
        let decoded = parse_hub_uri(&content).expect("should decode uri");
        assert_eq!(decoded, uri);
    }

    #[test]
    fn hub_discovery_interest_has_correct_name() {
        let wire = build_hub_discovery_interest();
        let parsed = parse_raw_interest(&wire).expect("should parse as Interest");
        assert!(
            parsed.name.has_prefix(localhop_autoconf_hub())
                || localhop_autoconf_hub().has_prefix(&parsed.name)
        );
    }

    #[test]
    fn parse_http_url_basic() {
        let (host, port, path) = parse_http_url("http://ndn-fch.named-data.net/").unwrap();
        assert_eq!(host, "ndn-fch.named-data.net");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_http_url_with_port() {
        let (host, port, path) = parse_http_url("http://example.com:8080/fch").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/fch");
    }
}
