//! A sink that never reads, seen from the sender's own forwarder (ndn-rs docs/specs/channel.md
//! §14.4): the first hop holds a stream frame back for its sender while no live sink of its
//! route has room, and a sink is live while its `Keep`s come, read or not. A peer that keeps
//! its link up and never reads its channel stream would hold the sender's `send_side` for the
//! life of the link; the link's stall bound (`LinkHandle::set_stream_stall`, 30 s by default)
//! ends it: the link is closed with words the peer can read, the forwarder drops the face and
//! its sinks, and the sender is released.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{Connection, EngineAppExt};
use ndn_engine::side::SideId;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face_quic::{CloseReason, LinkError, LinkTransportConfig};
use ndn_security::SecurityProfile;
use ndn_transport::side_header::{SideHeader, SideKind};
use ndn_transport::{Face, FaceId, FacePersistency, SideClass};
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
#[path = "../examples/common/pair.rs"]
mod pair;

const ROUTE: u64 = 0x5eed_0000_0000_0002;
const T: Duration = Duration::from_secs(10);

async fn engine() -> ForwarderEngine {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    engine
}

/// A stream data frame of `ROUTE` of one mebibyte.
fn big_frame(tag: u8) -> Bytes {
    let mut v = SideHeader::new(SideClass::Stream, SideKind::Data, ROUTE)
        .expect("a data header")
        .encode()
        .to_vec();
    v.resize(1024 * 1024, tag);
    Bytes::from(v)
}

#[tokio::test]
async fn an_emitter_held_back_by_a_sink_that_never_reads_is_released_when_its_link_is_closed() {
    let here = tokio::runtime::Handle::current();
    let cancel = CancellationToken::new();
    let engine = engine().await;
    let link_id = engine.faces().alloc_id();
    let (link, peer, _endpoints) = pair::connect_ids(
        &LinkTransportConfig::default(),
        &here,
        &here,
        link_id,
        FaceId(9_000),
    )
    .await;
    let stall = Duration::from_secs(2);
    link.handle.set_stream_stall(stall);
    let handle = link.handle.clone();
    assert_eq!(
        engine.add_composed_face(
            Face::from_transport(link.face),
            cancel.child_token(),
            FacePersistency::Persistent,
        ),
        link_id
    );

    // The node's own face is the route's source and the link its only sink, kept live for ten
    // minutes (a sink whose `Keep`s keep coming: the 30 s lapse does not end it). The peer
    // holds its end of the link and never reads it.
    let before = engine.faces().face_ids();
    let conn: Arc<dyn Connection> = engine.app_face(cancel.child_token());
    let app_id = engine
        .faces()
        .face_ids()
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the app face is on the engine");
    engine
        .side()
        .install(SideId(ROUTE), app_id, link_id, Duration::from_secs(600))
        .unwrap();

    // 256 MiB is far more than the peer's inbox, QUIC's flow-control windows and the link's
    // 4 MiB queue take, so the emitter is held back, and held back for good unless something
    // ends the wait.
    let started = Instant::now();
    let emitter = tokio::spawn({
        let conn = Arc::clone(&conn);
        async move {
            for tag in 0..=255u8 {
                conn.send_side(big_frame(tag), SideClass::Stream).await?;
            }
            Ok::<(), ndn_app::AppError>(())
        }
    });
    let done = tokio::time::timeout(Duration::from_secs(60), emitter)
        .await
        .expect(
            "the emitter was held back by a sink that never reads for longer than a minute: a \
             live sink the link's stall bound does not end holds it for ever",
        )
        .expect("the emitter task");
    done.expect("the emitter was told something other than that it may go on");
    assert!(
        started.elapsed() >= stall,
        "the emitter was never held back: the test did not reach the sink's bound"
    );
    assert!(
        engine.side().stats().held_back >= 1,
        "the first hop never held a frame back"
    );

    // The link was closed here with the reason, the peer was told it in words, and the
    // forwarder let go of the face and its sink.
    match tokio::time::timeout(T, handle.closed()).await.unwrap() {
        LinkError::RefusedHere { reason, text } => {
            assert_eq!(reason, CloseReason::Protocol);
            assert!(text.contains("did not read the channel stream"), "{text}");
        }
        other => panic!("expected the close this side made, got {other}"),
    }
    match tokio::time::timeout(T, peer.handle.closed()).await.unwrap() {
        LinkError::Refused { reason, text } => {
            assert_eq!(reason, Some(CloseReason::Protocol));
            assert!(text.contains("link again"), "{text}");
        }
        other => panic!("the peer was not told why: {other}"),
    }
    let start = Instant::now();
    while engine.faces().get(link_id).is_some() || engine.side().sinks(SideId(ROUTE)) != 0 {
        assert!(
            start.elapsed() < T,
            "the forwarder still holds the closed link or its sink"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cancel.cancel();
}
