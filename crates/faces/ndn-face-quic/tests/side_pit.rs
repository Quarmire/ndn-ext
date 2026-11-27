//! A `QUERY` and its `ANSWER` over a real QUIC link (ndn-rs docs/specs/channel.md §14.13).
//!
//! Two forwarders, each in this process, joined by a `LinkFace` on loopback: a server's app face
//! on one, two askers' app faces on the other. The frames are raw side frames: the forwarder's
//! breadcrumb table is generic and reads only the routing prefix, so the test needs no data
//! layer. It confirms what the design expected of the link and left unchanged: `QUERY` and
//! `ANSWER` ride `send_side` and `forward_side_from` like `UP` and `DATA`, a link needs no
//! change for them, and an `ANSWER` goes back to the one face that asked on either carrier.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Connection, EngineAppExt};
use ndn_engine::side::SideId;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face_quic::LinkTransportConfig;
use ndn_security::SecurityProfile;
use ndn_transport::side_header::{AnswerPrefix, QueryPrefix};
use ndn_transport::{Face, FaceId, FacePersistency, SideClass};
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
#[path = "../examples/common/pair.rs"]
mod pair;

const ROUTE: u64 = 0x5eed_0000_0000_0001;
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

/// An app face on `engine` and its id.
fn app(engine: &ForwarderEngine, cancel: &CancellationToken) -> (Arc<dyn Connection>, FaceId) {
    let before = engine.faces().face_ids();
    let conn = engine.app_face(cancel.child_token());
    let id = engine
        .faces()
        .face_ids()
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the app face is on the engine");
    (conn, id)
}

fn query(token: u64, len: usize) -> Bytes {
    let mut v = QueryPrefix {
        id: ROUTE,
        token,
        ttl_ticks: 50,
    }
    .encode()
    .to_vec();
    v.resize(len, (token & 0xff) as u8);
    Bytes::from(v)
}

fn answer(class: SideClass, token: u64, len: usize) -> Bytes {
    let mut v = AnswerPrefix {
        class,
        id: ROUTE,
        token,
    }
    .encode()
    .to_vec();
    v.resize(len, (token & 0xff) as u8 ^ 0x5a);
    Bytes::from(v)
}

async fn next(conn: &Arc<dyn Connection>) -> (Bytes, FaceId) {
    tokio::time::timeout(T, conn.recv_side())
        .await
        .expect("a side frame within 10 s")
        .expect("the face is open")
}

async fn nothing(conn: &Arc<dyn Connection>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(300), conn.recv_side())
            .await
            .is_err(),
        "a face that did not ask was handed a frame"
    );
}

#[tokio::test]
async fn a_query_and_an_answer_cross_a_real_ndn_link() {
    let here = tokio::runtime::Handle::current();
    let cancel = CancellationToken::new();
    let (server, asker) = (engine().await, engine().await);

    // The server's forwarder listens, the askers' forwarder dials; each face takes the id its
    // forwarder gave it.
    let (id_server_link, id_asker_link) = (server.faces().alloc_id(), asker.faces().alloc_id());
    let (listening, dialing, _endpoints) = pair::connect_ids(
        &LinkTransportConfig::default(),
        &here,
        &here,
        id_server_link,
        id_asker_link,
    )
    .await;
    for (engine, link, want) in [
        (&server, listening, id_server_link),
        (&asker, dialing, id_asker_link),
    ] {
        let id = engine.add_composed_face(
            Face::from_transport(link.face),
            cancel.child_token(),
            FacePersistency::Persistent,
        );
        assert_eq!(id, want);
    }

    // The channel's route, as its session Data would lay it: the server sends, the link is its
    // sink; at the askers' forwarder the link is the source and each asker is a sink.
    let (srv, srv_id) = app(&server, &cancel);
    let (a1, a1_id) = app(&asker, &cancel);
    let (a2, a2_id) = app(&asker, &cancel);
    let ttl = Duration::from_secs(60);
    server
        .side()
        .install(SideId(ROUTE), srv_id, id_server_link, ttl)
        .unwrap();
    for sink in [a1_id, a2_id] {
        asker
            .side()
            .install(SideId(ROUTE), id_asker_link, sink, ttl)
            .unwrap();
    }

    // Asker 1 asks. The query goes up over the link; the server's app face gets it with the
    // link's face as ingress.
    let q1 = query(0x11, 120);
    a1.send_side(q1.clone(), SideClass::Datagram).await.unwrap();
    let (got, ingress) = next(&srv).await;
    assert_eq!(got, q1, "the link carries the query whole");
    assert_eq!(ingress, id_server_link);
    assert_eq!(
        (
            asker.side().stats().breadcrumbs,
            server.side().stats().breadcrumbs
        ),
        (1, 1),
        "a breadcrumb at each hop"
    );

    // The answer goes down over the link to asker 1 only.
    let r1 = answer(SideClass::Datagram, 0x11, 90);
    srv.send_side(r1.clone(), SideClass::Datagram)
        .await
        .unwrap();
    let (got, ingress) = next(&a1).await;
    assert_eq!(got, r1);
    assert_eq!(ingress, id_asker_link);
    nothing(&a2).await;

    // A second answer for the token is unmatched at the server's own forwarder.
    srv.send_side(r1, SideClass::Datagram).await.unwrap();
    nothing(&a1).await;
    assert_eq!(server.side().stats().unmatched, 1);

    // Asker 2 asks, and is answered on the stream: a larger answer than a datagram takes.
    let q2 = query(0x22, 100);
    a2.send_side(q2.clone(), SideClass::Datagram).await.unwrap();
    assert_eq!(next(&srv).await.0, q2);
    let r2 = answer(SideClass::Stream, 0x22, 3_000);
    srv.send_side(r2.clone(), SideClass::Stream).await.unwrap();
    assert_eq!(next(&a2).await.0, r2, "the stream carries the answer whole");
    nothing(&a1).await;

    let (s, a) = (server.side().stats(), asker.side().stats());
    assert_eq!(
        (s.breadcrumbs, a.breadcrumbs),
        (0, 0),
        "every breadcrumb was consumed"
    );
    assert_eq!((a.queries, a.answers), (2, 2));
    assert_eq!((s.queries, s.answers), (2, 2));
    assert_eq!(
        (a.wrong_source, a.unmatched, a.late, s.wrong_source, s.late),
        (0, 0, 0, 0, 0)
    );
    cancel.cancel();
}
