//! The low findings of the signals review, between real `ndn_data::Device`s: the
//! push budget counts every group's copy of a packet (L2), and a sealed scope's
//! packets leave padded to their size bucket and still open (L3).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::{World, engine, n, no_ring};
use ndn_app::EngineAppExt;
use ndn_data::{DataLayer, Rule, Share, Sharing};
use ndn_surface::signal::wire::{self, Packet};
use ndn_surface::signal::{SignalError, SignalOptions, SignalRun};

const WITHIN: Duration = Duration::from_secs(20);
/// One frame at 60 Hz.
const FRAME_US: u64 = 16_667;

fn system_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// A clock the test moves, and the options of a sender dated by it.
fn moved_clock() -> (Arc<AtomicU64>, SignalOptions) {
    let clock = Arc::new(AtomicU64::new(system_us()));
    let read = Arc::clone(&clock);
    let options = SignalOptions {
        clock: Some(Arc::new(move || read.load(Ordering::Relaxed))),
        ..no_ring()
    };
    (clock, options)
}

/// Six seconds of one signal per frame at 60 Hz on `run`, the clock moved a frame
/// before each: the frame of the first refusal and the refusal, if any.
async fn sixty_hertz(run: &mut SignalRun, clock: &AtomicU64) -> Option<(u64, SignalError)> {
    for frame in 0u64..6 * 60 {
        clock.fetch_add(FRAME_US, Ordering::Relaxed);
        if let Err(e) = run.send(b"cursor", &frame.to_be_bytes()).await {
            return Some((frame, e));
        }
    }
    None
}

/// L2: a relay counts every push Interest a device sends against its quota, and a
/// packet goes out once per group. 60 Hz into one group is 60 push Interests/s,
/// within the default push budget; into two it is 120/s, over it: once the burst
/// is spent the run is refused `RateLimited`, though its own packet rate (60/s)
/// is half the run's limit. A send after `retry_after` is let.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_push_budget_counts_a_packet_once_per_group() {
    let mut world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    // Bob's namespace held here: a record naming it counts its group.
    let bob = World::new("/bob", &[]).await;
    world.trust(&bob);
    let e = engine().await;

    let (one_clock, one_options) = moved_clock();
    let laptop = world.host(&e, "/alice/laptop", one_options).await;
    let one = n("/alice/32=data/one");
    laptop.share(&one, world.ns(), false).await;
    let mut run = laptop.signals.open(&one).await.unwrap();
    assert!(
        sixty_hertz(&mut run, &one_clock).await.is_none(),
        "60 Hz into one group stays within the push budget"
    );

    let (two_clock, two_options) = moved_clock();
    let phone = world.host(&e, "/alice/phone", two_options).await;
    let two = n("/alice/32=data/two");
    phone
        .device
        .share_folder(
            &two,
            Sharing::Whole(Share {
                rule: Rule::Log,
                writers: vec![world.ns().clone(), n("/bob")],
                readers: Vec::new(),
            }),
        )
        .await
        .expect("the owner shares the folder");
    let mut run = phone.signals.open(&two).await.unwrap();
    let (frame, refused) = sixty_hertz(&mut run, &two_clock)
        .await
        .expect("60 Hz into two groups is refused once the push budget's burst is spent");
    let SignalError::RateLimited { retry_after } = refused else {
        panic!("refused RateLimited, not {refused:?}");
    };
    assert!(
        frame > 30,
        "the run's own burst of 30 packets is not what refused it (frame {frame})"
    );
    two_clock.fetch_add(retry_after.as_micros() as u64, Ordering::Relaxed);
    run.send(b"cursor", b"again")
        .await
        .expect("a send after retry_after is let");
    world.cancel.cancel();
}

/// L3: every packet of a sealed scope leaves as a multiple of 128 octets (its size
/// bucket), whatever its signals' sizes, and the member reads each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_scopes_packets_leave_padded_to_their_bucket_and_open() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let laptop = world.host(&e, "/alice/laptop", no_ring()).await;
    let phone = world.host(&e, "/alice/phone", no_ring()).await;
    let tap = e.engine.app_face(world.cancel.child_token());
    tap.register_prefix(&wire::sync_group(world.ns()))
        .await
        .unwrap();
    let secret = n("/alice/32=data/secret");
    laptop.share(&secret, world.ns(), true).await;
    let mut sub = phone.subscribe(&secret, WITHIN).await;
    let mut run = laptop.signals.open(&secret).await.unwrap();
    // The run's header admitted: a first signal read.
    let mut admitted = false;
    for _ in 0..50 {
        run.send(b"hello", b"").await.unwrap();
        if tokio::time::timeout(Duration::from_millis(500), sub.next())
            .await
            .is_ok_and(|s| s.is_some())
        {
            admitted = true;
            break;
        }
    }
    assert!(admitted, "the member reads the sealed scope's signals");
    let sizes: Vec<usize> = (0..=400).step_by(37).collect();
    for (i, size) in sizes.iter().enumerate() {
        let address = format!("a/{i}");
        run.send(address.as_bytes(), &vec![0x5A; *size])
            .await
            .unwrap();
    }
    let mut read = 0;
    while read < sizes.len() {
        let s = tokio::time::timeout(Duration::from_secs(5), sub.next())
            .await
            .expect("each padded packet opens and is read")
            .expect("the subscriber is open");
        if s.address.starts_with(b"a/") {
            let i: usize = std::str::from_utf8(&s.address[2..])
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(s.payload.len(), sizes[i], "the payload as sent");
            read += 1;
        }
    }
    let mut lengths = Vec::new();
    while let Ok(Some(wire)) = tokio::time::timeout(Duration::from_millis(200), tap.recv()).await {
        let Ok(interest) = ndn_packet::Interest::decode(wire) else {
            continue;
        };
        let Some(packet) = wire::push_packet(&interest) else {
            continue;
        };
        assert!(matches!(
            wire::decode_packet(packet.clone()),
            Ok(Packet::Sealed(_))
        ));
        lengths.push(packet.len());
    }
    assert!(lengths.len() > sizes.len(), "the tap heard the pushes");
    assert!(
        lengths.iter().all(|l| l % 128 == 0),
        "every sealed packet is a multiple of 128 octets: {lengths:?}"
    );
    world.cancel.cancel();
}
