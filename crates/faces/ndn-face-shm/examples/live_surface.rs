//! G11 APPLIED TEST #1 (dogfood) — build a real "live surface" pipeline using
//! ONLY the public `ndn_face_shm` API, as an outside developer would, and record
//! the friction (search for `FRICTION:`). This is not a benchmark; it's a
//! usability probe — the awkward bits are the deliverable.
//!
//! Goal a developer would state: *"Publish a live surface (a stream of frames)
//! under a name like `/app/surface`; an authorized consumer process reads each
//! frame zero-copy and renders it."*
//!
//! Run: `cargo run -p ndn-face-shm --example live_surface --release`

// FRICTION #0 (paradigm): the task is stated in terms of *names* and *surfaces*,
// but nothing in the public API mentions either. The whole feature is presented
// as faces/rings/tokens/fds. A newcomer has to translate the goal down to
// plumbing before writing a line.

#[cfg(unix)]
use ndn_face_shm::{
    ShmFace, ShmHandle, ShmToken, connect_fd_handoff, control_socket_path, mint_token,
    serve_fd_handoff,
};
#[cfg(unix)]
use ndn_transport::FaceId; // FRICTION #1: need a dep the docs never mentioned just to call create_*.

#[cfg(unix)]
const FRAME_LEN: usize = 64 * 1024; // FRICTION #2: ring slot must hold a whole frame; see note for large frames.
#[cfg(unix)]
const FRAMES: u32 = 50;

#[cfg(unix)]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--consumer") {
        // FRICTION #3: the consumer learns the channel via a 64-hex token on argv.
        // There is no "open /app/surface" — the dev must invent token transport.
        let token = parse_token(&args[pos + 1]);
        consumer(token).await;
    } else {
        producer().await;
    }
}

#[cfg(unix)]
async fn producer() {
    // FRICTION #4 (who mints?): in the forwarder flow the *client* mints the
    // token; standalone, the producer must. The docs give no guidance, and the
    // two roles are inverted from the only worked example.
    let token = mint_token().expect("mint token");

    // FRICTION #5 (FaceId): a standalone surface has no engine, yet I must pass a
    // FaceId. What value? `FaceId(1)`? It's an engine concept leaking out.
    // FRICTION #6 (sizing): capacity/slot_size are magic numbers. I reached for a
    // "size this for 64 KiB frames" helper; `create_anon_for_mtu` exists — but I
    // only found it by scanning every constructor (create / create_with /
    // create_anon / create_anon_with / create_anon_for_mtu — which one??).
    let (face, fds) = ShmFace::create_anon_for_mtu(FaceId(1), FRAME_LEN).expect("create anon face");

    // FRICTION #7 (I assemble the rendezvous myself): derive path, remove stale
    // file, bind a UnixListener, know it's a tokio one. None of this is wrapped.
    let path = control_socket_path(&token);
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).expect("bind control socket");

    // Spawn the consumer process, hand it the token.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--consumer")
        .arg(hex(&token))
        .spawn()
        .expect("spawn consumer");

    // FRICTION #8 (handoff ceremony): I must spawn serve_fd_handoff, and *I* own
    // the ordering — stream only after the consumer has its handle, or the ring
    // fills. There's no "wait until a consumer is attached".
    serve_fd_handoff(listener, token, fds)
        .await
        .expect("serve fd handoff");

    // Stream the surface.
    println!("producer: streaming {FRAMES} frames of {FRAME_LEN} B under /app/surface");
    for n in 0..FRAMES {
        // FRICTION #9 (no name on the wire): I *want* to publish
        // `/app/surface/v=n`; all I can do is push the next ring message. The
        // name lives only in my comments. The consumer gets "the next frame",
        // not "/app/surface/v=n".
        face.send_with(FRAME_LEN, |slot| {
            // "render" frame n in place (zero-copy produce).
            slot.fill((n % 251) as u8);
            slot[0] = n as u8;
        })
        .await
        .expect("send frame");
    }
    let _ = child.wait();
    let _ = std::fs::remove_file(&path);
    println!("producer: done");
}

#[cfg(unix)]
async fn consumer(token: ShmToken) {
    // FRICTION #10 (racy connect + sync-in-async): connect_fd_handoff is blocking
    // and will fail if the producer isn't serving yet, so I hand-roll a retry
    // loop and call a blocking fn straight inside async (no spawn_blocking guard
    // offered). There's no "await until available".
    let path = control_socket_path(&token);
    let handle: ShmHandle = loop {
        match connect_fd_handoff(&path, &token) {
            Ok(h) => break h,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    };

    // Consume each frame zero-copy.
    let mut rendered = 0u32;
    let mut checksum = 0u64;
    // FRICTION #11 (when does the stream end?): recv_with returns
    // Option/Result, but there is no end-of-stream concept — I just count to
    // FRAMES, which the consumer only knows because I hard-coded it. A real
    // surface needs a "closed"/length signal the API doesn't carry.
    while let Some(v) = handle
        .recv_with(|slot| (slot[0] as u64) + slot.len() as u64)
        .await
    {
        checksum = checksum.wrapping_add(v);
        rendered += 1;
        if rendered >= FRAMES {
            break;
        }
    }
    eprintln!("consumer: rendered {rendered} frames (checksum {checksum})");
}

#[cfg(unix)]
fn hex(t: &ShmToken) -> String {
    t.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
fn parse_token(s: &str) -> ShmToken {
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    t
}

#[cfg(not(unix))]
fn main() {
    eprintln!("Unix only");
}
