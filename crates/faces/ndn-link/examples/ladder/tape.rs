//! The recorder: the data layer's timeline events (target `ndn_heap::timeline`; level trace) and the
//! link's events (target `face.quic`, every level: the drop notices at info, and the trace-level
//! "datagram over the path size, dropped" of a frame over the path's datagram size), each kept with this machine's
//! clock. A child installs it only in a traced run (`LADDER_TRACE`); the timed runs have no
//! subscriber, so every callsite there is the disabled-callsite check and nothing else.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::Metadata;

/// Nanoseconds since the epoch on this machine's clock: both children and the parent are on it, so
/// their times subtract.
pub fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// What was recorded since the last `CLEAR`: (time, target, "message field=value ...").
pub static TAPE: Mutex<Vec<(u128, String, String)>> = Mutex::new(Vec::new());

pub struct Tape;
struct Text(String);

impl tracing::field::Visit for Text {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            self.0.insert_str(0, &format!("{v:?} "))
        } else {
            self.0.push_str(&format!("{}={v:?} ", f.name()))
        }
    }
}

fn wanted(m: &Metadata<'_>) -> bool {
    m.target() == "ndn_heap::timeline" || m.target() == "face.quic"
}

impl tracing::Subscriber for Tape {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        wanted(m)
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        static N: AtomicU64 = AtomicU64::new(1);
        tracing::span::Id::from_u64(N.fetch_add(1, Relaxed))
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        let mut t = Text(String::new());
        e.record(&mut t);
        TAPE.lock().unwrap().push((
            now_ns(),
            e.metadata().target().to_owned(),
            t.0.trim_end().replace('\n', " "),
        ));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// `CLEAR` empties the recorder; `DUMP` prints what it holds (`EV <ns> <target> <text>`), then `END`.
pub fn command(c: &str) {
    if c == "CLEAR" {
        TAPE.lock().unwrap().clear();
        println!("CLEAR");
    }
    if c == "DUMP" {
        for (t, tg, m) in TAPE.lock().unwrap().drain(..) {
            println!("EV {t} {tg} {m}");
        }
        println!("END");
    }
}
