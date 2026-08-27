//! recode-at-relay vs store-and-forward — the RLNC value proposition, on the REAL codec (task #58).
//!
//! A relay holds a full generation of K coded source packets and must get them across a LOSSY link to
//! a consumer. Two disciplines:
//!   • FORWARD  — replay the K stored packets round-robin. The consumer must collect all K *distinct*
//!                rows, so loss triggers the coupon-collector problem (late duplicates waste airtime).
//!   • RECODE   — mint a fresh random GF(256) linear combination per transmission (`recode_combine`).
//!                Every survivor is innovative w.h.p., so the consumer decodes after any K get through.
//!
//! We measure transmissions-until-the-consumer-decodes at a range of erasure rates, averaged over
//! seeds, and confirm correctness with the codec's verify-on-decode. Recode should need ≈ K/(1−e);
//! forward needs ≈ K·H_K/(1−e) — the recode win grows with K and loss.
//!
//! Run: `cargo run -p ndn-coding --example rlnc_recode --features f2-recode`

use bytes::Bytes;
use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodedPacket, CodingVector, GenerationBuffer, GenerationDescriptor, RecodePolicy,
    SourceCommitment, recode_combine, row_hash,
};
use ndn_packet::Name;

const K: u16 = 12;
const SYM: usize = 64;
const SEEDS: u64 = 200;
const CAP: u32 = 400; // transmission budget before we call it a failure

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

enum Mode {
    Forward,
    Recode,
}

/// One trial: transmit from the relay until the consumer decodes or the budget runs out.
/// Returns Some(transmissions) on decode, None on failure.
fn trial(
    mode: &Mode,
    e: f64,
    held: &[CodedPacket],
    make_desc: &dyn Fn() -> GenerationDescriptor,
    gen_id: u64,
    mut rng: u64,
) -> Option<u32> {
    let mut buf = GenerationBuffer::new(make_desc());
    let mut tx = 0u32;
    let mut fwd = 0usize;
    while !buf.is_decodable() && tx < CAP {
        tx += 1;
        let packet = match mode {
            Mode::Forward => {
                let p = held[fwd % held.len()].clone();
                fwd += 1;
                p
            }
            Mode::Recode => {
                let coeffs: Vec<u8> = (0..held.len()).map(|_| (xs(&mut rng) as u8) | 1).collect();
                recode_combine(held, &coeffs).expect("recode")
            }
        };
        // Erasure on the relay→consumer link.
        if (xs(&mut rng) % 1000) as f64 / 1000.0 < e {
            continue;
        }
        let meta = CodedMetadata {
            generation_id: gen_id,
            k: K,
            field: Field::Gf8,
            vector: packet.vector.clone(),
        };
        let _ = buf.absorb(&meta, packet.payload);
    }
    if buf.is_decodable() {
        // Verify-on-decode: the recovered content must match the original (RowHashes commitment).
        buf.decode().ok().map(|_| tx)
    } else {
        None
    }
}

fn main() {
    let payload: Vec<u8> = (0..K as usize * SYM)
        .map(|i| ((i * 7 + 13) & 0xff) as u8)
        .collect();
    let sources: Vec<Vec<u8>> = payload.chunks(SYM).map(|c| c.to_vec()).collect();
    let object: Name = "/sim/nc/clip".parse().unwrap();
    let gen_id = 1u64;
    let make_desc = || GenerationDescriptor {
        generation_id: gen_id,
        k: K,
        symbol_size: SYM as u32,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    };
    // The relay holds all K systematic source packets (unit coding vectors).
    let held: Vec<CodedPacket> = sources
        .iter()
        .enumerate()
        .map(|(i, r)| CodedPacket {
            vector: CodingVector::unit(K, i as u16),
            payload: Bytes::from(r.clone()),
        })
        .collect();

    println!("recode-at-relay vs store-and-forward — K={K}, {SEEDS} seeds, verify-on-decode\n");
    println!("erasure   forward txs   recode txs   speedup   forward ok   recode ok");
    let mut json = format!("{{\"k\":{K},\"seeds\":{SEEDS},\"rows\":[");
    for (ri, &e) in [0.0, 0.1, 0.2, 0.3, 0.5, 0.7].iter().enumerate() {
        let stat = |mode: &Mode| {
            let (mut sum, mut ok) = (0u64, 0u64);
            for seed in 0..SEEDS {
                if let Some(tx) = trial(mode, e, &held, &make_desc, gen_id, (seed << 1) | 1) {
                    sum += tx as u64;
                    ok += 1;
                }
            }
            let mean = if ok > 0 {
                sum as f64 / ok as f64
            } else {
                f64::NAN
            };
            (mean, ok as f64 / SEEDS as f64)
        };
        let (ftx, fok) = stat(&Mode::Forward);
        let (rtx, rok) = stat(&Mode::Recode);
        println!(
            "  {e:.2}     {ftx:8.1}     {rtx:8.1}     {:5.2}x     {:6.0}%     {:6.0}%",
            ftx / rtx,
            fok * 100.0,
            rok * 100.0
        );
        if ri > 0 {
            json.push(',');
        }
        json.push_str(&format!(
            "{{\"e\":{e},\"fwd_tx\":{ftx:.1},\"rec_tx\":{rtx:.1},\"fwd_ok\":{fok:.3},\"rec_ok\":{rok:.3}}}"
        ));
    }
    json.push_str("]}");
    let path = std::env::temp_dir().join("rlnc_recode.json");
    let _ = std::fs::write(&path, &json);
    println!("\ntelemetry → {}", path.display());
}
