//! End-to-end recover-time under a live pollution attacker (§8 TODO).
//!
//! A structural, deterministic simulation that drives the **real** coding
//! logic — `GenerationBuffer` (rank-aware admission), `decode()` (GF(2^8) RREF),
//! and verify-on-decode against the `SourceCommitment` — under an attacker who
//! injects polluted coded packets at a Bernoulli rate `p`. It measures how the
//! in-flight homomorphic filter ([`FingerprintSet`]) changes recover-time as `p`
//! and the projection count `m` vary.
//!
//! The mechanism being measured: a polluted packet that reaches the basis is
//! linearly innovative (random vector), so it raises rank to K and `decode()`
//! then fails the commitment (`CommitmentFailed`) — poisoning the *whole*
//! generation, forcing the consumer to discard buffer state and re-pull. The
//! filter rejects pollution *before* the basis, so clean recovery proceeds.
//! A single GF(2^8) projection leaks ~1/256 of pollution into the basis;
//! `m` projections leak ~256^-m, which the high-`p` rows expose.
//!
//! Structural (counts offered packets ≈ airtime/RTT proxy, decode attempts, and
//! buffer restarts; wall-clock is printed but not asserted — it is
//! environment-dependent). Deterministic LCG, no `rand`. Gated by `f2-recode`.
//! Run with `--nocapture` to see the tables.

#![cfg(feature = "f2-recode")]

use std::time::{Duration, Instant};

use bytes::Bytes;

use ndn_coding::field;
use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodingVector, DecodeError, FingerprintSet, GenerationBuffer,
    GenerationDescriptor, RecodePolicy, SourceCommitment, row_hash,
};

const K: u16 = 16;
const SYMBOL: usize = 256; // 16 * 256 = 4 KiB generation
/// Hard ceiling on offered packets per recovery — past this we call it a
/// failure to recover (the attacker has won / livelock).
const OFFER_BUDGET: usize = 4096;

/// Tiny seedable LCG → deterministic, no `rand` dependency.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
    fn nonzero_byte(&mut self) -> u8 {
        let b = self.byte();
        if b == 0 { 1 } else { b }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
    /// Bernoulli: `true` with probability `p` (parts-per-1000).
    fn hit(&mut self, p_permille: u64) -> bool {
        (self.next_u64() >> 11) % 1000 < p_permille
    }
}

fn make_sources(seed: u64) -> Vec<Vec<u8>> {
    let mut rng = Lcg(seed);
    (0..K).map(|_| rng.bytes(SYMBOL)).collect()
}

/// `y = Σ c[s]·source[s]` over GF(2^8) — a genuine coded payload.
fn combine(coeffs: &[u8], sources: &[Vec<u8>]) -> Vec<u8> {
    let mut y = vec![0u8; SYMBOL];
    for (s, &c) in coeffs.iter().enumerate() {
        for j in 0..SYMBOL {
            y[j] ^= field::mul(c, sources[s][j]);
        }
    }
    y
}

fn descriptor(sources: &[Vec<u8>]) -> GenerationDescriptor {
    GenerationDescriptor {
        generation_id: 1,
        k: K,
        symbol_size: SYMBOL as u32,
        field: Field::Gf8,
        content_name: "/bench/gen".parse().unwrap(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None, // the buffer does no filtering; the FingerprintSet does
        fingerprint: None,
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Outcome {
    offered: usize,
    rejected: usize,
    restarts: usize,
    decode_attempts: usize,
    recovered: bool,
    elapsed: Duration,
}

/// Drive one recovery under pollution rate `p_permille` with an optional
/// `m`-projection in-flight filter (`None` = no filter).
fn simulate(
    sources: &[Vec<u8>],
    filter: Option<&FingerprintSet>,
    p_permille: u64,
    seed: u64,
) -> Outcome {
    let desc = descriptor(sources);
    let mut rng = Lcg(seed);
    let mut out = Outcome::default();
    let start = Instant::now();

    let mut buf = GenerationBuffer::new(desc.clone());
    while out.offered < OFFER_BUDGET {
        out.offered += 1;

        // Generate a packet: polluted w.p. p, else a genuine combination.
        let polluted = rng.hit(p_permille);
        let coeffs: Vec<u8> = (0..K).map(|_| rng.nonzero_byte()).collect();
        let vector = CodingVector(coeffs.clone());
        let payload = if polluted {
            Bytes::from(rng.bytes(SYMBOL)) // garbage, not Σ c·source
        } else {
            Bytes::from(combine(&coeffs, sources))
        };

        // In-flight filter (modelled with the real FingerprintSet::check).
        if let Some(set) = filter
            && !set.check(&vector, &payload)
        {
            out.rejected += 1;
            continue;
        }

        let meta = CodedMetadata {
            generation_id: 1,
            k: K,
            field: Field::Gf8,
            vector,
        };
        // absorb may report dependent (Ok(false)) — just keep pulling.
        let _ = buf.absorb(&meta, payload);

        if buf.is_decodable() {
            out.decode_attempts += 1;
            match buf.decode() {
                Ok(_) => {
                    out.recovered = true;
                    break;
                }
                Err(DecodeError::CommitmentFailed) => {
                    // A polluted packet slipped into the basis (filter leak or
                    // no filter): the generation is poisoned. Discard and re-pull.
                    out.restarts += 1;
                    buf = GenerationBuffer::new(desc.clone());
                }
                Err(_) => break,
            }
        }
    }
    out.elapsed = start.elapsed();
    out
}

/// Build an `m`-projection immediate-mode filter for the generation.
fn filter_set(sources: &[Vec<u8>], m: usize, seed: u64) -> FingerprintSet {
    let mut rng = Lcg(seed);
    let seeds: Vec<Vec<u8>> = (0..m).map(|_| rng.bytes(SYMBOL)).collect();
    FingerprintSet::for_sources(&seeds, sources)
}

#[test]
fn recover_time_under_pollution() {
    let sources = make_sources(0xABCD);
    let f1 = filter_set(&sources, 1, 0x11);
    let f4 = filter_set(&sources, 4, 0x44);

    let rates = [0u64, 100, 200, 300, 400, 500]; // 0%..50% pollution
    println!(
        "\nrecover-time under pollution (K={K}, symbol={SYMBOL}B, offer-budget={OFFER_BUDGET})"
    );
    println!("  filter      p     offered  rejected  restarts  decodes  recovered   time");
    println!("  ----------------------------------------------------------------------------");

    for &p in &rates {
        for (label, set) in [
            ("none   ", None),
            ("m=1    ", Some(&f1)),
            ("m=4    ", Some(&f4)),
        ] {
            let o = simulate(&sources, set, p, 0xBEEF ^ p);
            println!(
                "  {label}  {:>4}%  {:>8}  {:>8}  {:>8}  {:>7}  {:>8}   {:>7.2?}",
                p / 10,
                o.offered,
                o.rejected,
                o.restarts,
                o.decode_attempts,
                o.recovered,
                o.elapsed,
            );
        }
    }
    println!();

    // --- assertions on the structural counts (deterministic) -------------

    // Clean channel (p=0): everyone recovers with exactly K offers, no waste.
    for set in [None, Some(&f1), Some(&f4)] {
        let o = simulate(&sources, set, 0, 0xBEEF);
        assert!(o.recovered);
        assert_eq!(
            o.offered, K as usize,
            "clean channel needs exactly K offers"
        );
        assert_eq!(o.restarts, 0);
    }

    // At 30% pollution the m=4 filter recovers cleanly with ≈ K/(1-p) offers
    // and (almost surely) no poison leak / restarts.
    let m4 = simulate(&sources, Some(&f4), 300, 0xBEEF ^ 300);
    assert!(m4.recovered, "m=4 must recover at 30% pollution");
    assert_eq!(m4.restarts, 0, "m=4 (2^-32) leaks no poison at 30%");
    // ~ K/(0.7) ≈ 23; allow generous slack for the Bernoulli draw.
    assert!(
        m4.offered < 2 * K as usize + 16,
        "m=4 offered {} should be ≈ K/(1-p)",
        m4.offered
    );

    // No filter at 30%: the basis is poisoned almost every batch, so it burns
    // far more offers (restart storm) and needs many more decode attempts —
    // or fails to recover within budget. Either way it is dramatically worse
    // than the filtered path.
    let none = simulate(&sources, None, 300, 0xBEEF ^ 300);
    assert!(
        none.offered > 4 * m4.offered || !none.recovered,
        "no-filter (offered {}, recovered {}) must be far worse than m=4 (offered {})",
        none.offered,
        none.recovered,
        m4.offered
    );
    assert!(
        none.restarts > m4.restarts,
        "no-filter must suffer more poison-induced restarts than m=4"
    );

    // The multi-projection advantage over a single projection shows at high p:
    // m=1 leaks ~1/256 of pollution into the basis, so at 50% it restarts at
    // least as often as m=4 (which essentially never leaks).
    let s1 = simulate(&sources, Some(&f1), 500, 0xBEEF ^ 500);
    let s4 = simulate(&sources, Some(&f4), 500, 0xBEEF ^ 500);
    assert!(s4.recovered, "m=4 recovers even at 50% pollution");
    assert!(
        s1.restarts >= s4.restarts,
        "m=1 (2^-8) should leak at least as much as m=4 (2^-32) at 50%"
    );
}
