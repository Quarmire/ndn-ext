//! Authenticated-network-coding benchmarks (feature `f2-recode`).
//!
//! Produces the numbers behind the coding-auth design note: what the in-flight
//! homomorphic pollution filter costs per packet versus an Ed25519 verify (the
//! per-packet-signature alternative it replaces), how the multi-projection
//! [`FingerprintSet`] scales with `m`, and what verify-on-decode commitment
//! checking costs as the generation size `K` grows.
//!
//! Run: `cargo bench -p ndn-coding --features f2-recode --bench recode_auth`

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use ndn_coding::field;
use ndn_coding::recode::{CodingVector, FingerprintSet, LinearFingerprint, merkle_root, row_hash};

/// Deterministic xorshift64 — reproducible inputs, no `rand` dependency.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

/// A valid coded payload `y = Σ c[s]·source[s]` over GF(2⁸).
fn combine(coeffs: &[u8], sources: &[Vec<u8>]) -> Vec<u8> {
    let sym = sources[0].len();
    let mut y = vec![0u8; sym];
    for (s, &c) in coeffs.iter().enumerate() {
        for j in 0..sym {
            y[j] ^= field::mul(c, sources[s][j]);
        }
    }
    y
}

/// Per-packet in-flight `check` cost vs symbol size (one GF(2⁸) projection).
fn bench_fingerprint_check(c: &mut Criterion) {
    let mut g = c.benchmark_group("fingerprint_check_vs_symbol_size");
    let k = 16;
    for &sym in &[256usize, 1024, 4096, 16384] {
        let mut rng = XorShift(0xA1);
        let sources: Vec<Vec<u8>> = (0..k).map(|_| rng.bytes(sym)).collect();
        let fp = LinearFingerprint::for_sources(rng.bytes(sym), &sources);
        let coeffs: Vec<u8> = (0..k).map(|_| rng.byte()).collect();
        let payload = combine(&coeffs, &sources);
        let vector = CodingVector(coeffs);
        g.throughput(Throughput::Bytes(sym as u64));
        g.bench_with_input(BenchmarkId::from_parameter(sym), &sym, |b, _| {
            b.iter(|| black_box(fp.check(black_box(&vector), black_box(&payload))));
        });
    }
    g.finish();
}

/// `FingerprintSet::check` cost as `m` grows (the 2⁻⁸ᵐ strength knob), fixed sym.
fn bench_fingerprint_set_check(c: &mut Criterion) {
    let mut g = c.benchmark_group("fingerprint_set_check_vs_m");
    let k = 16;
    let sym = 1024;
    let mut rng = XorShift(0xB2);
    let sources: Vec<Vec<u8>> = (0..k).map(|_| rng.bytes(sym)).collect();
    let coeffs: Vec<u8> = (0..k).map(|_| rng.byte()).collect();
    let payload = combine(&coeffs, &sources);
    let vector = CodingVector(coeffs);
    for &m in &[1usize, 2, 4, 8] {
        let seeds: Vec<Vec<u8>> = (0..m).map(|_| rng.bytes(sym)).collect();
        let set = FingerprintSet::for_sources(&seeds, &sources);
        g.bench_with_input(BenchmarkId::from_parameter(m), &m, |b, _| {
            b.iter(|| black_box(set.check(black_box(&vector), black_box(&payload))));
        });
    }
    g.finish();
}

/// Baseline: a single Ed25519 verify — what per-packet signing would cost on
/// each coded/recoded packet (and which can't even authenticate recoded
/// combinations). Compare against `fingerprint_check` at sym=1024.
fn bench_ed25519_verify_baseline(c: &mut Criterion) {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();
    let mut rng = XorShift(0xC3);
    let msg = rng.bytes(1024);
    let sig = sk.sign(&msg);
    c.bench_function("ed25519_verify_baseline_1024B", |b| {
        b.iter(|| black_box(vk.verify(black_box(&msg), black_box(&sig)).is_ok()));
    });
}

/// Verify-on-decode commitment cost vs generation size `K`: hash the K recovered
/// rows and compare (RowHashes) or fold a Merkle root (MerkleRoot).
fn bench_commitment_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("commitment_verify_vs_k");
    let sym = 1024;
    for &k in &[16usize, 64, 255] {
        let mut rng = XorShift(0xD4);
        let sources: Vec<Vec<u8>> = (0..k).map(|_| rng.bytes(sym)).collect();
        g.bench_with_input(BenchmarkId::new("row_hashes", k), &k, |b, _| {
            b.iter(|| {
                let hashes: Vec<[u8; 32]> = sources.iter().map(|r| row_hash(r)).collect();
                black_box(hashes)
            });
        });
        g.bench_with_input(BenchmarkId::new("merkle_root", k), &k, |b, _| {
            b.iter(|| {
                let hashes: Vec<[u8; 32]> = sources.iter().map(|r| row_hash(r)).collect();
                black_box(merkle_root(&hashes))
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_fingerprint_check,
    bench_fingerprint_set_check,
    bench_ed25519_verify_baseline,
    bench_commitment_verify,
);
criterion_main!(benches);
