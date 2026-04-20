//! Compare SHA-256 implementations used (or proposed) for `get_status_hash`.
//!
//! Three variants:
//!   1. `rust-crypto` 0.2 — the pre-PR implementation (unmaintained, CVE-flagged)
//!   2. `sha2` 0.10       — the current PR's choice (RustCrypto, uses SHA-NI
//!                          + ARMv8 crypto extensions via `cpufeatures`)
//!   3. `bitcoin_hashes`  — reviewer's suggestion (re-exported through
//!                          `bitcoin::hashes`; has its own SHA-NI path for x86,
//!                          no ARMv8 crypto-ext path as of 0.14.1)
//!
//! The workload mirrors `get_status_hash`: feed N short strings of the form
//! `"<64-hex-txid>:<height>:"` (~72 bytes each) through one hasher and finalize.
//!
//! Run with:  cargo bench --bench sha256_variants

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

/// Build a deterministic list of `n` status-hash input parts that look like
/// the real `get_status_hash` input: "<txid>:<height>:"
fn make_parts(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            // 64 hex chars of fake txid derived from i, then a height
            let mut txid = String::with_capacity(64);
            for j in 0..32 {
                txid.push_str(&format!("{:02x}", (i + j) as u8));
            }
            format!("{}:{}:", txid, i as i32)
        })
        .collect()
}

fn bench_rust_crypto(parts: &[String]) -> [u8; 32] {
    use crypto::digest::Digest;
    use crypto::sha2::Sha256;
    let mut hash = [0u8; 32];
    let mut h = Sha256::new();
    for p in parts {
        h.input(p.as_bytes());
    }
    h.result(&mut hash);
    hash
}

fn bench_sha2(parts: &[String]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
    }
    h.finalize().into()
}

fn bench_bitcoin_hashes(parts: &[String]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let mut eng = sha256::Hash::engine();
    for p in parts {
        eng.input(p.as_bytes());
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn criterion_benchmark(c: &mut Criterion) {
    // Realistic wallet sizes: a scripthash with a handful of txs (10),
    // a moderately active one (100), and a heavy one (1000).
    for &n in &[10_usize, 100, 1000] {
        let parts = make_parts(n);
        let mut group = c.benchmark_group(format!("status_hash_{}_txs", n));

        group.bench_with_input(BenchmarkId::new("rust-crypto", n), &parts, |b, parts| {
            b.iter(|| black_box(bench_rust_crypto(parts)))
        });
        group.bench_with_input(BenchmarkId::new("sha2", n), &parts, |b, parts| {
            b.iter(|| black_box(bench_sha2(parts)))
        });
        group.bench_with_input(
            BenchmarkId::new("bitcoin_hashes", n),
            &parts,
            |b, parts| b.iter(|| black_box(bench_bitcoin_hashes(parts))),
        );

        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
