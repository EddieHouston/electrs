use crate::chain::{Network, Transaction, TxOut, Txid};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use electrs_macros::trace;

const VSIZE_BIN_WIDTH: u64 = 50_000; // in vbytes

pub struct TxFeeInfo {
    pub fee: u64,           // in satoshis
    pub vsize: u64,         // in virtual bytes (= weight/4)
    pub fee_per_vbyte: f64, // in sat/vb
}

impl TxFeeInfo {
    pub fn new(tx: &Transaction, prevouts: &HashMap<u32, &TxOut>, network: Network) -> Self {
        let fee = get_tx_fee(tx, prevouts, network);

        let weight = tx.weight();
        #[cfg(not(feature = "liquid"))] // rust-bitcoin has a wrapper Weight type
        let weight = weight.to_wu();

        let vsize_float = weight as f64 / 4f64; // for more accurate sat/vB

        TxFeeInfo {
            fee,
            vsize: vsize_float.ceil() as u64,
            fee_per_vbyte: fee as f64 / vsize_float,
        }
    }
}

#[cfg(not(feature = "liquid"))]
pub fn get_tx_fee(tx: &Transaction, prevouts: &HashMap<u32, &TxOut>, _network: Network) -> u64 {
    if tx.is_coinbase() {
        return 0;
    }

    let total_in: u64 = prevouts
        .values()
        .map(|prevout| prevout.value.to_sat())
        .sum();
    let total_out: u64 = tx.output.iter().map(|vout| vout.value.to_sat()).sum();
    total_in - total_out
}

#[cfg(feature = "liquid")]
pub fn get_tx_fee(tx: &Transaction, _prevouts: &HashMap<u32, &TxOut>, network: Network) -> u64 {
    tx.fee_in(*network.native_asset())
}

/// Build a CPFP/package-aware mempool fee histogram.
///
/// Rather than binning each transaction by its own standalone feerate, every
/// transaction is assigned an *effective* feerate that reflects the
/// child-pays-for-parent (CPFP) package it would be mined as part of, mirroring
/// how bitcoind orders transactions for block templates. A low-fee parent that
/// is being pulled in by a high-fee child is therefore counted at the higher
/// package feerate (and the child at the lower package feerate), instead of both
/// being binned at their misleading standalone rates.
///
/// `entries` maps each mempool txid to its fee info; `parents` maps each txid to
/// the list of its in-mempool parents (the txids whose outputs it spends). Txids
/// with no in-mempool ancestry can be omitted from `parents`.
#[trace]
pub fn make_fee_histogram(
    entries: &HashMap<Txid, TxFeeInfo>,
    parents: &HashMap<Txid, Vec<Txid>>,
) -> Vec<(f64, u64)> {
    build_histogram(effective_feerates(entries, parents))
}

/// Assign every transaction an effective (package-aware) feerate, returned as
/// `(effective_feerate, vsize)` pairs.
///
/// Transactions with no in-mempool relatives keep their own feerate (the common
/// case). The rest are split into connected packages and resolved per-package by
/// greedily selecting the sub-package with the best ancestor feerate and
/// assigning each of its members that package feerate — the same ancestor-score
/// ordering bitcoind uses when building a block. Packages are bounded in size by
/// bitcoind's ancestor/cluster limits, keeping the per-package work small.
fn effective_feerates<K: Copy + Eq + Hash>(
    entries: &HashMap<K, TxFeeInfo>,
    parents: &HashMap<K, Vec<K>>,
) -> Vec<(f64, u64)> {
    // Reverse adjacency (txid -> children) so packages can be discovered from
    // any member, not just the leaves.
    let mut children: HashMap<K, Vec<K>> = HashMap::new();
    for (txid, ps) in parents {
        for p in ps {
            children.entry(*p).or_default().push(*txid);
        }
    }

    let mut result = Vec::with_capacity(entries.len());
    let mut visited: HashSet<K> = HashSet::new();

    for (txid, feeinfo) in entries {
        if visited.contains(txid) {
            continue;
        }
        let has_parents = parents.get(txid).map_or(false, |p| !p.is_empty());
        let has_children = children.get(txid).map_or(false, |c| !c.is_empty());
        if !has_parents && !has_children {
            // Singleton: not part of any package, mined at its own feerate.
            visited.insert(*txid);
            result.push((feeinfo.fee_per_vbyte, feeinfo.vsize));
            continue;
        }
        let cluster = collect_cluster(*txid, parents, &children, &mut visited);
        chunk_cluster(&cluster, entries, parents, &mut result);
    }
    result
}

/// Collect the full connected package containing `start`, walking both parent
/// and child edges. Visited members are recorded so each package is processed
/// once.
fn collect_cluster<K: Copy + Eq + Hash>(
    start: K,
    parents: &HashMap<K, Vec<K>>,
    children: &HashMap<K, Vec<K>>,
    visited: &mut HashSet<K>,
) -> Vec<K> {
    let mut cluster = vec![];
    let mut queue = vec![start];
    visited.insert(start);
    while let Some(txid) = queue.pop() {
        cluster.push(txid);
        let neighbors = parents
            .get(&txid)
            .into_iter()
            .flatten()
            .chain(children.get(&txid).into_iter().flatten());
        for &n in neighbors {
            if visited.insert(n) {
                queue.push(n);
            }
        }
    }
    cluster
}

/// Resolve effective feerates within a single connected package by repeatedly
/// mining the sub-package with the best remaining ancestor feerate.
fn chunk_cluster<K: Copy + Eq + Hash>(
    cluster: &[K],
    entries: &HashMap<K, TxFeeInfo>,
    parents: &HashMap<K, Vec<K>>,
    result: &mut Vec<(f64, u64)>,
) {
    let mut remaining: HashSet<K> = cluster.iter().copied().collect();

    while !remaining.is_empty() {
        // Pick the tx whose still-unmined ancestor package has the highest
        // aggregate feerate.
        let mut best: Option<(f64, Vec<K>)> = None;
        for &txid in &remaining {
            let package = ancestor_package(txid, parents, &remaining);
            let (fee, vsize) = package.iter().fold((0u64, 0u64), |(fee, vsize), t| {
                let fi = &entries[t];
                (fee + fi.fee, vsize + fi.vsize)
            });
            if vsize == 0 {
                continue;
            }
            let rate = fee as f64 / vsize as f64;
            if best.as_ref().map_or(true, |(best_rate, _)| rate > *best_rate) {
                best = Some((rate, package));
            }
        }

        let (rate, package) = best.expect("non-empty package yields a sub-package");
        for txid in package {
            result.push((rate, entries[&txid].vsize));
            remaining.remove(&txid);
        }
    }
}

/// The ancestor package of `txid`: itself plus all of its transitive ancestors
/// that are still in `remaining`.
fn ancestor_package<K: Copy + Eq + Hash>(
    txid: K,
    parents: &HashMap<K, Vec<K>>,
    remaining: &HashSet<K>,
) -> Vec<K> {
    let mut package = vec![];
    let mut seen = HashSet::new();
    let mut queue = vec![txid];
    seen.insert(txid);
    while let Some(t) = queue.pop() {
        package.push(t);
        if let Some(ps) = parents.get(&t) {
            for &p in ps {
                if remaining.contains(&p) && seen.insert(p) {
                    queue.push(p);
                }
            }
        }
    }
    package
}

/// Bin `(feerate, vsize)` entries into the Electrum fee histogram format:
/// `[(feerate, total_vsize_at_or_above), ...]` in descending feerate order.
fn build_histogram(mut entries: Vec<(f64, u64)>) -> Vec<(f64, u64)> {
    entries.sort_unstable_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    let mut histogram = vec![];
    let mut bin_size = 0;
    let mut last_fee_rate = 0.0;
    for &(fee_rate, vsize) in entries.iter().rev() {
        if bin_size > VSIZE_BIN_WIDTH && last_fee_rate != fee_rate {
            // vsize of transactions paying >= last_fee_rate
            histogram.push((last_fee_rate, bin_size));
            bin_size = 0;
        }
        last_fee_rate = fee_rate;
        bin_size += vsize;
    }
    if bin_size > 0 {
        histogram.push((last_fee_rate, bin_size));
    }
    histogram
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feeinfo(fee: u64, vsize: u64) -> TxFeeInfo {
        TxFeeInfo {
            fee,
            vsize,
            fee_per_vbyte: fee as f64 / vsize as f64,
        }
    }

    // Effective feerates are returned in arbitrary order; collect them sorted so
    // assertions don't depend on HashMap iteration order.
    fn sorted_rates(mut rates: Vec<(f64, u64)>) -> Vec<(f64, u64)> {
        rates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        rates
    }

    #[test]
    fn singletons_keep_their_own_feerate() {
        let entries = HashMap::from([(1u32, feeinfo(100, 100)), (2u32, feeinfo(500, 100))]);
        let parents = HashMap::new();

        assert_eq!(
            sorted_rates(effective_feerates(&entries, &parents)),
            vec![(1.0, 100), (5.0, 100)]
        );
    }

    #[test]
    fn cpfp_lifts_parent_and_lowers_child_to_package_rate() {
        // Low-fee parent (1 sat/vB) rescued by a high-fee child (100 sat/vB).
        let entries = HashMap::from([
            (1u32, feeinfo(100, 100)),   // parent: own rate 1 sat/vB
            (2u32, feeinfo(10_000, 100)), // child: own rate 100 sat/vB
        ]);
        // child (2) spends parent (1)
        let parents = HashMap::from([(2u32, vec![1u32])]);

        // package rate = (100 + 10_000) / (100 + 100) = 50.5 sat/vB for both
        assert_eq!(
            sorted_rates(effective_feerates(&entries, &parents)),
            vec![(50.5, 100), (50.5, 100)]
        );
    }

    #[test]
    fn high_parent_is_not_dragged_down_by_low_child() {
        // High-fee parent (100 sat/vB) with a low-fee child (1 sat/vB). The
        // parent should be mined first at its own rate; the child follows alone.
        let entries = HashMap::from([
            (1u32, feeinfo(10_000, 100)), // parent: own rate 100 sat/vB
            (2u32, feeinfo(100, 100)),    // child: own rate 1 sat/vB
        ]);
        let parents = HashMap::from([(2u32, vec![1u32])]);

        assert_eq!(
            sorted_rates(effective_feerates(&entries, &parents)),
            vec![(1.0, 100), (100.0, 100)]
        );
    }
}
