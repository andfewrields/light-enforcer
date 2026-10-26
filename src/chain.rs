// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! The header chain: every header received that connects to it and follows
//! the network's header rules, and the best chain among them (most work).
//!
//! Headers are checked for linkage, proof of work, difficulty (Bitcoin's
//! adjustment every 2016 blocks, and a fork's reset) and the median time
//! past, but not against the clock. Kept compactly, since there are close to
//! a million: about 100 bytes each.

use std::collections::HashMap;

use bitcoin::{BlockHash, CompactTarget, Target, Work, block::Header, hashes::Hash as _, params::Params as PowParams};

use crate::params::Params;

/// Bitcoin's difficulty adjustment interval
const RETARGET_INTERVAL: u32 = 2016;
/// Blocks in the median time past (BIP113)
const MEDIAN_TIME_SPAN: usize = 11;

/// No parent: the genesis block's
const NO_PARENT: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct Entry {
    /// Index of the parent
    prev: u32,
    height: u32,
    time: u32,
    bits: CompactTarget,
    /// Work of the chain up to and including this header. Bitcoin's whole
    /// chain has less than 2^96.
    chainwork: u128,
}

/// What the chain knows of a header
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderInfo {
    pub hash: BlockHash,
    pub prev_hash: BlockHash,
    pub height: u32,
    pub time: u32,
    pub bits: CompactTarget,
}

impl HeaderInfo {
    /// The work of this block alone
    pub fn work(&self) -> Work {
        Target::from_compact(self.bits).to_work()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddHeaderError {
    #[error("header {0} does not connect to the chain")]
    Unconnected(BlockHash),
    #[error("header {0} has invalid proof of work")]
    BadProofOfWork(BlockHash),
    #[error("header {0} has the wrong difficulty")]
    BadDifficulty(BlockHash),
    #[error("header {0} is timestamped before the median time of its ancestors")]
    TimeTooOld(BlockHash),
}

pub struct Chain {
    params: Params,
    pow_params: PowParams,
    hashes: Vec<BlockHash>,
    entries: Vec<Entry>,
    index: HashMap<BlockHash, u32>,
    /// The best chain, by height
    best: Vec<u32>,
    /// The header with the most work (first seen on ties)
    candidate: u32,
}

fn work_u128(bits: CompactTarget) -> u128 {
    let bytes = Target::from_compact(bits).to_work().to_le_bytes();
    u128::from_le_bytes(bytes[..16].try_into().expect("16 bytes"))
}

impl Chain {
    pub fn new(params: Params) -> Self {
        let genesis = params.genesis();
        let hash = genesis.block_hash();
        let pow_params = PowParams::new(params.network);
        Self {
            params,
            pow_params,
            hashes: vec![hash],
            entries: vec![Entry {
                prev: NO_PARENT,
                height: 0,
                time: genesis.time,
                bits: genesis.bits,
                chainwork: work_u128(genesis.bits),
            }],
            index: HashMap::from([(hash, 0)]),
            best: vec![0],
            candidate: 0,
        }
    }

    fn info_at(&self, idx: u32) -> HeaderInfo {
        let entry = &self.entries[idx as usize];
        HeaderInfo {
            hash: self.hashes[idx as usize],
            prev_hash: if entry.prev == NO_PARENT {
                BlockHash::all_zeros()
            } else {
                self.hashes[entry.prev as usize]
            },
            height: entry.height,
            time: entry.time,
            bits: entry.bits,
        }
    }

    pub fn get(&self, hash: &BlockHash) -> Option<HeaderInfo> {
        self.index.get(hash).map(|idx| self.info_at(*idx))
    }

    pub fn tip(&self) -> HeaderInfo {
        self.info_at(*self.best.last().expect("the best chain has its genesis"))
    }

    pub fn tip_height(&self) -> u32 {
        (self.best.len() - 1) as u32
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The best chain's block at `height`
    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        self.best.get(height as usize).map(|idx| self.hashes[*idx as usize])
    }

    pub fn in_best_chain(&self, hash: &BlockHash) -> bool {
        self.get(hash)
            .is_some_and(|info| self.hash_at(info.height) == Some(*hash))
    }

    /// The ancestor of `idx` at `height` (at most its own height)
    fn ancestor(&self, idx: u32, height: u32) -> u32 {
        let entry = &self.entries[idx as usize];
        debug_assert!(height <= entry.height);
        if self.best.get(entry.height as usize) == Some(&idx) {
            return self.best[height as usize];
        }
        let mut idx = idx;
        while self.entries[idx as usize].height > height {
            idx = self.entries[idx as usize].prev;
        }
        idx
    }

    /// The ancestor of `hash` at `height`, if `hash` is known and that high
    pub fn ancestor_hash(&self, hash: &BlockHash, height: u32) -> Option<BlockHash> {
        let idx = *self.index.get(hash)?;
        (height <= self.entries[idx as usize].height).then(|| self.hashes[self.ancestor(idx, height) as usize])
    }

    /// A block locator for the best chain: the last 10 blocks, then
    /// exponentially further apart, down to genesis
    pub fn locator(&self) -> Vec<BlockHash> {
        let mut res = Vec::new();
        let mut height = self.best.len() - 1;
        let mut step = 1;
        loop {
            res.push(self.hashes[self.best[height] as usize]);
            if height == 0 {
                return res;
            }
            if res.len() >= 10 {
                step *= 2;
            }
            height = height.saturating_sub(step);
        }
    }

    /// The difficulty a child of `parent` must have, if the network has
    /// difficulty rules (Bitcoin Core's `GetNextWorkRequired`, mainnet).
    fn required_bits(&self, parent: u32) -> Option<CompactTarget> {
        if !self.params.retarget {
            return None;
        }
        let last = &self.entries[parent as usize];
        let height = last.height + 1;
        if !height.is_multiple_of(RETARGET_INTERVAL) {
            return Some(last.bits);
        }
        if let Some(reset) = self.params.difficulty_reset
            && reset.height == height
        {
            return Some(reset.bits);
        }
        let first = &self.entries[self.ancestor(parent, height - RETARGET_INTERVAL) as usize];
        let timespan = (i64::from(last.time) - i64::from(first.time)).max(0) as u64;
        Some(CompactTarget::from_next_work_required(
            last.bits,
            timespan,
            &self.pow_params,
        ))
    }

    fn median_time_past(&self, idx: u32) -> u32 {
        let mut times = Vec::with_capacity(MEDIAN_TIME_SPAN);
        let mut idx = idx;
        while idx != NO_PARENT && times.len() < MEDIAN_TIME_SPAN {
            let entry = &self.entries[idx as usize];
            times.push(entry.time);
            idx = entry.prev;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Add a header extending the chain. Returns whether it was new.
    pub fn add_header(&mut self, header: &Header) -> Result<bool, AddHeaderError> {
        let hash = header.block_hash();
        if self.index.contains_key(&hash) {
            return Ok(false);
        }
        let Some(&parent) = self.index.get(&header.prev_blockhash) else {
            return Err(AddHeaderError::Unconnected(hash));
        };
        let target = header.target();
        if target > self.pow_params.max_attainable_target || header.validate_pow(target).is_err() {
            return Err(AddHeaderError::BadProofOfWork(hash));
        }
        if self.required_bits(parent).is_some_and(|bits| bits != header.bits) {
            return Err(AddHeaderError::BadDifficulty(hash));
        }
        if header.time <= self.median_time_past(parent) {
            return Err(AddHeaderError::TimeTooOld(hash));
        }
        let parent_entry = self.entries[parent as usize];
        let entry = Entry {
            prev: parent,
            height: parent_entry.height + 1,
            time: header.time,
            bits: header.bits,
            chainwork: parent_entry.chainwork.saturating_add(work_u128(header.bits)),
        };
        let idx = u32::try_from(self.entries.len()).expect("fewer than 4 billion headers");
        if entry.chainwork > self.entries[self.candidate as usize].chainwork {
            self.candidate = idx;
        }
        self.entries.push(entry);
        self.hashes.push(hash);
        self.index.insert(hash, idx);
        Ok(true)
    }

    /// Move the best chain to the header with the most work, if one has more
    /// than the tip (the first seen wins ties). Returns the height of the
    /// last block the old and new best chains share, if it changed.
    pub fn update_best_chain(&mut self) -> Option<u32> {
        if self.best.last() == Some(&self.candidate) {
            return None;
        }
        let mut connected = Vec::new();
        let mut idx = self.candidate;
        while self.best.get(self.entries[idx as usize].height as usize) != Some(&idx) {
            connected.push(idx);
            idx = self.entries[idx as usize].prev;
        }
        let fork_height = self.entries[idx as usize].height;
        self.best.truncate(fork_height as usize + 1);
        self.best.extend(connected.into_iter().rev());
        Some(fork_height)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{CompactTarget, TxMerkleNode, block::Version, hashes::Hash as _};

    use super::{AddHeaderError, Chain, Header};
    use crate::params::Params;

    /// A regtest-difficulty header on `prev`, mined
    fn mine(prev: &Header, seed: u32) -> Header {
        let mut header = Header {
            version: Version::TWO,
            prev_blockhash: prev.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: prev.time + 1,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: seed.wrapping_mul(1000),
        };
        while header.validate_pow(header.target()).is_err() {
            header.nonce += 1;
        }
        header
    }

    #[test]
    fn follows_most_work() {
        let mut chain = Chain::new(Params::regtest());
        let genesis = Params::regtest().genesis();
        let a1 = mine(&genesis, 1);
        let a2 = mine(&a1, 2);
        assert!(chain.add_header(&a1).unwrap());
        assert!(chain.add_header(&a2).unwrap());
        assert!(!chain.add_header(&a2).unwrap());
        assert_eq!(chain.update_best_chain(), Some(0));
        assert_eq!(chain.tip().hash, a2.block_hash());
        assert_eq!(chain.tip().prev_hash, a1.block_hash());

        // A branch with as much work doesn't take over; one with more does
        let b1 = mine(&genesis, 3);
        let b2 = mine(&b1, 4);
        let b3 = mine(&b2, 5);
        chain.add_header(&b1).unwrap();
        chain.add_header(&b2).unwrap();
        assert_eq!(chain.update_best_chain(), None);
        chain.add_header(&b3).unwrap();
        assert_eq!(chain.update_best_chain(), Some(0));
        assert_eq!(chain.tip_height(), 3);
        assert_eq!(chain.hash_at(1), Some(b1.block_hash()));
        assert!(!chain.in_best_chain(&a1.block_hash()));
        assert_eq!(chain.ancestor_hash(&a2.block_hash(), 1), Some(a1.block_hash()));
        assert_eq!(chain.locator().last(), Some(&genesis.block_hash()));

        // The old branch comes back with more work
        let a3 = mine(&a2, 6);
        let a4 = mine(&a3, 7);
        chain.add_header(&a3).unwrap();
        chain.add_header(&a4).unwrap();
        assert_eq!(chain.update_best_chain(), Some(0));
        assert_eq!(chain.hash_at(1), Some(a1.block_hash()));
    }

    #[test]
    fn rejects_bad_headers() {
        let mut chain = Chain::new(Params::regtest());
        let genesis = Params::regtest().genesis();
        let a1 = mine(&genesis, 1);
        let orphan = mine(&a1, 2);
        assert!(matches!(chain.add_header(&orphan), Err(AddHeaderError::Unconnected(_))));
        let mut bad = a1;
        bad.bits = CompactTarget::from_consensus(0x1d00ffff);
        assert!(matches!(chain.add_header(&bad), Err(AddHeaderError::BadProofOfWork(_))));
        let mut old = mine(&genesis, 3);
        old.time = genesis.time;
        while old.validate_pow(old.target()).is_err() {
            old.nonce += 1;
        }
        assert!(matches!(chain.add_header(&old), Err(AddHeaderError::TimeTooOld(_))));
    }

    /// Bitcoin's adjustment: target × actual / expected time, at most 4×
    /// either way, never above the proof-of-work limit
    #[test]
    fn retargets_as_bitcoin() {
        let pow = bitcoin::params::Params::new(Params::betanet().network);
        let two_weeks = 14 * 24 * 60 * 60;
        let next = |bits: u32, timespan: u64| {
            CompactTarget::from_next_work_required(CompactTarget::from_consensus(bits), timespan, &pow).to_consensus()
        };
        assert_eq!(next(0x1b0404cb, two_weeks), 0x1b0404cb);
        assert_eq!(next(0x1b0404cb, two_weeks / 2), 0x1b020265);
        assert_eq!(next(0x1b0404cb, two_weeks / 100), next(0x1b0404cb, two_weeks / 4));
        assert_eq!(next(0x1b0404cb, two_weeks * 100), 0x1b10132c);
        assert_eq!(next(0x1d00ffff, two_weeks * 2), 0x1d00ffff);
    }
}
