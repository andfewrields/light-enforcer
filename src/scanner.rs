// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Scanning the blocks of the trusted chain for the slot's events.
//!
//! The trusted chain is the best header chain up to its last block with
//! more than `confirmations` confirmations: those blocks are assumed fully
//! valid, and no other is used. Its blocks from the scan start height on are
//! downloaded, in order, and scanned (`bip300::connect_block`); what's kept
//! of each is its events and, for recent ones, the slot's state after it,
//! to scan on from after a reorg. Scanned blocks that leave the trusted
//! chain are kept too, as a full enforcer keeps the blocks it connected.
//! Everything is kept in `scan.json`.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bitcoin::BlockHash;
use futures::{StreamExt as _, stream};
use serde::{Deserialize, Serialize};

use crate::{
    bip300::{self, Event, Rules, SlotState},
    chain::HeaderInfo,
    node::{GetBlockError, Node, lock},
};

/// Blocks to download at once
const CONCURRENCY: usize = 16;
/// Blocks to plan at once, between checks of the trusted chain
const BATCH: u32 = 256;
/// How many blocks below the scanned tip keep the slot's state: a reorg
/// deeper than that scans again from the start height
const STATE_WINDOW: u32 = 2_000;
const SAVE_EVERY: Duration = Duration::from_secs(30);
const RETRY_AFTER: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScannedBlock {
    pub height: u32,
    pub prev: BlockHash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
    /// The slot after this block; dropped for old blocks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<SlotState>,
}

#[derive(Default, Deserialize, Serialize)]
struct Scanned {
    network: String,
    slot: u8,
    scan_start_height: u32,
    /// The trusted chain's last scanned block: the tip served
    tip: Option<BlockHash>,
    blocks: HashMap<BlockHash, ScannedBlock>,
    #[serde(skip)]
    dirty: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PegDataError {
    #[error("block {0} is not scanned")]
    EndNotFound(BlockHash),
    #[error("block {start} is not an ancestor of block {end}")]
    StartNotAncestor { start: BlockHash, end: BlockHash },
}

pub struct Scanner {
    node: Arc<Node>,
    rules: Rules,
    start_height: u32,
    confirmations: u32,
    path: PathBuf,
    scanned: Mutex<Scanned>,
}

impl Scanner {
    /// The scanner, with what earlier runs scanned (in `datadir`) if they
    /// scanned the same
    pub fn load(node: Arc<Node>, rules: Rules, start_height: u32, confirmations: u32, datadir: &Path) -> Self {
        let path = datadir.join("scan.json");
        let fresh = Scanned {
            network: node.params.name.to_owned(),
            slot: rules.slot,
            scan_start_height: start_height,
            ..Scanned::default()
        };
        let scanned = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Scanned>(&bytes) {
                Ok(stored)
                    if (stored.network.as_str(), stored.slot, stored.scan_start_height)
                        == (fresh.network.as_str(), fresh.slot, fresh.scan_start_height) =>
                {
                    tracing::info!(blocks = stored.blocks.len(), "Loaded scanned blocks");
                    stored
                }
                Ok(_) => {
                    tracing::info!("Scanning again: the stored scan is for another network, slot or start height");
                    fresh
                }
                Err(err) => {
                    tracing::warn!("Scanning again: can't read {}: {err:#}", path.display());
                    fresh
                }
            },
            Err(_) => fresh,
        };
        Self {
            node,
            rules,
            start_height,
            confirmations,
            path,
            scanned: Mutex::new(scanned),
        }
    }

    /// Write the scanned blocks to disk, if they changed
    pub fn save(&self) {
        let json = {
            let mut scanned = lock(&self.scanned);
            if !scanned.dirty {
                return;
            }
            // Old blocks' states, which only a deep reorg would need
            if let Some(tip_height) = scanned
                .tip
                .and_then(|tip| scanned.blocks.get(&tip))
                .map(|block| block.height)
            {
                for block in scanned.blocks.values_mut() {
                    if block.height + STATE_WINDOW < tip_height {
                        block.state = None;
                    }
                }
            }
            scanned.dirty = false;
            serde_json::to_vec(&*scanned).expect("serializable")
        };
        let tmp = self.path.with_extension("json.tmp");
        if let Err(err) = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, &self.path)) {
            tracing::error!("Can't write {}: {err:#}", self.path.display());
        }
    }

    pub async fn run(self: Arc<Self>) {
        let mut last_save = Instant::now();
        loop {
            match self.step().await {
                Ok(true) => (),
                Ok(false) => {
                    let _ = tokio::time::timeout(RETRY_AFTER, self.node.chain_changed.notified()).await;
                }
                Err(err) => {
                    tracing::warn!("Can't scan: {err:#}");
                    tokio::time::sleep(RETRY_AFTER).await;
                }
            }
            if last_save.elapsed() > SAVE_EVERY {
                self.save();
                last_save = Instant::now();
            }
        }
    }

    /// Scan the trusted chain's next blocks. Returns whether there may be
    /// more to do at once.
    async fn step(&self) -> Result<bool, GetBlockError> {
        if !self.node.is_synced() {
            return Ok(false);
        }
        let (trusted_height, todo) = self.node.with_chain(|chain| {
            let mut scanned = lock(&self.scanned);
            // Blocks with more than `confirmations` confirmations
            let trusted_height = chain
                .tip_height()
                .checked_sub(self.confirmations)
                .filter(|height| *height >= self.start_height);
            let Some(trusted_height) = trusted_height else {
                set_tip(&mut scanned, None);
                return (0, vec![]);
            };
            // The trusted chain's last block scanned, which we can scan on from
            let resume = (self.start_height..=trusted_height).rev().find(|height| {
                let hash = chain.hash_at(*height).expect("below the tip");
                scanned.blocks.get(&hash).is_some_and(|block| block.state.is_some())
            });
            set_tip(
                &mut scanned,
                resume.map(|height| chain.hash_at(height).expect("below the tip")),
            );
            let from = resume.map_or(self.start_height, |height| height + 1);
            let to = trusted_height.min(from.saturating_add(BATCH - 1));
            let todo: Vec<_> = (from..=to)
                .map(|height| (height, chain.hash_at(height).expect("below the tip")))
                .collect();
            (trusted_height, todo)
        });
        if todo.is_empty() {
            return Ok(false);
        }

        let mut blocks = stream::iter(todo)
            .map(|(height, hash)| {
                let node = self.node.clone();
                async move { node.get_block(hash).await.map(|block| (height, block)) }
            })
            .buffered(CONCURRENCY);
        while let Some(res) = blocks.next().await {
            let (height, block) = res?;
            let hash = block.block_hash();
            if !self.node.with_chain(|chain| chain.in_best_chain(&hash)) {
                // The chain changed: plan again
                return Ok(true);
            }
            let mut scanned = lock(&self.scanned);
            let state = if height == self.start_height {
                Some(SlotState::default())
            } else {
                scanned
                    .blocks
                    .get(&block.header.prev_blockhash)
                    .and_then(|parent| parent.state.clone())
            };
            let Some(state) = state else {
                return Ok(true);
            };
            let (events, state) = bip300::connect_block(&self.rules, height, &block, state);
            if !events.is_empty() {
                let json = serde_json::to_string(&events).expect("serializable");
                tracing::info!(height, block = %hash, events = json, "Slot events");
            }
            scanned.blocks.insert(
                hash,
                ScannedBlock {
                    height,
                    prev: block.header.prev_blockhash,
                    events,
                    state: Some(state),
                },
            );
            set_tip(&mut scanned, Some(hash));
            if height == trusted_height || height % 1000 == 0 {
                tracing::info!(height, trusted_height, "Scanned");
            }
        }
        Ok(true)
    }

    /// The tip served: the trusted chain's last scanned block
    pub fn tip(&self) -> Option<HeaderInfo> {
        let tip = lock(&self.scanned).tip?;
        self.node.with_chain(|chain| chain.get(&tip))
    }

    /// The scanned blocks with events after `start` (or from the scan start
    /// height) up to `end`, in height order, with their events
    pub fn two_way_peg_data(
        &self,
        start: Option<BlockHash>,
        end: BlockHash,
    ) -> Result<Vec<(HeaderInfo, Vec<Event>)>, PegDataError> {
        let mut blocks = Vec::new();
        {
            let scanned = lock(&self.scanned);
            let mut hash = end;
            loop {
                let Some(block) = scanned.blocks.get(&hash) else {
                    return Err(PegDataError::EndNotFound(hash));
                };
                blocks.push((hash, block.events.clone()));
                if start == Some(hash) {
                    break;
                }
                hash = block.prev;
                if start == Some(hash) {
                    break;
                }
                if block.height == self.start_height {
                    // Below, there are no events; `start` must be there
                    let reached = hash;
                    if let Some(start) = start {
                        let ancestor = self.node.with_chain(|chain| {
                            let height = chain.get(&start)?.height;
                            chain.ancestor_hash(&reached, height)
                        });
                        if ancestor != Some(start) {
                            return Err(PegDataError::StartNotAncestor { start, end });
                        }
                    }
                    break;
                }
            }
        }
        blocks.reverse();
        Ok(self.node.with_chain(|chain| {
            blocks
                .into_iter()
                .filter(|(_, events)| !events.is_empty())
                .filter_map(|(hash, events)| Some((chain.get(&hash)?, events)))
                .collect()
        }))
    }
}

fn set_tip(scanned: &mut Scanned, tip: Option<BlockHash>) {
    if scanned.tip != tip {
        scanned.tip = tip;
        scanned.dirty = true;
    }
}
