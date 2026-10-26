// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! State shared by the peers, the scanner and the server: the header chain
//! (kept in `headers.dat` too), the peers, and blocks being fetched.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read as _, Write as _},
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bitcoin::{Block, BlockHash, block::Header, consensus::encode};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::{
    chain::{AddHeaderError, Chain},
    params::Params,
};

/// How long to wait for a block from one peer before asking another
const BLOCK_PEER_TIMEOUT: Duration = Duration::from_secs(20);
/// How many times to ask for a block, across peers
const BLOCK_ATTEMPTS: usize = 4;
/// Block requests a peer may let time out before it is dropped
const MAX_PEER_TIMEOUTS: u32 = 2;
/// Most addresses to remember
const MAX_ADDRESSES: usize = 2000;
const HEADER_SIZE: usize = 80;

/// What a peer task is asked to do
#[derive(Debug)]
pub enum PeerCommand {
    GetBlock(BlockHash),
    /// Too slow to answer
    Disconnect,
}

struct PeerHandle {
    commands: mpsc::UnboundedSender<PeerCommand>,
    /// Blocks asked for and not received yet
    in_flight: usize,
    timeouts: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum GetBlockError {
    #[error("no peer to fetch block {0} from")]
    NoPeers(BlockHash),
    #[error("no peer sent block {0} in time")]
    Timeout(BlockHash),
}

#[derive(Debug, thiserror::Error)]
#[error("block {0} doesn't match its Merkle root or witness commitment")]
pub struct BadBlock(BlockHash);

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct Node {
    pub params: Params,
    chain: Mutex<Chain>,
    headers_file: Mutex<BufWriter<File>>,
    /// Whether a peer has no more headers for us
    synced: AtomicBool,
    /// Signalled when the best chain changes, or headers are synced
    pub chain_changed: Notify,
    peers: Mutex<HashMap<usize, PeerHandle>>,
    /// The peer syncing headers, while not synced: one at a time, so that
    /// they are downloaded once
    sync_peer: Mutex<Option<usize>>,
    waiting: Mutex<HashMap<BlockHash, Vec<oneshot::Sender<Arc<Block>>>>>,
    /// Known peer addresses, with when they were last tried
    pub addresses: Mutex<HashMap<SocketAddr, Option<Instant>>>,
}

impl Node {
    /// The node, with the headers kept in `datadir` from earlier runs
    pub fn load(params: Params, datadir: &Path) -> anyhow::Result<Self> {
        let path = datadir.join("headers.dat");
        let mut chain = Chain::new(params.clone());
        let mut valid_len = 0;
        if let Ok(file) = File::open(&path) {
            let mut reader = BufReader::new(file);
            let mut bytes = [0; HEADER_SIZE];
            while reader.read_exact(&mut bytes).is_ok() {
                let added = encode::deserialize::<Header>(&bytes)
                    .map_err(anyhow::Error::from)
                    .and_then(|header| Ok(chain.add_header(&header)?));
                if let Err(err) = added {
                    tracing::warn!("Dropping stored headers from the first invalid one: {err:#}");
                    break;
                }
                valid_len += HEADER_SIZE as u64;
            }
        }
        chain.update_best_chain();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.set_len(valid_len)?;
        let tip = chain.tip();
        tracing::info!(headers = chain.len(), height = tip.height, tip = %tip.hash, "Loaded headers");
        Ok(Self {
            params,
            chain: Mutex::new(chain),
            headers_file: Mutex::new(BufWriter::new(file)),
            synced: AtomicBool::new(false),
            chain_changed: Notify::new(),
            peers: Mutex::new(HashMap::new()),
            sync_peer: Mutex::new(None),
            waiting: Mutex::new(HashMap::new()),
            addresses: Mutex::new(HashMap::new()),
        })
    }

    pub fn with_chain<R>(&self, f: impl FnOnce(&Chain) -> R) -> R {
        f(&lock(&self.chain))
    }

    /// Add headers from a peer, keeping the new ones, and follow the most
    /// work. Returns how many were new, or the first bad one's error (after
    /// adding those before it).
    pub fn add_headers(&self, headers: &[Header]) -> Result<usize, AddHeaderError> {
        let mut chain = lock(&self.chain);
        let mut added = 0;
        let mut res = Ok(());
        {
            let mut file = lock(&self.headers_file);
            for header in headers {
                match chain.add_header(header) {
                    Ok(true) => {
                        added += 1;
                        if let Err(err) = file.write_all(&encode::serialize(header)) {
                            tracing::error!("Can't write headers.dat: {err:#}");
                        }
                    }
                    Ok(false) => (),
                    Err(err) => {
                        res = Err(err);
                        break;
                    }
                }
            }
            if let Err(err) = file.flush() {
                tracing::error!("Can't write headers.dat: {err:#}");
            }
        }
        let old_height = chain.tip_height();
        if let Some(fork_height) = chain.update_best_chain() {
            let tip = chain.tip();
            if fork_height < old_height {
                tracing::info!(height = tip.height, tip = %tip.hash, fork_height, "Header chain reorganized");
            } else if self.is_synced() {
                tracing::info!(height = tip.height, tip = %tip.hash, "New best header");
            } else if tip.height / 50_000 != old_height / 50_000 {
                tracing::info!(height = tip.height, "Syncing headers");
            }
            self.chain_changed.notify_one();
        }
        res.map(|()| added)
    }

    pub fn is_synced(&self) -> bool {
        self.synced.load(Ordering::Relaxed)
    }

    pub fn set_synced(&self) {
        if !self.synced.swap(true, Ordering::Relaxed) {
            let tip = self.with_chain(Chain::tip);
            tracing::info!(height = tip.height, tip = %tip.hash, "Header sync complete");
            self.chain_changed.notify_one();
        }
    }

    /// Whether peer `id` should sync headers: it does already, or no peer
    /// does
    pub fn claim_sync(&self, id: usize) -> bool {
        let mut sync_peer = lock(&self.sync_peer);
        *sync_peer.get_or_insert(id) == id
    }

    pub fn peer_count(&self) -> usize {
        lock(&self.peers).len()
    }

    pub fn add_peer(&self, id: usize, commands: mpsc::UnboundedSender<PeerCommand>) {
        lock(&self.peers).insert(
            id,
            PeerHandle {
                commands,
                in_flight: 0,
                timeouts: 0,
            },
        );
    }

    pub fn remove_peer(&self, id: usize) {
        lock(&self.peers).remove(&id);
        let mut sync_peer = lock(&self.sync_peer);
        if *sync_peer == Some(id) {
            *sync_peer = None;
        }
    }

    pub fn add_addresses(&self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let mut addresses = lock(&self.addresses);
        for addr in addrs {
            if addresses.len() >= MAX_ADDRESSES {
                break;
            }
            addresses.entry(addr).or_insert(None);
        }
    }

    /// Ask for a block the peer with the fewest blocks to send, preferring
    /// peers not `tried` yet. Returns the peer.
    fn request_block(&self, hash: BlockHash, tried: &[usize]) -> Option<usize> {
        let mut peers = lock(&self.peers);
        let (&id, peer) = peers
            .iter_mut()
            .min_by_key(|(id, peer)| (tried.contains(id), peer.in_flight, **id))?;
        peer.commands.send(PeerCommand::GetBlock(hash)).ok()?;
        peer.in_flight += 1;
        Some(id)
    }

    /// A block request to peer `id` is over: answered, or not in time
    fn request_done(&self, id: usize, timed_out: bool) {
        let mut peers = lock(&self.peers);
        let Some(peer) = peers.get_mut(&id) else { return };
        peer.in_flight = peer.in_flight.saturating_sub(1);
        if timed_out {
            peer.timeouts += 1;
            if peer.timeouts >= MAX_PEER_TIMEOUTS {
                let _send: Result<(), _> = peer.commands.send(PeerCommand::Disconnect);
            }
        }
    }

    /// A block, from a peer
    pub async fn get_block(&self, hash: BlockHash) -> Result<Arc<Block>, GetBlockError> {
        let (tx, mut rx) = oneshot::channel();
        lock(&self.waiting).entry(hash).or_default().push(tx);
        let mut tried = Vec::new();
        for _ in 0..BLOCK_ATTEMPTS {
            let Some(peer) = self.request_block(hash, &tried) else {
                break;
            };
            tried.push(peer);
            match tokio::time::timeout(BLOCK_PEER_TIMEOUT, &mut rx).await {
                Ok(Ok(block)) => {
                    self.request_done(peer, false);
                    return Ok(block);
                }
                // The sender is only dropped with the node
                Ok(Err(_)) => break,
                Err(_elapsed) => {
                    tracing::debug!(%hash, peer, "No block from a peer in time, asking another");
                    self.request_done(peer, true);
                }
            }
        }
        lock(&self.waiting).remove(&hash);
        if self.peer_count() == 0 {
            Err(GetBlockError::NoPeers(hash))
        } else {
            Err(GetBlockError::Timeout(hash))
        }
    }

    /// A block from a peer. Unrequested blocks are ignored; a requested one
    /// must match its header's Merkle root and witness commitment (its
    /// header is the one requested, since it has its hash).
    pub fn block_received(&self, block: Block) -> Result<(), BadBlock> {
        let hash = block.block_hash();
        if !lock(&self.waiting).contains_key(&hash) {
            return Ok(());
        }
        if !block.check_merkle_root() || !block.check_witness_commitment() {
            return Err(BadBlock(hash));
        }
        let block = Arc::new(block);
        let waiters = lock(&self.waiting).remove(&hash).unwrap_or_default();
        for waiter in waiters {
            // The waiter may have given up
            let _send: Result<(), _> = waiter.send(block.clone());
        }
        Ok(())
    }
}
