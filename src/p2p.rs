// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Connections to full ECX nodes: finding them (DNS seeds and `addr`
//! messages, or `--connect`), header sync, and fetching blocks.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bitcoin::{
    BlockHash,
    block::Header,
    consensus::encode,
    hashes::Hash as _,
    p2p::{
        Address, ServiceFlags,
        message::{NetworkMessage, RawNetworkMessage},
        message_blockdata::{GetHeadersMessage, Inventory},
        message_network::VersionMessage,
    },
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpStream, tcp::OwnedWriteHalf},
    sync::mpsc,
    time::{interval, timeout},
};

use crate::{
    chain::{AddHeaderError, Chain},
    node::{Node, PeerCommand, lock},
};

/// Bitcoin Core's `MAX_PROTOCOL_MESSAGE_LENGTH`
const MAX_PAYLOAD_LEN: usize = 4_000_000;
const HEADER_LEN: usize = 24;
/// Bitcoin Core's `MAX_HEADERS_RESULTS`: a shorter reply means the peer has
/// no more
const MAX_HEADERS: usize = 2000;
/// `sendheaders` and witness blocks need at least 70012
const PROTOCOL_VERSION: u32 = 70016;
const USER_AGENT: &str = concat!("/light-enforcer:", env!("CARGO_PKG_VERSION"), "/");
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
/// How often to ask for headers anyway: often while syncing, rarely after
/// (peers announce new blocks with `headers`)
const POLL_SYNCING: Duration = Duration::from_secs(5);
const POLL_SYNCED: Duration = Duration::from_secs(60);
/// How long the header sync peer may go without sending headers
const SYNC_STALL_TIMEOUT: Duration = Duration::from_secs(120);
/// How soon to try an address again
const RETRY_ADDRESS_AFTER: Duration = Duration::from_secs(600);
const RESOLVE_SEEDS_EVERY: Duration = Duration::from_secs(60);

static NEXT_PEER_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("failed to decode a message")]
    Decode(#[from] encode::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("timed out")]
    Timeout,
}

/// Keep connected to peers: those given (`connect`, reconnecting after
/// failures), or else up to `max_peers` found through the DNS seeds and
/// other peers.
pub async fn run(node: Arc<Node>, connect: Vec<String>, max_peers: usize) {
    if !connect.is_empty() {
        for addr in connect {
            let node = node.clone();
            tokio::spawn(async move {
                loop {
                    run_session(&node, &addr, false).await;
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            });
        }
        return;
    }
    let sessions = Arc::new(AtomicUsize::new(0));
    let mut last_resolved: Option<Instant> = None;
    let mut tick = interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        while sessions.load(Ordering::Relaxed) < max_peers {
            let Some(addr) = next_address(&node) else { break };
            sessions.fetch_add(1, Ordering::Relaxed);
            let (node, sessions) = (node.clone(), sessions.clone());
            tokio::spawn(async move {
                run_session(&node, &addr.to_string(), true).await;
                sessions.fetch_sub(1, Ordering::Relaxed);
            });
        }
        if sessions.load(Ordering::Relaxed) < max_peers
            && last_resolved.is_none_or(|time| time.elapsed() > RESOLVE_SEEDS_EVERY)
        {
            last_resolved = Some(Instant::now());
            resolve_seeds(&node).await;
        }
    }
}

/// An address not tried lately, marked as tried
fn next_address(node: &Node) -> Option<SocketAddr> {
    let mut addresses = lock(&node.addresses);
    let (addr, tried) = addresses
        .iter_mut()
        .find(|(_, tried)| tried.is_none_or(|time| time.elapsed() > RETRY_ADDRESS_AFTER))?;
    *tried = Some(Instant::now());
    Some(*addr)
}

async fn resolve_seeds(node: &Node) {
    for seed in node.params.dns_seeds {
        match tokio::net::lookup_host((*seed, node.params.default_port)).await {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                tracing::debug!(seed, found = addrs.len(), "Resolved DNS seed");
                node.add_addresses(addrs);
            }
            Err(err) => tracing::debug!(seed, "Can't resolve DNS seed: {err:#}"),
        }
    }
}

async fn run_session(node: &Arc<Node>, addr: &str, discover: bool) {
    let id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
    match session(node, addr, id, discover).await {
        Ok(()) => tracing::info!(%addr, "Peer disconnected"),
        Err(err) => tracing::debug!(%addr, "Peer connection ended: {err:#}"),
    }
    node.remove_peer(id);
}

async fn write_message(writer: &mut OwnedWriteHalf, node: &Node, message: NetworkMessage) -> Result<(), Error> {
    writer
        .write_all(&encode::serialize(&RawNetworkMessage::new(node.params.magic, message)))
        .await?;
    Ok(())
}

/// Read messages into `messages` until the connection fails
async fn read_messages(
    stream: tokio::net::tcp::OwnedReadHalf,
    node: Arc<Node>,
    messages: mpsc::Sender<NetworkMessage>,
) -> Error {
    let mut reader = BufReader::new(stream);
    loop {
        let mut bytes = vec![0; HEADER_LEN];
        if let Err(err) = reader.read_exact(&mut bytes).await {
            return err.into();
        }
        if bytes[0..4] != node.params.magic.to_bytes() {
            return Error::Protocol("wrong network magic".to_owned());
        }
        let len = u32::from_le_bytes(bytes[16..20].try_into().expect("4 bytes")) as usize;
        if len > MAX_PAYLOAD_LEN {
            return Error::Protocol(format!("message of {len} bytes"));
        }
        bytes.resize(HEADER_LEN + len, 0);
        if let Err(err) = reader.read_exact(&mut bytes[HEADER_LEN..]).await {
            return err.into();
        }
        // Checks the checksum; unknown commands decode as `Unknown`
        let message = match encode::deserialize::<RawNetworkMessage>(&bytes) {
            Ok(message) => message.into_payload(),
            Err(err) => return err.into(),
        };
        if messages.send(message).await.is_err() {
            return Error::Protocol("message handler stopped".to_owned());
        }
    }
}

fn version_message(peer: SocketAddr) -> VersionMessage {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let mut message = VersionMessage::new(
        ServiceFlags::NONE,
        now.as_secs() as i64,
        Address::new(&peer, ServiceFlags::NONE),
        Address::new(&unspecified, ServiceFlags::NONE),
        // Only for detecting connections to ourselves, which we don't accept
        now.as_nanos() as u64,
        USER_AGENT.to_owned(),
        0,
    );
    message.version = PROTOCOL_VERSION;
    message.relay = false;
    message
}

fn get_headers(locator: Vec<BlockHash>) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, BlockHash::all_zeros()))
}

async fn session(node: &Arc<Node>, addr: &str, id: usize, discover: bool) -> Result<(), Error> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout)??;
    let peer_addr = stream.peer_addr()?;
    let (reader, mut writer) = stream.into_split();
    let (messages_tx, mut messages) = mpsc::channel(16);
    let reader_task = tokio::spawn(read_messages(reader, node.clone(), messages_tx));
    let res = handle(node, addr, id, peer_addr, discover, &mut writer, &mut messages).await;
    reader_task.abort();
    res
}

struct Peer<'a> {
    node: &'a Arc<Node>,
    id: usize,
    writer: &'a mut OwnedWriteHalf,
    /// When the peer last sent headers we didn't have
    last_progress: Instant,
}

async fn handle(
    node: &Arc<Node>,
    addr: &str,
    id: usize,
    peer_addr: SocketAddr,
    discover: bool,
    writer: &mut OwnedWriteHalf,
    messages: &mut mpsc::Receiver<NetworkMessage>,
) -> Result<(), Error> {
    // Handshake
    write_message(writer, node, NetworkMessage::Version(version_message(peer_addr))).await?;
    let (mut got_version, mut got_verack) = (false, false);
    while !(got_version && got_verack) {
        let message = timeout(CONNECT_TIMEOUT, messages.recv())
            .await
            .map_err(|_| Error::Timeout)?
            .ok_or_else(|| Error::Protocol("connection closed during the handshake".to_owned()))?;
        match message {
            NetworkMessage::Version(version) => {
                // Blocks below the tip are needed: no pruned peers
                if !version.services.has(ServiceFlags::NETWORK) {
                    return Err(Error::Protocol("not a full node".to_owned()));
                }
                tracing::info!(%addr, user_agent = %version.user_agent, height = version.start_height, "Connected to peer");
                got_version = true;
                write_message(writer, node, NetworkMessage::Verack).await?;
            }
            NetworkMessage::Verack => got_verack = true,
            _ => (),
        }
    }
    write_message(writer, node, NetworkMessage::SendHeaders).await?;
    if discover {
        write_message(writer, node, NetworkMessage::GetAddr).await?;
    }

    let (commands_tx, mut commands) = mpsc::unbounded_channel();
    node.add_peer(id, commands_tx);
    let mut peer = Peer {
        node,
        id,
        writer,
        // So that the first poll asks
        last_progress: Instant::now().checked_sub(POLL_SYNCING).unwrap_or_else(Instant::now),
    };
    let mut poll = interval(POLL_SYNCING);
    loop {
        tokio::select! {
            _ = poll.tick() => {
                if !node.is_synced() {
                    if !node.claim_sync(id) {
                        continue;
                    }
                    if peer.last_progress.elapsed() > SYNC_STALL_TIMEOUT {
                        return Err(Error::Protocol("stalled header sync".to_owned()));
                    }
                    // Its replies ask for more themselves
                    if peer.last_progress.elapsed() < POLL_SYNCING {
                        continue;
                    }
                }
                let locator = node.with_chain(Chain::locator);
                write_message(peer.writer, node, get_headers(locator)).await?;
                let period = if node.is_synced() { POLL_SYNCED } else { POLL_SYNCING };
                if poll.period() != period {
                    poll = interval(period);
                    poll.tick().await;
                }
            }
            Some(command) = commands.recv() => match command {
                PeerCommand::GetBlock(hash) => {
                    let inv = vec![Inventory::WitnessBlock(hash)];
                    write_message(peer.writer, node, NetworkMessage::GetData(inv)).await?;
                }
                PeerCommand::Disconnect => return Err(Error::Protocol("too slow to send blocks".to_owned())),
            },
            message = messages.recv() => {
                let Some(message) = message else { return Ok(()) };
                handle_message(&mut peer, message).await?;
            }
        }
    }
}

async fn handle_message(peer: &mut Peer<'_>, message: NetworkMessage) -> Result<(), Error> {
    let node = peer.node;
    match message {
        NetworkMessage::Headers(headers) => handle_headers(peer, headers).await?,
        NetworkMessage::Inv(inv) => {
            let announces_block = inv
                .iter()
                .any(|item| matches!(item, Inventory::Block(_) | Inventory::WitnessBlock(_)));
            if announces_block {
                let locator = node.with_chain(Chain::locator);
                write_message(peer.writer, node, get_headers(locator)).await?;
            }
        }
        NetworkMessage::Block(block) => node
            .block_received(block)
            .map_err(|err| Error::Protocol(err.to_string()))?,
        NetworkMessage::Ping(nonce) => write_message(peer.writer, node, NetworkMessage::Pong(nonce)).await?,
        NetworkMessage::Addr(addrs) => node.add_addresses(
            addrs
                .iter()
                .filter(|(_, addr)| addr.services.has(ServiceFlags::NETWORK))
                .filter_map(|(_, addr)| addr.socket_addr().ok()),
        ),
        _ => (),
    }
    Ok(())
}

async fn handle_headers(peer: &mut Peer<'_>, headers: Vec<Header>) -> Result<(), Error> {
    let node = peer.node;
    let Some(last) = headers.last().map(Header::block_hash) else {
        if node.claim_sync(peer.id) {
            node.set_synced();
        }
        return Ok(());
    };
    let locator = match node.add_headers(&headers) {
        Ok(added) => {
            if added > 0 {
                peer.last_progress = Instant::now();
            }
            if headers.len() < MAX_HEADERS {
                if node.is_synced() || node.claim_sync(peer.id) {
                    node.set_synced();
                }
                return Ok(());
            }
            // More to come, from the last one: asked by the sync peer only
            if !node.is_synced() && !node.claim_sync(peer.id) {
                return Ok(());
            }
            let mut locator = vec![last];
            locator.extend(node.with_chain(Chain::locator));
            locator
        }
        // An announcement we can't connect: sync from our chain
        Err(AddHeaderError::Unconnected(_)) => node.with_chain(Chain::locator),
        Err(err) => return Err(Error::Protocol(err.to_string())),
    };
    write_message(peer.writer, node, get_headers(locator)).await
}
