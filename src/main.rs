// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! A light BIP300 enforcer for SideBoost, in place of a full ECX node and
//! bip300301_enforcer.
//!
//! It follows ECX over P2P: it downloads every header (checking proof of
//! work and difficulty, and following the most work), and the blocks from
//! the scan start height on (`params::SCAN_START_HEIGHT`), which it scans for
//! SideBoost's sidechain slot only (`params::SIDEBOOST_SLOT`), discarding
//! everything else. Blocks with more than `--confirmations` confirmations
//! are assumed fully valid, and it uses no other. It serves SideBoost nodes
//! the part of the enforcer's API they use (see `server`).

mod bip300;
mod chain;
mod node;
mod p2p;
mod params;
mod scanner;
mod server;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context as _;
use clap::Parser;

use crate::params::{DEFAULT_CONFIRMATIONS, Params, SIDEBOOST_SLOT};

/// A light BIP300 enforcer for SideBoost
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The ECX network: betanet, or regtest (the betanet build's)
    #[arg(long, default_value = "betanet")]
    network: String,
    /// Blocks with more confirmations than this are assumed fully valid;
    /// no other block is used (0: up to the tip, as a full enforcer)
    #[arg(long, default_value_t = DEFAULT_CONFIRMATIONS)]
    confirmations: u32,
    /// The first block to download and scan, if not the network's
    #[arg(long)]
    scan_start_height: Option<u32>,
    /// Full ECX nodes to follow the chain from (`host:port`, repeatable),
    /// instead of finding peers through the network's DNS seeds
    #[arg(long)]
    connect: Vec<String>,
    /// Most peers to connect to when finding them
    #[arg(long, default_value_t = 8)]
    max_peers: usize,
    /// Where to serve the enforcer API (the enforcer's default port)
    #[arg(long, default_value = "127.0.0.1:50051")]
    serve_addr: SocketAddr,
    /// Where to keep headers and scanned blocks [default: ~/.light-enforcer/<network>]
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Report deposits to SideBoost's slot even before it is active, as if it
    /// were, to test SideBoost before activation. Every SideBoost node of the
    /// network must do the same. Those deposits are anyone-can-spend on ECX
    /// and can never be withdrawn; their sequence numbers stay in use after
    /// activation, unlike a full enforcer's.
    #[arg(long)]
    assume_slot_active: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    let params = Params::from_name(&cli.network)
        .with_context(|| format!("unknown network `{}`: betanet or regtest", cli.network))?;
    let datadir = match cli.data_dir {
        Some(dir) => dir,
        None => PathBuf::from(std::env::var_os("HOME").context("no HOME: pass --data-dir")?)
            .join(".light-enforcer")
            .join(params.name),
    };
    std::fs::create_dir_all(&datadir).with_context(|| format!("can't create {}", datadir.display()))?;
    let start_height = cli.scan_start_height.unwrap_or(params.scan_start_height);
    tracing::info!(
        network = params.name,
        slot = SIDEBOOST_SLOT,
        start_height,
        confirmations = cli.confirmations,
        datadir = %datadir.display(),
        "Starting"
    );
    let rules = bip300::Rules {
        slot: SIDEBOOST_SLOT,
        op_drivechain: params.op_drivechain,
        thresholds: params.thresholds,
        assume_active: cli.assume_slot_active,
    };
    if rules.assume_active {
        tracing::warn!(
            slot = SIDEBOOST_SLOT,
            "Reporting the slot's deposits as if it were active (--assume-slot-active): they are anyone-can-spend on ECX and can't be withdrawn"
        );
    }

    let node = Arc::new(node::Node::load(params, &datadir)?);
    let scanner = Arc::new(scanner::Scanner::load(
        node.clone(),
        rules,
        start_height,
        cli.confirmations,
        &datadir,
    ));
    tokio::spawn(p2p::run(node.clone(), cli.connect, cli.max_peers));
    tokio::spawn(scanner.clone().run());

    let listener = tokio::net::TcpListener::bind(cli.serve_addr)
        .await
        .with_context(|| format!("can't listen on {}", cli.serve_addr))?;
    tracing::info!(addr = %cli.serve_addr, "Serving the enforcer API");
    let router = server::router(node, scanner.clone(), SIDEBOOST_SLOT);
    tokio::select! {
        res = axum::serve(listener, router) => res.context("server failed")?,
        () = shutdown_signal() => tracing::info!("Shutting down"),
    }
    scanner.save();
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("can listen for SIGTERM");
        tokio::select! {
            _ = ctrl_c => (),
            _ = term.recv() => (),
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}
