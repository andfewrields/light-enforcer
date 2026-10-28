// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! The ECX networks the light enforcer follows, and what it scans of them.

use bitcoin::{CompactTarget, Network, block::Header, p2p::Magic};

/// The sidechain slot the light enforcer follows: SideBoost's. Everything
/// about other slots is discarded.
pub const SIDEBOOST_SLOT: u8 = 83;

/// The first ECX block (betanet) the light enforcer downloads: below it,
/// headers only. It must be below any event of SideBoost's slot, since
/// whatever happened to the slot before it is unknown (its proposals, its
/// activation, its treasury). Betanet's fork from Bitcoin: nothing BIP300
/// happened on it before.
pub const SCAN_START_HEIGHT: u32 = 967_680;

/// Blocks with more confirmations than this (the tip has 1) are assumed
/// fully valid, and the light enforcer uses no other: it serves the chain up
/// to the last of them. `--confirmations` overrides it. By default it serves
/// the tip, as a full enforcer does, so a SideBoost node on it credits
/// deposits at the same ECX block as one on a full enforcer: SideBoost itself
/// waits for 3 ECX blocks on top of a deposit's (4 confirmations).
pub const DEFAULT_CONFIRMATIONS: u32 = 0;

/// BIP300's ages and vote thresholds, in blocks, as the enforcer has them
/// (`Thresholds` in bip300301_enforcer). Only those the light enforcer needs
/// to follow one slot: slot activation, and bundle expiry. Bundles that pay
/// out are seen paying out, so their votes need no counting.
#[derive(Clone, Copy, Debug)]
pub struct Thresholds {
    pub withdrawal_bundle_max_age: u32,
    pub used_sidechain_slot_proposal_max_age: u32,
    pub used_sidechain_slot_activation_threshold: u32,
    pub unused_sidechain_slot_proposal_max_age: u32,
    pub unused_sidechain_slot_activation_threshold: u32,
}

impl Thresholds {
    /// The enforcer's betanet values: the spec's (mainnet) ones, but slot
    /// activation after 1,008 ACKs.
    pub const BETANET: Self = Self {
        withdrawal_bundle_max_age: 26_300,
        used_sidechain_slot_proposal_max_age: 26_300,
        used_sidechain_slot_activation_threshold: 13_150,
        unused_sidechain_slot_proposal_max_age: 2016,
        unused_sidechain_slot_activation_threshold: 1008,
    };

    /// The enforcer's values for every network but mainnet (and its forks).
    pub const SHORT: Self = Self {
        withdrawal_bundle_max_age: 10,
        used_sidechain_slot_proposal_max_age: 10,
        used_sidechain_slot_activation_threshold: 5,
        unused_sidechain_slot_proposal_max_age: 10,
        unused_sidechain_slot_activation_threshold: 5,
    };
}

/// A difficulty reset at a fork from Bitcoin: the block at `height` must
/// have `bits`.
#[derive(Clone, Copy, Debug)]
pub struct DifficultyReset {
    pub height: u32,
    pub bits: CompactTarget,
}

#[derive(Clone, Debug)]
pub struct Params {
    pub name: &'static str,
    /// The Bitcoin network whose genesis block and proof-of-work limit it
    /// shares
    pub network: Network,
    pub magic: Magic,
    pub default_port: u16,
    pub dns_seeds: &'static [&'static str],
    /// Whether headers are checked for Bitcoin's difficulty adjustment (every
    /// 2016 blocks, at most 4× either way). Off on regtest.
    pub retarget: bool,
    pub difficulty_reset: Option<DifficultyReset>,
    /// The opcode the network's build reserves for `OP_DRIVECHAIN`
    pub op_drivechain: u8,
    pub thresholds: Thresholds,
    pub scan_start_height: u32,
}

impl Params {
    /// ECX betanet (`ecash-com/bitcoin`, branch `betanet`): a fork of Bitcoin
    /// at height 967,680, with its own P2P magic and port, a difficulty reset
    /// at the fork, and `OP_DRIVECHAIN` as `OP_NOP8`.
    pub fn betanet() -> Self {
        Self {
            name: "betanet",
            network: Network::Bitcoin,
            magic: Magic::from_bytes([0xec, 0xa5, 0xb1, 0x04]),
            default_port: 8533,
            dns_seeds: &[
                "seed.beta.ecash.ninja",
                "seed.beta.bip300.xyz",
                "seed.beta.ecash.drivecha.in",
                "seed.beta.ecash.zuexeuz.net",
            ],
            retarget: true,
            difficulty_reset: Some(DifficultyReset {
                height: 967_680,
                bits: CompactTarget::from_consensus(0x19044b7e),
            }),
            op_drivechain: 0xb7,
            thresholds: Thresholds::BETANET,
            scan_start_height: SCAN_START_HEIGHT,
        }
    }

    /// Regtest of the betanet build, for tests: scanned from genesis.
    pub fn regtest() -> Self {
        Self {
            name: "regtest",
            network: Network::Regtest,
            magic: Magic::from_bytes([0xec, 0xa5, 0xb1, 0x34]),
            default_port: 18644,
            dns_seeds: &[],
            retarget: false,
            difficulty_reset: None,
            op_drivechain: 0xb7,
            thresholds: Thresholds::SHORT,
            scan_start_height: 0,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "betanet" => Some(Self::betanet()),
            "regtest" => Some(Self::regtest()),
            _ => None,
        }
    }

    pub fn genesis(&self) -> Header {
        bitcoin::constants::genesis_block(self.network).header
    }
}
