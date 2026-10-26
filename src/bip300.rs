// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! BIP300 for a single sidechain slot: the slot's events in a block, and its
//! state after it.
//!
//! This follows bip300301_enforcer's `connect_block` for the one slot, so
//! that the events (deposits, and withdrawal bundles submitted, failed or
//! paid out, with the treasury's sequence numbers) are the ones a full
//! enforcer reports for it. Blocks are assumed valid, so what a full
//! enforcer would reject a block for is only logged. Everything about other
//! slots is discarded; that is what makes this light: proposals and
//! activations of the slot are followed (M1, M2), bundles are seen proposed
//! (M3), paid out (M6) or expiring, and the treasury moves (M5, M6), but
//! bundle votes (M4) aren't counted, since they would need every slot's
//! bundles.
//!
//! <https://github.com/LayerTwo-Labs/bip300_bip301_specifications/blob/master/bip300.md>

use bitcoin::{
    Amount, Block, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
    hashes::{Hash as _, sha256d},
    opcodes::all::{OP_PUSHBYTES_1, OP_PUSHNUM_1, OP_RETURN},
    script::Instruction,
};
use serde::{Deserialize, Serialize};

use crate::params::Thresholds;

const M1_TAG: [u8; 4] = [0xD5, 0xE0, 0xC4, 0xAF];
const M2_TAG: [u8; 4] = [0xD6, 0xE1, 0xC5, 0xDF];
const M3_TAG: [u8; 4] = [0xD4, 0x5A, 0xA9, 0x43];

/// A withdrawal bundle's ID, in consensus (txid) byte order
pub type M6id = [u8; 32];

/// What a slot's events need of the network
#[derive(Clone, Copy, Debug)]
pub struct Rules {
    pub slot: u8,
    pub op_drivechain: u8,
    pub thresholds: Thresholds,
    /// Report the slot's deposits before it is active (`--assume-slot-active`),
    /// as if it were. Nothing guards its treasury outputs then: anyone can
    /// spend them, and they can never be withdrawn.
    pub assume_active: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ctip {
    pub outpoint: OutPoint,
    pub value: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Proposal {
    #[serde(with = "hex32")]
    pub description_hash: [u8; 32],
    pub vote_count: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingBundle {
    #[serde(with = "hex32")]
    pub m6id: M6id,
    pub proposal_height: u32,
}

/// The slot after a block
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlotState {
    /// Whether a sidechain is active in the slot
    pub active: bool,
    /// The treasury output
    pub ctip: Option<Ctip>,
    /// Treasury outputs so far: the next one's sequence number
    pub treasury_count: u64,
    /// Bundles waiting for votes, oldest first
    pub pending: Vec<PendingBundle>,
    /// Proposals for the slot, oldest first
    pub proposals: Vec<Proposal>,
}

/// An event of the slot, as the enforcer reports it
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// M5: a deposit, in the treasury output it created
    Deposit {
        sequence: u64,
        outpoint: OutPoint,
        #[serde(with = "hex::serde")]
        address: Vec<u8>,
        value: u64,
    },
    /// M3: a bundle proposed
    BundleSubmitted {
        #[serde(with = "hex32")]
        m6id: M6id,
    },
    /// A bundle expired without paying out
    BundleFailed {
        #[serde(with = "hex32")]
        m6id: M6id,
    },
    /// M6: a bundle paid out, in this transaction
    BundleSucceeded {
        #[serde(with = "hex32")]
        m6id: M6id,
        sequence: u64,
        #[serde(with = "hex::serde")]
        transaction: Vec<u8>,
    },
}

/// The slot's message in a coinbase output: `OP_RETURN <tag ‖ body>`, one
/// push and nothing else
enum Message {
    M1 { description_hash: [u8; 32] },
    M2 { description_hash: [u8; 32] },
    M3 { m6id: M6id },
}

fn parse_message(script: &ScriptBuf, slot: u8) -> Option<Message> {
    let mut instructions = script.instructions();
    let Some(Ok(Instruction::Op(OP_RETURN))) = instructions.next() else {
        return None;
    };
    let Some(Ok(Instruction::PushBytes(data))) = instructions.next() else {
        return None;
    };
    if instructions.next().is_some() {
        return None;
    }
    let data = data.as_bytes();
    if data.len() < 5 || data[4] != slot {
        return None;
    }
    let (tag, body) = (&data[..4], &data[5..]);
    if tag == M1_TAG {
        Some(Message::M1 {
            description_hash: sha256d::Hash::hash(body).to_byte_array(),
        })
    } else if tag == M2_TAG && body.len() == 32 {
        Some(Message::M2 {
            description_hash: body.try_into().expect("32 bytes"),
        })
    } else if tag == M3_TAG && body.len() == 32 {
        Some(Message::M3 {
            m6id: body.try_into().expect("32 bytes"),
        })
    } else {
        None
    }
}

/// Whether `script` is the slot's treasury script:
/// `OP_DRIVECHAIN OP_PUSHBYTES_1 <slot> OP_TRUE`
fn is_treasury(script: &ScriptBuf, rules: &Rules) -> bool {
    script.as_bytes()
        == [
            rules.op_drivechain,
            OP_PUSHBYTES_1.to_u8(),
            rules.slot,
            OP_PUSHNUM_1.to_u8(),
        ]
}

/// A deposit's address: an `OP_RETURN <address>` output, one push
fn deposit_address(output: &TxOut) -> Option<Vec<u8>> {
    let mut instructions = output.script_pubkey.instructions();
    let Some(Ok(Instruction::Op(OP_RETURN))) = instructions.next() else {
        return None;
    };
    let Some(Ok(Instruction::PushBytes(address))) = instructions.next() else {
        return None;
    };
    instructions.next().is_none().then(|| address.as_bytes().to_vec())
}

/// BIP300's M6ID of a bundle payout `tx` spending a treasury of
/// `old_treasury` sats: the txid of the tx without inputs, its treasury
/// output (index 0) replaced by `OP_RETURN <fee, 8 bytes BE>`
pub fn compute_m6id(tx: &Transaction, old_treasury: u64) -> Option<M6id> {
    let (treasury, payouts) = tx.output.split_first()?;
    let total = payouts.iter().try_fold(treasury.value.to_sat(), |total, output| {
        total.checked_add(output.value.to_sat())
    })?;
    let fee = old_treasury.checked_sub(total)?;
    let mut blinded = tx.clone();
    blinded.input.clear();
    blinded.output[0] = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(fee.to_be_bytes()),
    };
    Some(blinded.compute_txid().to_byte_array())
}

/// The slot's events in `block`, at `height`, and its state after it,
/// given its state before (`state`).
pub fn connect_block(rules: &Rules, height: u32, block: &Block, mut state: SlotState) -> (Vec<Event>, SlotState) {
    let thresholds = &rules.thresholds;
    let block_hash = block.block_hash();
    let mut events = Vec::new();
    let Some(coinbase) = block.txdata.first() else {
        tracing::warn!(%block_hash, "Block without a coinbase");
        return (events, state);
    };

    // Coinbase messages, in output order
    for output in &coinbase.output {
        match parse_message(&output.script_pubkey, rules.slot) {
            None => (),
            Some(Message::M1 { description_hash }) => {
                // A known proposal is ignored, so its votes can't be reset
                if !state.proposals.iter().any(|p| p.description_hash == description_hash) {
                    tracing::info!(height, slot = rules.slot, "Sidechain proposed for the slot");
                    state.proposals.push(Proposal {
                        description_hash,
                        vote_count: 0,
                        height,
                    });
                }
            }
            Some(Message::M2 { description_hash }) => {
                let Some(pos) = state
                    .proposals
                    .iter()
                    .position(|p| p.description_hash == description_hash)
                else {
                    continue;
                };
                let proposal = &mut state.proposals[pos];
                // Only ACKs in later blocks count
                if proposal.height == height {
                    continue;
                }
                proposal.vote_count += 1;
                let age = height.saturating_sub(proposal.height);
                let activates = if state.active {
                    proposal.vote_count > thresholds.used_sidechain_slot_activation_threshold
                        && age <= thresholds.used_sidechain_slot_proposal_max_age
                } else {
                    proposal.vote_count > thresholds.unused_sidechain_slot_activation_threshold
                        && age <= thresholds.unused_sidechain_slot_proposal_max_age
                };
                if activates {
                    tracing::info!(height, slot = rules.slot, "Sidechain activated in the slot");
                    // Assumed active before: its treasury starts again (as a
                    // full enforcer's does), its sequence numbers go on
                    if rules.assume_active && !state.active {
                        state.ctip = None;
                    }
                    // A replaced sidechain leaves its treasury and bundles
                    state.active = true;
                    state.proposals.remove(pos);
                }
            }
            Some(Message::M3 { m6id }) => {
                if !state.active || state.pending.iter().any(|b| b.m6id == m6id) {
                    tracing::warn!(%block_hash, m6id = hex::encode(m6id), "Bundle proposed for an inactive slot, or again");
                    continue;
                }
                state.pending.push(PendingBundle {
                    m6id,
                    proposal_height: height,
                });
                events.push(Event::BundleSubmitted { m6id });
            }
        }
    }

    // Proposals that can no longer activate
    let active = state.active;
    state.proposals.retain(|proposal| {
        let (max_age, threshold) = if active {
            (
                thresholds.used_sidechain_slot_proposal_max_age,
                thresholds.used_sidechain_slot_activation_threshold,
            )
        } else {
            (
                thresholds.unused_sidechain_slot_proposal_max_age,
                thresholds.unused_sidechain_slot_activation_threshold,
            )
        };
        let age = height.saturating_sub(proposal.height);
        let max_fails = max_age.saturating_sub(threshold);
        let fails = age.saturating_sub(proposal.vote_count);
        !(age > max_age || (age > max_fails && fails >= max_fails))
    });

    // Bundles that expired
    state.pending.retain(|bundle| {
        let expired = height.saturating_sub(bundle.proposal_height) > thresholds.withdrawal_bundle_max_age;
        if expired {
            events.push(Event::BundleFailed { m6id: bundle.m6id });
        }
        !expired
    });

    // Treasury moves: only once the slot is active, since before that its
    // OP_DRIVECHAIN outputs are ordinary ones (unless assumed active)
    if state.active || rules.assume_active {
        for tx in &block.txdata[1..] {
            if let Some(event) = connect_tx(rules, &block_hash, tx, &mut state) {
                events.push(event);
            }
        }
    }
    (events, state)
}

/// A transaction's deposit (M5) or payout (M6), if it moves the treasury
fn connect_tx(
    rules: &Rules,
    block_hash: &bitcoin::BlockHash,
    tx: &Transaction,
    state: &mut SlotState,
) -> Option<Event> {
    let txid: Txid = tx.compute_txid();
    // Before activation, assumed active: nothing guards the treasury, so its
    // outputs may be swept, or not spent by the next deposit
    let assumed = rules.assume_active && !state.active;
    let mut treasury_outputs = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, output)| is_treasury(&output.script_pubkey, rules));
    let spends_ctip = state
        .ctip
        .as_ref()
        .is_some_and(|ctip| tx.input.iter().any(|input| input.previous_output == ctip.outpoint));
    let Some((vout, new_ctip)) = treasury_outputs.next() else {
        if spends_ctip && assumed {
            tracing::info!(%block_hash, %txid, "Treasury swept, as the slot isn't active");
            state.ctip = None;
        } else if spends_ctip {
            tracing::warn!(%block_hash, %txid, "Treasury spent without a new treasury output");
        }
        return None;
    };
    if treasury_outputs.next().is_some() {
        tracing::warn!(%block_hash, %txid, "Several treasury outputs");
        return None;
    }
    let old_value = match &state.ctip {
        Some(ctip) if spends_ctip => ctip.value,
        // A deposit of all its value, beside the unguarded treasury
        Some(_) if assumed => 0,
        Some(_) => {
            tracing::warn!(%block_hash, %txid, "New treasury output without spending the old one");
            return None;
        }
        None => 0,
    };
    let new_value = new_ctip.value.to_sat();
    let outpoint = OutPoint {
        txid,
        vout: vout as u32,
    };
    let sequence = state.treasury_count;
    if assumed && new_value <= old_value {
        // No payout can come out of an inactive slot: the treasury just moved
        tracing::info!(%block_hash, %txid, "Treasury moved without a deposit, as the slot isn't active");
        state.ctip = Some(Ctip {
            outpoint,
            value: new_value,
        });
        return None;
    }
    let event = if new_value > old_value {
        // M5: the address follows the treasury output
        let Some(address) = tx.output.get(vout + 1).and_then(deposit_address) else {
            tracing::warn!(%block_hash, %txid, "Deposit without an address");
            return None;
        };
        Event::Deposit {
            sequence,
            outpoint,
            address,
            value: new_value - old_value,
        }
    } else if new_value < old_value {
        // M6
        if tx.input.len() != 1 || vout != 0 {
            tracing::warn!(%block_hash, %txid, "Malformed bundle payout");
            return None;
        }
        let Some(m6id) = compute_m6id(tx, old_value) else {
            tracing::warn!(%block_hash, %txid, "Bundle payout pays out more than the treasury");
            return None;
        };
        match state.pending.iter().position(|bundle| bundle.m6id == m6id) {
            Some(pos) => {
                state.pending.remove(pos);
            }
            None => {
                tracing::warn!(%block_hash, %txid, m6id = hex::encode(m6id), "Payout of a bundle that isn't pending")
            }
        }
        Event::BundleSucceeded {
            m6id,
            sequence,
            transaction: bitcoin::consensus::serialize(tx),
        }
    } else {
        tracing::warn!(%block_hash, %txid, "Treasury output of unchanged value");
        return None;
    };
    state.ctip = Some(Ctip {
        outpoint,
        value: new_value,
    });
    state.treasury_count += 1;
    Some(event)
}

/// `[u8; 32]` as hex
mod hex32 {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let mut res = [0; 32];
        hex::decode_to_slice(String::deserialize(deserializer)?, &mut res).map_err(D::Error::custom)?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid,
        Witness, absolute::LockTime, block::Header, block::Version, hashes::Hash as _, script::PushBytesBuf,
        transaction,
    };

    use super::{Event, M1_TAG, M2_TAG, M3_TAG, Rules, SlotState, compute_m6id, connect_block};
    use crate::params::Thresholds;

    const SLOT: u8 = 83;
    const RULES: Rules = Rules {
        slot: SLOT,
        op_drivechain: 0xb7,
        thresholds: Thresholds::SHORT,
        assume_active: false,
    };
    const ASSUMED: Rules = Rules {
        assume_active: true,
        ..RULES
    };

    fn op_return(data: Vec<u8>) -> TxOut {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(PushBytesBuf::try_from(data).unwrap()),
        }
    }

    fn message(tag: [u8; 4], slot: u8, body: &[u8]) -> TxOut {
        op_return([&tag[..], &[slot], body].concat())
    }

    fn treasury(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0xb7, 0x01, SLOT, 0x51]),
        }
    }

    fn payout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }
    }

    fn tx(inputs: Vec<OutPoint>, output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output,
        }
    }

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        }
    }

    fn block(coinbase_outputs: Vec<TxOut>, txs: Vec<Transaction>) -> Block {
        let coinbase = tx(vec![OutPoint::null()], [vec![payout(0)], coinbase_outputs].concat());
        Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: [vec![coinbase], txs].concat(),
        }
    }

    /// The slot activated at height 1 from a proposal at height 0
    fn activated() -> SlotState {
        let description = b"SideBoost".to_vec();
        let hash = bitcoin::hashes::sha256d::Hash::hash(&description).to_byte_array();
        let (_, mut state) = connect_block(
            &RULES,
            0,
            &block(vec![message(M1_TAG, SLOT, &description)], vec![]),
            SlotState::default(),
        );
        for height in 1..=6 {
            assert!(!state.active);
            (_, state) = connect_block(
                &RULES,
                height,
                &block(vec![message(M2_TAG, SLOT, &hash)], vec![]),
                state,
            );
        }
        assert!(state.active);
        assert!(state.proposals.is_empty());
        state
    }

    #[test]
    fn activation() {
        let description = b"SideBoost".to_vec();
        let hash = bitcoin::hashes::sha256d::Hash::hash(&description).to_byte_array();
        // An ACK in the proposal's own block doesn't count
        let both = block(
            vec![message(M1_TAG, SLOT, &description), message(M2_TAG, SLOT, &hash)],
            vec![],
        );
        let (_, state) = connect_block(&RULES, 0, &both, SlotState::default());
        assert_eq!(state.proposals[0].vote_count, 0);
        // Other slots' messages are ignored
        let other = block(vec![message(M1_TAG, SLOT + 1, &description)], vec![]);
        let (_, state) = connect_block(&RULES, 1, &other, state);
        assert_eq!(state.proposals.len(), 1);
        // Five ACKs aren't enough, six are
        let ack = block(vec![message(M2_TAG, SLOT, &hash)], vec![]);
        let mut state = state;
        for height in 2..7 {
            (_, state) = connect_block(&RULES, height, &ack, state);
        }
        assert_eq!((state.active, state.proposals[0].vote_count), (false, 5));
        (_, state) = connect_block(&RULES, 7, &ack, state);
        assert!(state.active);

        // A proposal without ACKs fails once it can't reach the threshold
        let (_, mut state) = connect_block(
            &RULES,
            0,
            &block(vec![message(M1_TAG, SLOT, &description)], vec![]),
            SlotState::default(),
        );
        let empty = block(vec![], vec![]);
        for height in 1..6 {
            (_, state) = connect_block(&RULES, height, &empty, state);
            assert_eq!(state.proposals.len(), 1);
        }
        (_, state) = connect_block(&RULES, 6, &empty, state);
        assert!(state.proposals.is_empty());
    }

    #[test]
    fn treasury_before_activation_is_ignored() {
        let deposit = tx(vec![outpoint(1)], vec![treasury(1000), op_return(b"addr".to_vec())]);
        let (events, state) = connect_block(&RULES, 0, &block(vec![], vec![deposit]), SlotState::default());
        assert!(events.is_empty());
        assert_eq!(state.ctip, None);
    }

    #[test]
    fn deposits_before_activation_if_assumed_active() {
        let deposit = tx(vec![outpoint(1)], vec![treasury(1000), op_return(b"addr".to_vec())]);
        let first_ctip = OutPoint {
            txid: deposit.compute_txid(),
            vout: 0,
        };
        let (events, state) = connect_block(&ASSUMED, 0, &block(vec![], vec![deposit]), SlotState::default());
        assert_eq!(
            events,
            vec![Event::Deposit {
                sequence: 0,
                outpoint: first_ctip,
                address: b"addr".to_vec(),
                value: 1000
            }]
        );
        assert!(!state.active);

        // One beside the treasury, not spending it, deposits all its value
        let beside = tx(vec![outpoint(2)], vec![treasury(700), op_return(b"b".to_vec())]);
        let (events, state) = connect_block(&ASSUMED, 1, &block(vec![], vec![beside.clone()]), state);
        assert!(matches!(events[..], [Event::Deposit { sequence: 1, value: 700, .. }]));
        let ctip = state.ctip.clone().unwrap().outpoint;
        assert_eq!(ctip.txid, beside.compute_txid());

        // Moved to a smaller output: no payout, no event
        let smaller = tx(vec![ctip], vec![treasury(100), op_return(b"c".to_vec())]);
        let (events, state) = connect_block(&ASSUMED, 2, &block(vec![], vec![smaller.clone()]), state);
        assert!(events.is_empty());
        assert_eq!(state.ctip.as_ref().unwrap().value, 100);
        assert_eq!(state.treasury_count, 2);

        // Swept: the next deposit starts from nothing
        let ctip = state.ctip.clone().unwrap().outpoint;
        let sweep = tx(vec![ctip], vec![payout(100)]);
        let again = tx(vec![outpoint(3)], vec![treasury(50), op_return(b"d".to_vec())]);
        let (events, state) = connect_block(&ASSUMED, 3, &block(vec![], vec![sweep, again]), state);
        assert!(matches!(events[..], [Event::Deposit { sequence: 2, value: 50, .. }]));
        assert_eq!(state.treasury_count, 3);

        // Once active, its treasury starts again: the first deposit spends
        // nothing, as a full enforcer has it, and numbers go on
        let description = b"SideBoost".to_vec();
        let hash = bitcoin::hashes::sha256d::Hash::hash(&description).to_byte_array();
        let (_, mut state) = connect_block(&ASSUMED, 4, &block(vec![message(M1_TAG, SLOT, &description)], vec![]), state);
        for height in 5..=10 {
            (_, state) = connect_block(&ASSUMED, height, &block(vec![message(M2_TAG, SLOT, &hash)], vec![]), state);
        }
        assert!(state.active);
        assert_eq!(state.ctip, None);
        let real = tx(vec![outpoint(4)], vec![treasury(2000), op_return(b"e".to_vec())]);
        let (events, state) = connect_block(&ASSUMED, 11, &block(vec![], vec![real]), state);
        assert!(matches!(events[..], [Event::Deposit { sequence: 3, value: 2000, .. }]));
        // And from then on the slot's rules are the full enforcer's
        let beside = tx(vec![outpoint(5)], vec![treasury(3000), op_return(b"f".to_vec())]);
        let (events, _) = connect_block(&ASSUMED, 12, &block(vec![], vec![beside]), state);
        assert!(events.is_empty());
    }

    #[test]
    fn deposits_and_bundles() {
        let state = activated();

        // Deposits, with sequence numbers
        let first = tx(
            vec![outpoint(1)],
            vec![treasury(1000), op_return(b"addr".to_vec()), payout(5)],
        );
        let (events, state) = connect_block(&RULES, 7, &block(vec![], vec![first.clone()]), state);
        let first_ctip = OutPoint {
            txid: first.compute_txid(),
            vout: 0,
        };
        assert_eq!(
            events,
            vec![Event::Deposit {
                sequence: 0,
                outpoint: first_ctip,
                address: b"addr".to_vec(),
                value: 1000
            }]
        );
        // Without spending the treasury, or without an address, it's no deposit
        let unspent = tx(vec![outpoint(2)], vec![treasury(3000), op_return(b"x".to_vec())]);
        let no_address = tx(vec![first_ctip], vec![treasury(3000)]);
        let second = tx(
            vec![outpoint(2), first_ctip],
            vec![payout(1), treasury(1500), op_return(b"b".to_vec())],
        );
        let (events, state) = connect_block(
            &RULES,
            8,
            &block(vec![], vec![unspent, no_address, second.clone()]),
            state,
        );
        assert_eq!(
            events,
            vec![Event::Deposit {
                sequence: 1,
                outpoint: OutPoint {
                    txid: second.compute_txid(),
                    vout: 1
                },
                address: b"b".to_vec(),
                value: 500
            }]
        );

        // A bundle paying 1,000 sats with a 100-sat fee, proposed
        let ctip = state.ctip.clone().unwrap().outpoint;
        let m6 = tx(vec![ctip], vec![treasury(400), payout(1000)]);
        let m6id = compute_m6id(&m6, 1500).unwrap();
        let other_m6id = [7; 32];
        let m3 = |m6id: [u8; 32]| message(M3_TAG, SLOT, &m6id);
        let (events, state) = connect_block(&RULES, 9, &block(vec![m3(m6id), m3(other_m6id)], vec![]), state);
        assert_eq!(
            events,
            vec![
                Event::BundleSubmitted { m6id },
                Event::BundleSubmitted { m6id: other_m6id }
            ]
        );
        // Proposed again, it's ignored
        let (events, state) = connect_block(&RULES, 10, &block(vec![m3(m6id)], vec![]), state);
        assert!(events.is_empty());
        assert_eq!(state.pending.len(), 2);

        // Paid out
        let (events, state) = connect_block(&RULES, 11, &block(vec![], vec![m6.clone()]), state);
        assert_eq!(
            events,
            vec![Event::BundleSucceeded {
                m6id,
                sequence: 2,
                transaction: bitcoin::consensus::serialize(&m6)
            }]
        );
        assert_eq!(state.ctip.as_ref().unwrap().value, 400);
        assert_eq!(state.treasury_count, 3);

        // The other expires after 10 blocks
        let (events, state) = connect_block(&RULES, 19, &block(vec![], vec![]), state);
        assert!(events.is_empty());
        let (events, state) = connect_block(&RULES, 20, &block(vec![], vec![]), state);
        assert_eq!(events, vec![Event::BundleFailed { m6id: other_m6id }]);
        assert!(state.pending.is_empty());
    }

    /// The txid of the payout blinded: no inputs, and the fee in place of
    /// the treasury output
    #[test]
    fn m6id_is_bip300s() {
        let m6 = tx(vec![outpoint(1)], vec![treasury(400), payout(1000)]);
        let mut blinded = m6.clone();
        blinded.input.clear();
        blinded.output[0] = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(100u64.to_be_bytes()),
        };
        assert_eq!(compute_m6id(&m6, 1500), Some(blinded.compute_txid().to_byte_array()));
        // More than the treasury
        assert_eq!(compute_m6id(&m6, 1300), None);
    }

    #[test]
    fn state_roundtrips_as_json() {
        let mut state = activated();
        state.pending.push(super::PendingBundle {
            m6id: [1; 32],
            proposal_height: 3,
        });
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<SlotState>(&json).unwrap(), state);
    }
}
