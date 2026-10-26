# light-enforcer

A light BIP300 enforcer for [SideBoost](../sideboost-core): it lets a
SideBoost node follow ECX without running a full ECX node.

## What it is

SideBoost is a sidechain of ECX (slot 83). Its coins come in through
deposits on ECX and leave through withdrawal bundles that ECX miners vote
on, so every SideBoost node has to know what happens to slot 83 on ECX.
Normally that takes a full ECX node (hundreds of GB) plus
`bip300301_enforcer`, which tracks every sidechain.

`light-enforcer` replaces both with one small program. It:

1. **connects to ECX betanet** by itself, finding peers through betanet's
   DNS seeds;
2. **downloads all the headers** (about 80 MB), checking proof of work and
   difficulty, and follows the chain with the most work;
3. **downloads the blocks from height 967,680** (betanet's fork from Bitcoin)
   on, **keeps only what concerns slot 83** (its activation, deposits and
   withdrawal bundles) and discards everything else;
4. **trusts blocks with more than 10 confirmations** as fully valid, and
   uses no other.

It answers the SideBoost node exactly as a full enforcer would, so the node
needs no changes: you only point it at the light enforcer.

## Using it

### 1. Build

Needs Rust 1.88 or later.

```bash
cargo build --release
```

The binary is `target/release/light-enforcer`.

### 2. Start it

```bash
target/release/light-enforcer
```

No settings are needed. On the first start it syncs the headers (about 2
minutes), then scans the blocks (a few minutes); later starts resume in
seconds. Stop it with Ctrl-C: it saves its progress.

It's ready once it serves a tip, which is 10 blocks below the betanet tip:

```bash
curl -s -X POST -d '{}' http://127.0.0.1:50051/cusf.mainchain.v1.ValidatorService/GetChainTip
```

(Before that it answers `Validator is not synced`.)

### 3. Point SideBoost at it

Start the SideBoost node with the light enforcer as its enforcer:

```bash
namecoind -enforcer=127.0.0.1:50051
```

That's the full enforcer's port, so a node already configured for one needs
nothing else (but don't run both on the same machine on the same port).

### Options

| Option | Default | |
|---|---|---|
| `--confirmations N` | 10 | blocks with more than N confirmations are assumed valid |
| `--connect host:port` | DNS seeds | follow only these ECX nodes (repeatable), e.g. your own |
| `--max-peers` | 8 | peers to keep when finding them |
| `--serve-addr` | `127.0.0.1:50051` | where SideBoost reaches it |
| `--data-dir` | `~/.light-enforcer/betanet` | where it keeps headers and scan results |
| `--scan-start-height` | 967,680 | first block downloaded |
| `--network` | `betanet` | or `regtest`, for tests |
| `--assume-slot-active` | off | report deposits to slot 83 before it is active (see below) |

More detail in the logs with `RUST_LOG=debug`. The defaults for the start
height, the confirmations and the slot are constants in
[`src/params.rs`](src/params.rs) (`SCAN_START_HEIGHT`,
`DEFAULT_CONFIRMATIONS`, `SIDEBOOST_SLOT`).

## What to know

- **It can't mine.** Proposing withdrawal bundles to ECX and voting for them
  are done by ECX miners with a full enforcer. A SideBoost node on a light
  enforcer only logs a debug message when it tries.
- **Its view of ECX is 10 blocks behind** a full enforcer's, so deposits
  reach a SideBoost node on it about 100 minutes later.
- **Trust is SPV.** It assumes the chain with the most proof of work follows
  ECX's rules. Peers can't fake headers without the hashrate; they can
  withhold blocks, so it asks several and drops slow ones.

## Testing before slot 83 activates: `--assume-slot-active`

To try SideBoost with real ECX deposits before slot 83 is active, this
reports the slot's deposits as if it were. Off by default; it changes
nothing about which ECX blocks it follows. Know what it means:

- **Every SideBoost node of the network must use it.** A node behind a full
  enforcer (or a light one without it) sees none of these deposits, and
  stops at the first block crediting one (`bad-deposit-unconfirmed`).
- **The coins can't come back.** Before activation the treasury output
  (`OP_DRIVECHAIN <83> OP_TRUE`) is anyone-can-spend on ECX, so deposit tiny
  amounts. ECX rejects bundles for an inactive slot, so withdrawals never
  pay out; after activation, nothing deposited before is in the treasury.
- **Its sequence numbers stay ahead of a full enforcer's** after activation
  (by the deposits before), so a SideBoost chain credited this way only
  works with it for good, or is dropped at activation.

Before activation, a deposit is the slot's new treasury output, worth its
value minus that of the treasury output it spends (if any); a treasury spent
without a new one (swept) starts again from nothing, and a smaller one isn't
a deposit. At activation the treasury starts again, as a full enforcer's
does, and from then on the slot's rules are the full enforcer's. The scan is
redone when the option is switched.

## How it works

| File | |
|---|---|
| [`src/params.rs`](src/params.rs) | networks (betanet, regtest) and the settings |
| [`src/chain.rs`](src/chain.rs) | header chain: checks, most-work chain |
| [`src/p2p.rs`](src/p2p.rs), [`src/node.rs`](src/node.rs) | peers, header sync, block downloads |
| [`src/bip300.rs`](src/bip300.rs) | BIP300 for one slot: its events in a block |
| [`src/scanner.rs`](src/scanner.rs) | scans the trusted chain, handles reorgs, saves results |
| [`src/server.rs`](src/server.rs) | the API SideBoost calls |

For slot 83 it follows the enforcer's rules: proposals and activation (M1,
M2; before activation, treasury outputs are ordinary outputs), deposits
(M5) and payouts (M6), each a new treasury output with the next sequence
number, bundles proposed (M3), and bundles that expire. Bundle votes (M4)
aren't counted, since a payout is seen when it happens.

It serves three calls, in the JSON form of the Connect protocol as
SideBoost's client makes them (POST `/cusf.mainchain.v1.<Service>/<Method>`):
`ValidatorService/GetChainTip`, `GetBlockHeaderInfo` and `GetTwoWayPegData`
(slot 83 only). Anything else is answered as unimplemented.

## Tests

```bash
cargo test
tests/compare_with_enforcer.py
```

The second starts an ECX regtest node, a full `bip300301_enforcer` that
mines on it, and the light enforcer, then checks that both answer the same
through slot 83's activation, deposits, a bundle paid out, one expiring, a
reorganization and a restart. It needs the ECX and enforcer builds, from
`ECX_BITCOIND` and `BIP300301_ENFORCER` or next to this repository.

## License

MIT, see [COPYING](COPYING).
