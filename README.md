# light-enforcer

A light BIP300 enforcer for SideBoost. A SideBoost node needs to know what
happens to its sidechain slot on ECX (deposits, withdrawal bundles); with
this, it doesn't need a full ECX node and `bip300301_enforcer` for that.

It connects to the ECX network (betanet) over P2P and:

- downloads all the headers, checking proof of work and difficulty
  (Bitcoin's adjustment, and betanet's reset at its fork), and follows the
  chain with the most work;
- downloads every block from `SCAN_START_HEIGHT` (967,680, betanet's fork
  from Bitcoin) on, scans it for SideBoost's slot (`SIDEBOOST_SLOT`, 83)
  only, and discards everything else;
- assumes every block with more than `--confirmations` (10) confirmations
  is fully valid, and uses no other: it serves the chain up to the last of
  them.

It serves SideBoost nodes the part of the enforcer's API they use, so a node
uses it like a full enforcer: `-enforcer=127.0.0.1:50051`.

## Running

```bash
cargo build --release --offline
target/release/light-enforcer
```

It finds betanet peers through the DNS seeds, keeps its data in
`~/.light-enforcer/betanet` (headers, about 80 MB, and what it scanned), and
serves on `127.0.0.1:50051`, the enforcer's port. Options:

| Option | Default | |
|---|---|---|
| `--confirmations` | 10 | blocks with more confirmations are assumed valid |
| `--scan-start-height` | 967,680 | first block downloaded and scanned |
| `--connect host:port` | DNS seeds | follow these nodes only (repeatable) |
| `--max-peers` | 8 | peers to keep when finding them |
| `--serve-addr` | `127.0.0.1:50051` | where to serve the API |
| `--data-dir` | `~/.light-enforcer/<network>` | |
| `--network` | `betanet` | or `regtest` (the betanet build's), for tests |

The two settings live in [`src/params.rs`](src/params.rs): `SCAN_START_HEIGHT`
and `DEFAULT_CONFIRMATIONS`. Changing the start height scans again from it.

## What it follows

The slot's events as a full enforcer reports them, following its
`connect_block` for the one slot ([`src/bip300.rs`](src/bip300.rs)):

- the slot's proposals and activation (M1, M2): before it activates, its
  treasury outputs are ordinary outputs;
- deposits (M5) and bundle payouts (M6), each a new treasury output with the
  next sequence number;
- bundles proposed (M3), and bundles that expire (`failed`).

Bundle votes (M4) aren't counted: they would need every slot's bundles, and
a payout is seen paying out anyway. What a full enforcer would reject a block
for is only logged, since the blocks used are assumed valid.

The start height must be below any event of the slot: what happened to it
before is unknown. Nothing BIP300 happened on betanet before its fork from
Bitcoin at 967,680, so it starts there.

## API

The JSON form of the Connect protocol over HTTP/1.1, as SideBoost's
`EnforcerClient` calls it (POST `/cusf.mainchain.v1.<Service>/<Method>`):

- `ValidatorService/GetChainTip`: the last block assumed valid, once scanned
- `ValidatorService/GetBlockHeaderInfo`: any header, with ancestors
- `ValidatorService/GetTwoWayPegData`: slot 83's events, by block

Anything else is answered as unimplemented, including the block producer: a
light enforcer can't mine, so it can't propose withdrawal bundles or vote
for them (a SideBoost node's proposals only log a debug message).

## Trust

SPV: the chain with the most work, from peers it found itself, is assumed
to follow ECX's rules, BIP300's included, once blocks are 10 deep. Peers
can't forge headers without the hashrate, but can withhold blocks; it asks
several.

A SideBoost node on a light enforcer sees ECX 10 blocks later than one on a
full enforcer, so its deposit confirmations (3) count from there.

## Tests

```bash
cargo test --offline
tests/compare_with_enforcer.py [--confirmations 3]
```

The second runs an ECX regtest node, a full enforcer that mines on it and
the light enforcer, and checks that the light enforcer serves the right tip
and answers exactly as the full enforcer does, through the slot's
activation, deposits, a bundle paid out, one expiring, a reorganization and
a restart. It needs `ECX_BITCOIND` and `BIP300301_ENFORCER` (default: the
builds next to this repository).
