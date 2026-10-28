#!/usr/bin/env python3
# Copyright (c) 2026 The SideBoost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compare the light enforcer with a full bip300301_enforcer on ECX regtest.

Runs an ECX regtest node (the betanet build), a full enforcer that mines on
it, and the light enforcer following the node over P2P. Slot 83 is
activated, takes deposits, and has one withdrawal bundle paid out and one
expire; the parent chain reorganizes. Throughout, the light enforcer must
serve the chain up to the last block with more than --confirmations
confirmations, and answer exactly as the full enforcer does for it.

    tests/compare_with_enforcer.py [--confirmations N] [--tmpdir DIR]

Binaries, from the environment or next to this repository:
ECX_BITCOIND (../ecash-bitcoin/build/bin/bitcoind), BIP300301_ENFORCER
(../bip300301_enforcer/target/debug/bip300301_enforcer), LIGHT_ENFORCER
(target/debug/light-enforcer).
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from decimal import Decimal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLOT = 83
TREASURY = bytes([0xb7, 0x01, SLOT, 0x51])  # OP_NOP8 (betanet's OP_DRIVECHAIN) <83> OP_TRUE
ECX_FEE = 10_000
COIN = 100_000_000


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(predicate, timeout=60, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return
        except (OSError, urllib.error.URLError, KeyError, RuntimeError):
            pass
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {what}")


# Transactions, serialized by hand (no witness)

def varint(n):
    if n < 0xfd:
        return bytes([n])
    return b"\xfd" + struct.pack("<H", n) if n <= 0xffff else b"\xfe" + struct.pack("<I", n)


def push(data):
    assert len(data) <= 0xff
    return (bytes([len(data)]) if len(data) < 0x4c else b"\x4c" + bytes([len(data)])) + data


def op_return(data):
    return b"\x6a" + push(data)


def serialize_tx(inputs, outputs, version=2):
    """inputs: (txid hex, vout); outputs: (sats, script)"""
    res = struct.pack("<i", version) + varint(len(inputs))
    for txid, vout in inputs:
        res += bytes.fromhex(txid)[::-1] + struct.pack("<I", vout) + b"\x00" + b"\xff" * 4
    res += varint(len(outputs))
    for value, script in outputs:
        res += struct.pack("<q", value) + varint(len(script)) + script
    return res + b"\x00" * 4


class Rpc:
    def __init__(self, url):
        self.url = url

    def __getattr__(self, method):
        def call(*params):
            body = json.dumps({"jsonrpc": "1.0", "id": 0, "method": method, "params": params}, default=float).encode()
            req = urllib.request.Request(self.url, body, {"Content-Type": "application/json",
                                                          "Authorization": "Basic " + base64.b64encode(b"u:p").decode()})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    reply = json.load(resp, parse_float=Decimal)
            except urllib.error.HTTPError as err:
                reply = json.load(err, parse_float=Decimal)
            if reply.get("error"):
                raise RuntimeError(f"{method}: {reply['error']}")
            return reply["result"]
        return call


class Test:
    def __init__(self, args):
        self.args = args
        self.confirmations = args.confirmations
        self.tmpdir = args.tmpdir or tempfile.mkdtemp(prefix="light-enforcer-")
        self.procs = []

    def log(self, message):
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)

    def spawn(self, name, cmd):
        log = open(os.path.join(self.tmpdir, f"{name}.log"), "w")
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        self.procs.append(proc)
        return proc

    def stop(self):
        for proc in reversed(self.procs):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def call(self, port, method, request=None):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/cusf.mainchain.v1.{method}",
                                     json.dumps(request or {}).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)

    def full(self, method, request=None):
        return self.call(self.full_port, method, request)

    def light(self, method, request=None):
        return self.call(self.light_port, method, request)

    def start(self):
        ecx_bin = os.getenv("ECX_BITCOIND", os.path.join(ROOT, "../ecash-bitcoin/build/bin/bitcoind"))
        enforcer_bin = os.getenv("BIP300301_ENFORCER", os.path.join(ROOT, "../bip300301_enforcer/target/debug/bip300301_enforcer"))
        light_bin = os.getenv("LIGHT_ENFORCER", os.path.join(ROOT, "target/debug/light-enforcer"))
        p2p, rpc, zmq = free_port(), free_port(), free_port()
        self.full_port, self.light_port = free_port(), free_port()
        for name in ("ecx", "enforcer", "light"):
            os.makedirs(os.path.join(self.tmpdir, name), exist_ok=True)
        self.spawn("ecx", [ecx_bin, "-regtest", f"-datadir={self.tmpdir}/ecx", f"-port={p2p}", f"-rpcport={rpc}",
                           "-rpcuser=u", "-rpcpassword=p", "-server", "-rest", "-txindex", "-listen=1", "-bind=127.0.0.1",
                           "-listenonion=0", "-fallbackfee=0.0001", f"-zmqpubsequence=tcp://127.0.0.1:{zmq}"])
        node = Rpc(f"http://127.0.0.1:{rpc}")
        wait_until(lambda: node.getblockcount() is not None, what="the ECX node")
        node.createwallet("w")
        self.ecx = Rpc(f"http://127.0.0.1:{rpc}/wallet/w")
        self.spawn("enforcer", [enforcer_bin, f"--data-dir={self.tmpdir}/enforcer",
                                f"--node-rpc-addr=127.0.0.1:{rpc}", "--node-rpc-user=u", "--node-rpc-pass=p",
                                f"--node-zmq-addr-sequence=tcp://127.0.0.1:{zmq}",
                                "--network-magic=eca5b134", "--op-drivechain=nop8",
                                f"--serve-grpc-addr=127.0.0.1:{self.full_port}", f"--serve-rpc-addr=127.0.0.1:{free_port()}",
                                "--enable-mempool", "--enable-block-template-server",
                                f"--coinbase-recipient={self.ecx.getnewaddress()}"])
        wait_until(lambda: self.full("ValidatorService/GetChainTip"), what="the full enforcer")
        # Assuming the slot active: the same, but for deposits before
        # activation (started first, as the plain one is restarted below)
        self.assumed_port = free_port()
        os.makedirs(os.path.join(self.tmpdir, "assumed"), exist_ok=True)
        self.spawn("assumed", [light_bin, "--network=regtest", f"--connect=127.0.0.1:{p2p}",
                               f"--confirmations={self.confirmations}", f"--data-dir={self.tmpdir}/assumed",
                               f"--serve-addr=127.0.0.1:{self.assumed_port}", "--assume-slot-active"])
        self.spawn("light", [light_bin, "--network=regtest", f"--connect=127.0.0.1:{p2p}",
                             f"--confirmations={self.confirmations}", f"--data-dir={self.tmpdir}/light",
                             f"--serve-addr=127.0.0.1:{self.light_port}"])

    # The parent chain

    def mine(self, n=1):
        if n == 0:
            return self.ecx.getbestblockhash()
        hashes = self.full("MiningService/GenerateToAddress", {"blocks": n, "address": self.ecx.getnewaddress()})["blockHashes"]
        tip = hashes[-1]["hex"]
        wait_until(lambda: self.full("ValidatorService/GetChainTip")["blockHeaderInfo"]["blockHash"]["hex"] == tip,
                   what="the full enforcer's tip")
        return tip

    def activate_slot(self):
        self.mine(101)
        self.full("BlockProducerService/SubmitSidechainProposal", {"sidechainId": SLOT, "declaration": {"v0": {
            "title": "SideBoost", "description": "SideBoost regtest",
            "hashId1": {"hex": "00" * 32}, "hashId2": {"hex": "00" * 20}}}})
        self.full("BlockProducerService/SetAckAllProposals", {"policy": "ACK_ALL_PROPOSALS_POLICY_NEW_SLOTS"})
        self.mine(8)
        sidechains = self.full("ValidatorService/GetSidechains").get("sidechains", [])
        assert [s["sidechainNumber"] for s in sidechains] == [SLOT], sidechains

    def deposit(self, address, sats):
        """A deposit (M5) of `sats` to `address`, mined"""
        ctip = self.full("ValidatorService/GetCtip", {"sidechainNumber": SLOT}).get("ctip")
        old_value = int(ctip.get("value", 0)) if ctip else 0
        utxo = next(u for u in self.ecx.listunspent() if u["amount"] * COIN >= sats + ECX_FEE)
        inputs, prevtxs = [], []
        if ctip:
            inputs.append((ctip["txid"]["hex"], ctip.get("vout", 0)))
            prevtxs.append({"txid": ctip["txid"]["hex"], "vout": ctip.get("vout", 0), "scriptPubKey": TREASURY.hex(),
                            "amount": Decimal(old_value) / COIN})
        inputs.append((utxo["txid"], utxo["vout"]))
        change = bytes.fromhex(self.ecx.getaddressinfo(self.ecx.getnewaddress())["scriptPubKey"])
        outputs = [(old_value + sats, TREASURY), (0, op_return(address.encode())),
                   (int(utxo["amount"] * COIN) - sats - ECX_FEE, change)]
        signed = self.ecx.signrawtransactionwithwallet(serialize_tx(inputs, outputs).hex(), prevtxs)
        txid = self.ecx.sendrawtransaction(signed["hex"])
        self.mine()
        return txid

    def propose_bundle(self, payout_sats, fee_sats):
        """Propose a bundle paying `payout_sats` to a new ECX address; return
        its M6ID, as the enforcer has it (consensus byte order)"""
        script = bytes.fromhex(self.ecx.getaddressinfo(self.ecx.getnewaddress())["scriptPubKey"])
        blinded = serialize_tx([], [(0, op_return(struct.pack(">Q", fee_sats))), (payout_sats, script)])
        self.full("BlockProducerService/ProposeWithdrawalBundle",
                  {"sidechainId": SLOT, "transaction": base64.b64encode(blinded).decode()})
        return hashlib.sha256(hashlib.sha256(blinded).digest()).digest().hex()

    def peg_events(self, port, end):
        reply = self.call(port, "ValidatorService/GetTwoWayPegData", {"sidechainId": SLOT, "endBlockHash": {"hex": end}})
        return [e for b in reply.get("blocks", []) for e in b["blockInfo"].get("events", [])]

    # Checks

    def trusted_tip(self):
        """The last block with more than `confirmations` confirmations"""
        return self.ecx.getblockhash(self.ecx.getblockcount() - self.confirmations)

    @staticmethod
    def same(light, full):
        assert light == full, f"\nlight: {json.dumps(light, indent=1)}\nfull: {json.dumps(full, indent=1)}"

    def check(self):
        """The light enforcer serves the trusted tip, and answers as the
        full enforcer does"""
        tip = self.trusted_tip()
        wait_until(lambda: self.light("ValidatorService/GetChainTip")["blockHeaderInfo"]["blockHash"]["hex"] == tip,
                   what=f"the light enforcer's tip {tip}")
        self.same(self.light("ValidatorService/GetChainTip"), {
            "blockHeaderInfo": self.full("ValidatorService/GetBlockHeaderInfo", {"blockHash": {"hex": tip}})["headerInfos"][0]})
        request = {"blockHash": {"hex": tip}, "maxAncestors": 20}
        self.same(self.light("ValidatorService/GetBlockHeaderInfo", request), self.full("ValidatorService/GetBlockHeaderInfo", request))
        request = {"sidechainId": SLOT, "endBlockHash": {"hex": tip}}
        full, light = self.full("ValidatorService/GetTwoWayPegData", request), self.light("ValidatorService/GetTwoWayPegData", request)
        self.same(light, full)
        # From a start block on
        height = self.ecx.getblockcount() - self.confirmations
        start = self.ecx.getblockhash(max(0, height - 15))
        request["startBlockHash"] = {"hex": start}
        self.same(self.light("ValidatorService/GetTwoWayPegData", request), self.full("ValidatorService/GetTwoWayPegData", request))
        return [e for b in full.get("blocks", []) for e in b["blockInfo"].get("events", [])]

    def run(self):
        self.start()
        self.log(f"Started, in {self.tmpdir}")

        self.log("Before the slot activates, nothing, but deposits if assumed active")
        self.mine(101)
        early = self.deposit("before-activation", COIN // 10)
        self.mine(self.confirmations)
        assert self.check() == []
        tip = self.trusted_tip()
        wait_until(lambda: self.call(self.assumed_port, "ValidatorService/GetChainTip")["blockHeaderInfo"]["blockHash"]["hex"] == tip,
                   what="the assumed-active light enforcer's tip")
        events = self.peg_events(self.assumed_port, tip)
        assert [(e["deposit"]["sequenceNumber"], e["deposit"]["outpoint"]["txid"]["hex"]) for e in events] == [("0", early)], events

        self.log("Slot 83 activates")
        self.activate_slot()
        self.check()

        self.log("Deposits, each its own treasury output")
        for i in range(3):
            self.deposit(f"sideboost-address-{i}", (i + 1) * COIN)
        self.mine(self.confirmations)
        events = self.check()
        assert [e["deposit"]["sequenceNumber"] for e in events] == ["0", "1", "2"], events
        # Assumed active, the same deposits, numbered after the early one
        assumed = self.peg_events(self.assumed_port, self.trusted_tip())
        assert [(e["deposit"]["sequenceNumber"], e["deposit"]["output"]["valueSats"]) for e in assumed] == \
            [("0", str(COIN // 10))] + [(str(int(e["deposit"]["sequenceNumber"]) + 1), e["deposit"]["output"]["valueSats"]) for e in events], assumed

        self.log("A bundle is proposed, voted for and paid out")
        self.full("BlockProducerService/SetWithdrawalBundlePolicy", {"policy": "WITHDRAWAL_BUNDLE_POLICY_KNOWN"})
        paid = self.propose_bundle(COIN, 10_000)
        for _ in range(30):
            self.mine()
            if any(e.get("withdrawalBundle", {}).get("event", {}).get("succeeded")
                   for e in self.peg_events(self.full_port, self.ecx.getbestblockhash())):
                break
        self.mine(self.confirmations)
        bundles = [e["withdrawalBundle"] for e in self.check() if "withdrawalBundle" in e]
        assert [(b["m6id"]["hex"], list(b["event"])) for b in bundles] == [(paid, ["submitted"]), (paid, ["succeeded"])], bundles
        assert bundles[1]["event"]["succeeded"]["sequenceNumber"] == "3"

        self.log("A bundle nobody votes for expires")
        self.full("BlockProducerService/SetWithdrawalBundlePolicy", {"policy": "WITHDRAWAL_BUNDLE_POLICY_NONE"})
        failed = self.propose_bundle(COIN // 2, 10_000)
        self.mine(14 + self.confirmations)
        bundles = [e["withdrawalBundle"] for e in self.check() if "withdrawalBundle" in e]
        assert [(b["m6id"]["hex"], list(b["event"])) for b in bundles[2:]] == [(failed, ["submitted"]), (failed, ["failed"])], bundles

        self.log("A deposit after the payout")
        self.deposit("after-the-payout", COIN // 4)
        self.mine(self.confirmations)
        events = self.check()
        assert events[-1]["deposit"]["sequenceNumber"] == "4"

        self.log("A reorganization deeper than the confirmations, replacing a deposit's block")
        replaced_height = self.ecx.getblockcount() - self.confirmations - 2
        replaced = self.ecx.getblockhash(replaced_height)
        assert self.light("ValidatorService/GetChainTip")["blockHeaderInfo"]["height"] > replaced_height
        self.ecx.invalidateblock(replaced)
        # Mined by the node, from its mempool, which has the deposit back
        self.ecx.generatetoaddress(self.confirmations + 5, self.ecx.getnewaddress())
        tip = self.ecx.getbestblockhash()
        wait_until(lambda: self.full("ValidatorService/GetChainTip")["blockHeaderInfo"]["blockHash"]["hex"] == tip,
                   what="the full enforcer's tip")
        events = self.check()
        # The node mines the deposit again, unless its input is immature on
        # the new branch
        remined = "deposit" in events[-1]
        self.deposit("after-the-reorg", COIN // 4)
        self.mine(self.confirmations)
        events = self.check()
        assert events[-1]["deposit"]["sequenceNumber"] == ("5" if remined else "4"), events[-1]

        self.log("Restarted, it carries on from what it saved")
        light = self.procs.pop()
        light.terminate()
        light.wait(timeout=30)
        self.spawn("light-restarted", light.args)
        self.mine(2)
        self.check()

        self.log("Calls it doesn't serve")
        try:
            self.light("BlockProducerService/ProposeWithdrawalBundle", {"sidechainId": SLOT, "transaction": ""})
            raise AssertionError("served")
        except urllib.error.HTTPError as err:
            assert err.code == 501 and json.load(err)["code"] == "unimplemented"
        try:
            self.light("ValidatorService/GetTwoWayPegData", {"sidechainId": 9, "endBlockHash": {"hex": self.trusted_tip()}})
            raise AssertionError("served")
        except urllib.error.HTTPError as err:
            assert err.code == 400
        self.log("Passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--confirmations", type=int, default=0)
    parser.add_argument("--tmpdir")
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
    test = Test(parser.parse_args())
    ok = False
    try:
        test.run()
        ok = True
    finally:
        test.stop()
        if ok and not test.args.keep and not test.args.tmpdir:
            shutil.rmtree(test.tmpdir)
        elif not ok:
            print(f"Failed; logs in {test.tmpdir}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
