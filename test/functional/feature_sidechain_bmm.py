#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Inquisition developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Blind-merge-mine a sidechain block end to end.

Exercises the whole peg path against a real bip300301_enforcer: slot proposal
and activation, get_block_template, a BMM bid on the mainchain, and
connect_block. Everything under `!template_only` -- FindBmmAnchor, the
prev_main<=anchor rule, GetDepositsBetween against live enforcer data,
CheckCoinbaseDeposits and the reward equation -- only runs here; the unit tests
drive those against fakes.

Needs the enforcer binary:

    BIP300301_ENFORCER=/path/to/bip300301_enforcer \\
        build/test/functional/feature_sidechain_bmm.py
"""

import json
import os
from base64 import b64encode
import subprocess
import time
import urllib.error
import urllib.request

from decimal import Decimal

from io import BytesIO

from test_framework.blocktools import COINBASE_MATURITY, MAX_BLOCK_SIGOPS_WEIGHT, add_witness_commitment
from test_framework.script import CScript, OP_CHECKMULTISIG, OP_DROP, OP_RETURN, OP_TRUE
from test_framework.messages import COIN, CBlock, COutPoint, CTransaction, CTxIn, CTxOut, from_hex
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error, rpc_port

#! Small so the mempool can fill a block, and above the miner's own reserve.
BLOCK_MAX_WEIGHT = 200_000
WITNESS_SCALE_FACTOR = 4
#! Sized so the settlement outgrows the weight the assembler holds back for the
#! coinbase. A smaller one hides inside that reserve and proves nothing.
PEG_TEST_WITHDRAWALS = 40
#! What one block leaves the deposits in the cut test. Added to the reserve the
#! node reports, so a change to the reserve moves the block size with it.
CUT_TEST_DEPOSITS = 60
CUT_TEST_DEPOSIT_BUDGET = 4_400
#! Matches BUNDLE_PUBLISH_DEPTH in src/rpc/sidechain.cpp.
BUNDLE_PUBLISH_DEPTH = 6
#! More aborts than one transaction may carry, so the queue waits its turn.
ABORT_TEST_COUNT = 70

SLOT = 119
ENFORCER_PORT = 51151
ZMQ_PORT = 29332


class SidechainBmmTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.enforcer = None
        # node0 is the mainchain. Consensus Cleanup is renounced because the
        # enforcer's block producer builds a plain coinbase, which BIP54's
        # nLockTime rule rejects; a real deployment runs stock Core here.
        self.extra_args = [
            [
                "-rest",
                "-txindex",
                f"-zmqpubsequence=tcp://127.0.0.1:{ZMQ_PORT}",
                "-renounce=consensuscleanup",
            ],
            # -txindex: settling a failed bundle means handing back exactly the
            # requests it swept, and the only record of those is the transaction
            # that opened it. A node without it still validates settlements, it
            # just cannot build one.
            [f"-sidechainslot={SLOT}", f"-enforcerport={ENFORCER_PORT}", "-txindex"],
            # node2 never builds a block, only receives them. Everything the peg
            # rules check is checked here against blocks it did not assemble.
            # No -txindex on purpose: only a producer needs it, to read back the
            # requests a failed bundle swept. A validator must not.
            [f"-sidechainslot={SLOT}", f"-enforcerport={ENFORCER_PORT}"],
        ]

    def add_options(self, parser):
        # The sidechain node owns the deposit it credits and funds the
        # withdrawal from it, so it needs a wallet. Descriptors only.
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        if not os.environ.get("BIP300301_ENFORCER"):
            raise SkipTest("BIP300301_ENFORCER not set")

    def setup_network(self):
        self.setup_nodes()
        # The two sidechain nodes peer with each other and with nothing else:
        # node0 is a different chain entirely.
        self.connect_nodes(1, 2)

    def call(self, service, method, body=None):
        url = f"http://127.0.0.1:{ENFORCER_PORT}/cusf.mainchain.v1.{service}/{method}"
        data = json.dumps(body or {}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as failure:
            # The status alone says nothing, and CI keeps no copy of the
            # enforcer log, so a failure here is otherwise undiagnosable.
            raise AssertionError(
                f"enforcer {service}/{method} answered {failure.code}: "
                f"{failure.read().decode(errors='replace')}\n"
                f"enforcer log:\n{self.enforcer_log_tail()}") from failure

    def enforcer_log_tail(self, lines=40):
        path = os.path.join(self.options.tmpdir, "enforcer", "enforcer.log")
        try:
            with open(path, encoding="utf-8", errors="replace") as log:
                return "".join(log.readlines()[-lines:])
        except OSError as missing:
            return f"(no enforcer log: {missing})"

    def start_enforcer(self):
        # The enforcer learns about new mainchain blocks over ZMQ only. Without
        # it the wait below just times out, which says nothing about the cause.
        assert self.is_zmq_compiled(), "the peg tests need a bitcoind built with -DWITH_ZMQ=ON"
        datadir = os.path.join(self.options.tmpdir, "enforcer")
        os.makedirs(datadir, exist_ok=True)
        cookie = os.path.join(self.nodes[0].datadir_path, "regtest", ".cookie")
        user, _, password = open(cookie, encoding="utf-8").read().partition(":")

        self.enforcer = subprocess.Popen(
            [
                os.environ["BIP300301_ENFORCER"],
                f"--data-dir={datadir}",
                f"--node-rpc-addr=127.0.0.1:{rpc_port(0)}",
                f"--node-rpc-user={user}",
                f"--node-rpc-pass={password}",
                f"--node-zmq-addr-sequence=tcp://127.0.0.1:{ZMQ_PORT}",
                f"--serve-grpc-addr=127.0.0.1:{ENFORCER_PORT}",
                "--enable-wallet",
                # BDK syncs from an Esplora server we do not run; new blocks are
                # enough on regtest.
                "--wallet-sync-source=disabled",
                "--wallet-auto-create",
            ],
            stdout=open(os.path.join(datadir, "enforcer.log"), "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                self.call("ValidatorService", "GetChainTip")
                return
            except (AssertionError, urllib.error.URLError, ConnectionError, OSError):
                # The enforcer answers "not synced" until it reads the chain,
                # and `call` turns that status into an AssertionError.
                time.sleep(0.5)
        raise AssertionError("enforcer did not come up")

    def stop_enforcer(self):
        if self.enforcer is not None:
            self.enforcer.terminate()
            self.enforcer.wait(timeout=30)
            self.enforcer = None

    def generate_mainchain(self, count, address):
        """Mine through the enforcer, so coinbases carry the M1/M2 messages."""
        self.call("MiningService", "GenerateToAddress", {"blocks": count, "address": address})

    def activate_slot(self, address):
        self.log.info("Proposing and activating slot %d", SLOT)
        self.call(
            "BlockProducerService",
            "SubmitSidechainProposal",
            {
                "sidechainId": SLOT,
                "declaration": {
                    "v0": {
                        "title": "Inquisition",
                        "description": "Covenant sidechain",
                        "hashId1": {"hex": "11" * 32},
                        "hashId2": {"hex": "22" * 20},
                    }
                },
            },
        )
        # Field is ack_all; a wrong key here is silently ignored and the
        # proposal expires without ever gaining a vote.
        self.call("BlockProducerService", "SetAckAllProposals", {"ackAll": True})

        for _ in range(12):
            self.generate_mainchain(1, address)
            active = self.call("ValidatorService", "GetSidechains")
            if any(s.get("sidechainNumber") == SLOT for s in active.get("sidechains", [])):
                return
        raise AssertionError("slot never activated")

    def bmm_one_block(self, address):
        """One full cycle: template -> mainchain bid -> mine -> connect."""
        node = self.nodes[1]
        template = node.get_block_template()

        tip = self.call("ValidatorService", "GetChainTip")["blockHeaderInfo"]["blockHash"]["hex"]
        self.call(
            "WalletService",
            "CreateBmmCriticalDataTransaction",
            {
                "sidechainId": SLOT,
                "valueSats": "1000",
                # The enforcer makes this the bid's nLockTime. A block takes a
                # transaction only when nLockTime is below the block height, so
                # the tip keeps the bid final for the block it competes for.
                "height": self.nodes[0].getblockcount(),
                # critical_hash is ConsensusHex: internal byte order, which is
                # why get_block_template does not emit display order.
                "criticalHash": {"hex": template["critical_hash"]},
                "prevBytes": {"hex": tip},
            },
        )

        # Nothing commits to the block until a miner takes the bid, which is what
        # the orchestrator polls between CreateBid and ConnectBid.
        assert_equal(node.get_bmm_inclusions(template["critical_hash"]), [])

        self.generate_mainchain(1, address)
        main_hash = self.nodes[0].getbestblockhash()

        # The commitment reaches the cache by polling, and connect_block reads
        # the cache -- so waiting on anything else races it.
        self.wait_until(
            lambda: node.get_bmm_inclusions(template["critical_hash"]) == [main_hash],
            timeout=30,
        )

        assert_equal(node.connect_block(template["block"], main_hash), True)

        # The peg rules have to hold on a node that did not assemble the block.
        # Everything under !template_only -- the deposit range, the coinbase
        # credit, the whole withdrawal lifecycle -- runs here for the first time
        # against something it received rather than built.
        peer = self.nodes[2]
        self.wait_until(lambda: peer.getbestblockhash() == node.getbestblockhash(), timeout=30)
        return main_hash

    def check_peer_rejects(self, block, critical):
        """The block must be refused by a node that did not assemble it.

        The reason is asserted on the producer instead: once node1 relays the
        header, node2 may fetch and judge the block on its own, and then reports
        it as an already-known invalid rather than re-validating it.
        """
        peer = self.nodes[2]
        self.wait_until(lambda: peer.get_bmm_inclusions(critical) != [], timeout=30)
        assert peer.submitblock(block.serialize().hex()) is not None
        assert_equal({t["hash"]: t["status"] for t in peer.getchaintips()}.get(block.hash), "invalid")
        assert peer.getbestblockhash() != block.hash

    def publish_bundle(self, node, address):
        """Hand the live bundle's M6 to the enforcer.

        The M6 only exists once a block commits to the bundle, so this runs
        after that block, never at create_bundle time. Two M6s for one slot is
        how the mainchain pays a bundle this chain dropped.
        """
        # The M6 only appears once the block that opened the bundle is buried.
        # The mainchain cannot un-see one, so a shallower publication risks a
        # payout for a bundle a sidechain reorg took away.
        pending = node.pending_withdrawal_bundle()
        assert pending is not None
        assert "blinded_m6" not in pending
        for _ in range(BUNDLE_PUBLISH_DEPTH):
            self.bmm_one_block(address)
            pending = node.pending_withdrawal_bundle()
            assert pending is not None, "the bundle resolved before its M6 went out"
            if "blinded_m6" in pending:
                break
        else:
            raise AssertionError("the M6 never became readable")
        assert_greater_than(pending["confirmations"], 5)
        self.call(
            "WalletService",
            "BroadcastWithdrawalBundle",
            {
                "sidechainId": SLOT,
                # A proto BytesValue is base64 in JSON, unlike the hex-wrapped
                # fields everywhere else in this API.
                "transaction": b64encode(bytes.fromhex(pending["blinded_m6"])).decode(),
            },
        )
        return pending

    def recommit(self, block):
        """Rebuild the commitments a hand-added transaction invalidates.

        Without this the block is refused for its witness commitment and never
        reaches the peg rules at all.
        """
        coinbase = CTransaction()
        coinbase.deserialize(BytesIO(block.vtx[0].serialize()))
        coinbase.vout = [o for o in coinbase.vout
                         if not o.scriptPubKey.startswith(bytes.fromhex("6a24aa21a9ed"))]
        coinbase.rehash()
        block.vtx[0] = coinbase
        add_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        block.rehash()

    def critical_of(self, block):
        return bytes.fromhex(block.hash)[::-1].hex()

    def bid_for(self, block, address):
        """Win the auction for this exact block, then submit it.

        An attacker who wins is entitled to author the block; the peg rules are
        what must stop it. Returns what submitblock says.
        """
        critical = self.critical_of(block)
        tip = self.call("ValidatorService", "GetChainTip")["blockHeaderInfo"]["blockHash"]["hex"]
        self.call(
            "WalletService",
            "CreateBmmCriticalDataTransaction",
            {
                "sidechainId": SLOT,
                "valueSats": "1000",
                # The enforcer makes this the bid's nLockTime. A block takes a
                # transaction only when nLockTime is below the block height, so
                # the tip keeps the bid final for the block it competes for.
                "height": self.nodes[0].getblockcount(),
                "criticalHash": {"hex": critical},
                "prevBytes": {"hex": tip},
            },
        )
        self.generate_mainchain(1, address)
        self.wait_until(lambda: self.nodes[1].get_bmm_inclusions(critical) != [], timeout=30)
        return self.nodes[1].submitblock(block.serialize().hex())

    def check_withdrawal_can_be_aborted(self, address):
        """A queued withdrawal is not a one-way door.

        Nothing obliges the mainchain to ever pay a bundle, so a request that is
        only ever queued has to be recoverable. Abort returns it to the owner
        script the request committed to, which is a wallet address -- so the
        coins are spendable again, not merely un-encumbered.
        """
        node = self.nodes[1]

        # The third argument is a fee rate in satoshis per 1000 vbytes, so the
        # transaction pays that rate over its own size, and a rate below the
        # relay minimum is refused rather than built.
        assert_raises_rpc_error(-6, "lower than the minimum fee rate setting", node.withdraw,
                                self.nodes[0].getnewaddress(), 400_000, 10, 10_000)
        # A payout the mainchain would never confirm keeps its whole bundle from
        # ever being paid, and selection takes the oldest request first.
        assert_raises_rpc_error(-8, "below the dust threshold", node.withdraw,
                                self.nodes[0].getnewaddress(), 100, 1_000, 10_000)
        txid = node.withdraw(self.nodes[0].getnewaddress(), 400_000, 2_000, 10_000)
        paid = int(-node.gettransaction(txid)["fee"] * COIN)
        # The wallet sizes the transaction before it signs it, so the rate lands
        # on a size a byte or two above the one the chain sees.
        vsize = node.gettransaction(txid, True, True)["decoded"]["vsize"]
        assert_greater_than(paid + 1, 2_000 * vsize // 1000)
        assert_greater_than(2_000 * (vsize + 4) // 1000, paid)
        self.bmm_one_block(address)
        encumbered = node.getbalance()
        queued = [r for r in node.list_withdrawal_requests() if r["payout_sats"] == 400_000]
        assert_equal(len(queued), 1)
        request = queued[0]

        aborted = node.abort_withdrawal(request["txid"], request["vout"])
        assert_equal(aborted["amount_sats"], 410_000)
        assert_equal(aborted["owner"], request["owner"])
        self.bmm_one_block(address)

        # Gone from the queue, and paid to the owner as an ordinary output.
        assert_equal([r for r in node.list_withdrawal_requests() if r["payout_sats"] == 400_000], [])
        found = [o for o in node.listunspent(0) if o["amount"] == Decimal("0.0041")]
        assert_equal(len(found), 1)
        assert_equal(node.getbalance(), encumbered + Decimal("0.0041"))

        # A staged bundle wins over an abort staged first. Both build a
        # transaction that spends the request, and a block carrying both is
        # invalid -- which the producer would only find after it built it, every
        # time, forever.
        node.withdraw(self.nodes[0].getnewaddress(), 450_000, 1_000, 10_000)
        self.bmm_one_block(address)
        staged = next(r for r in node.list_withdrawal_requests() if r["payout_sats"] == 450_000)
        node.abort_withdrawal(staged["txid"], staged["vout"])
        node.create_bundle()
        template = node.get_block_template()
        assert template["block"]["hex"]

        # And an abort cannot take a request a bundle already claims.
        assert_raises_rpc_error(-1, "a bundle already claims this withdrawal",
                                node.abort_withdrawal, staged["txid"], staged["vout"])

        # The queue is visible, and an abort can be taken back.
        assert_equal(node.list_staged()["aborts"], [])
        assert f"{staged['txid']}:{staged['vout']}" in node.list_staged()["bundle"]

        # Cancel gives the request back, and the abort the bundle took with it.
        assert_equal(node.cancel_bundle(), True)
        assert_equal(node.cancel_bundle(), False)
        self.bmm_one_block(address)
        assert node.gettxout(staged["txid"], staged["vout"]) is None
        assert node.pending_withdrawal_bundle() is None
        assert_equal([r for r in node.list_withdrawal_requests()
                      if r["payout_sats"] == 450_000], [])
        assert_equal(node.list_staged()["bundle"], [])

        # A staged abort can be taken back before a block carries it.
        node.withdraw(self.nodes[0].getnewaddress(), 470_000, 1_000, 10_000)
        self.bmm_one_block(address)
        keep = next(r for r in node.list_withdrawal_requests() if r["payout_sats"] == 470_000)
        node.abort_withdrawal(keep["txid"], keep["vout"])
        assert_equal(node.list_staged()["aborts"], [f"{keep['txid']}:{keep['vout']}"])
        assert_equal(node.cancel_abort(keep["txid"], keep["vout"]), True)
        assert_equal(node.cancel_abort(keep["txid"], keep["vout"]), False)
        self.bmm_one_block(address)
        assert node.gettxout(keep["txid"], keep["vout"]) is not None

        # An outpoint that holds no pending request cannot be aborted.
        assert_raises_rpc_error(-8, "no pending withdrawal request at that outpoint",
                                node.abort_withdrawal, request["txid"], request["vout"])

    def cut_test_block_weight(self):
        """A block that leaves the deposits CUT_TEST_DEPOSIT_BUDGET.

        The peg reserve and the coinbase share come from the node, so a change
        to either moves this with them instead of failing for a reason the test
        does not name.
        """
        reserve = self.nodes[1].list_staged()["peg_reserve"]
        return reserve + 8_000 + 504 + CUT_TEST_DEPOSIT_BUDGET

    def check_deposit_cut_runs_in_the_miner(self, address):
        """The producer prices the peg, then gives the deposits what is left.

        A block credits every deposit in its range, so a range whose deposits do
        not fit is a block nobody can build. The producer ends the range earlier
        and takes the rest next block. The unit tests cover the choice; this
        covers the miner, where the peg competes for the same room.
        """
        node = self.nodes[1]
        # One deposit per mainchain block, so the range has somewhere to stop.
        # Deposits inside one mainchain block cannot be split: a block credits
        # its whole range or none of it.
        credited = []
        for _ in range(CUT_TEST_DEPOSITS):
            credited.append(self.deposit(self.nodes[0].getnewaddress(), 100_000))
            self.generate_mainchain(1, address)

        # A block that leaves the deposits less than the backlog costs, so the
        # range has to be cut. Sized off the reserve the node reports, so it
        # cannot drift away from the number the producer uses.
        weight = self.cut_test_block_weight()
        self.restart_node(1, self.extra_args[1] + [f"-blockmaxweight={weight}"])
        self.connect_nodes(1, 2)

        paid = 0
        blocks = 0
        for _ in range(10):
            self.bmm_one_block(address)
            blocks += 1
            block = node.getblock(node.getbestblockhash(), 2)
            assert_greater_than(weight + 1, block["weight"])
            paid += sum(1 for out in block["tx"][0]["vout"]
                        if out["scriptPubKey"].get("hex") in credited)
            if paid == len(credited):
                break
        else:
            raise AssertionError("the deposit backlog never drained")

        # More than one block, so the range really was cut short and picked up
        # again. One block would mean the budget never bit.
        assert_greater_than(blocks, 1)

        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(1, 2)

    def check_aborts_wait_for_room(self, address):
        """One abort carries at most MAX_BUNDLE_WITHDRAWALS requests.

        A settlement spends every request in a bundle, so an unbounded one would
        be an unbounded transaction. The abort obeys the same cap, and the rest
        of the queue waits for the next block. The queue only drains when a
        block spends the requests, so a cap that stopped the whole template
        would stop it for good.
        """
        node = self.nodes[1]

        # A deposit, and a bundle the mainchain pays, at the same time. A paid
        # settlement is far lighter than a failed one, and the producer prices
        # every verdict as failed -- so a budget that follows the settlement
        # weight would leave the built block more room than the priced one had.
        deposited = self.deposit(self.nodes[0].getnewaddress(), 700_000)
        node.withdraw(self.nodes[0].getnewaddress(), 490_000, 1_000, 10_000)
        self.bmm_one_block(address)
        node.create_bundle()
        self.bmm_one_block(address)
        self.call("BlockProducerService", "SetAckAllProposals", {"ackAll": True})
        self.publish_bundle(node, address)

        # The queue is made after the bundle, so the bundle does not sweep it.
        made = []
        for i in range(ABORT_TEST_COUNT):
            node.withdraw(self.nodes[0].getnewaddress(), 60_000, 1_000, 10_000)
            # The wallet spends its own change every time, so a block every so
            # often keeps the chain of unconfirmed transactions inside its limit.
            if i % 20 == 19:
                self.bmm_one_block(address)
        self.bmm_one_block(address)

        # The queue lives in memory, so it is staged after the restart.
        weight = self.cut_test_block_weight()
        self.restart_node(1, self.extra_args[1] + [f"-blockmaxweight={weight}"])
        self.connect_nodes(1, 2)
        for r in node.list_withdrawal_requests():
            if r["payout_sats"] == 60_000:
                node.abort_withdrawal(r["txid"], r["vout"])
                made.append((r["txid"], r["vout"]))
        assert_equal(len(made), ABORT_TEST_COUNT)

        blocks = 0
        for _ in range(30):
            self.bmm_one_block(address)
            blocks += 1
            block = node.getblock(node.getbestblockhash())
            assert_greater_than(weight + 1, block["weight"])
            drained = all(node.gettxout(txid, vout) is None for txid, vout in made)
            if drained and node.pending_withdrawal_bundle() is None:
                break
        else:
            raise AssertionError("the abort queue never drained")

        # More than one block: one transaction carries at most
        # MAX_BUNDLE_WITHDRAWALS requests, so the rest waited.
        assert_greater_than(blocks, 1)

        # The queue drops a spent entry when the next template asks for it, so
        # one more block prunes what the last one paid.
        self.bmm_one_block(address)
        self.call("BlockProducerService", "SetAckAllProposals", {"ackAll": False})
        staged = node.list_staged()["aborts"]
        assert_equal([f"{txid}:{vout}" for txid, vout in made if f"{txid}:{vout}" in staged], [])

        # The deposit reached the chain too, so the peg made room for all three.
        found = False
        for height in range(node.getblockcount(), node.getblockcount() - 30, -1):
            block = node.getblock(node.getblockhash(height), 2)
            if any(out["scriptPubKey"].get("hex") == deposited for out in block["tx"][0]["vout"]):
                found = True
                break
        assert found, "the deposit never reached a coinbase"

        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(1, 2)

    def check_producer_drops_a_ruled_bundle(self, address):
        """The producer never opens a bundle the mainchain already ruled on.

        A verdict is visible over exactly one block's range, so a block that
        opened such a bundle would strand it -- and consensus refuses that
        block. A producer that staged one anyway would fail its own validation
        on every later template. Anyone can propose an m6id first: the pending
        requests and the selection order are both public, which is what this
        test does with a hand-built M6.
        """
        node = self.nodes[1]
        node.withdraw(self.nodes[0].getnewaddress(), 520_000, 1_000, 10_000)
        self.bmm_one_block(address)
        pending = [r for r in node.list_withdrawal_requests() if r["payout_sats"] == 520_000]
        assert_equal(len(pending), 1)

        # The M6 a bundle over these requests would produce. It is a function of
        # the destination, the payout and the fee, and every one of those is
        # public, so anyone can build it before any block carries the bundle.
        fee_total = sum(r["mainchain_fee_sats"] for r in pending)
        m6 = CTransaction()
        m6.vin = []
        m6.vout = [CTxOut(0, CScript([OP_RETURN, fee_total.to_bytes(8, "big")]))]
        for r in pending:
            m6.vout.append(CTxOut(r["payout_sats"], bytes.fromhex(r["dest"])))
        self.call(
            "WalletService",
            "BroadcastWithdrawalBundle",
            {
                "sidechainId": SLOT,
                "transaction": b64encode(m6.serialize_without_witness()).decode(),
            },
        )

        # Let it age out while the sidechain stands still, so the verdict lands
        # inside the range of the next sidechain block.
        self.generate_mainchain(15, address)

        node.create_bundle()
        assert_equal(len(node.list_staged()["bundle"]), 1)
        self.bmm_one_block(address)

        # Dropped, and the requests are pending again. A stage kept here would
        # fail every later template.
        assert_equal(node.list_staged()["bundle"], [])
        assert node.pending_withdrawal_bundle() is None
        assert_equal(len([r for r in node.list_withdrawal_requests()
                          if r["payout_sats"] == 520_000]), 1)

        # And the chain goes on: the next block builds and connects.
        self.bmm_one_block(address)
        assert_equal(self.nodes[2].getbestblockhash(), node.getbestblockhash())

    def check_abort_stops_at_the_sigop_cap(self, address):
        """An owner script is the owner's to choose, so an abort caps its cost.

        A request output is standard on a sidechain, so anyone can make one by
        hand with an owner script that costs 5,120 signature operations. A queue
        of them passes what a whole block may hold, and the producer would then
        fail its own validation on every template. The abort takes what fits,
        and the rest waits for the next block.
        """
        node = self.nodes[1]
        # 64 bytes of bare OP_CHECKMULTISIG: 20 signature operations per byte,
        # which is the most any script can cost.
        expensive = bytes([OP_CHECKMULTISIG]) * 64
        # One abort may spend a quarter of what a block holds, so make one
        # request more than that many.
        count = MAX_BLOCK_SIGOPS_WEIGHT // 4 // (4 * 20 * len(expensive)) + 1
        # A coin of its own for each, so each request has a confirmed input.
        node.sendmany("", {node.getnewaddress(): Decimal("0.004") for _ in range(count)})
        self.bmm_one_block(address)
        funds = [u for u in node.listunspent() if u["amount"] == Decimal("0.004")][:count]
        assert_equal(len(funds), count)

        made = []
        for funding in funds:
            value = 200_000
            payload = (b"\x01" + (10_000).to_bytes(8, "little")
                       + bytes([22]) + b"\x00" * 22
                       + bytes([len(expensive)]) + expensive)
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["vout"]))]
            tx.vout = [
                CTxOut(value, CScript([payload, OP_DROP, OP_TRUE])),
                CTxOut(int(funding["amount"] * COIN) - value - 10_000,
                       bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"])),
            ]
            signed = node.signrawtransactionwithwallet(tx.serialize().hex())
            txid = node.sendrawtransaction(signed["hex"])
            made.append((txid, 0))
        self.bmm_one_block(address)

        for txid, vout in made:
            node.abort_withdrawal(txid, vout)
        self.bmm_one_block(address)

        # What fits goes in, so one waits. A cap that took them all would make
        # a block the node refuses, and the queue would never drain.
        left = [1 for txid, vout in made if node.gettxout(txid, vout) is not None]
        assert_equal(len(left), 1)
        self.bmm_one_block(address)
        assert all(node.gettxout(txid, vout) is None for txid, vout in made)

    def check_malformed_request_cannot_relay(self):
        """A request-shaped output the parser rejects must not relay.

        The script alone cannot tell: whether a request is real also depends on
        the value, and the mainchain fee has to be below it. One the parser
        rejects matches no peg rule at all, and its script ends in OP_TRUE, so
        the next block author takes the coins with an empty scriptSig.
        """
        node = self.nodes[1]
        funding = next(u for u in node.listunspent() if u["amount"] > Decimal("0.001"))
        value = 100_000

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["vout"]))]
        # A mainchain fee at the value. The M6 payout would be zero or less.
        payload = b"\x01" + (value).to_bytes(8, "little") + b"\x16" + b"\x00" * 22 + b"\x01\x51"
        tx.vout = [
            CTxOut(value, CScript([payload, OP_DROP, OP_TRUE])),
            CTxOut(int(funding["amount"] * COIN) - value - 10_000,
                   bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"])),
        ]
        signed = node.signrawtransactionwithwallet(tx.serialize().hex())
        refused = node.testmempoolaccept([signed["hex"]])[0]
        assert_equal(refused["allowed"], False)
        assert_equal(refused["reject-reason"], "scriptpubkey")

    def check_abort_pays_only_the_owner(self, address):
        """A request is anyone-can-spend, so only consensus keeps it its owner's.

        The block author picks the transactions, and a request carries no
        signature to stop it. If an abort were not checked against the owner
        script the request committed to, whoever won the auction could take
        every queued withdrawal on the sidechain.
        """
        node = self.nodes[1]

        node.withdraw(self.nodes[0].getnewaddress(), 600_000, 1_000, 10_000)
        self.bmm_one_block(address)
        request = next(r for r in node.list_withdrawal_requests() if r["payout_sats"] == 600_000)

        template = node.get_block_template()
        block = from_hex(CBlock(), template["block"]["hex"])

        theft = CTransaction()
        theft.vin = [CTxIn(COutPoint(int(request["txid"], 16), request["vout"]))]
        theft.vout = [CTxOut(request["amount_sats"],
                             bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"]))]
        block.vtx.append(theft)
        self.recommit(block)

        assert_equal(self.bid_for(block, address), "bad-abort-payout")
        self.check_peer_rejects(block, self.critical_of(block))
        # Untouched: still queued, still worth what it was.
        assert_equal(node.gettxout(request["txid"], request["vout"])["value"],
                     Decimal(request["amount_sats"]) / COIN)

        # Aborting it properly still works, so the rule refuses the theft only.
        node.abort_withdrawal(request["txid"], request["vout"])
        self.bmm_one_block(address)
        assert node.gettxout(request["txid"], request["vout"]) is None

    def check_bundle_needs_an_index(self):
        """A producer without -txindex must not open a bundle.

        Settling a failed bundle reads the requests back off the transaction
        that opened it. Without the index the producer cannot build that
        settlement -- and consensus makes it mandatory, so no block can be
        built at all. The validator is the node that has no index here.
        """
        assert_raises_rpc_error(-1, "a synced -txindex is required to open a bundle",
                                self.nodes[2].create_bundle)
        # And it refuses to build a block at all, before it takes a bid: any
        # producer settles a failed bundle, not only the node that opened it.
        assert_raises_rpc_error(-1, "a synced -txindex is required to build a sidechain block",
                                self.nodes[2].get_block_template)

    def check_validator_sees_a_live_bundle(self):
        """A node without the index still sees what is in flight.

        The m6id, the outpoint and the value all come off the tip coinbase. Only
        the requests, and the M6 built from them, read blocks the index finds.
        """
        producer = self.nodes[1].pending_withdrawal_bundle()
        assert producer is not None
        self.sync_blocks(self.nodes[1:3])

        peer = self.nodes[2].pending_withdrawal_bundle()
        assert peer is not None
        assert_equal(peer["m6id"], producer["m6id"])
        assert_equal(peer["value_sats"], producer["value_sats"])
        assert_equal(peer["requests_readable"], False)
        assert "blinded_m6" not in peer

    def check_peg_and_mempool_share_a_block(self, address):
        """The peg claims its weight before the mempool spends the budget.

        Consensus makes a settlement mandatory. If the mempool takes the whole
        block first, the peg pushes the template past the weight limit, the
        producer rejects its own block, and the settlement stays owed -- so no
        later block works either. The limit is lowered here, because filling a
        real block costs far more than a functional test should.
        """
        node = self.nodes[1]
        # The wallet spends its own change every time, so the fill is one long
        # chain of unconfirmed transactions.
        self.restart_node(1, self.extra_args[1] + [
            f"-blockmaxweight={BLOCK_MAX_WEIGHT}",
            "-limitancestorcount=500",
            "-limitdescendantcount=500",
        ])
        self.connect_nodes(1, 2)

        # Many requests, so the settlement that hands them back is larger than
        # the room the assembler holds back for the coinbase.
        for _ in range(PEG_TEST_WITHDRAWALS):
            node.withdraw(self.nodes[0].getnewaddress(), 300_000, 1_000, 10_000)
        self.bmm_one_block(address)
        node.create_bundle()
        self.bmm_one_block(address)
        self.publish_bundle(node, address)

        # A deposit inside the small block, so this does not quietly show that
        # a small -blockmaxweight works only while nothing is deposited. The
        # peg prices its own transactions, so the deposits take what is left.
        self.deposit(self.nodes[0].getnewaddress(), 1_000_000)
        self.generate_mainchain(1, address)

        settled = None
        for _ in range(20):
            # More than the block holds, so the mempool wants every byte of it.
            # The chain of unconfirmed transactions has a limit of its own, and
            # reaching it is fine: the mempool already wants the whole block.
            while node.getmempoolinfo()["bytes"] * WITNESS_SCALE_FACTOR < BLOCK_MAX_WEIGHT:
                try:
                    node.sendtoaddress(node.getnewaddress(), Decimal("0.0001"))
                except JSONRPCException:
                    break
            self.bmm_one_block(address)
            block = node.getblock(node.getbestblockhash())
            assert_greater_than(BLOCK_MAX_WEIGHT + 1, block["weight"])
            if node.pending_withdrawal_bundle() is None:
                settled = block
                break
        else:
            raise AssertionError("the bundle never aged out")

        # The settlement went in while the mempool was competing for that room,
        # and the requests came back.
        assert_greater_than(len(settled["tx"]), 2)
        # Only the ones this check made, so what earlier checks left behind
        # cannot change the answer.
        assert_equal(len([r for r in node.list_withdrawal_requests()
                          if r["payout_sats"] == 300_000]), PEG_TEST_WITHDRAWALS)

        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(1, 2)
        # The fill leaves a long chain of unconfirmed transactions. The wallet
        # cannot spend its own change past the ancestor limit, so every later
        # withdrawal in this test fails until full blocks clear the mempool.
        while node.getmempoolinfo()["size"] > 0:
            self.bmm_one_block(address)

    def check_bundle_cannot_be_stolen(self, address):
        """A bundle output may only be spent by a settlement.

        Winning a BMM auction is permissionless, so whoever does gets to author
        a sidechain block. If a transaction that spends a bundle alongside
        anything else were left unclassified, that author could pay the whole
        in-flight bundle to itself -- and the mainchain would still pay the
        treasury out, because the M6 is already with the enforcer.
        """
        node = self.nodes[1]

        # Open a bundle to steal.
        node.withdraw(self.nodes[0].getnewaddress(), 500_000, 1_000, 10_000)
        self.bmm_one_block(address)
        bundle = node.create_bundle()
        self.bmm_one_block(address)
        live = node.pending_withdrawal_bundle()
        assert live is not None
        assert_equal(live["m6id"], bundle["m6id"])

        template = node.get_block_template()
        block = from_hex(CBlock(), template["block"]["hex"])

        # Spend the bundle plus one ordinary coin, paying it all to ourselves.
        funding = next(u for u in node.listunspent() if u["amount"] > Decimal("0.001"))
        theft = CTransaction()
        theft.vin = [
            CTxIn(COutPoint(int(live["txid"], 16), live["vout"])),
            CTxIn(COutPoint(int(funding["txid"], 16), funding["vout"])),
        ]
        stolen = live["value_sats"] + int(funding["amount"] * COIN) - 10_000
        theft.vout = [CTxOut(stolen, bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"]))]
        signed = node.signrawtransactionwithwallet(theft.serialize().hex())
        block.vtx.append(from_hex(CTransaction(), signed["hex"]))

        self.recommit(block)

        # A bundle is spendable only by a settlement, which has exactly one input.
        assert_equal(self.bid_for(block, address), "bad-settlement-inputs")
        # And a node that did not build it must refuse it too. Every other peer
        # assertion in this test is "reached the same tip", which can only ever
        # catch a false reject.
        self.check_peer_rejects(block, self.critical_of(block))
        # Untouched: still live, still worth what it was.
        assert_equal(node.pending_withdrawal_bundle()["m6id"], bundle["m6id"])
        assert node.gettxout(live["txid"], live["vout"]) is not None

    def check_script_failure_is_not_deferred(self):
        """A script-invalid block must be rejected, never filed as retry-later.

        Script checks are queued and only surface when the control completes, so
        a peg error raised before that would hide them. The peg reasons are
        deferrable, so the block would keep its work, stay the best candidate,
        and be fully re-verified on every advance without ever being banned.
        """
        node = self.nodes[1]

        block = from_hex(CBlock(), node.get_block_template()["block"]["hex"])
        funding = next(u for u in node.listunspent() if u["amount"] > Decimal("0.001"))
        unsigned = CTransaction()
        unsigned.vin = [CTxIn(COutPoint(int(funding["txid"], 16), funding["vout"]))]
        unsigned.vout = [CTxOut(
            int(funding["amount"] * COIN) - 10_000,
            bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"]),
        )]
        # Never signed, so only script verification can reject it.
        block.vtx.append(unsigned)

        coinbase = CTransaction()
        coinbase.deserialize(BytesIO(block.vtx[0].serialize()))
        coinbase.vout = [o for o in coinbase.vout
                         if not o.scriptPubKey.startswith(bytes.fromhex("6a24aa21a9ed"))]
        coinbase.rehash()
        block.vtx[0] = coinbase
        add_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        block.rehash()

        reason = node.submitblock(block.serialize().hex())
        assert reason is not None and reason.startswith("mandatory-script-verify-flag-failed"), reason
        # Settled, not parked. A block left deferred keeps its work and stays the
        # best candidate, which is what starves every later block of a verdict.
        assert_equal({t["hash"]: t["status"] for t in node.getchaintips()}.get(block.hash), "invalid")

        # The peg hook really would have errored on this block: an otherwise
        # valid one at the same height, with no bid either, raises instead of
        # returning a reason -- because it is deferred rather than judged.
        clean = from_hex(CBlock(), node.get_block_template()["block"]["hex"])
        clean.solve()
        assert_raises_rpc_error(-25, "sidechain-bmm-not-found",
                                node.submitblock, clean.serialize().hex())

    def check_coinbase_cannot_overpay(self, address):
        """A sidechain block has no subsidy, so only deposits and fees may be paid.

        CheckCoinbaseDeposits constrains the leading deposit outputs and nothing
        else, which leaves bad-cb-amount as the only rule standing between a
        block author and minting coins the peg never received.
        """
        node = self.nodes[1]
        template = node.get_block_template()
        block = from_hex(CBlock(), template["block"]["hex"])

        coinbase = CTransaction()
        coinbase.deserialize(BytesIO(block.vtx[0].serialize()))
        coinbase.vout = [o for o in coinbase.vout
                         if not o.scriptPubKey.startswith(bytes.fromhex("6a24aa21a9ed"))]
        # One satoshi out of nothing.
        coinbase.vout.append(
            CTxOut(1, bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"]))
        )
        coinbase.rehash()
        block.vtx[0] = coinbase
        add_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        block.rehash()
        critical = bytes.fromhex(block.hash)[::-1].hex()
        tip = self.call("ValidatorService", "GetChainTip")["blockHeaderInfo"]["blockHash"]["hex"]
        self.call(
            "WalletService",
            "CreateBmmCriticalDataTransaction",
            {
                "sidechainId": SLOT,
                "valueSats": "1000",
                # The enforcer makes this the bid's nLockTime. A block takes a
                # transaction only when nLockTime is below the block height, so
                # the tip keeps the bid final for the block it competes for.
                "height": self.nodes[0].getblockcount(),
                "criticalHash": {"hex": critical},
                "prevBytes": {"hex": tip},
            },
        )
        self.generate_mainchain(1, address)
        self.wait_until(lambda: node.get_bmm_inclusions(critical) != [], timeout=30)

        assert_equal(node.submitblock(block.serialize().hex()), "bad-cb-amount")
        self.check_peer_rejects(block, critical)

    def sidechain_supply(self, node):
        """Total unspent value. Every coin here arrived through the peg."""
        return node.gettxoutsetinfo()["total_amount"]

    def treasury_value(self):
        """What the mainchain still holds for this slot."""
        ctip = self.call("ValidatorService", "GetCtip", {"sidechainNumber": SLOT}).get("ctip")
        return int(ctip["value"]) if ctip else 0

    def deposit(self, address, value_sats):
        """Peg in, and return the sidechain script that should be credited.

        The M5 pays an OP_DRIVECHAIN treasury output, which only relays because
        this build treats it as standard -- the mainchain node here is started
        without -acceptnonstdtxn on purpose.

        One deposit per mainchain block: the enforcer's wallet spends the
        treasury output the last M5 made, so an unconfirmed one is replaced
        rather than chained.
        """
        node = self.nodes[1]
        side_address = node.getnewaddress()
        self.call(
            "WalletService",
            "CreateDepositTransaction",
            {
                "sidechainId": SLOT,
                "address": side_address,
                "valueSats": str(value_sats),
                "feeSats": "10000",
            },
        )
        # The deposit has to be confirmed at or below the mainchain tip the next
        # template builds on, or it falls outside the range the coinbase covers.
        self.generate_mainchain(1, address)
        return node.getaddressinfo(side_address)["scriptPubKey"]

    def run_test(self):
        self.start_enforcer()
        try:
            address = self.call("WalletService", "CreateNewAddress")["address"]
            # Coinbase maturity, so the enforcer wallet can pay BMM bids.
            self.generate_mainchain(101, address)
            self.activate_slot(address)

            node = self.nodes[1]
            self.wait_until(lambda: node.getsidechaininfo()["synced"], timeout=60)
            assert_equal(node.getblockcount(), 0)

            self.log.info("Blind merge mining sidechain blocks")
            for expected in range(1, 4):
                self.bmm_one_block(address)
                assert_equal(node.getblockcount(), expected)

            self.log.info("Crediting a deposit")
            deposit_sats = 50_000_000
            credited = self.deposit(address, deposit_sats)
            self.bmm_one_block(address)
            assert_equal(node.getblockcount(), 4)

            coinbase = node.getblock(node.getblockhash(4), 2)["tx"][0]
            paid = [out for out in coinbase["vout"] if out["scriptPubKey"]["hex"] == credited]
            assert_equal(len(paid), 1)
            assert_equal(paid[0]["value"], Decimal(deposit_sats) / COIN)
            # The deposit is the only thing minted: it lands in the coinbase and
            # nothing else on this chain creates value.
            assert_equal(
                sum(out["value"] for out in coinbase["vout"]),
                Decimal(deposit_sats) / COIN,
            )

            # A deposit is credited exactly once. The next block covers a range
            # that no longer contains it.
            self.bmm_one_block(address)
            later = node.getblock(node.getblockhash(5), 2)["tx"][0]
            assert_equal(sum(out["value"] for out in later["vout"]), 0)

            self.log.info("Checking a block with no deposits")
            block = node.getblock(node.getblockhash(3), 2)
            coinbase = block["tx"][0]
            # No subsidy: every satoshi on this chain arrives through the peg,
            # and with no deposits or fees the coinbase pays exactly nothing.
            assert_equal(sum(out["value"] for out in coinbase["vout"]), 0)
            # Deposits (none here), the miner's fee output, the BMM commitment,
            # and the witness commitment Core appends.
            assert_equal(len(coinbase["vout"]), 3)


            # Deposits arrive in the coinbase, so they are immature for a
            # hundred blocks like any other. On this chain that applies to every
            # coin in existence, because the peg is the only source of them.
            self.log.info("Maturing the deposit")
            for _ in range(COINBASE_MATURITY):
                self.bmm_one_block(address)

            self.log.info("Requesting a withdrawal")
            mainchain_address = self.nodes[0].getnewaddress()
            payout, main_fee = 20_000_000, 100_000
            request_txid = node.withdraw(mainchain_address, payout, 1_000, main_fee)
            self.bmm_one_block(address)
            assert_equal(node.getrawtransaction(request_txid, True, node.getbestblockhash())["confirmations"], 1)

            # The coins are encumbered, not burnt: still in the UTXO set, still
            # the owner's, and worth the payout plus the fee the bundle will pay.
            pending = node.list_withdrawal_requests()
            assert_equal(len(pending), 1)
            assert_equal(pending[0]["txid"], request_txid)
            assert_equal(pending[0]["payout_sats"], payout)
            assert_equal(pending[0]["mainchain_fee_sats"], main_fee)
            assert_equal(pending[0]["amount_sats"], payout + main_fee)
            assert_equal(
                pending[0]["dest"],
                self.nodes[0].getaddressinfo(mainchain_address)["scriptPubKey"],
            )
            assert node.gettxout(request_txid, pending[0]["vout"]) is not None

            # No spend of a request relays. Every way to move one arrives in a
            # block, and a block costs a BMM bid.
            steal = CTransaction()
            steal.vin = [CTxIn(COutPoint(int(request_txid, 16), pending[0]["vout"]))]
            steal.vout = [
                CTxOut(payout, bytes.fromhex(node.getaddressinfo(node.getnewaddress())["scriptPubKey"])),
                CTxOut(0, CScript([OP_RETURN, b"\x00" * 20])),
            ]
            refused = node.testmempoolaccept([steal.serialize().hex()])[0]
            assert_equal(refused["allowed"], False)
            assert_equal(refused["reject-reason"], "bad-txns-nonstandard-inputs")

            self.log.info("Bundling it")
            bundle = node.create_bundle()
            assert_equal(bundle["payout_sats"], payout)
            assert_equal(bundle["mainchain_fee_sats"], main_fee)
            assert_equal(bundle["requests"], 1)
            self.log.info("Carrying the bundle into a block")
            self.bmm_one_block(address)
            bundle_height = node.getblockcount()
            # The enforcer is the authority on this shape, so hand it the bundle
            # and let it decide -- a byte it disagrees with is a bundle that
            # could never be voted on. This waits for the publish depth.
            self.publish_bundle(node, address)
            block = node.getblock(node.getblockhash(bundle_height), 2)
            # The bundle transaction spent the request, so the request is gone
            # from the UTXO set and the coins are now held by the bundle.
            assert_equal(node.gettxout(request_txid, pending[0]["vout"]), None)
            assert_equal(node.list_withdrawal_requests(), [])
            bundled = [tx for tx in block["tx"] if any(
                vin.get("txid") == request_txid for vin in tx.get("vin", []))]
            assert_equal(len(bundled), 1)
            assert_equal(len(bundled[0]["vout"]), 1)
            assert_equal(bundled[0]["vout"][0]["value"], Decimal(payout + main_fee) / COIN)
            # Still ours, still backed: nothing was destroyed by bundling.
            assert node.gettxout(bundled[0]["txid"], 0) is not None

            # What the frontend polls while a peg-out is in flight.
            in_flight = node.pending_withdrawal_bundle()
            assert in_flight is not None
            assert_equal(in_flight["m6id"], bundle["m6id"])
            assert_equal(in_flight["value_sats"], payout + main_fee)
            assert_equal(in_flight["height_created"], bundle_height)
            assert_equal(len(in_flight["requests"]), 1)
            assert_equal(in_flight["requests"][0]["txid"], request_txid)
            # Nothing has failed, so there is nothing to report.
            assert_equal(node.latest_failed_withdrawal_bundle_height(), None)

            self.log.info("Reading a live bundle without an index")
            self.check_validator_sees_a_live_bundle()

            self.log.info("Letting the mainchain vote it through")
            # The enforcer's producer upvotes a proposed bundle in every block it
            # mines while ack_all is on, and regtest needs only a handful of
            # votes rather than mainnet's 13,150.
            supply_before = self.sidechain_supply(node)
            for _ in range(20):
                self.bmm_one_block(address)
                if node.pending_withdrawal_bundle() is None:
                    break
            else:
                raise AssertionError("the bundle was never resolved")

            # Paid out on the mainchain, so the sidechain's copy is destroyed:
            # the bundle output is spent and nothing replaced it.
            assert_equal(node.gettxout(bundled[0]["txid"], 0), None)
            assert_equal(node.list_withdrawal_requests(), [])
            assert_equal(node.latest_failed_withdrawal_bundle_height(), None)
            assert_equal(self.sidechain_supply(node), supply_before - Decimal(payout + main_fee) / COIN)

            # And the mainchain really paid: the M6 spent the treasury down by
            # the payout plus the fee it carried.
            self.wait_until(lambda: self.treasury_value() == 50_000_000 - (payout + main_fee), timeout=30)

            self.log.info("Failing a bundle and getting the coins back")
            # Stop upvoting, so this one ages out instead of winning.
            self.call("BlockProducerService", "SetAckAllProposals", {"ackAll": False})
            node.withdraw(mainchain_address, 1_000_000, 1_000, 10_000)
            self.bmm_one_block(address)

            queued = node.list_withdrawal_requests()
            assert_equal(len(queued), 1)
            second = node.create_bundle()
            self.bmm_one_block(address)
            pending = self.publish_bundle(node, address)
            before_failure = self.sidechain_supply(node)

            # The M6 the chain hands back is the one for the bundle it opened.
            assert_equal(pending["m6id"], second["m6id"])
            # A second bundle could never be paid: the mainchain votes on one
            # per slot. Staging one would hand out an M6 nothing backs.
            assert_raises_rpc_error(-1, "a bundle is already in flight",
                                    node.create_bundle)

            for _ in range(20):
                self.bmm_one_block(address)
                if node.pending_withdrawal_bundle() is None:
                    break
            else:
                raise AssertionError("the bundle never aged out")

            # Nothing was taken, so nothing had to be given back: the requests
            # are simply pending again, worth exactly what they were.
            restored = node.list_withdrawal_requests()
            assert_equal(len(restored), 1)
            assert_equal(restored[0]["payout_sats"], 1_000_000)
            assert_equal(restored[0]["mainchain_fee_sats"], 10_000)
            assert_equal(self.sidechain_supply(node), before_failure)
            assert node.latest_failed_withdrawal_bundle_height() is not None
            # The peer has no -txindex. Prove it validated the failed settlement
            # rather than merely staying quiet: same tip, same view of what is
            # pending, and the settlement block really is in its chain.
            peer = self.nodes[2]
            assert_equal(peer.getbestblockhash(), node.getbestblockhash())
            assert_equal(peer.getblockcount(), node.getblockcount())
            assert_equal(len(peer.list_withdrawal_requests()), 1)
            assert_equal(peer.getindexinfo(), {})

            # It came back under a new outpoint, because the settlement spent the
            # bundle to recreate it, but it is the same withdrawal.
            assert_equal(node.gettxout(queued[0]["txid"], queued[0]["vout"]), None)
            assert restored[0]["txid"] != queued[0]["txid"]
            assert_equal(restored[0]["dest"], queued[0]["dest"])
            assert_equal(restored[0]["owner"], queued[0]["owner"])

            self.log.info("Refusing to bundle without an index")
            self.check_bundle_needs_an_index()

            self.log.info("Aborting a withdrawal")
            self.check_withdrawal_can_be_aborted(address)

            self.log.info("Waiting for room to abort")
            self.check_aborts_wait_for_room(address)

            self.log.info("Draining a deposit backlog through the miner")
            self.check_deposit_cut_runs_in_the_miner(address)

            self.log.info("Capping an abort by signature operations")
            self.check_abort_stops_at_the_sigop_cap(address)

            self.log.info("Dropping a bundle the mainchain already ruled on")
            self.check_producer_drops_a_ruled_bundle(address)

            self.log.info("Refusing a request output the parser rejects")
            self.check_malformed_request_cannot_relay()

            self.log.info("Refusing an abort that pays the wrong owner")
            self.check_abort_pays_only_the_owner(address)

            self.log.info("Sharing a block between the peg and the mempool")
            self.check_peg_and_mempool_share_a_block(address)

            self.log.info("Trying to steal the bundle")
            self.check_bundle_cannot_be_stolen(address)

            self.log.info("Trying to mint from the coinbase")
            self.check_coinbase_cannot_overpay(address)


            # A deposit confirmed in a mainchain block the sidechain skipped over
            # must still be credited: the range a block covers reaches back to its
            # parent's prev_main, not just one block. Every past regression in the
            # range arithmetic lived in this gap. Last, because it moves the
            # treasury total that the assertions above pin exactly.
            self.log.info("Crediting a deposit across skipped mainchain blocks")
            gap_sats = 25_000_000
            gap_credited = self.deposit(address, gap_sats)
            self.generate_mainchain(5, address)
            self.bmm_one_block(address)
            gap_coinbase = node.getblock(node.getbestblockhash(), 2)["tx"][0]
            gap_paid = [out for out in gap_coinbase["vout"]
                        if out["scriptPubKey"]["hex"] == gap_credited]
            assert_equal(len(gap_paid), 1)
            assert_equal(gap_paid[0]["value"], Decimal(gap_sats) / COIN)

            # Last: it leaves a deferred block at the next height, which stays a
            # candidate and would beat any block mined after it.
            self.log.info("Checking a script failure outranks a deferrable peg error")
            self.check_script_failure_is_not_deferred()

            # A block the mainchain never committed to must be refused.
            template = node.get_block_template()
            assert_raises_rpc_error(
                -26,
                "no mainchain block commits to this block",
                node.connect_block,
                template["block"],
                node.getblockhash(0),
            )

            # The block object carries what the orchestrator's BMM engine reads
            # to build the M8 request script. An empty string here would fail
            # only later, inside the engine.
            assert_equal(
                template["block"]["header"]["prev_main_hash"],
                self.nodes[0].getbestblockhash(),
            )
        finally:
            self.stop_enforcer()


if __name__ == "__main__":
    SidechainBmmTest(__file__).main()
