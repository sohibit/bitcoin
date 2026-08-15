#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Inquisition developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test drivechain sidechain mode.

Covers behaviour that does not need a running bip300301_enforcer. The peg round
trip itself is exercised separately against a live enforcer.
"""

import time

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SidechainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node0 is an ordinary regtest node. node1 runs as sidechain slot 119
        # pointed at a port with nothing on it, so the enforcer is unreachable.
        self.extra_args = [
            [],
            ["-sidechainslot=119", "-enforcerport=1"],
        ]

    def run_test(self):
        self.test_sidechain_mode_reported()
        self.test_subsidy_dependent_rpcs_are_honest()
        self.test_ordinary_node_unaffected()
        self.test_blocks_require_the_peg()
        self.test_unavailable_enforcer_is_not_fatal()
        self.test_restart_with_deferred_block()
        self.test_peg_rpcs_without_a_peg()
        self.test_coinstatsindex_is_refused()
        self.test_snapshot_load_is_refused()
        self.test_prune_is_refused()

    def test_sidechain_mode_reported(self):
        self.log.info("Sidechain node exposes cache state; ordinary node does not")
        assert_equal(self.nodes[1].getsidechaininfo()["synced"], False)
        assert_raises_rpc_error(
            -1, "not running as a sidechain", self.nodes[0].getsidechaininfo
        )

    def test_subsidy_dependent_rpcs_are_honest(self):
        """A sidechain has no subsidy but its coinbase still pays out deposits,
        so anything reporting the subsidy as the block's reward is lying."""
        self.log.info("RPCs that assume a subsidy are refused or omitted")

        # getblocktemplate cannot describe a consensus-mandated coinbase and
        # supplies no coinbasetxn, so an external miner could not build one.
        assert_raises_rpc_error(
            -32601,
            "cannot describe a sidechain coinbase",
            self.nodes[1].getblocktemplate,
            {"rules": ["segwit"]},
        )
        # Rejected before longpoll, not after waiting it out. A well-formed
        # longpollid is 74 chars; a shorter one is ignored and would make this
        # pass regardless of where the throw sits.
        longpollid = "%s%d" % (self.nodes[1].getbestblockhash(), 1234567890)
        assert_equal(len(longpollid), 74)
        started = time.time()
        assert_raises_rpc_error(
            -32601,
            "cannot describe a sidechain coinbase",
            self.nodes[1].getblocktemplate,
            {"rules": ["segwit"], "longpollid": longpollid},
        )
        assert time.time() - started < 5, "getblocktemplate waited on longpoll before rejecting"
        # Mode validation still runs first: the sidechain throw does not shadow it.
        assert_raises_rpc_error(-8, "Invalid mode", self.nodes[1].getblocktemplate, {"mode": "bogus"})

        assert "subsidy" not in self.nodes[1].getblockstats(0)
        assert "subsidy" in self.nodes[0].getblockstats(0)

    def test_ordinary_node_unaffected(self):
        """The peg rules are gated on sidechain mode, so an ordinary chain keeps
        its subsidy and mines normally."""
        self.log.info("Ordinary regtest node still has a block subsidy")
        block_hash = self.generatetoaddress(
            self.nodes[0], 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)[0]
        block = self.nodes[0].getblock(block_hash, 2)
        assert_equal(sum(out["value"] for out in block["tx"][0]["vout"]), 50)

    def test_blocks_require_the_peg(self):
        """A sidechain block must be blind-merge-mined and must credit exactly
        the deposits the enforcer reports, so it cannot be produced without one."""
        self.log.info("Sidechain blocks cannot be produced without the enforcer")
        assert_raises_rpc_error(
            -1,
            "enforcer unavailable",
            self.generatetoaddress,
            self.nodes[1],
            1,
            ADDRESS_BCRT1_UNSPENDABLE,
            sync_fun=self.no_op,
        )

    def test_peg_rpcs_without_a_peg(self):
        """Every peg RPC either answers from the chain, or says it cannot.

        None of them may guess. The six below read the chain and the staged
        view, so they answer with an unreachable enforcer. The rest read the
        mainchain, and each one reports an error instead of an empty answer
        that a caller could mistake for a real one.
        """
        self.log.info("Peg RPCs answer or refuse, and never guess")
        node = self.nodes[1]
        zero = "00" * 32

        assert_equal(node.list_withdrawal_requests(), [])
        assert_equal(node.pending_withdrawal_bundle(), None)
        assert_equal(node.latest_failed_withdrawal_bundle_height(), None)
        # Nothing is staged, so there is nothing to drop.
        assert_equal(node.cancel_bundle(), False)
        assert_equal(node.cancel_abort(zero, 0), False)
        assert_equal(node.list_staged()["bundle"], [])

        # A batch, because these all fail: the coverage tool records a call
        # from the batch request, and a failed single call it never sees.
        needs_mainchain = node.batch([
            node.getmainchaintip.get_request(),
            node.getmainchainblockinfo.get_request(zero),
            node.getbmmcommitment.get_request(zero),
            node.get_bmm_inclusions.get_request(zero),
            node.get_block_template.get_request(),
            node.connect_block.get_request({"hex": "00"}, zero),
            node.create_bundle.get_request(),
            node.abort_withdrawal.get_request(zero, 0),
        ])
        for answer in needs_mainchain:
            assert answer.get("error") is not None, answer
            assert answer.get("result") is None, answer

    def test_unavailable_enforcer_is_not_fatal(self):
        """An absent or lagging enforcer must never mark a block invalid. Doing
        so would have a node with a slow enforcer reject good blocks and ban
        itself off the network, so the failure is state.Error, not
        state.Invalid."""
        self.log.info("Unavailable enforcer degrades gracefully")
        node = self.nodes[1]

        # Make node1 actually receive node0's block, otherwise the assertions
        # below pass vacuously against a node that saw nothing.
        node0_tip = self.nodes[0].getbestblockhash()
        self.connect_nodes(0, 1)

        # Waiting for the header alone would be vacuous: headers arrive before
        # bodies, so the block could be "headers-only" and never validated. Wait
        # for the peg check to actually run and defer it.
        node.wait_until(
            lambda: node.getchaintips() and any(
                tip["hash"] == node0_tip for tip in node.getchaintips()),
            timeout=30,
        )
        self.wait_until(
            lambda: "sidechain-enforcer-unavailable"
            in node.debug_log_path.read_text(encoding="utf-8", errors="replace"),
            timeout=30,
        )

        # It arrived and could not be connected. It must sit unconnected and
        # never be marked invalid -- that is the whole distinction between
        # state.Error and state.Invalid, and marking it invalid would have a node
        # with a lagging enforcer ban itself off the network.
        tips = {tip["hash"]: tip["status"] for tip in node.getchaintips()}
        assert node0_tip in tips, tips
        assert tips[node0_tip] != "invalid", tips
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.getbestblockhash(), node.getblockhash(0))
        assert_equal(node.getsidechaininfo()["synced"], False)

        # And the enforcer-backed RPCs report the failure rather than crashing.
        assert_raises_rpc_error(-1, "", node.getmainchaintip)


    def test_restart_with_deferred_block(self):
        """A node holding a block it could not connect must still start. Making
        that deferral fatal left such a node permanently unstartable, since the
        peg data it is waiting for can only arrive after startup."""
        self.log.info("Node restarts while holding an unconnectable block")
        node = self.nodes[1]

        # It received node0's block earlier and could not connect it.
        node0_tip = self.nodes[0].getbestblockhash()
        assert node0_tip in [tip["hash"] for tip in node.getchaintips()]

        self.restart_node(1, extra_args=["-sidechainslot=119", "-enforcerport=1"])

        # Wait for the import path to actually reach the deferral, rather than
        # racing start_node's RPC readiness against a possible abort.
        self.wait_until(
            lambda: "Deferred connecting best block"
            in node.debug_log_path.read_text(encoding="utf-8", errors="replace"),
            timeout=30,
        )
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.getsidechaininfo()["synced"], False)

        # A node that starts but cannot connect its tip must say so: without this
        # it serves RPC and reports a plausible height while permanently stalled.
        assert any("cannot be connected" in w for w in node.getblockchaininfo()["warnings"]), \
            node.getblockchaininfo()["warnings"]
        # And an ordinary node must not carry it. Checked by substring rather than
        # equality so an unrelated warning does not mask a regression here.
        assert not any("cannot be connected" in w for w in self.nodes[0].getblockchaininfo()["warnings"])

    def test_snapshot_load_is_refused(self):
        """The block after a snapshot base reads that base block, which a
        snapshot does not carry."""
        self.log.info("loadtxoutset is refused on a sidechain")
        assert_raises_rpc_error(
            -8,
            "not supported on a sidechain",
            self.nodes[1].loadtxoutset,
            "/nonexistent/snapshot.dat",
        )

    def test_prune_is_refused(self):
        """Every block reads its parent to derive the credited deposit range, so
        a pruned parent would surface as an unrecoverable validation failure."""
        self.log.info("-prune is refused on a sidechain")
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(
            extra_args=["-sidechainslot=119", "-enforcerport=1", "-prune=550"],
            expected_msg="Error: -prune is not supported on a sidechain: every block reads "
                         "its parent to derive the credited deposit range.",
        )
        self.start_node(1, extra_args=["-sidechainslot=119", "-enforcerport=1"])

    def test_coinstatsindex_is_refused(self):
        """GetBlockSubsidy is 0 here while coinbases still create coins, so the
        index's unclaimed-rewards arithmetic would drift negative unnoticed."""
        self.log.info("-coinstatsindex is refused on a sidechain")
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(
            extra_args=["-sidechainslot=119", "-enforcerport=1", "-coinstatsindex"],
            expected_msg="Error: -coinstatsindex is not supported on a sidechain: deposits "
                         "create coins outside the block subsidy, which its accounting assumes.",
        )
        self.start_node(1, extra_args=["-sidechainslot=119", "-enforcerport=1"])


if __name__ == "__main__":
    SidechainTest(__file__).main()
