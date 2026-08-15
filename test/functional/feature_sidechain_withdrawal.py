#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Inquisition developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Refuse peg outputs on a chain that has no peg.

A withdrawal request output only means something to a sidechain. This node runs
without -sidechainslot, so it must not relay one at all. Otherwise the script is
a cheap way to put attacker bytes into the UTXO set of a chain that can never
spend them: policy refuses every spend, so they stay there for good.

The sidechain half of this -- that a request relays, holds its value, and moves
only inside a block -- lives in feature_sidechain_bmm.py, which runs a real
enforcer.
"""


from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, OP_DROP, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# version, mainchain_fee (8 bytes LE), then two length-prefixed scripts.
MARKER_V0 = 0x01
SLOT = 119


def request_payload(fee_sats, dest, owner):
    return (
        bytes([MARKER_V0])
        + fee_sats.to_bytes(8, "little")
        + bytes([len(dest)]) + dest
        + bytes([len(owner)]) + owner
    )


def request_script(fee_sats, dest, owner):
    return CScript([request_payload(fee_sats, dest, owner), OP_DROP, OP_TRUE])


def pad():
    """A one-input, one-output tx is under MIN_STANDARD_TX_NONWITNESS_SIZE."""
    return CTxOut(0, CScript([OP_RETURN, b"\x00" * 20]))


class SidechainWithdrawalTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Node 1 starts as an ordinary chain so it can make blocks, and takes
        # the peg on partway through. A sidechain makes no block without an
        # enforcer, and this file covers relay and the UTXO set, not the peg
        # lifecycle, so it needs no enforcer at all.
        self.extra_args = [[], []]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 101, sync_fun=self.no_op)

        self.log.info("Refusing a request output off a sidechain")
        utxo = self.wallet.get_utxo()
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        script = request_script(10_000, b"\x00" * 22, b"\x51")
        tx.vout = [CTxOut(int(utxo["value"] * COIN) - 10_000, script), pad()]
        self.wallet.sign_tx(tx)

        result = node.testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        assert_equal(result["reject-reason"], "scriptpubkey")

        # Solver still names it, so a decoded transaction reads the same on every
        # chain. Only the standardness of creating one changes.
        decoded = node.decoderawtransaction(tx.serialize().hex())
        assert_equal(decoded["vout"][0]["scriptPubKey"]["type"], "withdrawalrequest")

        self.log.info("Holding a request in the UTXO set on a sidechain")
        # Funded and confirmed while node 1 is an ordinary chain, because a
        # sidechain makes no block without an enforcer. The peg comes on after.
        peg = self.nodes[1]
        peg_wallet = MiniWallet(peg)
        self.generate(peg_wallet, 101, sync_fun=self.no_op)

        utxo = peg_wallet.get_utxo()
        value = int(utxo["value"] * COIN) - 10_000
        held = CTransaction()
        held.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        held.vout = [CTxOut(value, request_script(1_000, b"\x00" * 22, b"\x51")), pad()]
        peg_wallet.sign_tx(held)
        # Straight into a block: this chain has no peg yet, so it would not
        # relay one, which is what the first half of this test proves.
        self.generateblock(peg, peg.get_deterministic_priv_key().address,
                           [held.serialize().hex()], sync_fun=self.no_op)
        txid = held.rehash()

        self.restart_node(1, [f"-sidechainslot={SLOT}"])
        peg = self.nodes[1]

        # The coins are encumbered, not destroyed. Burning at request time is
        # what forces a status database and a minting refund path, and both are
        # where the reference sidechain's inflation bugs live.
        entry = peg.gettxout(txid, 0)
        assert entry is not None
        assert_equal(int(entry["value"] * COIN), value)
        assert_equal(entry["scriptPubKey"]["type"], "withdrawalrequest")

        # Nobody may take it through the mempool. Only a block moves it, and
        # every block costs a BMM bid.
        theft = CTransaction()
        theft.vin = [CTxIn(COutPoint(int(txid, 16), 0))]
        theft.vout = [CTxOut(value - 10_000, peg_wallet._scriptPubKey), pad()]
        refused = peg.testmempoolaccept([theft.serialize().hex()])[0]
        assert_equal(refused["allowed"], False)
        assert_equal(refused["reject-reason"], "bad-txns-nonstandard-inputs")

        # Making one does relay here, which is what the peg needs and what the
        # chain without a peg refuses.
        spend = peg_wallet.get_utxo()
        good = CTransaction()
        good.vin = [CTxIn(COutPoint(int(spend["txid"], 16), spend["vout"]))]
        good.vout = [CTxOut(int(spend["value"] * COIN) - 10_000,
                            request_script(1_000, b"\x00" * 22, b"\x51")), pad()]
        peg_wallet.sign_tx(good)
        assert_equal(peg.testmempoolaccept([good.serialize().hex()])[0]["allowed"], True)

        # A request the parser rejects does not relay even here: its fee is at
        # the value, so no bundle or abort could ever take it, and its script
        # ends in OP_TRUE.
        bad = CTransaction()
        bad.vin = [CTxIn(COutPoint(int(spend["txid"], 16), spend["vout"]))]
        bad.vout = [CTxOut(1_000, request_script(1_000, b"\x00" * 22, b"\x51")),
                    CTxOut(int(spend["value"] * COIN) - 11_000, peg_wallet._scriptPubKey)]
        peg_wallet.sign_tx(bad)
        rejected = peg.testmempoolaccept([bad.serialize().hex()])[0]
        assert_equal(rejected["allowed"], False)
        assert_equal(rejected["reject-reason"], "scriptpubkey")


if __name__ == "__main__":
    SidechainWithdrawalTest(__file__).main()
