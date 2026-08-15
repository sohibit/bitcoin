#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Inquisition developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Relay BIP300 treasury outputs without -acceptnonstdtxn.

A deposit (M5) and a withdrawal bundle (M6) both create an OP_DRIVECHAIN
treasury output, and an M6 spends the previous one. Stock Core rejects both
halves as non-standard, and -acceptnonstdtxn -- the usual workaround -- cannot
be set on mainnet at all (node/mempool_args.cpp). So the peg only works on a
node that treats these outputs as standard in their own right.

Deliberately started without -acceptnonstdtxn: that is the whole point.
"""

from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, OP_NOP5, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

SLOT = 119


def pad():
    """A one-input, one-output tx is under MIN_STANDARD_TX_NONWITNESS_SIZE."""
    return CTxOut(0, CScript([OP_RETURN, b"\x00" * 20]))


def treasury_script(slot):
    """OP_DRIVECHAIN OP_PUSHBYTES_1 <slot> OP_TRUE.

    Assembled bytewise rather than with CScript's push helpers: the enforcer
    emits a literal OP_PUSHBYTES_1 even for slots that would fit a minimal
    push, and the node has to accept exactly those bytes.
    """
    return CScript(bytes([OP_NOP5, 0x01, slot, OP_TRUE]))


class SidechainStandardnessTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 101)

        self.log.info("Creating a treasury output")
        treasury = self.create_treasury(node)

        self.log.info("Spending the treasury output")
        self.spend_treasury(node, treasury)

        self.log.info("Checking the scripts that must stay non-standard")
        self.check_near_misses(node)

    def create_treasury(self, node):
        """An M5 pays the treasury. Assert it relays and is typed correctly."""
        utxo = self.wallet.get_utxo()
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        value = int(utxo["value"] * COIN) - 10_000
        tx.vout = [CTxOut(value, treasury_script(SLOT)), pad()]
        self.wallet.sign_tx(tx)

        accept = node.testmempoolaccept([tx.serialize().hex()])[0]
        assert accept["allowed"], accept

        decoded = node.decoderawtransaction(tx.serialize().hex())
        assert_equal(decoded["vout"][0]["scriptPubKey"]["type"], "drivechain")

        txid = node.sendrawtransaction(tx.serialize().hex())
        blockhash = self.generate(self.wallet, 1)[0]
        assert txid in node.getblock(blockhash)["tx"]
        return tx

    def spend_treasury(self, node, treasury):
        """The M6 spends it bare. A scriptSig on it must be refused."""
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(int(treasury.rehash(), 16), 0))]
        spend.vout = [CTxOut(treasury.vout[0].nValue - 10_000, treasury_script(SLOT)), pad()]

        accept = node.testmempoolaccept([spend.serialize().hex()])[0]
        assert accept["allowed"], accept

        # OP_NOP5 is a consensus no-op and the script leaves a truthy stack, so
        # the output is anyone-can-spend by design; BIP300's security is the
        # miner vote, not the script. An empty scriptSig is what makes that
        # safe, because there is then nothing a third party can malleate.
        malleated = CTransaction()
        malleated.vin = [CTxIn(COutPoint(int(treasury.rehash(), 16), 0), CScript([OP_TRUE]))]
        malleated.vout = spend.vout
        rejected = node.testmempoolaccept([malleated.serialize().hex()])[0]
        assert_equal(rejected["allowed"], False)
        assert_equal(rejected["reject-reason"], "bad-txns-nonstandard-inputs")

        txid = node.sendrawtransaction(spend.serialize().hex())
        blockhash = self.generate(self.wallet, 1)[0]
        assert txid in node.getblock(blockhash)["tx"]

    def check_near_misses(self, node):
        """Only the exact treasury shape is standard."""
        utxo = self.wallet.get_utxo()
        for name, script in [
            # A minimal push, which is what a naive encoder would emit for a
            # small slot. Not what the enforcer produces, so not standard.
            ("minimal push", CScript(bytes([OP_NOP5, 0x51, OP_TRUE]))),
            ("wrong opcode", CScript(bytes([0xb3, 0x01, SLOT, OP_TRUE]))),
            ("trailing byte", CScript(bytes([OP_NOP5, 0x01, SLOT, OP_TRUE, OP_TRUE]))),
        ]:
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
            tx.vout = [CTxOut(int(utxo["value"] * COIN) - 10_000, script), pad()]
            self.wallet.sign_tx(tx)
            result = node.testmempoolaccept([tx.serialize().hex()])[0]
            assert_equal(result["allowed"], False)
            assert_equal(result["reject-reason"], "scriptpubkey")
            self.log.info("  %s stays non-standard", name)


if __name__ == "__main__":
    SidechainStandardnessTest(__file__).main()
