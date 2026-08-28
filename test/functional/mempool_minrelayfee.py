#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Inquisition developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the default minimum relay feerate."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

# 5 sat/vB, in BTC per kvB.
DEFAULT_MIN_RELAY_TX_FEE = Decimal("0.00005000")


class MempoolMinRelayFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # The node default is the subject here, so keep the suite pin away.
        self.pin_relay_fee = False

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, COINBASE_MATURITY + 2)

        self.log.info("Test that the node reports the default minimum relay feerate")
        assert_equal(node.getmempoolinfo()["minrelaytxfee"], DEFAULT_MIN_RELAY_TX_FEE)

        self.log.info("Test that the node rejects a transaction below the floor")
        too_cheap = wallet.create_self_transfer(fee_rate=DEFAULT_MIN_RELAY_TX_FEE / 2)
        assert_raises_rpc_error(-26, "min relay fee not met", node.sendrawtransaction, too_cheap["hex"])
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.log.info("Test that the node accepts a transaction at the floor")
        at_floor = wallet.create_self_transfer(fee_rate=DEFAULT_MIN_RELAY_TX_FEE)
        node.sendrawtransaction(at_floor["hex"])
        assert_equal(node.getmempoolinfo()["size"], 1)


if __name__ == '__main__':
    MempoolMinRelayFeeTest(__file__).main()
