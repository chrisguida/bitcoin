#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A garbageman node must broadcast the same feefilter as Libre Relay.

A node sends a feefilter message (value = its minrelaytxfee on a light mempool)
to tx-relay peers. Libre Relay's fee floor is 100 sat/kvB; the Knots default is
1000. A garbageman node preferentially peers as libre-relay, so a 1000 feefilter
makes it trivially distinguishable from a genuine libre peer. Garbageman now
lowers its fee floor to 100 at init, so a default node (no fee config) matches
Libre Relay.

The node is run WITHOUT -corepolicy: a garbageman node must run Knots filtering
policy (Core policy would disable the filtering that is its purpose). The version
tag makes the framework skip its default Knots-only args (notably -corepolicy),
so this exercises the init-time fee-floor handling, not the -corepolicy path.
"""
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

LIBRE_RELAY_FEE_FLOOR = 100  # sat/kvB


class FeefilterConn(P2PInterface):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.feefilter_rate = None

    def on_feefilter(self, message):
        self.feefilter_rate = message.feerate


class GarbagemanFeeFloor(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = False  # a forcerelay peer would be sent no feefilter
        self.extra_args = [["-softwareexpiry=0"]]  # no fee args: the default must already be 100

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args,
                       binary=[self.options.bitcoind],
                       binary_cli=[self.options.bitcoincli],
                       versions=[290300])  # skip framework's -corepolicy; keep Knots policy
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        # Leave IBD, else feefilter is the relay-suppressing override, not minrelaytxfee.
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, COINBASE_MATURITY + 1)

        peer = node.add_p2p_connection(FeefilterConn())
        peer.wait_until(lambda: peer.feefilter_rate is not None, timeout=20)
        self.log.info("default garbageman wire feefilter = %d sat/kvB", peer.feefilter_rate)
        assert_equal(peer.feefilter_rate, LIBRE_RELAY_FEE_FLOOR)


if __name__ == "__main__":
    GarbagemanFeeFloor(__file__).main()
