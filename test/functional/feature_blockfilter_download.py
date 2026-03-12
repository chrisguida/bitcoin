#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test downloading block filters from peers (headers-only to full upgrade).

When a node has a headers-only block filter index and is restarted with
-blockfilterindex=1, it should download filters from NODE_COMPACT_FILTERS
peers and verify them against its locally-built header chain.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlockFilterDownloadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # Node 0: full index + serving filters to peers
        # Node 1: starts with no blockfilterindex (builds headers-only during IBD)
        self.extra_args = [
            ["-blockfilterindex", "-peerblockfilters"],
            [],
        ]

    def run_test(self):
        self.log.info("Mine blocks and sync both nodes")
        self.generate(self.nodes[0], 200)
        self.sync_blocks()

        self.log.info("Verify node 1 has headers-only index synced")
        indexinfo = self.nodes[1].getindexinfo()
        assert "basic block filter index" in indexinfo
        assert_equal(indexinfo["basic block filter index"]["synced"], True)
        assert_equal(indexinfo["basic block filter index"]["best_block_height"], 200)

        self.log.info("Verify node 1 cannot serve filters (headers-only)")
        block_hash = self.nodes[1].getblockhash(100)
        try:
            self.nodes[1].getblockfilter(block_hash, "basic")
            assert False, "Expected getblockfilter to fail on headers-only node"
        except Exception:
            pass  # Expected

        self.log.info("Restart node 1 with -blockfilterindex to trigger filter download")
        self.restart_node(1, extra_args=["-blockfilterindex"])
        self.connect_nodes(0, 1)

        self.log.info("Wait for node 1 to download and verify all filters")
        self.wait_until(
            lambda: self.try_getblockfilter(1, block_hash),
            timeout=60,
        )

        self.log.info("Verify downloaded filter matches node 0's filter")
        result0 = self.nodes[0].getblockfilter(block_hash, "basic")
        result1 = self.nodes[1].getblockfilter(block_hash, "basic")
        assert_equal(result0["filter"], result1["filter"])
        assert_equal(result0["header"], result1["header"])

        self.log.info("Verify filters at multiple heights match")
        for height in [0, 1, 50, 150, 199]:
            bh = self.nodes[0].getblockhash(height)
            r0 = self.nodes[0].getblockfilter(bh, "basic")
            r1 = self.nodes[1].getblockfilter(bh, "basic")
            assert_equal(r0["filter"], r1["filter"])
            assert_equal(r0["header"], r1["header"])

        self.log.info("All tests passed")

    def try_getblockfilter(self, node_idx, block_hash):
        """Try getblockfilter, return True if it succeeds."""
        try:
            self.nodes[node_idx].getblockfilter(block_hash, "basic")
            return True
        except Exception:
            return False


if __name__ == '__main__':
    BlockFilterDownloadTest(__file__).main()
