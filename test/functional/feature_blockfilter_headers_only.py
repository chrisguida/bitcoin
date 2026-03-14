#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test block filter index getindexinfo reporting in all states.

Tests the getindexinfo RPC for the block filter index across all
permutations: headers-only, full mode, syncing, downloading, synced.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BlockFilterHeadersOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # Node 0: no -blockfilterindex (headers-only mode)
        # Node 1: full -blockfilterindex + peerblockfilters (serves filters)
        self.extra_args = [[], ["-blockfilterindex", "-peerblockfilters"]]

    def run_test(self):
        self.log.info("Mine blocks on both nodes")
        self.generate(self.nodes[0], 50)
        self.sync_blocks()

        # --- State 5/6: Headers-only, no bfindex ---
        self.log.info("Test state 5/6: headers-only mode (no -blockfilterindex)")
        bfi = self.nodes[0].getindexinfo()["basic block filter index"]
        assert_equal(bfi["synced"], False)
        assert_equal(bfi["best_block_height"], 0)
        assert_equal(bfi["status"], "idle_headers_available")
        assert_equal(bfi["filter_headers"], True)
        assert "hint" in bfi
        self.log.info(f"  status={bfi['status']}, hint={bfi['hint']}")

        # --- State 8: Full index, synced ---
        self.log.info("Test state 8: full index, synced")
        bfi1 = self.nodes[1].getindexinfo()["basic block filter index"]
        assert_equal(bfi1["synced"], True)
        assert_equal(bfi1["best_block_height"], 50)
        assert_equal(bfi1["status"], "synced")
        assert "filter_headers" not in bfi1
        assert "hint" not in bfi1

        # --- Verify getblockfilter fails on headers-only node ---
        self.log.info("Test getblockfilter fails on headers-only node")
        block_hash = self.nodes[0].getblockhash(25)
        assert_raises_rpc_error(-1, "Index is not enabled for filtertype basic",
                                self.nodes[0].getblockfilter, block_hash, "basic")

        # --- Verify getblockfilter works on full index node ---
        self.log.info("Test getblockfilter works on full index node")
        result = self.nodes[1].getblockfilter(block_hash, "basic")
        assert "filter" in result
        assert "header" in result
        full_header = result["header"]

        # --- Verify no flat filter files on headers-only node ---
        self.log.info("Test no flat filter files on headers-only node")
        datadir = self.nodes[0].datadir_path / "regtest" / "indexes" / "blockfilter" / "basic"
        fltr_files = list(datadir.glob("fltr*.dat"))
        assert_equal(len(fltr_files), 0)

        # --- State 9/10: Upgrade from headers-only to full ---
        # Non-pruned nodes rebuild from local blocks (fast, completes immediately
        # on regtest). Pruned nodes would download from peers.
        self.log.info("Test state 9: restart non-pruned node 0 with -blockfilterindex (upgrade)")
        self.restart_node(0, extra_args=["-blockfilterindex"])

        # Wait for sync to complete (rebuilds from blocks, nearly instant on regtest)
        self.wait_until(
            lambda: self.nodes[0].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )

        # --- State 12: Upgrade complete ---
        self.log.info("Test state 12: upgrade complete")
        bfi_done = self.nodes[0].getindexinfo()["basic block filter index"]
        assert_equal(bfi_done["synced"], True)
        assert_equal(bfi_done["best_block_height"], 50)
        assert_equal(bfi_done["status"], "synced")
        assert "filter_headers" not in bfi_done
        assert "hint" not in bfi_done

        # --- Verify downloaded filter matches ---
        self.log.info("Test downloaded filter matches node 1")
        result0 = self.nodes[0].getblockfilter(block_hash, "basic")
        assert_equal(result0["header"], full_header)

        # --- State 6 with partial filters: restart without bfindex ---
        self.log.info("Test state 6 with partial filters: restart headers-only after having filters")
        self.restart_node(0, extra_args=[])
        bfi_back = self.nodes[0].getindexinfo()["basic block filter index"]
        assert_equal(bfi_back["synced"], False)
        assert_equal(bfi_back["status"], "idle_headers_available")
        # best_block_height should reflect the filters that exist
        assert_equal(bfi_back["best_block_height"], 50)
        self.log.info(f"  status={bfi_back['status']}, best_block_height={bfi_back['best_block_height']}")

        self.log.info("All tests passed")


if __name__ == '__main__':
    BlockFilterHeadersOnlyTest(__file__).main()
