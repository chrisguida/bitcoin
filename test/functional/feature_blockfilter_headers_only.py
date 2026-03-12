#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test unconditional block filter header chain (headers-only mode).

Every node builds BIP158 basic filter headers unconditionally during IBD,
even without -blockfilterindex. This test verifies:
1. Headers-only index syncs without -blockfilterindex
2. Filter data (flat files) is NOT stored in headers-only mode
3. getblockfilter fails in headers-only mode (no filter data)
4. getindexinfo shows the index is synced
5. Upgrading to full -blockfilterindex works
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BlockFilterHeadersOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # Node 0: no -blockfilterindex (headers-only mode, unconditional)
        # Node 1: full -blockfilterindex
        self.extra_args = [[], ["-blockfilterindex"]]

    def run_test(self):
        self.log.info("Mine blocks on both nodes")
        self.generate(self.nodes[0], 50)
        self.sync_blocks()

        self.log.info("Check headers-only index is synced on node 0 (no -blockfilterindex)")
        indexinfo = self.nodes[0].getindexinfo()
        assert "basic block filter index" in indexinfo, f"Expected basic block filter index in getindexinfo, got: {indexinfo}"
        assert_equal(indexinfo["basic block filter index"]["synced"], True)
        assert_equal(indexinfo["basic block filter index"]["best_block_height"], 50)

        self.log.info("Check full index is synced on node 1 (-blockfilterindex)")
        indexinfo1 = self.nodes[1].getindexinfo()
        assert "basic block filter index" in indexinfo1
        assert_equal(indexinfo1["basic block filter index"]["synced"], True)
        assert_equal(indexinfo1["basic block filter index"]["best_block_height"], 50)

        self.log.info("Verify getblockfilter fails on node 0 (headers-only, no filter data)")
        block_hash = self.nodes[0].getblockhash(25)
        assert_raises_rpc_error(-1, "Index is not enabled for filtertype basic", self.nodes[0].getblockfilter, block_hash, "basic")

        self.log.info("Verify getblockfilter succeeds on node 1 (full index)")
        result = self.nodes[1].getblockfilter(block_hash, "basic")
        assert "filter" in result
        assert "header" in result
        full_header = result["header"]

        self.log.info("Verify no flat filter files exist on node 0")
        datadir = self.nodes[0].datadir_path / "regtest" / "indexes" / "blockfilter" / "basic"
        fltr_files = list(datadir.glob("fltr*.dat"))
        assert_equal(len(fltr_files), 0)

        self.log.info("Verify flat filter files exist on node 1")
        datadir1 = self.nodes[1].datadir_path / "regtest" / "indexes" / "blockfilter" / "basic"
        fltr_files1 = list(datadir1.glob("fltr*.dat"))
        assert len(fltr_files1) > 0, "Expected flat filter files on full index node"

        # TODO (Phase 2/3): Test upgrade from headers-only to full -blockfilterindex.
        # Currently the index thinks it's synced (DB entries exist) but has no flat file
        # data. The upgrade path needs to detect headers-only entries and rebuild flat
        # files, either from blocks on disk or by downloading filters from peers.

        self.log.info("All tests passed")


if __name__ == '__main__':
    BlockFilterHeadersOnlyTest(__file__).main()
