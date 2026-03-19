#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the block filter index across all sync methods, RPC states, and restart scenarios.

Node 0: reference — builds full index from blocks during IBD
Node 1: non-pruned — starts headers-only, upgrades to full
Node 2: pruned — starts headers-only, downloads from peers
"""

import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BlockFilterIndexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            ["-blockfilterindex", "-peerblockfilters"],  # Node 0: full index from start
            [],                                          # Node 1: headers-only
            ["-prune=1"],                                # Node 2: headers-only, pruned
        ]

    def collect_ref(self, node_idx, start, end):
        ref = {}
        for h in range(start, end + 1):
            bh = self.nodes[node_idx].getblockhash(h)
            r = self.nodes[node_idx].getblockfilter(bh, "basic")
            ref[h] = {"filter": r["filter"], "header": r["header"], "blockhash": bh}
        return ref

    def validate_node(self, node_idx, ref, heights, label):
        for h in heights:
            r = self.nodes[node_idx].getblockfilter(ref[h]["blockhash"], "basic")
            assert r["filter"] == ref[h]["filter"], \
                f"{label}: filter mismatch at height {h}"
            assert r["header"] == ref[h]["header"], \
                f"{label}: header mismatch at height {h}: got={r['header'][:16]}... want={ref[h]['header'][:16]}..."

    def try_getblockfilter(self, node_idx, block_hash):
        try:
            self.nodes[node_idx].getblockfilter(block_hash, "basic")
            return True
        except Exception:
            return False

    def run_test(self):
        self.log.info("Mine 200 blocks and sync all nodes")
        self.generate(self.nodes[0], 200)
        self.sync_blocks()

        # ===== getindexinfo RPC states =====
        self.log.info("Test getindexinfo: full index node reports synced")
        bfi0 = self.nodes[0].getindexinfo()["basic block filter index"]
        assert_equal(bfi0["synced"], True)
        assert_equal(bfi0["best_block_height"], 200)
        assert_equal(bfi0["status"], "synced")
        assert "filter_headers" not in bfi0
        assert "hint" not in bfi0

        self.log.info("Test getindexinfo: headers-only nodes report idle")
        for n in [1, 2]:
            bfi = self.nodes[n].getindexinfo()["basic block filter index"]
            assert_equal(bfi["synced"], False)
            assert_equal(bfi["best_block_height"], 0)
            assert_equal(bfi["status"], "idle_headers_available")
            assert_equal(bfi["filter_headers"], True)
            assert "hint" in bfi

        self.log.info("Test getblockfilter fails on headers-only node")
        block_hash = self.nodes[1].getblockhash(100)
        assert_raises_rpc_error(-1, "Index is not enabled for filtertype basic",
                                self.nodes[1].getblockfilter, block_hash, "basic")

        self.log.info("Test no flat filter files on headers-only node")
        datadir = self.nodes[1].datadir_path / "regtest" / "indexes" / "blockfilter" / "basic"
        assert_equal(len(list(datadir.glob("fltr*.dat"))), 0)

        ref = self.collect_ref(0, 0, 200)
        all_heights = list(range(0, 201))

        # ===== Non-pruned: headers-only → rebuild from blocks =====
        self.log.info("Test non-pruned upgrade: headers-only → rebuild from blocks")
        self.restart_node(1, extra_args=["-blockfilterindex"])
        self.wait_until(
            lambda: self.nodes[1].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )
        self.validate_node(1, ref, all_heights, "non-pruned rebuild")

        # ===== Pruned: headers-only → download from peers =====
        self.log.info("Test pruned upgrade: headers-only → download from peers")
        self.restart_node(2, extra_args=["-blockfilterindex", "-prune=1"])
        self.connect_nodes(0, 2)
        self.wait_until(
            lambda: self.try_getblockfilter(2, ref[200]["blockhash"]),
            timeout=60,
        )
        self.validate_node(2, ref, all_heights, "pruned download")

        # ===== Restart fully-synced non-pruned index =====
        self.log.info("Test restart of fully-synced non-pruned index")
        self.restart_node(1, extra_args=["-blockfilterindex"])
        self.wait_until(
            lambda: self.nodes[1].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )
        self.validate_node(1, ref, all_heights, "restart synced")

        # ===== Restart fully-synced pruned index =====
        self.log.info("Test restart of fully-synced pruned index")
        self.restart_node(2, extra_args=["-blockfilterindex", "-prune=1"])
        self.wait_until(
            lambda: self.nodes[2].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )
        self.validate_node(2, ref, all_heights, "restart pruned")

        # ===== Mine more blocks, restart, validate old + new =====
        self.log.info("Test mine more blocks, restart, validate all heights")
        self.connect_nodes(0, 1)
        self.generate(self.nodes[0], 100, sync_fun=lambda: self.sync_blocks([self.nodes[0], self.nodes[1]]))

        ref_extended = self.collect_ref(0, 0, 300)
        extended_heights = list(range(0, 301))

        self.restart_node(1, extra_args=["-blockfilterindex"])
        self.wait_until(
            lambda: self.nodes[1].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )
        self.validate_node(1, ref_extended, extended_heights, "after more blocks")

        # ===== Wipe filter index, rebuild from scratch, validate =====
        self.log.info("Test wipe and rebuild from scratch")
        self.stop_node(1)
        filter_dir = os.path.join(str(self.nodes[1].datadir_path), "regtest", "indexes", "blockfilter")
        if os.path.exists(filter_dir):
            shutil.rmtree(filter_dir)
        self.start_node(1, extra_args=["-blockfilterindex"])
        self.wait_until(
            lambda: self.nodes[1].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )
        self.validate_node(1, ref_extended, extended_heights, "fresh rebuild")

        # Restart after fresh rebuild
        self.restart_node(1, extra_args=["-blockfilterindex"])
        self.wait_until(
            lambda: self.nodes[1].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )
        self.validate_node(1, ref_extended, extended_heights, "restart after fresh rebuild")

        # ===== Toggle: full → headers-only → full =====
        self.log.info("Test toggle: disable blockfilterindex then re-enable")
        self.restart_node(1, extra_args=[])
        bfi_back = self.nodes[1].getindexinfo()["basic block filter index"]
        assert_equal(bfi_back["synced"], False)
        assert_equal(bfi_back["status"], "idle_headers_available")
        assert_equal(bfi_back["best_block_height"], 300)

        self.restart_node(1, extra_args=["-blockfilterindex"])
        self.wait_until(
            lambda: self.nodes[1].getindexinfo()["basic block filter index"]["synced"],
            timeout=60,
        )
        self.validate_node(1, ref_extended, extended_heights, "re-enabled after toggle")

        self.log.info("All tests passed")


if __name__ == '__main__':
    BlockFilterIndexTest(__file__).main()
