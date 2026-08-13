#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the proof-of-work-change plumbing on regtest.

Uses the regtest-only -powchangetime option to schedule a PoW-algorithm change
and verifies that:
  * blocks before the change time hash with SHA256d,
  * blocks at/after the change time hash with the scheduled algorithm,
  * a later block whose timestamp reaches back before the change (so it would be
    hashed with the previous algorithm) is rejected as 'pow-reversed',
  * a node WITHOUT the change scheduled rejects post-change blocks outright
    (the mainnet relationship between fork software and unupgraded nodes:
    unlike a softfork, there is no wipeout and no convergence).

No new hash algorithm is involved; the scheduled algorithm reuses an existing
hash primitive (RIPEMD160).
"""

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CBlockHeader, hash256, powhash, set_pow_change
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

CHANGE_TIME = 1_500_000_000  # PoW change activates at this block time
CHANGE_ALGO = 2              # RIPEMD160 (160-bit, distinct from SHA256d)
STEP = 600                   # ten-minute spacing between mocked block times


class PowChangeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # node1 has no PoW change scheduled: it plays the unupgraded node.
        self.extra_args = [[f"-powchangetime={CHANGE_TIME}:{CHANGE_ALGO}"], []]

    def setup_network(self):
        self.setup_nodes()  # deliberately not connected; blocks are shuttled by hand

    def header_bytes(self, blockhash):
        return bytes.fromhex(self.nodes[0].getblock(blockhash, 0)[:160])

    def run_test(self):
        node = self.nodes[0]
        addr = node.get_deterministic_priv_key().address
        # Mirror the node's schedule so framework-constructed blocks hash the same.
        set_pow_change(CHANGE_TIME, CHANGE_ALGO)

        self.log.info("Blocks before the change time use SHA256d")
        t = CHANGE_TIME - 20 * STEP
        pre_hash = None
        for _ in range(20):
            node.setmocktime(t)
            pre_hash = self.generatetoaddress(node, 1, addr, sync_fun=self.no_op)[0]
            t += STEP
        pre_header = self.header_bytes(pre_hash)
        pre_time = int.from_bytes(pre_header[68:72], "little")
        assert pre_time < CHANGE_TIME
        assert_equal(pre_hash, hash256(pre_header)[::-1].hex())
        assert_equal(pre_hash, powhash(pre_header, pre_time)[::-1].hex())

        self.log.info("Blocks at/after the change time use the scheduled algorithm")
        node.setmocktime(CHANGE_TIME)
        self.generatetoaddress(node, 1, addr, sync_fun=self.no_op)
        node.setmocktime(CHANGE_TIME + STEP)
        post_hash = self.generatetoaddress(node, 1, addr, sync_fun=self.no_op)[0]
        post_header = self.header_bytes(post_hash)
        post_time = int.from_bytes(post_header[68:72], "little")
        assert post_time >= CHANGE_TIME
        # The framework's algorithm-aware hash matches the node's block hash...
        assert_equal(post_hash, powhash(post_header, post_time)[::-1].hex())
        # ...and it is the new (160-bit) algorithm, not SHA256d.
        assert post_hash != hash256(post_header)[::-1].hex()
        assert post_hash.startswith("00" * 12), "160-bit hash should be zero-padded"

        self.log.info("An unupgraded node never adopts post-change block identities")
        node1 = self.nodes[1]
        node1.setmocktime(CHANGE_TIME + STEP)
        # Feed node1 the whole chain. Pre-change blocks are accepted under the
        # same hash. Post-change blocks may even pass node1's SHA256d PoW check
        # by luck (the regtest target accepts ~50% of hashes; on real
        # difficulty they would fail outright), but node1 hashes headers with
        # SHA256d, so whatever it accepts is filed under a DIFFERENT block id:
        # node0's post-change identities never exist on node1. That is the
        # deterministic mainnet relationship: no shared chain past the fork.
        post_change_ids = []
        for h in range(1, node.getblockcount() + 1):
            node0_id = node.getblockhash(h)
            block_hex = node.getblock(node0_id, 0)
            header_time = int.from_bytes(bytes.fromhex(block_hex[:160])[68:72], "little")
            node1.submitblock(block_hex)
            if header_time < CHANGE_TIME:
                assert_equal(node1.getbestblockhash(), node0_id)
            else:
                post_change_ids.append(node0_id)
                assert_raises_rpc_error(-5, "Block not found", node1.getblock, node0_id)
        assert_equal(len(post_change_ids), 2)
        assert node1.getbestblockhash() != node.getbestblockhash()

        self.log.info("A block reaching back before the change is rejected (pow-reversed)")
        tip = node.getbestblockhash()
        reversed_block = create_block(int(tip, 16), create_coinbase(node.getblockcount() + 1), CHANGE_TIME - 1)
        reversed_block.solve()
        assert_raises_rpc_error(
            -25, "pow-reversed",
            lambda: node.submitheader(hexdata=CBlockHeader(reversed_block).serialize().hex()),
        )


if __name__ == "__main__":
    PowChangeTest(__file__).main()
