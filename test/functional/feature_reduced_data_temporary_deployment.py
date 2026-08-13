#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the temporary RDTS flag-day deployment.

RDTS rules apply to blocks whose own nTime lies in [hardforktime, rdtsexpiry).
This branch carries no PoW-change machinery, so a node WITHOUT the flag day
can still follow the chain.

The test uses two nodes:
- Node 0: BIP-110 enforcing (flag day scheduled)
- Node 1: No flag day (simulates Bitcoin Core)

The test verifies:
1. Before the fork time, both nodes accept the same blocks (rules inactive)
2. Consensus rules ARE enforced for blocks with nTime >= fork time (node0 only)
3. Chain split: BIP-110 node rejects invalid blocks, non-BIP-110 accepts
4. Reorg: Longer valid chain wins when nodes reconnect
5. Rules are enforced up to the last pre-expiry block time
6. Rules STOP being enforced at nTime >= expiry; nodes converge again
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    add_witness_commitment,
)
from test_framework.messages import (
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# RDTS flag day. Block times are steered with setmocktime and explicit ntime;
# setup blocks stay below FORK_TIME.
FORK_TIME = 1_500_000_000
EXPIRY_TIME = FORK_TIME + 600_000
START_TIME = FORK_TIME - 10_000
VERSIONBITS_TOP_BITS = 0x20000000
REDUCED_DATA_BIT = 4
# node0 also carries a mandatory-signalling window; its end (150) is crossed
# near the end of the test, so getblocktemplate's height-only advertisement is
# exercised on both edges: inside the window (including post-fork
# over-signalling) and past its end.
SIGNAL_WINDOW_END = 150
RDTS_ARGS = [f'-hardforktime={FORK_TIME}', f'-rdtsexpiry={EXPIRY_TIME}',
             f'-rdtssignalwindow=50:{SIGNAL_WINDOW_END}']


class TemporaryDeploymentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Node 0: RDTS flag day scheduled
        # Node 1: no flag day (simulates Bitcoin Core; regtest default is inactive)
        self.extra_args = [
            RDTS_ARGS + ['-acceptnonstdtxn=1'],
            ['-acceptnonstdtxn=1'],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def set_mocktime(self, t):
        for node in self.nodes:
            node.setmocktime(t)

    def create_block_for_node(self, node, txs=None, ntime=None, time_offset=0):
        """Create a block for a specific node."""
        if txs is None:
            txs = []
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        tip_header = node.getblockheader(tip)
        block_time = (ntime if ntime is not None else tip_header['time'] + 1) + time_offset
        block = create_block(int(tip, 16), create_coinbase(height), ntime=block_time, txlist=txs)
        # Signal the RDTS bit unconditionally: required for pre-fork in-window
        # heights (node0's -rdtssignalwindow), harmless everywhere else.
        block.nVersion = VERSIONBITS_TOP_BITS | (1 << REDUCED_DATA_BIT)
        add_witness_commitment(block)
        block.solve()
        return block

    def mine_blocks_on_node(self, node, count, ntime=None):
        """Mine count blocks on a specific node (only the first uses ntime)."""
        for i in range(count):
            block = self.create_block_for_node(node, ntime=ntime if i == 0 else None)
            node.submitblock(block.serialize().hex())

    def assert_gbt_rdts(self, node, *, signalling, active):
        """Check getblocktemplate's RDTS surface: pre-fork signalling advert
        (vbavailable/vbrequired/version bit) and post-fork rules entry."""
        tmpl = node.getblocktemplate({'rules': ['segwit']})
        assert_equal('reduced_data' in tmpl['rules'], active)
        assert_equal('reduced_data' in tmpl['vbavailable'], signalling)
        assert_equal(bool(tmpl['vbrequired'] & (1 << REDUCED_DATA_BIT)), signalling)
        assert_equal(bool(tmpl['version'] & (1 << REDUCED_DATA_BIT)), signalling)

    def create_tx_with_large_output(self, wallet):
        """Create a transaction with 84-byte OP_RETURN (violates BIP-110's 83-byte limit)."""
        tx_dict = wallet.create_self_transfer()
        tx = tx_dict['tx']
        # 81 bytes data = 84-byte script (OP_RETURN + OP_PUSHDATA1 + len + data)
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b'x' * 81])))
        tx.rehash()
        return tx

    def run_test(self):
        node_bip110 = self.nodes[0]
        node_core = self.nodes[1]

        wallet = MiniWallet(node_bip110)

        # =====================================================================
        # Phase 1: Build common pre-fork chain
        # =====================================================================
        self.log.info("Phase 1: Building common pre-fork chain")

        self.set_mocktime(START_TIME)
        self.log.info("Mining initial blocks for spendable coins...")
        self.generate(wallet, 110)
        self.sync_all()
        assert node_bip110.getblockheader(node_bip110.getbestblockhash())['time'] < FORK_TIME

        # Rules are not enforced pre-fork: both nodes accept a violating block.
        self.log.info("Test: pre-fork, both nodes accept a block violating BIP-110 rules")
        self.disconnect_nodes(0, 1)
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid])
        assert_equal(node_bip110.submitblock(block_invalid.serialize().hex()), None)
        assert_equal(node_core.submitblock(block_invalid.serialize().hex()), None)
        self.connect_nodes(0, 1)
        self.sync_all()

        # GBT pre-fork, in the window: signalling advertised, rules not yet.
        self.assert_gbt_rdts(node_bip110, signalling=True, active=False)

        # =====================================================================
        # Phase 2: Cross the fork; test enforcement and chain split
        # =====================================================================
        self.log.info("Phase 2: Crossing the fork; testing chain split behavior")

        # Regression (halt repro): a parent stamped AHEAD of the clock across
        # the fork boundary must not wedge template creation. With mocktime an
        # hour short of the fork, submit a parent stamped FORK_TIME (legal:
        # within the 2h future allowance). The next template's own curtime is
        # then pre-fork and in-window, so consensus requires bit 4; a producer
        # deciding by the parent's (post-fork) time would omit it and fail its
        # own TestBlockValidity, halting mining until wall clock reaches the
        # fork. Height-only signalling must keep building valid templates.
        self.set_mocktime(FORK_TIME - 3600)
        self.mine_blocks_on_node(node_bip110, 1, ntime=FORK_TIME)
        self.sync_all()
        assert_equal(node_bip110.getblockheader(node_bip110.getbestblockhash())['time'], FORK_TIME)
        # The template still builds (no halt), signals by height, and its own
        # (pre-fork) time keeps the rules entry off.
        self.assert_gbt_rdts(node_bip110, signalling=True, active=False)

        self.set_mocktime(FORK_TIME)
        # After the crossing: signalling is advertised by HEIGHT (still in the
        # window, deliberate over-signalling), while the rules entry follows
        # the template time.
        self.assert_gbt_rdts(node_bip110, signalling=True, active=True)

        # Disconnect nodes BEFORE creating invalid block to prevent P2P relay
        # (Bitcoin Core relays blocks via compact blocks before full validation completes)
        self.log.info("Disconnecting nodes for chain split test...")
        self.disconnect_nodes(0, 1)

        # Create the invalid block (84-byte OP_RETURN violates BIP-110's 83-byte limit)
        self.log.info("Test: BIP-110 node rejects block with 84-byte OP_RETURN output")
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid])

        # Submit to BIP-110 node - should be rejected
        split_base_height = node_bip110.getblockcount()
        result_bip110 = node_bip110.submitblock(block_invalid.serialize().hex())
        assert_equal(result_bip110, 'bad-txns-vout-script-toolarge')
        assert_equal(node_bip110.getblockcount(), split_base_height)

        # Submit to non-BIP-110 node - should be accepted
        self.log.info("Test: Non-BIP-110 node accepts the same block")
        result_core = node_core.submitblock(block_invalid.serialize().hex())
        assert_equal(result_core, None)
        assert_equal(node_core.getblockcount(), split_base_height + 1)

        # Chain split confirmed
        self.log.info(f"Chain split: BIP-110={node_bip110.getblockcount()}, Core={node_core.getblockcount()}")

        # =====================================================================
        # Phase 3: Test reorg behavior
        # =====================================================================
        # NOTE: this phase models SOFTFORK dynamics (possible here because this
        # branch carries no PoW-change machinery): the non-enforcing node accepts
        # both chains and reorgs onto the enforcing chain when it has more work,
        # wiping out the violating block. On mainnet, with a real algorithm
        # change, a no-flag-day node cannot validate post-fork blocks at all
        # and no such reorg exists. What this phase pins is (a) RDTS rules stay
        # forward-compatible (valid-under-RDTS implies valid-without), and
        # (b) convergence among mixed-enforcement nodes on the same PoW.
        self.log.info("Phase 3: Testing reorg behavior (softfork wipeout dynamics)")

        # Non-BIP-110 extends its chain
        self.log.info("Non-BIP-110 node extends chain with 3 more blocks...")
        for i in range(3):
            block = self.create_block_for_node(node_core, time_offset=i)
            node_core.submitblock(block.serialize().hex())
        assert_equal(node_core.getblockcount(), split_base_height + 4)

        # BIP-110 node builds longer valid chain
        self.log.info("BIP-110 node builds longer valid chain (5 blocks)...")
        for i in range(5):
            block = self.create_block_for_node(node_bip110, time_offset=i + 10)
            node_bip110.submitblock(block.serialize().hex())
        assert_equal(node_bip110.getblockcount(), split_base_height + 5)

        # Reconnect - non-BIP-110 should reorg to BIP-110's chain
        self.log.info("Reconnecting nodes - expecting reorg...")
        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert_equal(node_core.getbestblockhash(), node_bip110.getbestblockhash())
        self.log.info(f"Reorg complete: both nodes at height {node_core.getblockcount()}")

        # =====================================================================
        # Phase 4: Test rules enforced until expiry
        # =====================================================================
        self.log.info("Phase 4: Testing rules enforced up to the expiry boundary")

        self.set_mocktime(EXPIRY_TIME)
        self.mine_blocks_on_node(node_bip110, 1, ntime=EXPIRY_TIME - 2)
        self.sync_all()

        # Disconnect nodes to prevent compact block relay of invalid block
        self.disconnect_nodes(0, 1)

        # Verify rules still enforced at nTime EXPIRY_TIME - 1 (last active time)
        self.log.info("Test: Rules still enforced at nTime EXPIRY_TIME - 1")
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid], ntime=EXPIRY_TIME - 1)
        result = node_bip110.submitblock(block_invalid.serialize().hex())
        assert_equal(result, 'bad-txns-vout-script-toolarge')

        # Mine a valid block at the last active time instead
        block_valid = self.create_block_for_node(node_bip110, ntime=EXPIRY_TIME - 1)
        assert_equal(node_bip110.submitblock(block_valid.serialize().hex()), None)

        # Reconnect and sync
        self.connect_nodes(0, 1)
        self.sync_all()

        # =====================================================================
        # Phase 5: Test expiry - rules no longer enforced
        # =====================================================================
        self.log.info("Phase 5: Testing expiry - rules no longer enforced")

        self.log.info("Test: BIP-110 node accepts 'invalid' block at nTime EXPIRY_TIME")
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_after_expiry = self.create_block_for_node(node_bip110, [tx_invalid], ntime=EXPIRY_TIME)
        result = node_bip110.submitblock(block_after_expiry.serialize().hex())
        assert_equal(result, None)
        self.sync_all()

        # =====================================================================
        # Phase 6: Test post-expiry convergence
        # =====================================================================
        self.log.info("Phase 6: Testing post-expiry convergence")

        # Both nodes should accept the same "invalid" blocks now
        self.log.info("Test: Both nodes accept 'invalid' blocks after expiry")
        for i in range(5):
            tx = self.create_tx_with_large_output(wallet)
            block = self.create_block_for_node(node_bip110, [tx], time_offset=i)
            result_bip110 = node_bip110.submitblock(block.serialize().hex())
            assert_equal(result_bip110, None)
            self.sync_all()
            assert_equal(node_core.getbestblockhash(), node_bip110.getbestblockhash())

        final_height = node_bip110.getblockcount()
        self.log.info(f"Final height: {final_height}, both nodes synced")

        # GBT post-expiry: no rules entry; signalling still advertised because
        # the height is inside the window (height-only, deliberate).
        assert node_bip110.getblockcount() + 1 < SIGNAL_WINDOW_END
        self.assert_gbt_rdts(node_bip110, signalling=True, active=False)

        # Past the window's end, the signalling advertisement stops too.
        while node_bip110.getblockcount() + 1 < SIGNAL_WINDOW_END:
            self.mine_blocks_on_node(node_bip110, 1)
        self.sync_all()
        self.assert_gbt_rdts(node_bip110, signalling=False, active=False)

        # =====================================================================
        # Summary
        # =====================================================================
        self.log.info("All tests passed:")
        self.log.info("  - Rules inactive pre-fork (both nodes accept violating block)")
        self.log.info("  - Chain split at the fork time (BIP-110 rejects, Core accepts)")
        self.log.info("  - Reorg to longer valid chain on reconnect")
        self.log.info("  - Rules enforced for block times in [fork, expiry)")
        self.log.info("  - Rules not enforced at nTime >= expiry")
        self.log.info("  - Post-expiry convergence (both nodes accept same blocks)")


if __name__ == '__main__':
    TemporaryDeploymentTest(__file__).main()
