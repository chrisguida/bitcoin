#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test REDUCED_DATA flag-day UTXO grandfathering.

RDTS activates for blocks whose own nTime lies in [powchangetime, rdtsexpiry).
Inputs spending coins created by PRE-FORK blocks (creating block's nTime before
the fork) are exempt from reduced_data script validation rules, as implemented
in validation.cpp (per-input GetAncestor time check).

Test scenarios:
1. Old UTXO (created pre-fork) spent post-fork with violation - ACCEPTED (EXEMPT)
2. New UTXO (created post-fork) spent with violation - REJECTED
3. Mixed inputs (old + new UTXOs) in same transaction - REJECTED
4. Boundary: coin created at nTime == fork time - 1 is exempt; at fork time is not
5. Reorg across the fork boundary: the same coin is judged per-branch, and the
   script-execution cache must not leak a verdict between branches
"""

from io import BytesIO

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
    add_witness_commitment,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_TRUE,
    OP_DROP,
)
from test_framework.script_util import (
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import MiniWallet


# RDTS flag day. Algo 1 (SHA256d) keeps the PoW side of the hardfork inert;
# only the RDTS rules flip at FORK_TIME. Effectively-permanent expiry.
FORK_TIME = 1_500_000_000
EXPIRY_TIME = 9_999_999_999
# Setup blocks are mined at this mocktime. MTP creep (+1/block once block times
# stall at the mocktime) stays far below FORK_TIME for the block counts here.
START_TIME = FORK_TIME - 10_000
RDTS_ARGS = [f'-powchangetime={FORK_TIME}:1', f'-rdtsexpiry={EXPIRY_TIME}']

# REDUCED_DATA enforces MAX_SCRIPT_ELEMENT_SIZE_REDUCED (256) instead of MAX_SCRIPT_ELEMENT_SIZE (520)
MAX_ELEMENT_SIZE_STANDARD = 520
MAX_ELEMENT_SIZE_REDUCED = 256
VIOLATION_SIZE = 300  # Violates reduced (256) but OK for standard (520)


class ReducedDataUTXOHeightTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [RDTS_ARGS]

    def create_p2wsh_funding_and_spending_tx(self, wallet, node, witness_element_size):
        """Create a P2WSH output, then a transaction spending it with custom witness size.

        Returns:
            tuple: (funding_tx, spending_tx) where funding_tx creates P2WSH output,
                   spending_tx spends it with witness element of specified size
        """
        # Create a simple witness script: <data> OP_DROP OP_TRUE
        # This allows us to put arbitrary data in the witness
        witness_script = CScript([OP_DROP, OP_TRUE])
        script_pubkey = script_to_p2wsh_script(witness_script)

        # Use MiniWallet to create funding transaction to P2WSH output
        funding_txid = wallet.send_to(from_node=node, scriptPubKey=script_pubkey, amount=100000)['txid']
        funding_tx_hex = node.getrawtransaction(funding_txid)
        funding_tx = CTransaction()
        funding_tx.deserialize(BytesIO(bytes.fromhex(funding_tx_hex)))
        funding_tx.rehash()  # Calculate sha256 hash after deserializing

        # Find the P2WSH output
        p2wsh_vout = None
        for i, vout in enumerate(funding_tx.vout):
            if vout.scriptPubKey == script_pubkey:
                p2wsh_vout = i
                break
        assert p2wsh_vout is not None, "P2WSH output not found"

        # Spending transaction: spend P2WSH output with custom witness
        spending_tx = CTransaction()
        spending_tx.vin = [CTxIn(COutPoint(funding_tx.sha256, p2wsh_vout))]
        spending_tx.vout = [CTxOut(funding_tx.vout[p2wsh_vout].nValue - 1000, CScript([OP_TRUE]))]

        # Create witness with element of specified size
        spending_tx.wit.vtxinwit.append(CTxInWitness())
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = [
            b'\x42' * witness_element_size,  # Data element of specified size
            witness_script  # Witness script
        ]
        spending_tx.rehash()

        return funding_tx, spending_tx

    def create_test_block(self, txs, *, ntime=None):
        """Create a block with the given transactions.

        ntime pins the block's timestamp; default is tip time + 1, which stays
        on the tip's side of the fork boundary."""
        # Always get fresh tip and height to ensure blocks chain correctly
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount() + 1
        tip_header = self.nodes[0].getblockheader(tip)
        block_time = ntime if ntime is not None else tip_header['time'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), ntime=block_time, txlist=txs)
        add_witness_commitment(block)
        block.solve()
        return block

    def mine_blocks(self, count, *, ntime=None):
        """Mine empty blocks (only the first uses ntime; the rest follow the tip)."""
        for i in range(count):
            block = self.create_test_block([], ntime=ntime if i == 0 else None)
            result = self.nodes[0].submitblock(block.serialize().hex())
            if result is not None:
                raise AssertionError(f"submitblock failed: {result}")
            # Verify block was accepted
            assert self.nodes[0].getbestblockhash() == block.hash

    def run_test(self):
        node = self.nodes[0]

        # Use MiniWallet for easy UTXO management
        wallet = MiniWallet(node)

        # All setup blocks are pre-fork: their nTime is START_TIME (< FORK_TIME).
        node.setmocktime(START_TIME)
        self.log.info(f"Mining pre-fork setup blocks at mocktime {START_TIME}...")
        self.generate(wallet, COINBASE_MATURITY + 30)
        assert node.getblockheader(node.getbestblockhash())['time'] < FORK_TIME

        # ======================================================================
        # Test 1: Create OLD UTXO before the fork
        # ======================================================================
        self.log.info("Test 1: Creating P2WSH UTXO before the fork time...")

        old_funding_tx, old_spending_tx = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        block = self.create_test_block([old_funding_tx])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        old_utxo_time = node.getblockheader(node.getbestblockhash())['time']
        assert old_utxo_time < FORK_TIME
        self.log.info(f"Created old P2WSH UTXO in block with nTime {old_utxo_time} (< {FORK_TIME})")

        # ======================================================================
        # Test 2: Cross the fork
        # ======================================================================
        self.log.info("Test 2: Mining the fork block (nTime == FORK_TIME)...")
        node.setmocktime(FORK_TIME)
        self.mine_blocks(1, ntime=FORK_TIME)
        assert_equal(node.getblockheader(node.getbestblockhash())['time'], FORK_TIME)

        # ======================================================================
        # Test 3: Create NEW UTXO after the fork
        # ======================================================================
        self.log.info("Test 3: Creating P2WSH UTXO after the fork...")

        new_funding_tx, new_spending_tx = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        block = self.create_test_block([new_funding_tx])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        new_utxo_time = node.getblockheader(node.getbestblockhash())['time']
        assert new_utxo_time >= FORK_TIME
        self.log.info(f"Created new P2WSH UTXO in block with nTime {new_utxo_time} (>= {FORK_TIME})")

        # Mine a few more blocks
        self.mine_blocks(5)

        # ======================================================================
        # Test 4: Spend OLD UTXO with oversized witness - should be ACCEPTED
        # ======================================================================
        self.log.info(f"Test 4: Spending old (pre-fork) UTXO with {VIOLATION_SIZE}-byte witness element...")
        self.log.info(f"        This violates REDUCED_DATA ({MAX_ELEMENT_SIZE_REDUCED} limit) but pre-fork coins are EXEMPT")

        block = self.create_test_block([old_spending_tx])
        result = node.submitblock(block.serialize().hex())
        assert result is None, f"Expected success, got: {result}"

        self.log.info(f"✓ SUCCESS: Pre-fork UTXO with {VIOLATION_SIZE}-byte witness element was ACCEPTED (correctly exempt)")

        # ======================================================================
        # Test 5: Spend NEW UTXO with oversized witness - should be REJECTED
        # ======================================================================
        self.log.info(f"Test 5: Spending new (post-fork) UTXO with {VIOLATION_SIZE}-byte witness element...")

        block = self.create_test_block([new_spending_tx])
        result = node.submitblock(block.serialize().hex())
        assert result is not None and 'mandatory-script-verify-flag-failed' in result, f"Expected rejection, got: {result}"

        self.log.info(f"✓ SUCCESS: Post-fork UTXO with {VIOLATION_SIZE}-byte witness element was REJECTED (correctly enforced)")

        def rewind_to(height):
            # Height-based loop: invalidating one tip can switch to an alternate branch at same height.
            while node.getblockcount() > height:
                node.invalidateblock(node.getbestblockhash())
            assert_equal(node.getblockcount(), height)

        # ======================================================================
        # Test 6: Boundary - the exemption pins to nTime < FORK_TIME exactly
        # ======================================================================
        self.log.info("Test 6: Boundary test - coins created at FORK_TIME - 1 vs FORK_TIME...")

        post_fork_tip = node.getbestblockhash()
        pre_fork_height = COINBASE_MATURITY + 31  # last setup block + test-1 funding block
        rewind_to(pre_fork_height)
        assert node.getblockheader(node.getbestblockhash())['time'] < FORK_TIME

        # Coin created in the LAST possible pre-fork block (nTime == FORK_TIME - 1).
        last_funding_tx, last_spending_tx = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        block = self.create_test_block([last_funding_tx], ntime=FORK_TIME - 1)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        # Cross the fork, then spend it: exempt.
        self.mine_blocks(1, ntime=FORK_TIME)
        block = self.create_test_block([last_spending_tx])
        result = node.submitblock(block.serialize().hex())
        assert result is None, f"Expected success for FORK_TIME - 1 coin, got: {result}"
        self.log.info("        ✓ Coin created at nTime FORK_TIME - 1 is EXEMPT")

        rewind_to(pre_fork_height)
        # The same coin created in the FIRST post-fork block (nTime == FORK_TIME): subject.
        boundary_funding_tx, boundary_spending_tx = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        block = self.create_test_block([boundary_funding_tx], ntime=FORK_TIME)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        self.mine_blocks(2)
        block = self.create_test_block([boundary_spending_tx])
        result = node.submitblock(block.serialize().hex())
        assert result is not None and 'mandatory-script-verify-flag-failed' in result, f"Expected rejection, got: {result}"
        self.log.info("        ✓ Coin created at nTime FORK_TIME is SUBJECT to rules (boundary is >=, not >)")

        # Restore the main chain.
        node.reconsiderblock(post_fork_tip)

        # ======================================================================
        # Test 7: Mixed inputs - one old (exempt) + one new (subject to rules)
        # ======================================================================
        self.log.info("Test 7: Creating transaction with mixed inputs (pre-fork + post-fork UTXOs)...")

        current_tip2 = node.getbestblockhash()
        rewind_to(pre_fork_height)

        # Create OLD UTXO pre-fork
        old_mixed_funding, _old_mixed_spending = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        block = self.create_test_block([old_mixed_funding])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        old_mixed_time = node.getblockheader(node.getbestblockhash())['time']

        # Cross the fork and create NEW UTXO post-fork
        self.mine_blocks(1, ntime=FORK_TIME)
        new_mixed_funding, _new_mixed_spending = self.create_p2wsh_funding_and_spending_tx(
            wallet, node, VIOLATION_SIZE
        )
        block = self.create_test_block([new_mixed_funding])
        assert_equal(node.submitblock(block.serialize().hex()), None)
        new_mixed_time = node.getblockheader(node.getbestblockhash())['time']

        # Find P2WSH outputs in funding transactions
        witness_script = CScript([OP_DROP, OP_TRUE])
        script_pubkey = script_to_p2wsh_script(witness_script)

        old_p2wsh_vout = None
        for i, vout in enumerate(old_mixed_funding.vout):
            if vout.scriptPubKey == script_pubkey:
                old_p2wsh_vout = i
                break

        new_p2wsh_vout = None
        for i, vout in enumerate(new_mixed_funding.vout):
            if vout.scriptPubKey == script_pubkey:
                new_p2wsh_vout = i
                break

        # Create transaction with BOTH inputs
        mixed_tx = CTransaction()
        mixed_tx.vin = [
            CTxIn(COutPoint(old_mixed_funding.sha256, old_p2wsh_vout)),  # Old UTXO (exempt)
            CTxIn(COutPoint(new_mixed_funding.sha256, new_p2wsh_vout)),  # New UTXO (subject to rules)
        ]
        total_value = (old_mixed_funding.vout[old_p2wsh_vout].nValue +
                      new_mixed_funding.vout[new_p2wsh_vout].nValue - 2000)
        mixed_tx.vout = [CTxOut(total_value, CScript([OP_TRUE]))]

        # Add witness for both inputs - both with 300-byte elements
        mixed_tx.wit.vtxinwit = []

        # Input 0: old UTXO (would pass alone)
        wit0 = CTxInWitness()
        wit0.scriptWitness.stack = [b'\x42' * VIOLATION_SIZE, witness_script]
        mixed_tx.wit.vtxinwit.append(wit0)

        # Input 1: new UTXO (would fail)
        wit1 = CTxInWitness()
        wit1.scriptWitness.stack = [b'\x42' * VIOLATION_SIZE, witness_script]
        mixed_tx.wit.vtxinwit.append(wit1)

        mixed_tx.rehash()

        self.log.info(f"        Mixed tx: old UTXO (nTime {old_mixed_time}, exempt) + new UTXO (nTime {new_mixed_time}, subject)")
        self.log.info(f"        Both inputs have {VIOLATION_SIZE}-byte witness elements")

        # Try to mine block - should REJECT because new input violates
        self.mine_blocks(2)
        block = self.create_test_block([mixed_tx])
        result = node.submitblock(block.serialize().hex())
        assert result is not None and 'mandatory-script-verify-flag-failed' in result, f"Expected rejection, got: {result}"

        self.log.info("✓ SUCCESS: Mixed transaction REJECTED (new input violated rules, even though old input was exempt)")

        # Restore chain
        node.reconsiderblock(current_tip2)

        # ======================================================================
        # Test 8: reorg across the fork boundary - per-branch verdicts, no
        # script-execution cache leakage between branches
        # ======================================================================
        self.log.info("Test 8: same coin judged per-branch across a fork-boundary reorg")

        rewind_to(pre_fork_height)

        # spend_tx has a 300-byte witness element: valid only via the pre-fork exemption.
        funding_tx, spend_tx = self.create_p2wsh_funding_and_spending_tx(wallet, node, VIOLATION_SIZE)

        # Branch A: funding block is the last pre-fork block (exempt coin).
        block = self.create_test_block([funding_tx], ntime=FORK_TIME - 1)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        branch_height = node.getblockcount()

        self.restart_node(0, extra_args=RDTS_ARGS + ['-par=1'])  # Single-threaded validation to maximize chance of hitting cache-related issues.
        node.setmocktime(FORK_TIME + 100)

        # Validate-only block on top (post-fork context). This calls
        # TestBlockValidity(fJustCheck=true): the spend passes only via the
        # per-input exemption, and must not poison the tx-wide script cache.
        self.generateblock(node, output=wallet.get_address(), transactions=[spend_tx.serialize().hex()], submit=False, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), branch_height)

        # Reorg to the branch point; cache state is intentionally retained.
        rewind_to(pre_fork_height)

        # Branch B: the SAME funding tx at the SAME height, but the block's
        # nTime is FORK_TIME: on this branch the coin is post-fork.
        block = self.create_test_block([funding_tx], ntime=FORK_TIME)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getblockcount(), branch_height)

        # The same spend is now non-exempt and must be rejected.
        attack_block = self.create_test_block([spend_tx])
        result = node.submitblock(attack_block.serialize().hex())
        assert result is not None and 'Push value size limit exceeded' in result, \
            f"Expected rejection after boundary-crossing reorg, got: {result}"

        self.log.info("✓ SUCCESS: Per-branch fork-boundary verdicts enforced; no cache poisoning")

        # ======================================================================
        # Test 9: -reindex replays the whole chain, including grandfathered
        # spends, to the same tip (the stateless cutoff needs no stored state)
        # ======================================================================
        self.log.info("Test 9: -reindex reproduces identical grandfathering verdicts")
        node.reconsiderblock(post_fork_tip)
        tip_before_reindex = node.getbestblockhash()
        self.restart_node(0, extra_args=RDTS_ARGS + ['-reindex'])
        self.wait_until(lambda: node.getbestblockhash() == tip_before_reindex, timeout=60)
        self.log.info("✓ SUCCESS: -reindex reconnected the chain with exempt spends intact")

        # ======================================================================
        # Summary
        # ======================================================================
        self.log.info(f"""
        ============================================================
        TEST SUMMARY - Flag-Day REDUCED_DATA Grandfathering
        ============================================================

        ✓ Test 1-3: Pre-fork and post-fork P2WSH UTXOs created
        ✓ Test 4: Pre-fork coin is EXEMPT - 300-byte witness ACCEPTED
        ✓ Test 5: Post-fork coin is SUBJECT - 300-byte witness REJECTED
        ✓ Test 6: Boundary pins to the creating block's nTime:
                  FORK_TIME - 1 exempt, FORK_TIME subject (>= not >)
        ✓ Test 7: Mixed inputs - transaction rejected if ANY input violates
        ✓ Test 8: Same coin, same height, different branch times:
                  per-branch verdicts, no cache poisoning across the reorg

        Key validations:
        • RDTS active for blocks with nTime in [powchangetime, rdtsexpiry)
        • Coins created by pre-fork blocks are EXEMPT from rules
        • Coins created by post-fork blocks are SUBJECT to rules
        • Per-input validation flags work correctly (validation.cpp)
        • Exemption derives from the creating block on THIS branch

        All 8 tests passed!
        ============================================================
        """)


if __name__ == '__main__':
    ReducedDataUTXOHeightTest(__file__).main()
