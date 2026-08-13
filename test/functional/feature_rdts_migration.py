#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license.
"""BIP110/RDTS: at startup, an enforcing node corrects chain state inherited
from a client that was not enforcing RDTS.

A data directory advanced by a non-enforcing client can contain blocks that
violate RDTS mandatory signaling. Normal startup does not re-validate inherited
history, so the enforcing node corrects it: every offending block in the index
(active chain or side branch) is marked invalid and the node reorganizes to the
best valid chain, mirroring BIP148.

The mandatory-signaling window is set via -rdtssignalwindow (heights [288, 432)
on regtest here). Blocks in the window whose nTime precedes the fork time
(-hardforktime) must signal; the fork itself ends the requirement.

Cases:
  A_ACTIVE     inherited non-signaling block on the ACTIVE chain -> auto-reorg to
               the last valid ancestor at startup (no operator command), block
               marked invalid, and the correction persists across a restart.
  A_NONACTIVE  a non-signaling block on a NON-active side branch -> marked invalid
               at startup while the (valid) active chain is left untouched.
  A_CLEAN      a fully-signaling chain -> untouched (no false-positive destruction).
  A_BOUNDARY   non-signaling only just OUTSIDE the window (287, 432) -> untouched.
  A_POSTFORK   the fork lands INSIDE the window: post-fork in-window blocks are
               signaling-exempt and untouched.
"""
from test_framework.blocktools import TIME_GENESIS_BLOCK, create_block, create_coinbase, add_witness_commitment
from test_framework.script import CScript, OP_RETURN, OP_NOP
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal

VERSIONBITS_TOP_BITS = 0x20000000
REDUCED_DATA_BIT = 4
# Fork far in the future: every block in these chains is pre-fork, so the
# window applies by height alone. Block times here are genesis + height
# (each block is parent time + 1).
FAR_FORK = 9_000_000_000
RDTS_ENFORCE = [f'-hardforktime={FAR_FORK}', '-rdtssignalwindow=288:432']
WINDOW_START = 288
WINDOW_END = 431    # last in-window height (the option's end bound is exclusive)
CHAIN_TIP = 440

# A_POSTFORK: fork time inside the window. Block h has nTime genesis + h, so
# heights 288..299 are pre-fork (must signal) and 300..431 post-fork (exempt).
POSTFORK_CROSS_HEIGHT = 300
RDTS_POSTFORK = [f'-hardforktime={TIME_GENESIS_BLOCK + POSTFORK_CROSS_HEIGHT}',
                 '-rdtssignalwindow=288:432']

# The pruned case needs the violator >= MIN_BLOCKS_TO_KEEP (288) below the tip.
# A lower window ([144, 288)) keeps that chain as short as possible while
# staying clear of genesis.
RDTS_PRUNE = [f'-hardforktime={FAR_FORK}', '-rdtssignalwindow=144:288']
PRUNE_VIOLATOR = 144
PRUNE_TIP = 432        # violator + MIN_BLOCKS_TO_KEEP
# A ~64kiB coinbase so each block fills a -fastprune block file (64kiB), making
# the violator's file independently prunable.
BIG_SCRIPT = CScript([OP_RETURN] + [OP_NOP] * 70000)


class RdtsMigrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 8
        self.setup_clean_chain = True
        # node0 clean-enforcing; node1/2/3 non-enforcing builders; node4 enforcing
        # with the fork inside the window (time-clause oracle); node5 non-enforcing
        # (multi-branch); node6 pruned; node7 non-enforcing builder for the
        # -reindex-chainstate recovery path.
        self.extra_args = [RDTS_ENFORCE, [], [], [], RDTS_POSTFORK, [], ['-prune=1', '-fastprune'], []]

    def setup_network(self):
        self.setup_nodes()  # driven directly, no connections

    # ---- block helpers -------------------------------------------------

    def make_block(self, node, parent_hash, parent_time, height, signal):
        block = create_block(int(parent_hash, 16), create_coinbase(height), ntime=parent_time + 1)
        block.nVersion = VERSIONBITS_TOP_BITS | ((1 << REDUCED_DATA_BIT) if signal else 0)
        add_witness_commitment(block)
        block.solve()
        return block

    def submit_tip(self, node, signal):
        """Extend the node's active tip by one block."""
        tip = node.getbestblockhash()
        blk = self.make_block(node, tip, node.getblockheader(tip)['time'], node.getblockcount() + 1, signal)
        assert_equal(node.submitblock(blk.serialize().hex()), None)
        return blk

    def mine_to(self, node, target, signal):
        while node.getblockcount() < target:
            self.submit_tip(node, signal)

    def build_bad_active_chain(self, node):
        """Non-signaling in-window block at WINDOW_START on the active chain."""
        self.mine_to(node, WINDOW_START - 1, signal=False)
        bad = self.submit_tip(node, signal=False)   # height WINDOW_START, violator
        assert_equal(node.getblockcount(), WINDOW_START)
        self.mine_to(node, CHAIN_TIP, signal=False)
        return bad

    def submit_big_tip(self, node, signal):
        """Extend the tip with a ~64kiB block (fills one -fastprune block file)."""
        tip = node.getbestblockhash()
        cb = create_coinbase(node.getblockcount() + 1, script_pubkey=BIG_SCRIPT)
        block = create_block(int(tip, 16), cb, ntime=node.getblockheader(tip)['time'] + 1)
        block.nVersion = VERSIONBITS_TOP_BITS | ((1 << REDUCED_DATA_BIT) if signal else 0)
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)

    def restart(self, i, extra):
        self.stop_node(i)
        self.start_node(i, extra_args=extra)
        return self.nodes[i]

    def chaintip_status(self, node, block_hash):
        for t in node.getchaintips():
            if t['hash'] == block_hash:
                return t['status']
        return None

    # ---- test ----------------------------------------------------------

    def run_test(self):
        n_clean, n_active, n_nonactive, n_bound, n_lockin, n_multi, n_prune, n_rc = self.nodes

        # A_CLEAN: fully-signaling chain must be left untouched.
        self.log.info("A_CLEAN: enforcing node with a fully-signaling chain is untouched")
        self.mine_to(n_clean, WINDOW_START - 1, signal=False)
        self.mine_to(n_clean, WINDOW_END, signal=True)
        self.mine_to(n_clean, CHAIN_TIP, signal=False)
        tip_before = n_clean.getbestblockhash()
        n_clean = self.restart(0, RDTS_ENFORCE)
        assert_equal(n_clean.getbestblockhash(), tip_before)
        assert_equal(n_clean.getblockcount(), CHAIN_TIP)
        self.log.info("  A_CLEAN CONFIRMED: valid chain not disturbed")

        # A_ACTIVE: inherited non-signaling block on the active chain -> auto-reorg.
        # Also plant a violator on a non-active side branch, so a SINGLE correction
        # pass has to handle both an active-chain reorg and a side-branch mark in one
        # go (mixed case).
        self.log.info("A_ACTIVE: inherited active-chain violator (+ a non-active one) auto-corrected")
        bad = self.build_bad_active_chain(n_active)
        old_tip = n_active.getbestblockhash()             # height CHAIN_TIP, the invalid branch tip
        assert_equal(old_tip, n_active.getblockhash(CHAIN_TIP))
        # Non-active side violator off a pre-window ancestor (lower work than main).
        s_hash = n_active.getblockhash(WINDOW_START - 2)
        s_t = n_active.getblockheader(s_hash)['time']
        s287 = self.make_block(n_active, s_hash, s_t + 100, WINDOW_START - 1, signal=False)
        assert n_active.submitblock(s287.serialize().hex()) in (None, "inconclusive")
        side_bad = self.make_block(n_active, s287.hash, s287.nTime, WINDOW_START, signal=False)
        assert n_active.submitblock(side_bad.serialize().hex()) in (None, "inconclusive")
        assert_equal(n_active.getbestblockhash(), old_tip)                 # still on the active (invalid) tip
        n_active = self.restart(1, RDTS_ENFORCE)          # enforcing, no manual command
        assert_equal(n_active.getblockcount(), WINDOW_START - 1)
        assert_equal(n_active.getbestblockhash(), n_active.getblockhash(WINDOW_START - 1))
        assert_equal(self.chaintip_status(n_active, old_tip), 'invalid')   # active branch invalidated
        assert n_active.getblock(bad.hash)['confirmations'] < 0            # active violator off the chain
        assert_equal(self.chaintip_status(n_active, side_bad.hash), 'invalid')  # non-active violator too
        self.log.info(f"  auto-reorged to height {n_active.getblockcount()}; active and non-active "
                      f"violators both invalidated in one pass")
        # persists across another restart
        n_active = self.restart(1, RDTS_ENFORCE)
        assert_equal(n_active.getblockcount(), WINDOW_START - 1)
        assert_equal(self.chaintip_status(n_active, old_tip), 'invalid')
        self.log.info("  A_ACTIVE CONFIRMED: correction persists across restart (idempotent)")

        # A_NONACTIVE: a violator on a lower-work side branch is invalidated,
        # while the valid active chain is untouched. This is the "non-active
        # blocks too" requirement.
        self.log.info("A_NONACTIVE: violator on a non-active side branch is marked invalid")
        # Valid, most-work main chain.
        self.mine_to(n_nonactive, WINDOW_START - 1, signal=False)
        self.mine_to(n_nonactive, WINDOW_END, signal=True)
        self.mine_to(n_nonactive, CHAIN_TIP, signal=False)
        main_tip = n_nonactive.getbestblockhash()
        # Side branch off a pre-window ancestor, ending in a non-signaling
        # in-window block. Far less work than main -> never active.
        fork_h = WINDOW_START - 2
        fork_hash = n_nonactive.getblockhash(fork_h)
        fork_time = n_nonactive.getblockheader(fork_hash)['time']
        # Offset the timestamp so the side branch differs from the identical-height
        # main-chain block (same parent/height/coinbase would otherwise collide).
        side287 = self.make_block(n_nonactive, fork_hash, fork_time + 100, fork_h + 1, signal=False)
        # "inconclusive" == accepted as a valid lower-work fork, not the active tip.
        assert n_nonactive.submitblock(side287.serialize().hex()) in (None, "inconclusive")
        side_bad = self.make_block(n_nonactive, side287.hash, side287.nTime, fork_h + 2, signal=False)
        assert n_nonactive.submitblock(side_bad.serialize().hex()) in (None, "inconclusive")  # height WINDOW_START, non-active
        assert_equal(n_nonactive.getbestblockhash(), main_tip)  # still on main
        assert_equal(self.chaintip_status(n_nonactive, side_bad.hash), 'valid-headers')
        n_nonactive = self.restart(2, RDTS_ENFORCE)
        assert_equal(n_nonactive.getbestblockhash(), main_tip)                    # main untouched
        assert_equal(n_nonactive.getblockcount(), CHAIN_TIP)
        assert_equal(self.chaintip_status(n_nonactive, side_bad.hash), 'invalid') # side branch corrected
        self.log.info("  A_NONACTIVE CONFIRMED: non-active violator invalidated, valid active chain kept")

        # A_BOUNDARY: non-signaling only just outside the window -> untouched.
        self.log.info("A_BOUNDARY: non-signaling only at 287/432 (outside window) is untouched")
        self.mine_to(n_bound, WINDOW_START - 2, signal=False)
        self.submit_tip(n_bound, signal=False)             # 287 outside
        self.mine_to(n_bound, WINDOW_END, signal=True)     # 288..431 signal
        self.submit_tip(n_bound, signal=False)             # 432 outside
        self.mine_to(n_bound, CHAIN_TIP, signal=False)
        bound_tip = n_bound.getbestblockhash()
        n_bound = self.restart(3, RDTS_ENFORCE)
        assert_equal(n_bound.getbestblockhash(), bound_tip)
        assert_equal(n_bound.getblockcount(), CHAIN_TIP)
        self.log.info("  A_BOUNDARY CONFIRMED: out-of-window blocks not corrected")

        # A_POSTFORK: the fork time lands inside the window (block times are
        # genesis + height, and node4's -hardforktime crosses at height 300).
        # Pre-fork in-window blocks (288..299) must signal; post-fork in-window
        # blocks (300..431) are exempt via RdtsMustSignalAt's time clause. Built
        # on an ENFORCING node, so its acceptance defines what is legal.
        self.log.info("A_POSTFORK: post-fork in-window blocks are signaling-exempt and untouched")
        self.mine_to(n_lockin, WINDOW_START - 1, signal=False)                 # ..287
        self.mine_to(n_lockin, POSTFORK_CROSS_HEIGHT - 2, signal=True)         # 288..298 must signal
        # A non-signaling block at the LAST pre-fork in-window height (299,
        # nTime genesis+299 < fork) is still invalid.
        tip = n_lockin.getbestblockhash()
        pre_fork_bad = self.make_block(n_lockin, tip, n_lockin.getblockheader(tip)['time'],
                                       n_lockin.getblockcount() + 1, signal=False)
        assert n_lockin.submitblock(pre_fork_bad.serialize().hex()) is not None
        self.submit_tip(n_lockin, signal=True)                                 # 299, signalling, valid
        exempt = 0
        while n_lockin.getblockcount() < WINDOW_END:
            tip = n_lockin.getbestblockhash()
            blk = self.make_block(n_lockin, tip, n_lockin.getblockheader(tip)['time'],
                                  n_lockin.getblockcount() + 1, signal=False)
            if n_lockin.submitblock(blk.serialize().hex()) is None:
                exempt += 1                              # accepted while non-signaling => post-fork exempt
            else:
                self.submit_tip(n_lockin, signal=True)   # still pre-fork at this height
        assert exempt > 0, "expected post-fork in-window blocks to be signaling-exempt"
        self.mine_to(n_lockin, CHAIN_TIP, signal=False)
        lockin_tip = n_lockin.getbestblockhash()
        n_lockin = self.restart(4, RDTS_POSTFORK)
        assert_equal(n_lockin.getbestblockhash(), lockin_tip)
        assert_equal(n_lockin.getblockcount(), CHAIN_TIP)
        self.log.info(f"  A_POSTFORK CONFIRMED: {exempt} exempt post-fork non-signaling blocks left intact")

        # A_MULTI: two independent non-active violating branches on one node must
        # BOTH be invalidated -- this exercises the multi-pass correction loop.
        self.log.info("A_MULTI: two non-active violating branches -> both invalidated (multi-pass)")
        self.mine_to(n_multi, WINDOW_START - 1, signal=False)
        self.mine_to(n_multi, WINDOW_END, signal=True)
        self.mine_to(n_multi, CHAIN_TIP, signal=False)
        main_tip2 = n_multi.getbestblockhash()          # valid, most-work, active
        # Branch A off height 286.
        a_hash = n_multi.getblockhash(WINDOW_START - 2)
        a_t = n_multi.getblockheader(a_hash)['time']
        a287 = self.make_block(n_multi, a_hash, a_t + 100, WINDOW_START - 1, signal=False)
        assert n_multi.submitblock(a287.serialize().hex()) in (None, "inconclusive")
        a288 = self.make_block(n_multi, a287.hash, a287.nTime, WINDOW_START, signal=False)
        assert n_multi.submitblock(a288.serialize().hex()) in (None, "inconclusive")
        # Branch B off height 285 (a distinct fork point, lower work than main).
        b_hash = n_multi.getblockhash(WINDOW_START - 3)
        b_t = n_multi.getblockheader(b_hash)['time']
        b286 = self.make_block(n_multi, b_hash, b_t + 200, WINDOW_START - 2, signal=False)
        assert n_multi.submitblock(b286.serialize().hex()) in (None, "inconclusive")
        b287 = self.make_block(n_multi, b286.hash, b286.nTime, WINDOW_START - 1, signal=False)
        assert n_multi.submitblock(b287.serialize().hex()) in (None, "inconclusive")
        b288 = self.make_block(n_multi, b287.hash, b287.nTime, WINDOW_START, signal=False)
        assert n_multi.submitblock(b288.serialize().hex()) in (None, "inconclusive")
        assert_equal(n_multi.getbestblockhash(), main_tip2)
        n_multi = self.restart(5, RDTS_ENFORCE)
        assert_equal(n_multi.getbestblockhash(), main_tip2)                     # valid main kept
        assert_equal(self.chaintip_status(n_multi, a288.hash), 'invalid')       # branch A corrected
        assert_equal(self.chaintip_status(n_multi, b288.hash), 'invalid')       # branch B corrected
        self.log.info("  A_MULTI CONFIRMED: both violating branches invalidated, valid main kept")

        # A_PRUNED: the violator sits below the prune horizon, so the data needed to
        # rewind to it is gone. The node must FAIL CLOSED (refuse to start, ask for
        # -reindex) rather than partially rewind and strand good blocks.
        self.log.info("A_PRUNED: violator's data pruned -> node offers reindex, fails closed if declined")
        # All non-signaling (avoids early lock-in); the lowest in-window violator
        # is at height PRUNE_VIOLATOR (blocks below the window are exempt anyway).
        for _ in range(PRUNE_TIP):
            self.submit_big_tip(n_prune, signal=False)
        assert_equal(n_prune.getblockcount(), PRUNE_TIP)
        pruned_to = n_prune.pruneblockchain(PRUNE_VIOLATOR)            # prune up to & including the violator
        assert pruned_to >= PRUNE_VIOLATOR, f"pruneblockchain only reached {pruned_to}"
        self.stop_node(6)
        # A daemon can't answer the "rebuild now?" prompt, so it declines and fails
        # closed with the recovery message rather than partially rewinding.
        self.nodes[6].assert_start_raises_init_error(
            extra_args=['-prune=1', '-fastprune'] + RDTS_PRUNE,
            expected_msg="A block that violates the BIP110/RDTS mandatory-signaling rule",
            match=ErrorMatch.PARTIAL_REGEX)
        # When the prompt is approved (here via the test option), the node takes the
        # reindex path instead of aborting. (A full re-sync of the pruned data needs
        # peers; offline we only confirm the reindex path is taken and the node no
        # longer holds the violator.)
        self.start_node(6, extra_args=['-prune=1', '-fastprune'] + RDTS_PRUNE +
                                      ['-test=reindex_after_failure_noninteractive_yes'])
        assert self.nodes[6].getblockcount() < PRUNE_TIP  # rebuilt, no longer on the invalid tip
        self.stop_node(6)
        self.log.info("  A_PRUNED CONFIRMED: prompts to rebuild; declined -> fail closed, approved -> reindex")

        # A_REINDEX_CHAINSTATE: an operator whose startup correction failed for a
        # transient reason is pointed at -reindex-chainstate (on a non-pruned node).
        # The startup correction is skipped on reindex; recovery comes entirely from
        # the rebuild, which re-connects blocks through ConnectBlock and re-enforces
        # the mandatory-signaling rule, so the violator is rejected and the enforcing
        # node still comes up on the valid chain.
        self.log.info("A_REINDEX_CHAINSTATE: enforcing node recovers a violator via -reindex-chainstate")
        bad_rc = self.build_bad_active_chain(n_rc)         # violator at WINDOW_START, tip at CHAIN_TIP
        rc_bad_tip = n_rc.getbestblockhash()
        assert_equal(n_rc.getblockcount(), CHAIN_TIP)
        n_rc = self.restart(7, RDTS_ENFORCE + ['-reindex-chainstate'])
        assert_equal(n_rc.getblockcount(), WINDOW_START - 1)                    # reorged to last valid ancestor
        assert_equal(n_rc.getbestblockhash(), n_rc.getblockhash(WINDOW_START - 1))
        assert_equal(self.chaintip_status(n_rc, rc_bad_tip), 'invalid')         # violating branch invalidated
        assert n_rc.getblock(bad_rc.hash)['confirmations'] < 0                  # violator off the active chain
        self.stop_node(7)
        self.log.info("  A_REINDEX_CHAINSTATE CONFIRMED: -reindex-chainstate recovers to the valid chain")

        self.log.info("")
        self.log.info("RESULT: enforcing node auto-corrects inherited RDTS-invalid history on both "
                      "the active chain (reorg) and non-active branches (mark invalid), persists the "
                      "correction, and never disturbs a chain that was validated correctly.")


if __name__ == '__main__':
    RdtsMigrationTest(__file__).main()
