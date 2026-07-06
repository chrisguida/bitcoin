#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""tx-pigeon getdata probe must not fingerprint a filtering node.

The "tx-pigeon" tool (stutxo/tx-pigeon) detects filtering nodes by delivering a
transaction to a peer and immediately re-requesting it on the same connection:

    version/verack (no wtxidrelay), Tx (unsolicited), GetData(MSG_TX, txid)

It treats a returned Tx/Inv as "relayed" and a notfound/timeout as "filtered".

The catch is that Bitcoin's serve-gate (see PR #18861, "Do not answer GETDATA
for to-be-announced tx") never serves a transaction back to the peer that just
submitted it, because the node has not announced it to that peer. So an honest
*relaying* node answers notfound to this probe too, for an unconfirmed tx it
accepted. A filtering node that also answers notfound is therefore
indistinguishable from an honest relay.

Any patch that answers this probe with the transaction (e.g. serving a filtered
tx out of a buffer) makes the filtering node the only node that returns the tx,
which is a unique fingerprint, the opposite of the intended effect. This test
guards against reintroducing such behaviour: the node must answer notfound to
the tx-pigeon probe whether the tx was filtered or accepted.
"""

from test_framework.messages import (
    CInv,
    CTxOut,
    MSG_TX,
    msg_getdata,
    msg_tx,
)
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class GarbagemanPigeonTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]  # default policy: oversize OP_RETURN is filtered

    def pigeon_probe(self, tx):
        """Replicate the tx-pigeon probe; return the node's response message name."""
        node = self.nodes[0]
        # tx-pigeon does not negotiate wtxidrelay (legacy txid relay).
        peer = node.add_p2p_connection(P2PInterface(wtxidrelay=False))
        txid_int = int(tx.rehash(), 16)
        with p2p_lock:
            peer.last_message.pop("tx", None)
            peer.last_message.pop("notfound", None)
        # Unsolicited tx, then immediately re-request it by txid on the same socket.
        peer.send_message(msg_tx(tx))
        peer.send_message(msg_getdata([CInv(t=MSG_TX, h=txid_int)]))
        peer.sync_with_ping()
        with p2p_lock:
            served = peer.last_message.get("tx")
            notfound = peer.last_message.get("notfound")
        node.disconnect_p2ps()
        return served, notfound

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, COINBASE_MATURITY + 1)

        self.log.info("Filtered tx (oversize OP_RETURN): probe must get notfound, not the tx")
        filtered = self.wallet.create_self_transfer_multi(num_outputs=1, fee_per_output=50000)["tx"]
        filtered.vout.append(CTxOut(0, CScript([OP_RETURN, b"\x11" * 200])))
        filtered.rehash()
        served, notfound = self.pigeon_probe(filtered)
        assert_equal(node.getrawmempool(), [])  # genuinely filtered
        assert served is None, "node served a filtered tx back to its submitter (fingerprint)"
        assert notfound is not None
        assert_equal(notfound.vec[0].hash, int(filtered.rehash(), 16))

        self.log.info("Accepted tx: an honest relay also answers notfound (same serve-gate)")
        accepted = self.wallet.create_self_transfer()["tx"]
        served, notfound = self.pigeon_probe(accepted)
        assert accepted.rehash() in node.getrawmempool()  # accepted
        assert served is None, "node served a tx back to its submitter"
        assert notfound is not None

        self.log.info("Filtered and accepted txs both answer notfound: no getdata tell")


if __name__ == "__main__":
    GarbagemanPigeonTest(__file__).main()
