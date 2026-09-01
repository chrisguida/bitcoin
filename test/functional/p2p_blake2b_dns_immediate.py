#!/usr/bin/env python3
"""ThreadDNSAddressSeed queries the DNS seeds immediately when addrman holds no
NODE_BLAKE2B address, instead of waiting DNSSEEDS_DELAY_MANY_PEERS: past the fork
the header chain can only be completed through such a peer. The normal delay
applies again as soon as any NODE_BLAKE2B address is present.

Case A: >1000 non-HF addresses          -> "Loading addresses from DNS seed", no 300s wait.
Case B: same, plus one NODE_BLAKE2B addr -> "Waiting 300 seconds ..." (normal delay).
"""
from test_framework.messages import NODE_NETWORK, NODE_WITNESS, NODE_BLAKE2B
from test_framework.netutil import UNREACHABLE_PROXY_ARG
from test_framework.test_framework import BitcoinTestFramework

NON_HF = NODE_NETWORK | NODE_WITNESS
HF = NODE_NETWORK | NODE_WITNESS | NODE_BLAKE2B


class Blake2bDnsImmediate(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-dnsseed=1", "-debug=net", UNREACHABLE_PROXY_ARG]]

    def _counts(self):
        raw = self.nodes[0].getrawaddrman()
        entries = [e for table in raw.values() for e in table.values()]
        hf = sum(1 for e in entries if int(e["services"]) & NODE_BLAKE2B)
        return len(entries), hf

    def run_test(self):
        node = self.nodes[0]

        # Buffer over DNSSEEDS_DELAY_PEER_THRESHOLD (1000); new-table bucketing
        # drops a non-deterministic fraction, so aim well past the boundary.
        self.log.info("Populate well over 1000 non-HF addresses")
        for i in range(20000):
            first, second, third = i % 2 + 1, i % 256, i % 100
            node.addpeeraddress(f"{first}.{second}.{third}.1", 8333, False, NON_HF)
            if i > 1000 and i % 100 == 0 and self._counts()[0] > 1100:
                break
        else:
            assert False, f"could not populate >1100 addrman entries; got {self._counts()[0]}"
        total, hf = self._counts()
        self.log.info(f"addrman: {total} entries, {hf} NODE_BLAKE2B")
        assert total > 1000 and hf == 0

        self.log.info("Case A: zero-HF, >1000 -> DNS immediately (no 300s wait)")
        with node.assert_debug_log(
                expected_msgs=["Loading addresses from DNS seed"],
                unexpected_msgs=["Waiting 300 seconds before querying DNS seeds."], timeout=30):
            self.restart_node(0)
        self.log.info("PASS A: queries DNS right away")

        self.log.info("Add one NODE_BLAKE2B address")
        node.addpeeraddress("8.8.8.8", 8333, False, HF)
        total, hf = self._counts()
        self.log.info(f"addrman: {total} entries, {hf} NODE_BLAKE2B")
        assert total > 1000 and hf >= 1

        self.log.info("Case B: one HF address present -> normal 5-minute delay returns")
        with node.assert_debug_log(
                expected_msgs=["Waiting 300 seconds before querying DNS seeds."], timeout=30):
            self.restart_node(0)
        self.log.info("PASS B: fix is targeted -- only forces DNS when zero HF in addrman")

        self.log.info("RESULT: zero-HF addrman -> instant DNS; any HF present -> normal delay")


if __name__ == '__main__':
    Blake2bDnsImmediate(__file__).main()
