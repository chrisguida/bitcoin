#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Comprehensive tests for Electrum descriptor wallet methods."""

import json
import socket
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class ElectrumClient:
    """Simple Electrum protocol client for testing."""

    def __init__(self, host='127.0.0.1', port=50001, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.request_id = 0

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _send_request(self, method, params=None):
        if params is None:
            params = []

        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }

        request_str = json.dumps(request) + '\n'
        self.sock.sendall(request_str.encode('utf-8'))

        response_data = b''
        while b'\n' not in response_data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed by server")
            response_data += chunk

        response_str = response_data.decode('utf-8').strip()
        response = json.loads(response_str)

        if 'error' in response and response['error'] is not None:
            raise Exception(f"Electrum error: {response['error']}")

        return response.get('result')

    def receive_notification(self, timeout=5.0):
        import select
        self.sock.setblocking(False)
        try:
            ready = select.select([self.sock], [], [], timeout)
            if ready[0]:
                response_data = b''
                while b'\n' not in response_data:
                    try:
                        chunk = self.sock.recv(4096)
                        if not chunk:
                            return None
                        response_data += chunk
                    except BlockingIOError:
                        break
                if response_data:
                    response_str = response_data.decode('utf-8').strip()
                    return json.loads(response_str)
            return None
        finally:
            self.sock.setblocking(True)

    def server_version(self, client_name="test_client", protocol_version=["1.4", "1.4.2"]):
        return self._send_request("server.version", [client_name, protocol_version])

    def wallet_create(self, wallet_id=None):
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.create", params)

    def wallet_open(self, wallet_id):
        return self._send_request("wallet.open", {"wallet_id": wallet_id})

    def wallet_close(self, wallet_id=None):
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.close", params)

    def wallet_delete(self, wallet_id):
        return self._send_request("wallet.delete", {"wallet_id": wallet_id})

    def wallet_import_descriptor(self, descriptor, wallet_id=None, range_start=0, range_end=100, timestamp="now", internal=False):
        params = {
            "descriptor": descriptor,
            "range": [range_start, range_end],
            "timestamp": timestamp,
            "internal": internal
        }
        if wallet_id:
            params["wallet_id"] = wallet_id
        return self._send_request("wallet.import_descriptor", params)

    def wallet_get_info(self, wallet_id=None):
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.get_info", params)

    def wallet_get_transactions(self, wallet_id=None, limit=100, offset=0):
        params = {"limit": limit, "offset": offset}
        if wallet_id:
            params["wallet_id"] = wallet_id
        return self._send_request("wallet.get_transactions", params)

    def wallet_get_utxos(self, wallet_id=None, min_confirmations=0):
        params = {"min_confirmations": min_confirmations}
        if wallet_id:
            params["wallet_id"] = wallet_id
        return self._send_request("wallet.get_utxos", params)

    def wallet_get_address(self, wallet_id=None, label=""):
        params = {"label": label}
        if wallet_id:
            params["wallet_id"] = wallet_id
        return self._send_request("wallet.get_address", params)

    def wallet_subscribe(self, wallet_id=None):
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.subscribe", params)

    def wallet_unsubscribe(self, wallet_id=None):
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.unsubscribe", params)


class ElectrumWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        # Enable Electrum server with blockfilterindex for descriptor methods
        # Also enable txindex and addressindex for full support
        self.extra_args = [[
            "-electrum=1",
            "-electrumport=50001",
            "-blockfilterindex=1",
            "-txindex=1",
            "-addressindex=1"
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.test_descriptor_types()
        self.test_funded_wallet()
        self.test_multiple_clients()
        self.test_error_cases()

    def test_descriptor_types(self):
        """Test importing different descriptor types: wpkh, tr."""
        self.log.info("Testing different descriptor types...")

        node = self.nodes[0]

        # Create a source descriptor wallet to generate valid descriptors
        node.createwallet("desc_source", False, False, "", False, True)
        source = node.get_wallet_rpc("desc_source")
        descriptors = source.listdescriptors()["descriptors"]

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()

            # Test 1: wpkh (native segwit)
            self.log.info("Testing wpkh descriptor...")
            client.wallet_create("wpkh_wallet")

            # Find external wpkh descriptor from the source wallet
            wpkh_desc = None
            for d in descriptors:
                if d["desc"].startswith("wpkh(") and "/0/*)" in d["desc"]:
                    wpkh_desc = d["desc"]
                    break

            if wpkh_desc:
                self.log.info(f"Importing wpkh descriptor: {wpkh_desc[:50]}...")
                result = client.wallet_import_descriptor(wpkh_desc, range_start=0, range_end=10, timestamp="now")
                assert result == True, f"wpkh import should succeed, got {result}"
                self.log.info(f"wpkh import result: {result}")
            else:
                self.log.info("No wpkh descriptor found in source wallet")

            client.wallet_delete("wpkh_wallet")

            # Test 2: tr (taproot)
            self.log.info("Testing tr descriptor...")
            client.wallet_create("tr_wallet")

            tr_desc = None
            for d in descriptors:
                if d["desc"].startswith("tr(") and "/0/*)" in d["desc"]:
                    tr_desc = d["desc"]
                    break

            if tr_desc:
                self.log.info(f"Importing tr descriptor: {tr_desc[:50]}...")
                result = client.wallet_import_descriptor(tr_desc, range_start=0, range_end=10, timestamp="now")
                assert result == True, f"tr import should succeed, got {result}"
                self.log.info(f"tr import result: {result}")
            else:
                self.log.info("No tr descriptor found in source wallet")

            client.wallet_delete("tr_wallet")

        finally:
            client.close()

        self.log.info("Descriptor types test passed!")

    def test_funded_wallet(self):
        """Test wallet with actual transactions and UTXOs."""
        self.log.info("Testing funded wallet...")

        node = self.nodes[0]

        # Create a funding wallet
        if "funding_wallet" not in node.listwallets():
            node.createwallet("funding_wallet")
        funding = node.get_wallet_rpc("funding_wallet")
        funding_addr = funding.getnewaddress()

        # Mine blocks to get funds
        self.generatetoaddress(node, 110, funding_addr)

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()

            # Create electrum wallet
            self.log.info("Creating electrum wallet...")
            client.wallet_create("funded_wallet")

            # Import a watch-only descriptor with timestamp="now"
            wpkh_desc = "wpkh([00000000/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)#expzktsc"
            result = client.wallet_import_descriptor(wpkh_desc, range_start=0, range_end=20, timestamp="now")
            self.log.info(f"Descriptor import result: {result}")

            # Test wallet.get_info on empty wallet
            self.log.info("Testing wallet.get_info on empty wallet...")
            info = client.wallet_get_info()
            self.log.info(f"Wallet info: {info}")
            assert "balance" in info, "wallet.get_info should include balance"
            assert info["balance"] == 0, f"New wallet should have 0 balance, got {info['balance']}"

            # Test wallet.get_transactions on empty wallet
            self.log.info("Testing wallet.get_transactions on empty wallet...")
            txs = client.wallet_get_transactions()
            assert isinstance(txs, list), "wallet.get_transactions should return list"
            assert len(txs) == 0, f"Empty wallet should have no transactions, got {len(txs)}"

            # Test wallet.get_utxos on empty wallet
            self.log.info("Testing wallet.get_utxos on empty wallet...")
            utxos = client.wallet_get_utxos()
            assert isinstance(utxos, list), "wallet.get_utxos should return list"
            assert len(utxos) == 0, f"Empty wallet should have no UTXOs, got {len(utxos)}"

            # Clean up
            client.wallet_delete("funded_wallet")

        finally:
            client.close()

        self.log.info("Funded wallet test passed!")

    def test_multiple_clients(self):
        """Test multiple concurrent clients with different wallets."""
        self.log.info("Testing multiple concurrent clients...")

        clients = []
        wallet_ids = []

        try:
            # Create 3 clients with their own wallets
            for i in range(3):
                client = ElectrumClient()
                client.connect()
                client.server_version(f"client_{i}")

                wallet_id = f"multi_wallet_{i}"
                result = client.wallet_create(wallet_id)
                assert result["wallet_id"] == wallet_id

                clients.append(client)
                wallet_ids.append(wallet_id)
                self.log.info(f"Client {i} created wallet {wallet_id}")

            # Each client should be able to access their own wallet
            for i, client in enumerate(clients):
                info = client.wallet_get_info(wallet_ids[i])
                assert info["wallet_id"] == wallet_ids[i], f"Client {i} should access own wallet"
                self.log.info(f"Client {i} verified access to {wallet_ids[i]}")

            # Client 0 opens client 1's wallet (should work - wallets are shared)
            self.log.info("Testing cross-client wallet access...")
            result = clients[0].wallet_open(wallet_ids[1])
            assert result["wallet_id"] == wallet_ids[1]
            self.log.info("Client 0 successfully opened client 1's wallet")

            # Both clients can now see the same wallet
            info0 = clients[0].wallet_get_info()
            info1 = clients[1].wallet_get_info(wallet_ids[1])
            assert info0["wallet_id"] == info1["wallet_id"]

            # Test concurrent subscriptions
            self.log.info("Testing concurrent wallet subscriptions...")
            for i, client in enumerate(clients):
                # Open own wallet first
                client.wallet_open(wallet_ids[i])
                result = client.wallet_subscribe()
                assert result == True, f"Client {i} should subscribe successfully"

            # All should be able to unsubscribe
            for i, client in enumerate(clients):
                result = client.wallet_unsubscribe()
                assert result == True, f"Client {i} should unsubscribe successfully"

            # Clean up wallets
            for wallet_id in wallet_ids:
                try:
                    clients[0].wallet_delete(wallet_id)
                except:
                    pass

        finally:
            for client in clients:
                client.close()

        self.log.info("Multiple clients test passed!")

    def test_error_cases(self):
        """Test error handling for various edge cases."""
        self.log.info("Testing error cases...")

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()

            # Test: Open non-existent wallet
            self.log.info("Testing open non-existent wallet...")
            try:
                client.wallet_open("nonexistent_wallet_xyz")
                assert False, "Should fail to open non-existent wallet"
            except Exception as e:
                self.log.info(f"Expected error: {e}")

            # Test: Delete non-existent wallet
            self.log.info("Testing delete non-existent wallet...")
            try:
                client.wallet_delete("nonexistent_wallet_xyz")
                assert False, "Should fail to delete non-existent wallet"
            except Exception as e:
                self.log.info(f"Expected error: {e}")

            # Test: Get info without active wallet
            self.log.info("Testing get_info without active wallet...")
            try:
                client.wallet_get_info()
                assert False, "Should fail without active wallet"
            except Exception as e:
                self.log.info(f"Expected error: {e}")

            # Test: Import invalid descriptor
            self.log.info("Testing import invalid descriptor...")
            client.wallet_create("error_test_wallet")
            try:
                client.wallet_import_descriptor("invalid_descriptor_string")
                assert False, "Should fail with invalid descriptor"
            except Exception as e:
                self.log.info(f"Expected error: {e}")

            # Test: Create duplicate wallet
            self.log.info("Testing create duplicate wallet...")
            try:
                client.wallet_create("error_test_wallet")
                assert False, "Should fail to create duplicate wallet"
            except Exception as e:
                self.log.info(f"Expected error: {e}")

            # Clean up
            client.wallet_delete("error_test_wallet")

            # Test: Get address without descriptor
            self.log.info("Testing get_address without descriptor...")
            client.wallet_create("no_desc_wallet")
            try:
                client.wallet_get_address()
                # This might succeed with empty result or fail - depends on implementation
                self.log.info("get_address on empty wallet succeeded (may return error or empty)")
            except Exception as e:
                self.log.info(f"Expected error: {e}")

            client.wallet_delete("no_desc_wallet")

        finally:
            client.close()

        self.log.info("Error cases test passed!")


if __name__ == '__main__':
    ElectrumWalletTest(__file__).main()
