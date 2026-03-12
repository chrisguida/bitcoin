#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Electrum protocol server functionality."""

import json
import socket
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.messages import sha256


def compute_scripthash(script_hex):
    """Compute Electrum-format scripthash from a scriptPubKey hex string."""
    script_bytes = bytes.fromhex(script_hex)
    hash_bytes = sha256(script_bytes)
    # Reverse bytes for Electrum format
    return hash_bytes[::-1].hex()


class ElectrumClient:
    """Simple Electrum protocol client for testing."""

    def __init__(self, host='127.0.0.1', port=50001, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.request_id = 0

    def connect(self):
        """Connect to the Electrum server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        """Close the connection."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def _send_request(self, method, params=None):
        """Send a JSON-RPC request and return the response."""
        if params is None:
            params = []

        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }

        # Send request (newline-delimited)
        request_str = json.dumps(request) + '\n'
        self.sock.sendall(request_str.encode('utf-8'))

        # Read response (newline-delimited)
        response_data = b''
        while b'\n' not in response_data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed by server")
            response_data += chunk

        # Parse response
        response_str = response_data.decode('utf-8').strip()
        response = json.loads(response_str)

        # Check for errors
        if 'error' in response and response['error'] is not None:
            raise Exception(f"Electrum error: {response['error']}")

        return response.get('result')

    def receive_notification(self, timeout=5.0):
        """Receive a notification from the server (non-blocking with timeout)."""
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
                    notification = json.loads(response_str)
                    return notification
            return None
        finally:
            self.sock.setblocking(True)

    def receive_notifications(self, timeout=10.0, max_count=100):
        """Receive multiple notifications until timeout or max_count reached."""
        import time
        notifications = []
        start_time = time.time()
        while time.time() - start_time < timeout and len(notifications) < max_count:
            notif = self.receive_notification(timeout=0.5)
            if notif:
                notifications.append(notif)
            elif len(notifications) > 0:
                # Got some notifications and now nothing more, done
                break
        return notifications

    def server_version(self, client_name="test_client", protocol_version=["1.4", "1.4.2"]):
        """Call server.version"""
        return self._send_request("server.version", [client_name, protocol_version])

    def server_ping(self):
        """Call server.ping"""
        return self._send_request("server.ping")

    def server_banner(self):
        """Call server.banner"""
        return self._send_request("server.banner")

    def server_features(self):
        """Call server.features"""
        return self._send_request("server.features")

    def blockchain_headers_subscribe(self):
        """Call blockchain.headers.subscribe"""
        return self._send_request("blockchain.headers.subscribe")

    def blockchain_block_header(self, height, cp_height=0):
        """Call blockchain.block.header"""
        return self._send_request("blockchain.block.header", [height, cp_height])

    def blockchain_block_headers(self, start_height, count):
        """Call blockchain.block.headers"""
        return self._send_request("blockchain.block.headers", [start_height, count])

    def blockchain_scripthash_subscribe(self, scripthash):
        """Call blockchain.scripthash.subscribe"""
        return self._send_request("blockchain.scripthash.subscribe", [scripthash])

    def blockchain_scripthash_unsubscribe(self, scripthash):
        """Call blockchain.scripthash.unsubscribe"""
        return self._send_request("blockchain.scripthash.unsubscribe", [scripthash])

    def blockchain_scripthash_get_history(self, scripthash):
        """Call blockchain.scripthash.get_history"""
        return self._send_request("blockchain.scripthash.get_history", [scripthash])

    def blockchain_scripthash_listunspent(self, scripthash):
        """Call blockchain.scripthash.listunspent"""
        return self._send_request("blockchain.scripthash.listunspent", [scripthash])

    def blockchain_transaction_get(self, txid, verbose=False):
        """Call blockchain.transaction.get"""
        return self._send_request("blockchain.transaction.get", [txid, verbose])

    def blockchain_estimatefee(self, target_blocks):
        """Call blockchain.estimatefee"""
        return self._send_request("blockchain.estimatefee", [target_blocks])

    def blockchain_relayfee(self):
        """Call blockchain.relayfee"""
        return self._send_request("blockchain.relayfee")

    # Wallet methods
    def wallet_create(self, wallet_id=None):
        """Call wallet.create"""
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.create", params)

    def wallet_open(self, wallet_id):
        """Call wallet.open"""
        return self._send_request("wallet.open", {"wallet_id": wallet_id})

    def wallet_close(self, wallet_id=None):
        """Call wallet.close"""
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.close", params)

    def wallet_delete(self, wallet_id):
        """Call wallet.delete"""
        return self._send_request("wallet.delete", {"wallet_id": wallet_id})

    def wallet_import_descriptor(self, descriptor, wallet_id=None, range_start=0, range_end=100, timestamp="now", internal=False):
        """Call wallet.import_descriptor"""
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
        """Call wallet.get_info"""
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.get_info", params)

    def wallet_get_transactions(self, wallet_id=None, limit=100, offset=0):
        """Call wallet.get_transactions"""
        params = {"limit": limit, "offset": offset}
        if wallet_id:
            params["wallet_id"] = wallet_id
        return self._send_request("wallet.get_transactions", params)

    def wallet_get_utxos(self, wallet_id=None, min_confirmations=0):
        """Call wallet.get_utxos"""
        params = {"min_confirmations": min_confirmations}
        if wallet_id:
            params["wallet_id"] = wallet_id
        return self._send_request("wallet.get_utxos", params)

    def wallet_get_address(self, wallet_id=None, label=""):
        """Call wallet.get_address"""
        params = {"label": label}
        if wallet_id:
            params["wallet_id"] = wallet_id
        return self._send_request("wallet.get_address", params)

    def wallet_subscribe(self, wallet_id=None):
        """Call wallet.subscribe"""
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.subscribe", params)

    def wallet_unsubscribe(self, wallet_id=None):
        """Call wallet.unsubscribe"""
        params = {"wallet_id": wallet_id} if wallet_id else {}
        return self._send_request("wallet.unsubscribe", params)


class ElectrumServerTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        # Enable Electrum server, address index, txindex, and blockfilterindex
        self.extra_args = [["-electrum=1", "-electrumport=50001", "-addressindex=1", "-txindex=1", "-blockfilterindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.test_server_methods()
        self.test_blockchain_headers()
        self.test_scripthash_methods()
        self.test_transaction_methods()
        self.test_fee_methods()
        self.test_wallet_methods()

    def test_server_methods(self):
        """Test server.* Electrum methods."""
        self.log.info("Testing server.* methods...")

        client = ElectrumClient()
        try:
            client.connect()

            # Test server.version
            self.log.info("Testing server.version...")
            result = client.server_version("test_client", ["1.4", "1.4.2"])
            assert isinstance(result, list), "server.version should return a list"
            assert len(result) == 2, "server.version should return [server_name, protocol_version]"
            assert "BitcoinKnots" in result[0], f"Server name should contain BitcoinKnots, got {result[0]}"
            self.log.info(f"Server version: {result}")

            # Test server.ping
            self.log.info("Testing server.ping...")
            result = client.server_ping()
            # ping returns null
            assert result is None, f"server.ping should return null, got {result}"

            # Test server.banner
            self.log.info("Testing server.banner...")
            result = client.server_banner()
            assert isinstance(result, str), "server.banner should return a string"
            assert len(result) > 0, "server.banner should not be empty"
            self.log.info(f"Banner: {result[:50]}...")

            # Test server.features
            self.log.info("Testing server.features...")
            result = client.server_features()
            assert isinstance(result, dict), "server.features should return an object"
            assert "genesis_hash" in result, "server.features should include genesis_hash"
            assert "protocol_max" in result, "server.features should include protocol_max"
            # pruning=null means not pruned
            assert "pruning" in result, "server.features should include pruning"
            assert result["pruning"] is None, "pruning should be null (not pruned)"
            # Capability flags (electrum-descriptor extension)
            assert "transaction_get" in result, "server.features should include transaction_get"
            assert result["transaction_get"] == True, "transaction_get should be true (txindex enabled)"
            assert "scripthash_methods" in result, "server.features should include scripthash_methods"
            assert result["scripthash_methods"] == True, "scripthash_methods should be true (addressindex enabled)"
            assert "descriptor_methods" in result, "server.features should include descriptor_methods"
            assert result["descriptor_methods"] == True, "descriptor_methods should be true (blockfilterindex enabled)"
            self.log.info(f"Features: genesis_hash={result['genesis_hash'][:16]}...")

        finally:
            client.close()

        self.log.info("server.* methods test passed!")

    def test_blockchain_headers(self):
        """Test blockchain header methods."""
        self.log.info("Testing blockchain header methods...")

        node = self.nodes[0]

        # Mine some blocks first
        node.createwallet("test_wallet")
        wallet = node.get_wallet_rpc("test_wallet")
        addr = wallet.getnewaddress()
        self.generatetoaddress(node, 10, addr)

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()  # Handshake

            # Test blockchain.headers.subscribe
            self.log.info("Testing blockchain.headers.subscribe...")
            result = client.blockchain_headers_subscribe()
            assert isinstance(result, dict), "headers.subscribe should return an object"
            assert "height" in result, "headers.subscribe should include height"
            assert "hex" in result, "headers.subscribe should include hex"
            assert result["height"] == node.getblockcount(), "Height should match node's block count"
            assert len(result["hex"]) == 160, "Header hex should be 80 bytes (160 hex chars)"
            self.log.info(f"Current tip: height={result['height']}")

            # Test blockchain.block.header
            self.log.info("Testing blockchain.block.header...")
            result = client.blockchain_block_header(5)
            assert isinstance(result, str), "block.header should return hex string"
            assert len(result) == 160, "Header should be 80 bytes"

            # Verify it matches the node's block header
            block_hash = node.getblockhash(5)
            block = node.getblockheader(block_hash, False)
            assert result == block, "Header should match node's block header"

            # Test blockchain.block.headers (batch)
            self.log.info("Testing blockchain.block.headers...")
            result = client.blockchain_block_headers(0, 5)
            assert isinstance(result, dict), "block.headers should return an object"
            assert result["count"] == 5, "Should return 5 headers"
            assert len(result["hex"]) == 160 * 5, "Should be 5 headers concatenated"

        finally:
            client.close()

        self.log.info("Blockchain header methods test passed!")

    def test_scripthash_methods(self):
        """Test blockchain.scripthash.* methods."""
        self.log.info("Testing blockchain.scripthash.* methods...")

        node = self.nodes[0]
        wallet = node.get_wallet_rpc("test_wallet")

        # Get a new address and compute its scripthash
        addr = wallet.getnewaddress()
        spk = node.validateaddress(addr)["scriptPubKey"]
        scripthash = compute_scripthash(spk)
        self.log.info(f"Test address: {addr}")
        self.log.info(f"Scripthash: {scripthash}")

        # Mine some blocks to this address
        self.generatetoaddress(node, 5, addr)

        # Wait for address index to sync
        self.wait_until(lambda: node.getindexinfo().get('addressindex', {}).get('synced', False))

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()  # Handshake

            # Test blockchain.scripthash.subscribe
            self.log.info("Testing blockchain.scripthash.subscribe...")
            result = client.blockchain_scripthash_subscribe(scripthash)
            # Result is the status hash (or null if no history)
            # Since we mined to this address, it should have a status
            assert result is not None, "scripthash.subscribe should return status for address with history"
            assert isinstance(result, str), "Status should be a hex string"
            assert len(result) == 64, "Status hash should be 32 bytes (64 hex chars)"
            self.log.info(f"Scripthash status: {result[:16]}...")

            # Test blockchain.scripthash.get_history
            self.log.info("Testing blockchain.scripthash.get_history...")
            result = client.blockchain_scripthash_get_history(scripthash)
            assert isinstance(result, list), "get_history should return a list"
            assert len(result) == 5, f"Should have 5 transactions, got {len(result)}"
            for entry in result:
                assert "tx_hash" in entry, "History entry should have tx_hash"
                assert "height" in entry, "History entry should have height"
                assert entry["height"] > 0, "Height should be positive (confirmed)"
            self.log.info(f"History: {len(result)} transactions")

            # Test blockchain.scripthash.listunspent
            self.log.info("Testing blockchain.scripthash.listunspent...")
            result = client.blockchain_scripthash_listunspent(scripthash)
            assert isinstance(result, list), "listunspent should return a list"
            assert len(result) == 5, f"Should have 5 UTXOs, got {len(result)}"
            for utxo in result:
                assert "tx_hash" in utxo, "UTXO should have tx_hash"
                assert "tx_pos" in utxo, "UTXO should have tx_pos"
                assert "height" in utxo, "UTXO should have height"
                assert "value" in utxo, "UTXO should have value"
                assert utxo["value"] > 0, "Value should be positive"
            self.log.info(f"UTXOs: {len(result)} unspent outputs")

            # Test blockchain.scripthash.unsubscribe
            self.log.info("Testing blockchain.scripthash.unsubscribe...")
            result = client.blockchain_scripthash_unsubscribe(scripthash)
            assert result == True, "unsubscribe should return true for subscribed scripthash"

            # Unsubscribe again should return false
            result = client.blockchain_scripthash_unsubscribe(scripthash)
            assert result == False, "unsubscribe should return false for non-subscribed scripthash"

            # Test empty scripthash (address with no history)
            empty_addr = wallet.getnewaddress()
            empty_spk = node.validateaddress(empty_addr)["scriptPubKey"]
            empty_scripthash = compute_scripthash(empty_spk)

            result = client.blockchain_scripthash_subscribe(empty_scripthash)
            assert result is None, "scripthash.subscribe should return null for address with no history"

            result = client.blockchain_scripthash_get_history(empty_scripthash)
            assert result == [], "get_history should return empty list for address with no history"

            result = client.blockchain_scripthash_listunspent(empty_scripthash)
            assert result == [], "listunspent should return empty list for address with no history"

        finally:
            client.close()

        self.log.info("blockchain.scripthash.* methods test passed!")

    def test_transaction_methods(self):
        """Test blockchain.transaction.* methods."""
        self.log.info("Testing blockchain.transaction.* methods...")

        node = self.nodes[0]
        wallet = node.get_wallet_rpc("test_wallet")

        # Get a txid from a mined block
        block_hash = node.getblockhash(5)
        block = node.getblock(block_hash)
        txid = block["tx"][0]  # Coinbase transaction

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()  # Handshake

            # Test blockchain.transaction.get (non-verbose)
            self.log.info("Testing blockchain.transaction.get (non-verbose)...")
            result = client.blockchain_transaction_get(txid, verbose=False)
            assert isinstance(result, str), "transaction.get should return hex string"
            assert len(result) > 0, "Transaction hex should not be empty"
            self.log.info(f"Transaction hex length: {len(result)}")

            # Verify it matches the node's transaction
            node_tx = node.getrawtransaction(txid)
            assert result == node_tx, "Transaction hex should match node's transaction"

            # Test blockchain.transaction.get (verbose)
            self.log.info("Testing blockchain.transaction.get (verbose)...")
            result = client.blockchain_transaction_get(txid, verbose=True)
            assert isinstance(result, dict), "transaction.get verbose should return object"
            assert "hex" in result, "Verbose result should have hex"
            assert "blockhash" in result, "Verbose result should have blockhash"
            assert "confirmations" in result, "Verbose result should have confirmations"
            assert result["blockhash"] == block_hash, "Block hash should match"
            self.log.info(f"Transaction confirmations: {result['confirmations']}")

        finally:
            client.close()

        self.log.info("blockchain.transaction.* methods test passed!")

    def test_fee_methods(self):
        """Test fee estimation methods."""
        self.log.info("Testing fee estimation methods...")

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()  # Handshake

            # Test blockchain.relayfee
            self.log.info("Testing blockchain.relayfee...")
            result = client.blockchain_relayfee()
            assert isinstance(result, (int, float)), "relayfee should return a number"
            assert result >= 0, "relayfee should be non-negative"
            self.log.info(f"Relay fee: {result} BTC/kB")

            # Test blockchain.estimatefee
            self.log.info("Testing blockchain.estimatefee...")
            result = client.blockchain_estimatefee(6)
            assert isinstance(result, (int, float)), "estimatefee should return a number"
            # May return -1 if not enough data
            self.log.info(f"Estimated fee (6 blocks): {result} BTC/kB")

        finally:
            client.close()

        self.log.info("Fee estimation methods test passed!")

    def test_wallet_methods(self):
        """Test wallet.* Electrum methods."""
        self.log.info("Testing wallet.* methods...")

        client = ElectrumClient()
        try:
            client.connect()
            client.server_version()  # Handshake

            # Test wallet.create with auto-generated ID
            self.log.info("Testing wallet.create (auto ID)...")
            result = client.wallet_create()
            assert isinstance(result, dict), "wallet.create should return an object"
            assert "wallet_id" in result, "wallet.create should return wallet_id"
            wallet_id = result["wallet_id"]
            assert len(wallet_id) > 0, "wallet_id should not be empty"
            self.log.info(f"Created wallet: {wallet_id}")

            # Test wallet.get_info
            self.log.info("Testing wallet.get_info...")
            result = client.wallet_get_info()
            assert isinstance(result, dict), "wallet.get_info should return an object"
            assert "wallet_id" in result, "wallet.get_info should include wallet_id"
            assert "balance" in result, "wallet.get_info should include balance"
            assert result["balance"] == 0, "New wallet should have 0 balance"
            self.log.info(f"Wallet info: balance={result['balance']}")

            # Test wallet.get_transactions (should be empty)
            self.log.info("Testing wallet.get_transactions (empty wallet)...")
            result = client.wallet_get_transactions()
            assert isinstance(result, list), "wallet.get_transactions should return a list"
            assert len(result) == 0, "New wallet should have no transactions"

            # Test wallet.get_utxos (should be empty)
            self.log.info("Testing wallet.get_utxos (empty wallet)...")
            result = client.wallet_get_utxos()
            assert isinstance(result, list), "wallet.get_utxos should return a list"
            assert len(result) == 0, "New wallet should have no UTXOs"

            # Test wallet.close
            self.log.info("Testing wallet.close...")
            result = client.wallet_close()
            assert result == True, "wallet.close should return true"

            # Test wallet.open
            self.log.info("Testing wallet.open...")
            result = client.wallet_open(wallet_id)
            assert isinstance(result, dict), "wallet.open should return an object"
            assert result["wallet_id"] == wallet_id, "wallet.open should return same wallet_id"

            # Test wallet.create with specific ID
            self.log.info("Testing wallet.create (specific ID)...")
            result = client.wallet_create("test_wallet_123")
            assert result["wallet_id"] == "test_wallet_123", "wallet.create should use provided ID"

            # Test wallet.delete
            self.log.info("Testing wallet.delete...")
            result = client.wallet_delete("test_wallet_123")
            assert result == True, "wallet.delete should return true"

            # Clean up first wallet
            client.wallet_delete(wallet_id)

            # Test wallet.get_address on empty wallet (should fail - no descriptors)
            self.log.info("Testing wallet.get_address (no descriptors - expect failure)...")
            result = client.wallet_create("addr_test_wallet")
            try:
                result = client.wallet_get_address()
                self.log.info(f"wallet.get_address returned: {result}")
            except Exception as e:
                self.log.info(f"wallet.get_address failed as expected: {e}")

            # Test wallet.import_descriptor
            self.log.info("Testing wallet.import_descriptor...")
            # Use a simple wpkh descriptor (watch-only, no private key)
            test_desc = "wpkh([00000000/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)#expzktsc"
            try:
                result = client.wallet_import_descriptor(test_desc, range_start=0, range_end=10)
                self.log.info(f"wallet.import_descriptor returned: {result}")

                # Now try to get an address
                self.log.info("Testing wallet.get_address (after import)...")
                result = client.wallet_get_address()
                self.log.info(f"wallet.get_address returned: {result}")
            except Exception as e:
                self.log.info(f"wallet.import_descriptor or get_address failed: {e}")

            client.wallet_delete("addr_test_wallet")

            # Test async rescan with blockfilterindex (now enabled)
            self.log.info("Testing wallet.import_descriptor with async rescan...")
            result = client.wallet_create("rescan_test_wallet")
            test_desc = "wpkh([00000000/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)#expzktsc"

            # Subscribe to wallet notifications first
            client.wallet_subscribe()

            # Import with historical timestamp (triggers async rescan)
            self.log.info("Importing descriptor with historical timestamp (async rescan)...")
            result = client.wallet_import_descriptor(test_desc, range_start=0, range_end=10, timestamp="0")
            assert result == True, "wallet.import_descriptor should return true immediately"
            self.log.info(f"wallet.import_descriptor returned immediately: {result}")

            # Wait for and collect notifications
            self.log.info("Waiting for scan notifications...")
            import time
            notifications = []
            start_time = time.time()
            timeout = 30  # 30 second timeout for scan to complete

            while time.time() - start_time < timeout:
                notif = client.receive_notification(timeout=1.0)
                if notif:
                    method = notif.get('method', '')
                    self.log.info(f"Received notification: {method}")
                    notifications.append(notif)
                    if method == 'wallet.scan_complete':
                        break
                time.sleep(0.1)

            # Verify we got notifications
            methods = [n.get('method', '') for n in notifications]
            self.log.info(f"Received {len(notifications)} notifications: {methods}")

            # Should have at least scan_complete (progress notifications may be skipped for small rescans)
            assert 'wallet.scan_complete' in methods, f"Should receive wallet.scan_complete, got: {methods}"

            # Check the scan_complete notification
            complete_notif = [n for n in notifications if n.get('method') == 'wallet.scan_complete'][0]
            params = complete_notif.get('params', [])
            if len(params) >= 2:
                result_info = params[1]
                assert result_info.get('success') == True, f"Scan should succeed, got: {result_info}"
                self.log.info("Scan completed successfully!")

            client.wallet_unsubscribe()
            client.wallet_delete("rescan_test_wallet")

            # Test wallet subscriptions
            self.log.info("Testing wallet subscriptions...")
            result = client.wallet_create("sub_test_wallet")
            assert result["wallet_id"] == "sub_test_wallet", "wallet.create should use provided ID"

            # Test wallet.subscribe
            self.log.info("Testing wallet.subscribe...")
            result = client.wallet_subscribe()
            assert result == True, "wallet.subscribe should return true"

            # Test wallet.unsubscribe
            self.log.info("Testing wallet.unsubscribe...")
            result = client.wallet_unsubscribe()
            assert result == True, "wallet.unsubscribe should return true for subscribed wallet"

            # Unsubscribe again should return false
            result = client.wallet_unsubscribe()
            assert result == False, "wallet.unsubscribe should return false when not subscribed"

            client.wallet_delete("sub_test_wallet")

        finally:
            client.close()

        self.log.info("wallet.* methods test passed!")


if __name__ == '__main__':
    ElectrumServerTest(__file__).main()
