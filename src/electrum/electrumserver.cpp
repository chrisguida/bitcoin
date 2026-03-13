// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <electrum/electrumserver.h>
#include <electrum/walletmanager.h>

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <httpserver.h>
#include <index/blockfilterindex.h>
#include <index/txindex.h>
#include <logging.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/types.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <serialize.h>
#include <streams.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <validation.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// Stub: address index is not available in this build.
// The scripthash methods will return "Address index not available" errors.
struct AddressIndexEntry {
    uint256 txid;
    int height{0};
    bool IsSpent() const { return false; }
    uint256 spending_txid;
    int spending_height{0};
    int64_t value{0};
    int vout{0};
    int output_index{0};
};
struct AddressIndexStub {
    bool GetHistory(const uint256&, std::vector<AddressIndexEntry>&) { return false; }
    bool GetUnspent(const uint256&, std::vector<AddressIndexEntry>&) { return false; }
};
static AddressIndexStub* g_addressindex = nullptr;

namespace electrum {

std::unique_ptr<ElectrumServer> g_electrum_server;

// Protocol version we support
static const std::string ELECTRUM_PROTOCOL_VERSION_MIN = "1.4";
static const std::string ELECTRUM_PROTOCOL_VERSION_MAX = "1.4.2";
static const std::string SERVER_VERSION = "BitcoinKnots/0.1";

//
// ElectrumServer implementation
//

ElectrumServer::ElectrumServer(node::NodeContext& node)
    : m_node(node)
{
    m_subscription_manager = std::make_unique<SubscriptionManager>(*this);
    m_wallet_manager = std::make_unique<ElectrumWalletManager>(node);
}

ElectrumServer::~ElectrumServer()
{
    Stop();
}

bool ElectrumServer::Init()
{
    m_port = static_cast<uint16_t>(gArgs.GetIntArg("-electrumport", 50001));
    m_bind_address = gArgs.GetArg("-electrumbind", "127.0.0.1");

    LogPrintf("Electrum server: initializing on %s:%d\n", m_bind_address, m_port);

    bool is_pruned = gArgs.GetIntArg("-prune", 0) > 0;
    bool has_txindex = gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX);
    bool has_addressindex = gArgs.GetBoolArg("-addressindex", false);
    bool has_blockfilterindex = gArgs.GetBoolArg("-blockfilterindex", false);

    // Pruned nodes can only use blockfilterindex
    if (is_pruned) {
        if (has_txindex) {
            LogPrintf("Electrum server: ERROR - txindex not compatible with pruning\n");
            return false;
        }
        if (has_addressindex) {
            LogPrintf("Electrum server: ERROR - addressindex not compatible with pruning\n");
            return false;
        }
        if (!has_blockfilterindex) {
            LogPrintf("Electrum server: ERROR - pruned node requires -blockfilterindex=1\n");
            return false;
        }
    }

    // Require at least one index
    if (!has_txindex && !has_addressindex && !has_blockfilterindex) {
        LogPrintf("Electrum server: ERROR - requires at least one of:\n");
        LogPrintf("Electrum server:   -txindex=1 (for blockchain.transaction.get)\n");
        LogPrintf("Electrum server:   -addressindex=1 (for blockchain.scripthash.*)\n");
        LogPrintf("Electrum server:   -blockfilterindex=1 (for descriptor methods)\n");
        return false;
    }

    // Log enabled capabilities
    LogPrintf("Electrum server: capabilities:\n");
    LogPrintf("Electrum server:   transaction_get: %s\n", has_txindex ? "enabled" : "disabled");
    LogPrintf("Electrum server:   scripthash_methods: %s\n", has_addressindex ? "enabled" : "disabled");
    LogPrintf("Electrum server:   descriptor_methods: %s\n", has_blockfilterindex ? "enabled" : "disabled");

    if (has_addressindex && !has_txindex) {
        LogPrintf("Electrum server: NOTE - scripthash methods have limited use without txindex\n");
    }

    return true;
}

bool ElectrumServer::Start()
{
    if (m_running) {
        return true;
    }

    struct event_base* base = EventBase();
    if (!base) {
        LogPrintf("Electrum server: event base not available\n");
        return false;
    }

    // Create socket address
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(m_port);

    if (inet_pton(AF_INET, m_bind_address.c_str(), &sin.sin_addr) <= 0) {
        LogPrintf("Electrum server: invalid bind address '%s'\n", m_bind_address);
        return false;
    }

    // Create listener
    m_listener = evconnlistener_new_bind(
        base,
        AcceptCallback,
        this,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
        -1, // backlog
        (struct sockaddr*)&sin,
        sizeof(sin)
    );

    if (!m_listener) {
        LogPrintf("Electrum server: failed to bind to %s:%d\n", m_bind_address, m_port);
        return false;
    }

    evconnlistener_set_error_cb(m_listener, AcceptErrorCallback);

    // Register for validation events
    m_subscription_manager->RegisterValidationInterface();

    m_running = true;
    LogPrintf("Electrum server: listening on %s:%d\n", m_bind_address, m_port);

    return true;
}

void ElectrumServer::Interrupt()
{
    LogPrintf("Electrum server: interrupting\n");
}

void ElectrumServer::Stop()
{
    if (!m_running) {
        return;
    }

    LogPrintf("Electrum server: stopping\n");

    m_running = false;

    // Unregister from validation events
    m_subscription_manager->UnregisterValidationInterface();

    // Close all connections
    {
        LOCK(m_connections_mutex);
        for (auto& [fd, conn] : m_connections) {
            conn->Close();
        }
        m_connections.clear();
    }

    // Free the listener
    if (m_listener) {
        evconnlistener_free(m_listener);
        m_listener = nullptr;
    }

    LogPrintf("Electrum server: stopped\n");
}

void ElectrumServer::AcceptCallback(struct evconnlistener* listener, int fd,
                                     struct sockaddr* addr, int socklen, void* ctx)
{
    ElectrumServer* server = static_cast<ElectrumServer*>(ctx);
    server->OnAccept(fd, addr, socklen);
}

void ElectrumServer::AcceptErrorCallback(struct evconnlistener* listener, void* ctx)
{
    LogPrintf("Electrum server: accept error\n");
}

void ElectrumServer::OnAccept(int fd, struct sockaddr* addr, int socklen)
{
    std::string address;
    if (addr->sa_family == AF_INET) {
        char buf[INET_ADDRSTRLEN];
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        address = std::string(buf) + ":" + std::to_string(ntohs(sin->sin_port));
    } else {
        address = "unknown";
    }

    LogPrintf("Electrum server: new connection from %s (fd=%d)\n", address, fd);

    auto conn = std::make_unique<ElectrumConnection>(this, fd, address);
    conn->Start();

    {
        LOCK(m_connections_mutex);
        m_connections[fd] = std::move(conn);
    }
}

void ElectrumServer::RemoveConnection(int fd)
{
    LOCK(m_connections_mutex);
    auto it = m_connections.find(fd);
    if (it != m_connections.end()) {
        // Remove from subscription manager
        m_subscription_manager->RemoveConnection(it->second.get());
        m_connections.erase(it);
    }
}

UniValue ElectrumServer::ProcessRequest(ElectrumConnection* conn, const UniValue& request)
{
    UniValue response(UniValue::VOBJ);

    // Get method and params
    if (!request.isObject()) {
        response.pushKV("jsonrpc", "2.0");
        UniValue error(UniValue::VOBJ);
        error.pushKV("code", -32600);
        error.pushKV("message", "Invalid Request");
        response.pushKV("error", error);
        return response;
    }

    std::string method;
    UniValue params(UniValue::VARR);
    UniValue id;

    if (request.exists("method")) {
        method = request["method"].get_str();
    }
    if (request.exists("params")) {
        params = request["params"];
    }
    if (request.exists("id")) {
        id = request["id"];
    }

    response.pushKV("jsonrpc", "2.0");
    if (!id.isNull()) {
        response.pushKV("id", id);
    }

    try {
        UniValue result;

        // Route to appropriate handler
        if (method == "server.version") {
            result = HandleServerVersion(conn, params);
        } else if (method == "server.ping") {
            result = HandleServerPing(conn, params);
        } else if (method == "server.banner") {
            result = HandleServerBanner(conn, params);
        } else if (method == "server.features") {
            result = HandleServerFeatures(conn, params);
        } else if (method == "blockchain.headers.subscribe") {
            result = HandleBlockchainHeadersSubscribe(conn, params);
        } else if (method == "blockchain.block.header") {
            result = HandleBlockchainBlockHeader(conn, params);
        } else if (method == "blockchain.block.headers") {
            result = HandleBlockchainBlockHeaders(conn, params);
        } else if (method == "blockchain.transaction.get") {
            result = HandleBlockchainTransactionGet(conn, params);
        } else if (method == "blockchain.transaction.broadcast") {
            result = HandleBlockchainTransactionBroadcast(conn, params);
        } else if (method == "blockchain.scripthash.subscribe") {
            result = HandleBlockchainScripthashSubscribe(conn, params);
        } else if (method == "blockchain.scripthash.unsubscribe") {
            result = HandleBlockchainScripthashUnsubscribe(conn, params);
        } else if (method == "blockchain.scripthash.get_history") {
            result = HandleBlockchainScripthashGetHistory(conn, params);
        } else if (method == "blockchain.scripthash.get_mempool") {
            result = HandleBlockchainScripthashGetMempool(conn, params);
        } else if (method == "blockchain.scripthash.listunspent") {
            result = HandleBlockchainScripthashListunspent(conn, params);
        } else if (method == "blockchain.estimatefee") {
            result = HandleBlockchainEstimateFee(conn, params);
        } else if (method == "blockchain.relayfee") {
            result = HandleBlockchainRelayFee(conn, params);
        } else if (method == "mempool.get_fee_histogram") {
            result = HandleMempoolGetFeeHistogram(conn, params);
        // Wallet methods
        } else if (method == "wallet.create") {
            result = HandleWalletCreate(conn, params);
        } else if (method == "wallet.open") {
            result = HandleWalletOpen(conn, params);
        } else if (method == "wallet.close") {
            result = HandleWalletClose(conn, params);
        } else if (method == "wallet.delete") {
            result = HandleWalletDelete(conn, params);
        } else if (method == "wallet.import_descriptor") {
            result = HandleWalletImportDescriptor(conn, params);
        } else if (method == "wallet.subscribe") {
            result = HandleWalletSubscribe(conn, params);
        } else if (method == "wallet.unsubscribe") {
            result = HandleWalletUnsubscribe(conn, params);
        } else if (method == "wallet.get_info") {
            result = HandleWalletGetInfo(conn, params);
        } else if (method == "wallet.get_transactions") {
            result = HandleWalletGetTransactions(conn, params);
        } else if (method == "wallet.get_transaction") {
            result = HandleWalletGetTransaction(conn, params);
        } else if (method == "wallet.get_utxos") {
            result = HandleWalletGetUtxos(conn, params);
        } else if (method == "wallet.get_address") {
            result = HandleWalletGetAddress(conn, params);
        } else {
            throw std::runtime_error("Unknown method: " + method);
        }

        response.pushKV("result", result);

    } catch (const std::exception& e) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("code", -32601);
        error.pushKV("message", e.what());
        response.pushKV("error", error);
    }

    return response;
}

//
// Server method handlers
//

UniValue ElectrumServer::HandleServerVersion(ElectrumConnection* conn, const UniValue& params)
{
    std::string client_name = "unknown";
    std::string client_version = "1.4";

    // Support both positional (array) and named (object) parameters
    // Some clients use named params in batch mode: {"client_name": "...", "protocol_version": [...]}
    if (params.isArray()) {
        // Positional parameters
        if (params.size() >= 1) {
            client_name = params[0].get_str();
        }
        if (params.size() >= 2) {
            if (params[1].isArray()) {
                // Client specifies range [min, max] - use max
                if (params[1].size() >= 2) {
                    client_version = params[1][1].get_str();
                } else if (params[1].size() >= 1) {
                    client_version = params[1][0].get_str();
                }
            } else {
                // Legacy: single version string (for EPS compatibility)
                client_version = params[1].get_str();
            }
        }
    } else if (params.isObject()) {
        // Named parameters (used by BatchedElectrumServerRpc)
        if (params.exists("client_name")) {
            client_name = params["client_name"].get_str();
        }
        if (params.exists("protocol_version")) {
            const UniValue& pv = params["protocol_version"];
            if (pv.isArray()) {
                if (pv.size() >= 2) {
                    client_version = pv[1].get_str();
                } else if (pv.size() >= 1) {
                    client_version = pv[0].get_str();
                }
            } else {
                client_version = pv.get_str();
            }
        }
    }

    // Negotiate version (use our max for now)
    conn->SetProtocolVersion(ELECTRUM_PROTOCOL_VERSION_MAX);

    LogPrintf("Electrum: client %s (%s) connected, using protocol %s\n",
              client_name, conn->GetAddress(), conn->GetProtocolVersion());

    UniValue result(UniValue::VARR);
    result.push_back(SERVER_VERSION);
    result.push_back(conn->GetProtocolVersion());
    return result;
}

UniValue ElectrumServer::HandleServerPing(ElectrumConnection* conn, const UniValue& params)
{
    return UniValue();  // null response
}

UniValue ElectrumServer::HandleServerBanner(ElectrumConnection* conn, const UniValue& params)
{
    return UniValue("Welcome to Bitcoin Knots Electrum Server\n"
                    "This server provides Electrum protocol access to the Bitcoin network.\n");
}

UniValue ElectrumServer::HandleServerFeatures(ElectrumConnection* conn, const UniValue& params)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("genesis_hash", Params().GenesisBlock().GetHash().GetHex());
    result.pushKV("hash_function", "sha256");

    UniValue hosts(UniValue::VOBJ);
    UniValue host_info(UniValue::VOBJ);
    host_info.pushKV("tcp_port", (int)m_port);
    hosts.pushKV(m_bind_address, host_info);
    result.pushKV("hosts", hosts);

    result.pushKV("protocol_max", ELECTRUM_PROTOCOL_VERSION_MAX);
    result.pushKV("protocol_min", ELECTRUM_PROTOCOL_VERSION_MIN);
    result.pushKV("server_version", SERVER_VERSION);

    // Report pruning status (standard Electrum field)
    ChainstateManager& chainman = *Assert(m_node.chainman);
    if (chainman.m_blockman.IsPruneMode()) {
        result.pushKV("pruning", chainman.m_blockman.GetPruneTarget());
    } else {
        result.pushKV("pruning", UniValue());  // null = not pruned
    }

    // Capability flags (electrum-descriptor extension)
    // Each flag indicates whether that category of methods is available
    bool has_txindex = gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX);
    bool has_addressindex = gArgs.GetBoolArg("-addressindex", false);
    BlockFilterIndex* filter_index = GetBlockFilterIndex(BlockFilterType::BASIC);

    result.pushKV("transaction_get", has_txindex);           // blockchain.transaction.get
    result.pushKV("scripthash_methods", has_addressindex);   // blockchain.scripthash.*
    result.pushKV("descriptor_methods", filter_index != nullptr);  // wallet.*/descriptor.*

    return result;
}

//
// Blockchain header handlers
//

UniValue ElectrumServer::HandleBlockchainHeadersSubscribe(ElectrumConnection* conn, const UniValue& params)
{
    conn->SetSubscribedToHeaders(true);

    // Register with subscription manager for header updates
    {
        LOCK(m_subscription_manager->m_headers_mutex);
        m_subscription_manager->m_header_subscriptions.insert(conn);
    }

    // Return current tip header
    ChainstateManager& chainman = *Assert(m_node.chainman);
    LOCK(cs_main);

    const CBlockIndex* tip = chainman.ActiveChain().Tip();
    if (!tip) {
        throw std::runtime_error("No active chain");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("height", tip->nHeight);

    // Serialize header
    DataStream ss{};
    ss << tip->GetBlockHeader();
    result.pushKV("hex", HexStr(ss));

    return result;
}

UniValue ElectrumServer::HandleBlockchainBlockHeader(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    int height = params[0].getInt<int>();
    bool cp_height = (params.size() >= 2) ? params[1].getInt<int>() : 0;

    ChainstateManager& chainman = *Assert(m_node.chainman);
    LOCK(cs_main);

    if (height < 0 || height > chainman.ActiveChain().Height()) {
        throw std::runtime_error("Invalid height");
    }

    const CBlockIndex* pindex = chainman.ActiveChain()[height];

    DataStream ss{};
    ss << pindex->GetBlockHeader();

    if (cp_height == 0) {
        return UniValue(HexStr(ss));
    }

    // With checkpoint height, return object with proof
    UniValue result(UniValue::VOBJ);
    result.pushKV("header", HexStr(ss));
    // TODO: Add merkle branch proof
    result.pushKV("root", pindex->GetBlockHash().GetHex());
    result.pushKV("branch", UniValue(UniValue::VARR));

    return result;
}

UniValue ElectrumServer::HandleBlockchainBlockHeaders(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 2) {
        throw std::runtime_error("Invalid params");
    }

    int start_height = params[0].getInt<int>();
    int count = params[1].getInt<int>();

    // Limit count
    if (count > 2016) count = 2016;

    ChainstateManager& chainman = *Assert(m_node.chainman);
    LOCK(cs_main);

    if (start_height < 0 || start_height > chainman.ActiveChain().Height()) {
        throw std::runtime_error("Invalid start height");
    }

    int end_height = std::min(start_height + count - 1, chainman.ActiveChain().Height());
    int actual_count = end_height - start_height + 1;

    std::string hex_headers;
    for (int h = start_height; h <= end_height; ++h) {
        const CBlockIndex* pindex = chainman.ActiveChain()[h];
        DataStream ss{};
        ss << pindex->GetBlockHeader();
        hex_headers += HexStr(ss);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("count", actual_count);
    result.pushKV("hex", hex_headers);
    result.pushKV("max", 2016);

    return result;
}

//
// Transaction handlers
//

UniValue ElectrumServer::HandleBlockchainTransactionGet(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    uint256 txid;
    auto txid_opt = uint256::FromHex(params[0].get_str());
    if (!txid_opt) {
        throw std::runtime_error("Invalid txid");
    }
    txid = *txid_opt;

    bool verbose = (params.size() >= 2) ? params[1].get_bool() : false;

    ChainstateManager& chainman = *Assert(m_node.chainman);

    // Get transaction from mempool or blockchain
    uint256 hashBlock;
    CTransactionRef tx = node::GetTransaction(/*block_index=*/nullptr, m_node.mempool.get(), txid, hashBlock, chainman.m_blockman);

    if (!tx) {
        throw std::runtime_error("Transaction not found");
    }

    if (verbose) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("hex", EncodeHexTx(*tx));
        if (!hashBlock.IsNull()) {
            LOCK(cs_main);
            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
            if (pindex) {
                result.pushKV("blockhash", hashBlock.GetHex());
                result.pushKV("confirmations", chainman.ActiveChain().Height() - pindex->nHeight + 1);
                result.pushKV("blocktime", (int64_t)pindex->nTime);
            }
        }
        return result;
    }

    return UniValue(EncodeHexTx(*tx));
}

UniValue ElectrumServer::HandleBlockchainTransactionBroadcast(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    std::string hex_tx = params[0].get_str();

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex_tx)) {
        throw std::runtime_error("Invalid transaction hex");
    }

    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    uint256 txid = tx->GetHash();

    // Broadcast transaction
    std::string err_string;
    const node::TransactionError err = node::BroadcastTransaction(
        m_node, tx, err_string,
        /*max_tx_fee=*/CFeeRate(0), // No fee limit
        /*relay=*/true,
        /*wait_callback=*/true
    );

    if (err != node::TransactionError::OK) {
        throw std::runtime_error(err_string.empty() ? "Transaction rejected" : err_string);
    }

    return UniValue(txid.GetHex());
}

//
// Scripthash handlers
//

UniValue ElectrumServer::HandleBlockchainScripthashSubscribe(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    uint256 scripthash;
    auto scripthash_opt = uint256::FromHex(params[0].get_str());
    if (!scripthash_opt) {
        throw std::runtime_error("Invalid scripthash");
    }
    scripthash = *scripthash_opt;

    // Add subscription
    m_subscription_manager->SubscribeScripthash(conn, scripthash);
    conn->AddScripthashSubscription(scripthash);

    // Return current status
    std::string status = m_subscription_manager->GetScripthashStatus(scripthash);
    if (status.empty()) {
        return UniValue();  // null if no history
    }
    return UniValue(status);
}

UniValue ElectrumServer::HandleBlockchainScripthashUnsubscribe(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    uint256 scripthash;
    auto scripthash_opt = uint256::FromHex(params[0].get_str());
    if (!scripthash_opt) {
        throw std::runtime_error("Invalid scripthash");
    }
    scripthash = *scripthash_opt;

    m_subscription_manager->UnsubscribeScripthash(conn, scripthash);
    bool was_subscribed = conn->RemoveScripthashSubscription(scripthash);

    return UniValue(was_subscribed);
}

UniValue ElectrumServer::HandleBlockchainScripthashGetHistory(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    uint256 scripthash;
    auto scripthash_opt = uint256::FromHex(params[0].get_str());
    if (!scripthash_opt) {
        throw std::runtime_error("Invalid scripthash");
    }
    scripthash = *scripthash_opt;

    // Query address index
    if (!g_addressindex) {
        throw std::runtime_error("Address index not available");
    }

    UniValue result(UniValue::VARR);

    // Get confirmed history from address index
    std::vector<AddressIndexEntry> entries;
    if (g_addressindex->GetHistory(scripthash, entries)) {
        // Deduplicate by txid (we store per-output but Electrum wants per-tx)
        std::map<uint256, int> tx_heights;
        for (const auto& entry : entries) {
            // Use the output's height for the tx
            auto it = tx_heights.find(entry.txid);
            if (it == tx_heights.end() || entry.height < it->second) {
                tx_heights[entry.txid] = entry.height;
            }
            // Also include spending tx if spent
            if (entry.IsSpent()) {
                auto sit = tx_heights.find(entry.spending_txid);
                if (sit == tx_heights.end() || entry.spending_height < sit->second) {
                    tx_heights[entry.spending_txid] = entry.spending_height;
                }
            }
        }

        // Convert to sorted vector (by height, then txid for determinism)
        std::vector<std::pair<int, uint256>> sorted_txs;
        for (const auto& [txid, height] : tx_heights) {
            sorted_txs.emplace_back(height, txid);
        }
        std::sort(sorted_txs.begin(), sorted_txs.end());

        for (const auto& [height, txid] : sorted_txs) {
            UniValue item(UniValue::VOBJ);
            item.pushKV("tx_hash", txid.GetHex());
            item.pushKV("height", height);
            result.push_back(item);
        }
    }

    // Add unconfirmed transactions from mempool
    // TODO: Query mempool for transactions involving this scripthash

    return result;
}

UniValue ElectrumServer::HandleBlockchainScripthashGetMempool(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    uint256 scripthash;
    auto scripthash_opt = uint256::FromHex(params[0].get_str());
    if (!scripthash_opt) {
        throw std::runtime_error("Invalid scripthash");
    }
    scripthash = *scripthash_opt;

    // TODO: Query mempool for unconfirmed transactions
    UniValue result(UniValue::VARR);
    return result;
}

UniValue ElectrumServer::HandleBlockchainScripthashListunspent(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    uint256 scripthash;
    auto scripthash_opt = uint256::FromHex(params[0].get_str());
    if (!scripthash_opt) {
        throw std::runtime_error("Invalid scripthash");
    }
    scripthash = *scripthash_opt;

    // Query address index
    if (!g_addressindex) {
        throw std::runtime_error("Address index not available");
    }

    UniValue result(UniValue::VARR);

    std::vector<AddressIndexEntry> entries;
    if (g_addressindex->GetUnspent(scripthash, entries)) {
        for (const auto& entry : entries) {
            UniValue item(UniValue::VOBJ);
            item.pushKV("tx_hash", entry.txid.GetHex());
            item.pushKV("tx_pos", (int)entry.output_index);
            item.pushKV("height", entry.height);
            item.pushKV("value", entry.value);
            result.push_back(item);
        }
    }

    return result;
}

//
// Fee estimation handlers
//

UniValue ElectrumServer::HandleBlockchainEstimateFee(ElectrumConnection* conn, const UniValue& params)
{
    if (!params.isArray() || params.size() < 1) {
        throw std::runtime_error("Invalid params");
    }

    int num_blocks = params[0].getInt<int>();
    if (num_blocks < 1) num_blocks = 1;

    // Use fee estimator if available
    if (m_node.fee_estimator) {
        FeeCalculation fee_calc;
        CFeeRate fee_rate = m_node.fee_estimator->estimateSmartFee(num_blocks, &fee_calc, true);
        if (fee_rate != CFeeRate(0)) {
            // Return fee in BTC/kB (Electrum format)
            return UniValue(fee_rate.GetFeePerK() / 100000000.0);
        }
    }

    // Return -1 if estimation not available
    return UniValue(-1);
}

UniValue ElectrumServer::HandleBlockchainRelayFee(ElectrumConnection* conn, const UniValue& params)
{
    // Return minimum relay fee in BTC/kB
    if (m_node.mempool) {
        return UniValue(m_node.mempool->m_opts.min_relay_feerate.GetFeePerK() / 100000000.0);
    }
    // Fallback to default
    return UniValue(DEFAULT_MIN_RELAY_TX_FEE / 100000000.0);
}

UniValue ElectrumServer::HandleMempoolGetFeeHistogram(ElectrumConnection* conn, const UniValue& params)
{
    // Return fee histogram as array of [fee, vsize] pairs
    // Fee is in satoshis/byte
    UniValue result(UniValue::VARR);

    if (!m_node.mempool) {
        return result;
    }

    // Get histogram from mempool
    // TODO: Implement proper fee histogram
    // For now, return empty array

    return result;
}

//
// Wallet method handlers
//

UniValue ElectrumServer::HandleWalletCreate(ElectrumConnection* conn, const UniValue& params)
{
    // params: {"wallet_id": "optional_id"} or [optional_id]
    std::string wallet_id;
    if (params.isArray() && params.size() > 0) {
        wallet_id = params[0].get_str();
    } else if (params.isObject() && params.exists("wallet_id")) {
        wallet_id = params["wallet_id"].get_str();
    }

    auto result = m_wallet_manager->CreateWallet(wallet_id);
    if (!result.success) {
        throw std::runtime_error(result.error);
    }

    // Set this wallet as active for the connection
    conn->SetWalletId(result.wallet_id);

    UniValue response(UniValue::VOBJ);
    response.pushKV("wallet_id", result.wallet_id);
    return response;
}

UniValue ElectrumServer::HandleWalletOpen(ElectrumConnection* conn, const UniValue& params)
{
    // params: {"wallet_id": "id"} or [wallet_id]
    std::string wallet_id;
    if (params.isArray() && params.size() > 0) {
        wallet_id = params[0].get_str();
    } else if (params.isObject() && params.exists("wallet_id")) {
        wallet_id = params["wallet_id"].get_str();
    } else {
        throw std::runtime_error("wallet_id required");
    }

    auto result = m_wallet_manager->OpenWallet(wallet_id);
    if (!result.success) {
        throw std::runtime_error(result.error);
    }

    // Set this wallet as active for the connection
    conn->SetWalletId(wallet_id);

    UniValue response(UniValue::VOBJ);
    response.pushKV("wallet_id", wallet_id);
    return response;
}

UniValue ElectrumServer::HandleWalletClose(ElectrumConnection* conn, const UniValue& params)
{
    // Use connection's active wallet if not specified
    std::string wallet_id = conn->GetWalletId();
    if (params.isArray() && params.size() > 0) {
        wallet_id = params[0].get_str();
    } else if (params.isObject() && params.exists("wallet_id")) {
        wallet_id = params["wallet_id"].get_str();
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    auto result = m_wallet_manager->CloseWallet(wallet_id);
    if (!result.success) {
        throw std::runtime_error(result.error);
    }

    // Clear active wallet if it was the one we closed
    if (conn->GetWalletId() == wallet_id) {
        conn->SetWalletId("");
        conn->SetSubscribedToWallet(false);
    }

    return UniValue(true);
}

UniValue ElectrumServer::HandleWalletDelete(ElectrumConnection* conn, const UniValue& params)
{
    // params: {"wallet_id": "id"} or [wallet_id]
    std::string wallet_id;
    if (params.isArray() && params.size() > 0) {
        wallet_id = params[0].get_str();
    } else if (params.isObject() && params.exists("wallet_id")) {
        wallet_id = params["wallet_id"].get_str();
    } else {
        throw std::runtime_error("wallet_id required");
    }

    auto result = m_wallet_manager->DeleteWallet(wallet_id);
    if (!result.success) {
        throw std::runtime_error(result.error);
    }

    // Clear active wallet if it was the one we deleted
    if (conn->GetWalletId() == wallet_id) {
        conn->SetWalletId("");
        conn->SetSubscribedToWallet(false);
    }

    return UniValue(true);
}

UniValue ElectrumServer::HandleWalletImportDescriptor(ElectrumConnection* conn, const UniValue& params)
{
    // params: {"wallet_id": "id", "descriptor": "desc", "range": [start, end], "timestamp": "now"/"timestamp", "internal": false}
    std::string wallet_id = conn->GetWalletId();
    std::string descriptor;
    int range_start = 0;
    int range_end = 1000;
    std::string timestamp = "now";
    bool internal = false;

    if (params.isObject()) {
        if (params.exists("wallet_id")) {
            wallet_id = params["wallet_id"].get_str();
        }
        if (params.exists("descriptor")) {
            descriptor = params["descriptor"].get_str();
        } else {
            throw std::runtime_error("descriptor required");
        }
        if (params.exists("range")) {
            const UniValue& range = params["range"];
            if (range.isArray() && range.size() >= 2) {
                range_start = range[0].getInt<int>();
                range_end = range[1].getInt<int>();
            }
        }
        if (params.exists("timestamp")) {
            if (params["timestamp"].isStr()) {
                timestamp = params["timestamp"].get_str();
            } else {
                timestamp = std::to_string(params["timestamp"].getInt<int64_t>());
            }
        }
        if (params.exists("internal")) {
            internal = params["internal"].get_bool();
        }
    } else {
        throw std::runtime_error("Object params required for wallet.import_descriptor");
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    // Create callbacks for async notifications via subscription manager
    SubscriptionManager* sub_mgr = m_subscription_manager.get();

    auto progress_callback = [sub_mgr](const std::string& wid, int current, int total, double progress) {
        sub_mgr->NotifyWalletScanProgress(wid, current, total, progress);
    };

    auto complete_callback = [sub_mgr](const std::string& wid, bool success, const std::string& error) {
        sub_mgr->NotifyWalletScanComplete(wid, success, error);
    };

    auto result = m_wallet_manager->ImportDescriptorAsync(
        wallet_id, descriptor, range_start, range_end, timestamp, internal,
        progress_callback, complete_callback);

    if (!result.success) {
        throw std::runtime_error(result.error);
    }

    // Return immediately - rescan runs in background if needed
    // Client should subscribe to wallet to receive progress/completion notifications
    return UniValue(true);
}

UniValue ElectrumServer::HandleWalletSubscribe(ElectrumConnection* conn, const UniValue& params)
{
    std::string wallet_id = conn->GetWalletId();
    if (params.isArray() && params.size() > 0) {
        wallet_id = params[0].get_str();
    } else if (params.isObject() && params.exists("wallet_id")) {
        wallet_id = params["wallet_id"].get_str();
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    // Set subscription state
    conn->SetWalletId(wallet_id);
    conn->SetSubscribedToWallet(true);

    // Register with subscription manager for wallet notifications
    m_subscription_manager->SubscribeWallet(conn, wallet_id);

    return UniValue(true);
}

UniValue ElectrumServer::HandleWalletUnsubscribe(ElectrumConnection* conn, const UniValue& params)
{
    std::string wallet_id = conn->GetWalletId();
    if (params.isArray() && params.size() > 0) {
        wallet_id = params[0].get_str();
    } else if (params.isObject() && params.exists("wallet_id")) {
        wallet_id = params["wallet_id"].get_str();
    }

    bool was_subscribed = conn->IsSubscribedToWallet() && conn->GetWalletId() == wallet_id;
    conn->SetSubscribedToWallet(false);

    // Unregister from subscription manager
    if (was_subscribed) {
        m_subscription_manager->UnsubscribeWallet(conn, wallet_id);
    }

    return UniValue(was_subscribed);
}

UniValue ElectrumServer::HandleWalletGetInfo(ElectrumConnection* conn, const UniValue& params)
{
    std::string wallet_id = conn->GetWalletId();
    if (params.isArray() && params.size() > 0) {
        wallet_id = params[0].get_str();
    } else if (params.isObject() && params.exists("wallet_id")) {
        wallet_id = params["wallet_id"].get_str();
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    auto [info, error] = m_wallet_manager->GetWalletInfo(wallet_id);
    if (!error.empty()) {
        throw std::runtime_error(error);
    }

    return info;
}

UniValue ElectrumServer::HandleWalletGetTransactions(ElectrumConnection* conn, const UniValue& params)
{
    std::string wallet_id = conn->GetWalletId();
    int limit = 100;
    int offset = 0;

    if (params.isObject()) {
        if (params.exists("wallet_id")) {
            wallet_id = params["wallet_id"].get_str();
        }
        if (params.exists("limit")) {
            limit = params["limit"].getInt<int>();
        }
        if (params.exists("offset")) {
            offset = params["offset"].getInt<int>();
        }
    } else if (params.isArray()) {
        if (params.size() > 0) wallet_id = params[0].get_str();
        if (params.size() > 1) limit = params[1].getInt<int>();
        if (params.size() > 2) offset = params[2].getInt<int>();
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    auto [txs, error] = m_wallet_manager->GetTransactions(wallet_id, limit, offset);
    if (!error.empty()) {
        throw std::runtime_error(error);
    }

    UniValue result(UniValue::VARR);
    for (const auto& tx : txs) {
        UniValue txObj(UniValue::VOBJ);
        txObj.pushKV("tx_hash", tx.txid);
        txObj.pushKV("height", tx.height);
        txObj.pushKV("timestamp", tx.timestamp);
        txObj.pushKV("value", tx.value);
        txObj.pushKV("hex", tx.raw_hex);
        result.push_back(txObj);
    }

    return result;
}

UniValue ElectrumServer::HandleWalletGetTransaction(ElectrumConnection* conn, const UniValue& params)
{
    std::string wallet_id = conn->GetWalletId();
    std::string txid;

    if (params.isObject()) {
        if (params.exists("wallet_id")) {
            wallet_id = params["wallet_id"].get_str();
        }
        if (params.exists("txid")) {
            txid = params["txid"].get_str();
        } else {
            throw std::runtime_error("txid required");
        }
    } else if (params.isArray() && params.size() >= 1) {
        txid = params[0].get_str();
        if (params.size() > 1) wallet_id = params[1].get_str();
    } else {
        throw std::runtime_error("txid required");
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    auto [tx, error] = m_wallet_manager->GetTransaction(wallet_id, txid);
    if (!error.empty()) {
        throw std::runtime_error(error);
    }
    if (!tx) {
        throw std::runtime_error("Transaction not found");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("tx_hash", tx->txid);
    result.pushKV("height", tx->height);
    result.pushKV("timestamp", tx->timestamp);
    result.pushKV("value", tx->value);
    result.pushKV("hex", tx->raw_hex);

    return result;
}

UniValue ElectrumServer::HandleWalletGetUtxos(ElectrumConnection* conn, const UniValue& params)
{
    std::string wallet_id = conn->GetWalletId();
    int min_confirmations = 0;

    if (params.isObject()) {
        if (params.exists("wallet_id")) {
            wallet_id = params["wallet_id"].get_str();
        }
        if (params.exists("min_confirmations")) {
            min_confirmations = params["min_confirmations"].getInt<int>();
        }
    } else if (params.isArray()) {
        if (params.size() > 0) wallet_id = params[0].get_str();
        if (params.size() > 1) min_confirmations = params[1].getInt<int>();
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    auto [utxos, error] = m_wallet_manager->GetUTXOs(wallet_id, min_confirmations);
    if (!error.empty()) {
        throw std::runtime_error(error);
    }

    UniValue result(UniValue::VARR);
    for (const auto& utxo : utxos) {
        UniValue utxoObj(UniValue::VOBJ);
        utxoObj.pushKV("tx_hash", utxo.txid);
        utxoObj.pushKV("tx_pos", static_cast<int>(utxo.vout));
        utxoObj.pushKV("height", utxo.height);
        utxoObj.pushKV("value", utxo.value);
        result.push_back(utxoObj);
    }

    return result;
}

UniValue ElectrumServer::HandleWalletGetAddress(ElectrumConnection* conn, const UniValue& params)
{
    std::string wallet_id = conn->GetWalletId();
    std::string label;

    if (params.isObject()) {
        if (params.exists("wallet_id")) {
            wallet_id = params["wallet_id"].get_str();
        }
        if (params.exists("label")) {
            label = params["label"].get_str();
        }
    } else if (params.isArray()) {
        if (params.size() > 0) wallet_id = params[0].get_str();
        if (params.size() > 1) label = params[1].get_str();
    }

    if (wallet_id.empty()) {
        throw std::runtime_error("No active wallet");
    }

    auto [address, error] = m_wallet_manager->GetNewAddress(wallet_id, label);
    if (!error.empty()) {
        throw std::runtime_error(error);
    }

    return UniValue(address);
}

//
// ElectrumConnection implementation
//

ElectrumConnection::ElectrumConnection(ElectrumServer* server, int fd, const std::string& address)
    : m_server(server), m_fd(fd), m_address(address)
{
}

ElectrumConnection::~ElectrumConnection()
{
    Close();
}

void ElectrumConnection::Start()
{
    struct event_base* base = EventBase();
    if (!base) {
        LogPrintf("Electrum: connection %s - no event base\n", m_address);
        return;
    }

    m_bev = bufferevent_socket_new(base, m_fd, BEV_OPT_CLOSE_ON_FREE);
    if (!m_bev) {
        LogPrintf("Electrum: connection %s - failed to create bufferevent\n", m_address);
        return;
    }

    bufferevent_setcb(m_bev, ReadCallback, WriteCallback, EventCallback, this);
    bufferevent_enable(m_bev, EV_READ | EV_WRITE);
}

void ElectrumConnection::Close()
{
    if (m_bev) {
        bufferevent_free(m_bev);
        m_bev = nullptr;
    }
    m_fd = -1;
}

void ElectrumConnection::Send(const UniValue& response)
{
    if (!m_bev) return;

    std::string json = response.write() + "\n";
    bufferevent_write(m_bev, json.data(), json.size());
}

void ElectrumConnection::SendNotification(const std::string& method, const UniValue& params)
{
    UniValue notification(UniValue::VOBJ);
    notification.pushKV("jsonrpc", "2.0");
    notification.pushKV("method", method);
    notification.pushKV("params", params);
    Send(notification);
}

void ElectrumConnection::ReadCallback(::bufferevent* bev, void* ctx)
{
    ElectrumConnection* conn = static_cast<ElectrumConnection*>(ctx);

    struct evbuffer* input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);

    if (len == 0) return;

    // Read into buffer
    std::vector<char> data(len);
    evbuffer_remove(input, data.data(), len);
    conn->m_read_buffer.append(data.data(), len);

    // Process complete messages (newline-delimited)
    size_t pos;
    while ((pos = conn->m_read_buffer.find('\n')) != std::string::npos) {
        std::string message = conn->m_read_buffer.substr(0, pos);
        conn->m_read_buffer.erase(0, pos + 1);

        if (!message.empty()) {
            conn->ProcessMessage(message);
        }
    }
}

void ElectrumConnection::WriteCallback(::bufferevent* bev, void* ctx)
{
    // Nothing to do on write complete
}

void ElectrumConnection::EventCallback(::bufferevent* bev, short events, void* ctx)
{
    ElectrumConnection* conn = static_cast<ElectrumConnection*>(ctx);

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        LogPrintf("Electrum: connection %s closed\n", conn->m_address);
        int fd = conn->m_fd;
        conn->m_server->RemoveConnection(fd);
    }
}

void ElectrumConnection::ProcessMessage(const std::string& message)
{
    UniValue request;
    if (!request.read(message)) {
        LogPrintf("Electrum: %s - invalid JSON: %s\n", m_address, message.substr(0, 100));
        return;
    }

    UniValue response = m_server->ProcessRequest(this, request);

    // Only send response if there's an id (not for notifications)
    if (request.exists("id") && !request["id"].isNull()) {
        Send(response);
    }
}

//
// SubscriptionManager implementation
//

SubscriptionManager::SubscriptionManager(ElectrumServer& server)
    : m_server(server)
{
}

SubscriptionManager::~SubscriptionManager()
{
}

void SubscriptionManager::RegisterValidationInterface()
{
    if (m_server.GetNodeContext().validation_signals) {
        m_server.GetNodeContext().validation_signals->RegisterValidationInterface(this);
    }
}

void SubscriptionManager::UnregisterValidationInterface()
{
    if (m_server.GetNodeContext().validation_signals) {
        m_server.GetNodeContext().validation_signals->UnregisterValidationInterface(this);
    }
}

void SubscriptionManager::SubscribeScripthash(ElectrumConnection* conn, const uint256& scripthash)
{
    LOCK(m_scripthash_mutex);
    m_scripthash_subscriptions[scripthash].insert(conn);
}

void SubscriptionManager::UnsubscribeScripthash(ElectrumConnection* conn, const uint256& scripthash)
{
    LOCK(m_scripthash_mutex);
    auto it = m_scripthash_subscriptions.find(scripthash);
    if (it != m_scripthash_subscriptions.end()) {
        it->second.erase(conn);
        if (it->second.empty()) {
            m_scripthash_subscriptions.erase(it);
        }
    }
}

void SubscriptionManager::SubscribeWallet(ElectrumConnection* conn, const std::string& wallet_id)
{
    LOCK(m_wallet_mutex);
    m_wallet_subscriptions[wallet_id].insert(conn);
    LogPrintf("Electrum: connection %s subscribed to wallet %s\n", conn->GetAddress(), wallet_id);
}

void SubscriptionManager::UnsubscribeWallet(ElectrumConnection* conn, const std::string& wallet_id)
{
    LOCK(m_wallet_mutex);
    auto it = m_wallet_subscriptions.find(wallet_id);
    if (it != m_wallet_subscriptions.end()) {
        it->second.erase(conn);
        if (it->second.empty()) {
            m_wallet_subscriptions.erase(it);
        }
    }
}

void SubscriptionManager::RemoveConnection(ElectrumConnection* conn)
{
    {
        LOCK(m_scripthash_mutex);
        for (auto& [scripthash, conns] : m_scripthash_subscriptions) {
            conns.erase(conn);
        }
        // Clean up empty scripthash entries
        for (auto it = m_scripthash_subscriptions.begin(); it != m_scripthash_subscriptions.end(); ) {
            if (it->second.empty()) {
                it = m_scripthash_subscriptions.erase(it);
            } else {
                ++it;
            }
        }
    }

    {
        LOCK(m_headers_mutex);
        m_header_subscriptions.erase(conn);
    }

    {
        LOCK(m_wallet_mutex);
        for (auto& [wallet_id, conns] : m_wallet_subscriptions) {
            conns.erase(conn);
        }
        // Clean up empty wallet entries
        for (auto it = m_wallet_subscriptions.begin(); it != m_wallet_subscriptions.end(); ) {
            if (it->second.empty()) {
                it = m_wallet_subscriptions.erase(it);
            } else {
                ++it;
            }
        }
    }
}

std::string SubscriptionManager::GetScripthashStatus(const uint256& scripthash)
{
    if (!g_addressindex) {
        return "";
    }

    // Get history and compute status hash
    std::vector<AddressIndexEntry> entries;
    if (!g_addressindex->GetHistory(scripthash, entries) || entries.empty()) {
        return "";
    }

    // Deduplicate by txid and collect (height, txid) pairs
    std::map<uint256, int> tx_heights;
    for (const auto& entry : entries) {
        auto it = tx_heights.find(entry.txid);
        if (it == tx_heights.end() || entry.height < it->second) {
            tx_heights[entry.txid] = entry.height;
        }
        // Also include spending tx if spent
        if (entry.IsSpent()) {
            auto sit = tx_heights.find(entry.spending_txid);
            if (sit == tx_heights.end() || entry.spending_height < sit->second) {
                tx_heights[entry.spending_txid] = entry.spending_height;
            }
        }
    }

    // Sort by height, then txid
    std::vector<std::pair<int, uint256>> sorted_txs;
    for (const auto& [txid, height] : tx_heights) {
        sorted_txs.emplace_back(height, txid);
    }
    std::sort(sorted_txs.begin(), sorted_txs.end());

    // Status is SHA256 of concatenated "txid:height:" strings
    // Electrum protocol format: lowercase hex, colon-separated
    std::string status_preimage;
    for (const auto& [height, txid] : sorted_txs) {
        status_preimage += txid.GetHex() + ":" + std::to_string(height) + ":";
    }

    // TODO: Add mempool transactions to status

    uint256 status_hash;
    CSHA256().Write((unsigned char*)status_preimage.data(), status_preimage.size())
             .Finalize(status_hash.begin());

    return status_hash.GetHex();
}

void SubscriptionManager::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
{
    if (fInitialDownload) return;

    NotifyHeaderSubscribers(pindexNew);
}

void SubscriptionManager::TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence)
{
    // Find affected scripthashes and notify subscribers
    auto affected_scripthashes = GetAffectedScripthashes(tx.info.m_tx);
    for (const auto& scripthash : affected_scripthashes) {
        NotifyScripthashSubscribers(scripthash);
    }

    // Find affected wallets and notify subscribers about new unconfirmed transaction
    auto affected_wallets = GetAffectedWallets(tx.info.m_tx);
    for (const auto& wallet_id : affected_wallets) {
        NotifyWalletTransaction(wallet_id, tx.info.m_tx->GetHash(), 0);  // 0 confirmations
        NotifyWalletBalanceChanged(wallet_id);
    }
}

void SubscriptionManager::TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t mempool_sequence)
{
    // Notify for removed transactions too
    auto affected = GetAffectedScripthashes(tx);
    for (const auto& scripthash : affected) {
        NotifyScripthashSubscribers(scripthash);
    }
}

void SubscriptionManager::BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex)
{
    if (role != ChainstateRole::NORMAL) return;

    // Notify header subscribers
    NotifyHeaderSubscribers(pindex);

    // Notify scripthash subscribers for each transaction in block
    std::set<uint256> affected_scripthashes;
    std::set<std::string> affected_wallets;
    for (const auto& tx : block->vtx) {
        auto scripthashes = GetAffectedScripthashes(tx);
        affected_scripthashes.insert(scripthashes.begin(), scripthashes.end());

        auto wallets = GetAffectedWallets(tx);
        affected_wallets.insert(wallets.begin(), wallets.end());
    }

    for (const auto& scripthash : affected_scripthashes) {
        NotifyScripthashSubscribers(scripthash);
    }

    // Notify wallet subscribers about confirmed transactions
    ChainstateManager& chainman = *Assert(m_server.GetNodeContext().chainman);
    int confirmations;
    {
        LOCK(cs_main);
        confirmations = chainman.ActiveChain().Height() - pindex->nHeight + 1;
    }

    for (const auto& wallet_id : affected_wallets) {
        // Notify about each transaction in the block that affects this wallet
        for (const auto& tx : block->vtx) {
            auto wallets = GetAffectedWallets(tx);
            if (wallets.count(wallet_id)) {
                NotifyWalletTransaction(wallet_id, tx->GetHash(), confirmations);
            }
        }
        // Also notify about balance change
        NotifyWalletBalanceChanged(wallet_id);
    }
}

void SubscriptionManager::BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex)
{
    // Similar to BlockConnected - notify affected subscribers
    std::set<uint256> affected_scripthashes;
    for (const auto& tx : block->vtx) {
        auto affected = GetAffectedScripthashes(tx);
        affected_scripthashes.insert(affected.begin(), affected.end());
    }

    for (const auto& scripthash : affected_scripthashes) {
        NotifyScripthashSubscribers(scripthash);
    }
}

void SubscriptionManager::NotifyHeaderSubscribers(const CBlockIndex* pindex)
{
    LOCK(m_headers_mutex);

    if (m_header_subscriptions.empty()) return;

    // Build notification
    UniValue params(UniValue::VARR);
    UniValue header_info(UniValue::VOBJ);
    header_info.pushKV("height", pindex->nHeight);

    DataStream ss{};
    ss << pindex->GetBlockHeader();
    header_info.pushKV("hex", HexStr(ss));

    params.push_back(header_info);

    // Send to all subscribers
    for (auto* conn : m_header_subscriptions) {
        conn->SendNotification("blockchain.headers.subscribe", params);
    }
}

void SubscriptionManager::NotifyScripthashSubscribers(const uint256& scripthash)
{
    LOCK(m_scripthash_mutex);

    auto it = m_scripthash_subscriptions.find(scripthash);
    if (it == m_scripthash_subscriptions.end() || it->second.empty()) {
        return;
    }

    // Compute new status
    std::string new_status = GetScripthashStatus(scripthash);

    // Build notification
    UniValue params(UniValue::VARR);
    params.push_back(scripthash.GetHex());
    if (new_status.empty()) {
        params.push_back(UniValue());  // null
    } else {
        params.push_back(new_status);
    }

    // Send to all subscribers
    for (auto* conn : it->second) {
        conn->SendNotification("blockchain.scripthash.subscribe", params);
    }
}

std::set<uint256> SubscriptionManager::GetAffectedScripthashes(const CTransactionRef& tx)
{
    std::set<uint256> result;

    // Check outputs
    for (const auto& output : tx->vout) {
        uint256 scripthash;
        CSHA256().Write(output.scriptPubKey.data(), output.scriptPubKey.size())
                 .Finalize(scripthash.begin());
        // Byte-reverse to match Electrum format
        std::reverse(scripthash.begin(), scripthash.end());

        LOCK(m_scripthash_mutex);
        if (m_scripthash_subscriptions.count(scripthash)) {
            result.insert(scripthash);
        }
    }

    // Check inputs (for spent outputs)
    // Note: Would need to look up previous outputs to get their scripthashes
    // For efficiency, skip for now and rely on address index updates

    return result;
}

std::set<std::string> SubscriptionManager::GetAffectedWallets(const CTransactionRef& tx)
{
    std::set<std::string> result;

    // Get the list of subscribed wallet IDs
    std::vector<std::string> subscribed_wallets;
    {
        LOCK(m_wallet_mutex);
        for (const auto& [wallet_id, conns] : m_wallet_subscriptions) {
            if (!conns.empty()) {
                subscribed_wallets.push_back(wallet_id);
            }
        }
    }

    if (subscribed_wallets.empty()) {
        return result;
    }

    // Check each subscribed wallet to see if this transaction involves it
    if (!m_server.GetWalletManager()) {
        return result;
    }

    for (const auto& wallet_id : subscribed_wallets) {
        auto [tx_info, error] = m_server.GetWalletManager()->GetTransaction(wallet_id, tx->GetHash().GetHex());
        if (tx_info.has_value()) {
            result.insert(wallet_id);
        }
    }

    return result;
}

void SubscriptionManager::NotifyWalletTransaction(const std::string& wallet_id, const uint256& txid, int confirmations)
{
    LOCK(m_wallet_mutex);

    auto it = m_wallet_subscriptions.find(wallet_id);
    if (it == m_wallet_subscriptions.end() || it->second.empty()) {
        return;
    }

    // Build notification
    UniValue params(UniValue::VARR);
    params.push_back(wallet_id);

    UniValue tx_info(UniValue::VOBJ);
    tx_info.pushKV("txid", txid.GetHex());
    tx_info.pushKV("confirmations", confirmations);
    params.push_back(tx_info);

    // Send to all subscribers
    for (auto* conn : it->second) {
        if (confirmations == 0) {
            conn->SendNotification("wallet.tx_added", params);
        } else {
            conn->SendNotification("wallet.tx_confirmed", params);
        }
    }

    LogPrintf("Electrum: notified %d subscribers of wallet %s tx %s (confirmations=%d)\n",
              it->second.size(), wallet_id, txid.GetHex(), confirmations);
}

void SubscriptionManager::NotifyWalletBalanceChanged(const std::string& wallet_id)
{
    LOCK(m_wallet_mutex);

    auto it = m_wallet_subscriptions.find(wallet_id);
    if (it == m_wallet_subscriptions.end() || it->second.empty()) {
        return;
    }

    // Get current balance
    if (!m_server.GetWalletManager()) {
        return;
    }

    auto [balance, error] = m_server.GetWalletManager()->GetBalance(wallet_id);
    if (!error.empty()) {
        return;
    }

    // Build notification
    UniValue params(UniValue::VARR);
    params.push_back(wallet_id);

    UniValue balance_info(UniValue::VOBJ);
    balance_info.pushKV("confirmed", balance.confirmed);
    balance_info.pushKV("unconfirmed", balance.unconfirmed);
    params.push_back(balance_info);

    // Send to all subscribers
    for (auto* conn : it->second) {
        conn->SendNotification("wallet.balance_changed", params);
    }
}

void SubscriptionManager::NotifyWalletScanProgress(const std::string& wallet_id, int current_height, int total_height, double progress)
{
    LOCK(m_wallet_mutex);

    auto it = m_wallet_subscriptions.find(wallet_id);
    if (it == m_wallet_subscriptions.end() || it->second.empty()) {
        return;
    }

    UniValue params(UniValue::VARR);
    params.push_back(wallet_id);

    UniValue progress_info(UniValue::VOBJ);
    progress_info.pushKV("current_height", current_height);
    progress_info.pushKV("total_height", total_height);
    progress_info.pushKV("progress", progress);
    params.push_back(progress_info);

    for (auto* conn : it->second) {
        conn->SendNotification("wallet.scan_progress", params);
    }
}

void SubscriptionManager::NotifyWalletScanComplete(const std::string& wallet_id, bool success, const std::string& error)
{
    LOCK(m_wallet_mutex);

    auto it = m_wallet_subscriptions.find(wallet_id);
    if (it == m_wallet_subscriptions.end() || it->second.empty()) {
        return;
    }

    UniValue params(UniValue::VARR);
    params.push_back(wallet_id);

    UniValue result_info(UniValue::VOBJ);
    result_info.pushKV("success", success);
    if (!success) {
        result_info.pushKV("error", error);
    }
    params.push_back(result_info);

    for (auto* conn : it->second) {
        conn->SendNotification("wallet.scan_complete", params);
    }
}

//
// Global initialization functions
//

bool InitElectrumServer(node::NodeContext& node)
{
    if (!gArgs.GetBoolArg("-electrum", false)) {
        return true;  // Not enabled
    }

    g_electrum_server = std::make_unique<ElectrumServer>(node);
    return g_electrum_server->Init();
}

bool StartElectrumServer()
{
    if (!g_electrum_server) {
        return true;  // Not enabled
    }

    return g_electrum_server->Start();
}

void InterruptElectrumServer()
{
    if (g_electrum_server) {
        g_electrum_server->Interrupt();
    }
}

void StopElectrumServer()
{
    if (g_electrum_server) {
        g_electrum_server->Stop();
        g_electrum_server.reset();
    }
}

} // namespace electrum
