// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ELECTRUM_ELECTRUMSERVER_H
#define BITCOIN_ELECTRUM_ELECTRUMSERVER_H

#include <net.h>
#include <sync.h>
#include <threadsafety.h>
#include <uint256.h>
#include <univalue.h>
#include <validationinterface.h>

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

// Forward declarations for libevent types (must be outside any namespace)
struct event_base;
struct event;
struct evconnlistener;
struct bufferevent;

class CBlockIndex;
class ChainstateManager;
class CTxMemPool;
namespace node {
struct NodeContext;
}

namespace electrum {

class ElectrumConnection;
class ElectrumWalletManager;
class SubscriptionManager;

/**
 * Electrum protocol server for Bitcoin Knots.
 *
 * Implements the Electrum JSON-RPC protocol over TCP, compatible with
 * Electrum-compatible wallets. Uses the shared libevent event loop from the
 * HTTP server for efficient async I/O.
 *
 * Protocol: Newline-delimited JSON-RPC 2.0
 * Default port: 50001 (TCP), 50002 (SSL - future)
 */
class ElectrumServer
{
public:
    ElectrumServer(node::NodeContext& node);
    ~ElectrumServer();

    /** Initialize the server (called before Start) */
    bool Init();

    /** Start listening for connections */
    bool Start();

    /** Stop the server and close all connections */
    void Stop();

    /** Interrupt pending operations */
    void Interrupt();

    /** Process an RPC request and return response */
    UniValue ProcessRequest(ElectrumConnection* conn, const UniValue& request);

    /** Get the subscription manager */
    SubscriptionManager& GetSubscriptionManager() { return *m_subscription_manager; }

    /** Get node context */
    node::NodeContext& GetNodeContext() { return m_node; }

    /** Get wallet manager */
    ElectrumWalletManager* GetWalletManager() { return m_wallet_manager.get(); }

private:
    node::NodeContext& m_node;

    /** The libevent listener for accepting connections */
    struct evconnlistener* m_listener{nullptr};

    /** All active connections */
    mutable Mutex m_connections_mutex;
    std::map<int, std::unique_ptr<ElectrumConnection>> m_connections GUARDED_BY(m_connections_mutex);

    /** Subscription manager for scripthash and header subscriptions */
    std::unique_ptr<SubscriptionManager> m_subscription_manager;

    /** Wallet manager for descriptor wallet operations */
    std::unique_ptr<ElectrumWalletManager> m_wallet_manager;

    /** Server state */
    std::atomic<bool> m_running{false};

    /** Port to listen on */
    uint16_t m_port{50001};

    /** Bind address */
    std::string m_bind_address{"127.0.0.1"};

    /** Callbacks for libevent */
    static void AcceptCallback(struct evconnlistener* listener, int fd,
                               struct sockaddr* addr, int socklen, void* ctx);
    static void AcceptErrorCallback(struct evconnlistener* listener, void* ctx);

    /** Handle a new connection */
    void OnAccept(int fd, struct sockaddr* addr, int socklen);

    /** Remove a connection (called when connection closes) */
    void RemoveConnection(int fd);

    /** RPC method handlers */
    UniValue HandleServerVersion(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleServerPing(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleServerBanner(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleServerFeatures(ElectrumConnection* conn, const UniValue& params);

    UniValue HandleBlockchainHeadersSubscribe(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainBlockHeader(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainBlockHeaders(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainTransactionGet(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainTransactionBroadcast(ElectrumConnection* conn, const UniValue& params);

    UniValue HandleBlockchainScripthashSubscribe(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainScripthashUnsubscribe(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainScripthashGetHistory(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainScripthashGetMempool(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainScripthashListunspent(ElectrumConnection* conn, const UniValue& params);

    UniValue HandleBlockchainEstimateFee(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleBlockchainRelayFee(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleMempoolGetFeeHistogram(ElectrumConnection* conn, const UniValue& params);

    /** Wallet method handlers */
    UniValue HandleWalletCreate(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletOpen(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletClose(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletDelete(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletImportDescriptor(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletSubscribe(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletUnsubscribe(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletGetInfo(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletGetTransactions(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletGetTransaction(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletGetUtxos(ElectrumConnection* conn, const UniValue& params);
    UniValue HandleWalletGetAddress(ElectrumConnection* conn, const UniValue& params);

    friend class ElectrumConnection;
};

/**
 * Represents a single client connection to the Electrum server.
 */
class ElectrumConnection
{
public:
    ElectrumConnection(ElectrumServer* server, int fd, const std::string& address);
    ~ElectrumConnection();

    /** Start reading from this connection */
    void Start();

    /** Send a JSON-RPC response or notification */
    void Send(const UniValue& response);

    /** Send a notification (no id field) */
    void SendNotification(const std::string& method, const UniValue& params);

    /** Close this connection */
    void Close();

    /** Get the file descriptor */
    int GetFd() const { return m_fd; }

    /** Get the client address string */
    const std::string& GetAddress() const { return m_address; }

    /** Check if connection is subscribed to headers */
    bool IsSubscribedToHeaders() const { return m_subscribed_headers; }

    /** Set header subscription state */
    void SetSubscribedToHeaders(bool subscribed) { m_subscribed_headers = subscribed; }

    /** Get scripthash subscriptions */
    const std::set<uint256>& GetScripthashSubscriptions() const { return m_subscribed_scripthashes; }

    /** Add scripthash subscription */
    void AddScripthashSubscription(const uint256& scripthash) { m_subscribed_scripthashes.insert(scripthash); }

    /** Remove scripthash subscription */
    bool RemoveScripthashSubscription(const uint256& scripthash) { return m_subscribed_scripthashes.erase(scripthash) > 0; }

    /** Get the negotiated protocol version */
    const std::string& GetProtocolVersion() const { return m_protocol_version; }

    /** Set the negotiated protocol version */
    void SetProtocolVersion(const std::string& version) { m_protocol_version = version; }

    /** Get the active wallet ID for this connection */
    const std::string& GetWalletId() const { return m_wallet_id; }

    /** Set the active wallet ID for this connection */
    void SetWalletId(const std::string& wallet_id) { m_wallet_id = wallet_id; }

    /** Check if connection is subscribed to wallet notifications */
    bool IsSubscribedToWallet() const { return m_wallet_subscribed; }

    /** Set wallet subscription state */
    void SetSubscribedToWallet(bool subscribed) { m_wallet_subscribed = subscribed; }

private:
    ElectrumServer* m_server;
    int m_fd;
    std::string m_address;

    /** libevent buffered event for this connection */
    ::bufferevent* m_bev{nullptr};

    /** Subscription state */
    bool m_subscribed_headers{false};
    std::set<uint256> m_subscribed_scripthashes;

    /** Negotiated protocol version */
    std::string m_protocol_version;

    /** Active wallet ID for this connection */
    std::string m_wallet_id;

    /** Whether this connection is subscribed to wallet notifications */
    bool m_wallet_subscribed{false};

    /** Read buffer for incomplete messages */
    std::string m_read_buffer;

    /** Callbacks for libevent */
    static void ReadCallback(::bufferevent* bev, void* ctx);
    static void WriteCallback(::bufferevent* bev, void* ctx);
    static void EventCallback(::bufferevent* bev, short events, void* ctx);

    /** Process a complete JSON-RPC message */
    void ProcessMessage(const std::string& message);
};

/**
 * Manages subscriptions and sends notifications to clients.
 *
 * Implements CValidationInterface to receive blockchain events and
 * forward them to subscribed clients.
 */
class SubscriptionManager : public CValidationInterface
{
public:
    SubscriptionManager(ElectrumServer& server);
    ~SubscriptionManager();

    /** Register with the validation interface */
    void RegisterValidationInterface();

    /** Unregister from the validation interface */
    void UnregisterValidationInterface();

    /** Subscribe a connection to a scripthash */
    void SubscribeScripthash(ElectrumConnection* conn, const uint256& scripthash);

    /** Unsubscribe a connection from a scripthash */
    void UnsubscribeScripthash(ElectrumConnection* conn, const uint256& scripthash);

    /** Subscribe a connection to wallet notifications */
    void SubscribeWallet(ElectrumConnection* conn, const std::string& wallet_id);

    /** Unsubscribe a connection from wallet notifications */
    void UnsubscribeWallet(ElectrumConnection* conn, const std::string& wallet_id);

    /** Remove all subscriptions for a connection (called on disconnect) */
    void RemoveConnection(ElectrumConnection* conn);

    /** Get the current scripthash status (hash of history) */
    std::string GetScripthashStatus(const uint256& scripthash);

    /** Notify wallet subscribers about scan progress */
    void NotifyWalletScanProgress(const std::string& wallet_id, int current_height, int total_height, double progress);

    /** Notify wallet subscribers about scan completion */
    void NotifyWalletScanComplete(const std::string& wallet_id, bool success, const std::string& error);

protected:
    /** CValidationInterface overrides */
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override;
    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override;
    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t mempool_sequence) override;
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override;
    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override;

private:
    ElectrumServer& m_server;

    /** Map of scripthash -> set of subscribed connections */
    mutable Mutex m_scripthash_mutex;
    std::map<uint256, std::set<ElectrumConnection*>> m_scripthash_subscriptions GUARDED_BY(m_scripthash_mutex);

    /** Set of connections subscribed to headers */
    mutable Mutex m_headers_mutex;
    std::set<ElectrumConnection*> m_header_subscriptions GUARDED_BY(m_headers_mutex);

    /** Map of wallet_id -> set of subscribed connections */
    mutable Mutex m_wallet_mutex;
    std::map<std::string, std::set<ElectrumConnection*>> m_wallet_subscriptions GUARDED_BY(m_wallet_mutex);

    /** Notify all header subscribers about a new block */
    void NotifyHeaderSubscribers(const CBlockIndex* pindex);

    /** Notify scripthash subscribers about changes */
    void NotifyScripthashSubscribers(const uint256& scripthash);

    /** Notify wallet subscribers about a new/confirmed transaction */
    void NotifyWalletTransaction(const std::string& wallet_id, const uint256& txid, int confirmations);

    /** Notify wallet subscribers about balance change */
    void NotifyWalletBalanceChanged(const std::string& wallet_id);

    /** Check if a transaction affects any subscribed scripthashes */
    std::set<uint256> GetAffectedScripthashes(const CTransactionRef& tx);

    /** Check which subscribed wallets are affected by a transaction */
    std::set<std::string> GetAffectedWallets(const CTransactionRef& tx);

    friend class ElectrumServer;
};

/** Global Electrum server instance */
extern std::unique_ptr<ElectrumServer> g_electrum_server;

/** Initialize the Electrum server (call from init.cpp) */
bool InitElectrumServer(node::NodeContext& node);

/** Start the Electrum server */
bool StartElectrumServer();

/** Interrupt the Electrum server */
void InterruptElectrumServer();

/** Stop and destroy the Electrum server */
void StopElectrumServer();

} // namespace electrum

#endif // BITCOIN_ELECTRUM_ELECTRUMSERVER_H
