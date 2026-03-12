// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ELECTRUM_WALLETMANAGER_H
#define BITCOIN_ELECTRUM_WALLETMANAGER_H

#include <consensus/amount.h>
#include <sync.h>
#include <univalue.h>

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>

namespace interfaces {
class Wallet;
class WalletLoader;
} // namespace interfaces

namespace node {
struct NodeContext;
}

namespace wallet {
class CWallet;
struct WalletContext;
} // namespace wallet

namespace electrum {

/**
 * Result of a wallet operation.
 */
struct WalletResult {
    bool success{false};
    std::string error;
    std::string wallet_id;

    static WalletResult Success(const std::string& id = "") {
        return WalletResult{true, "", id};
    }
    static WalletResult Error(const std::string& err) {
        return WalletResult{false, err, ""};
    }
};

/**
 * Transaction info for Electrum protocol responses.
 */
struct ElectrumTxInfo {
    std::string txid;
    std::string raw_hex;
    int64_t height{0};  // 0 = mempool, -1 = conflicted
    int64_t timestamp{0};
    int64_t fee{0};
    int64_t value{0};  // net value change for wallet
};

/**
 * UTXO info for Electrum protocol responses.
 */
struct ElectrumUTXO {
    std::string txid;
    uint32_t vout{0};
    int64_t value{0};
    int64_t height{0};
};

/**
 * Balance info for Electrum protocol responses.
 */
struct ElectrumBalance {
    int64_t confirmed{0};
    int64_t unconfirmed{0};
};

/**
 * Manages per-client wallets for the Electrum server.
 *
 * Each Electrum client can create/open a wallet identified by wallet_id.
 * Wallets are stored as standard Bitcoin Core descriptor wallets with
 * the naming convention "electrum_<wallet_id>".
 *
 * This class wraps the Bitcoin Core wallet interfaces to provide
 * Electrum-compatible operations.
 */
class ElectrumWalletManager
{
public:
    explicit ElectrumWalletManager(node::NodeContext& node);
    ~ElectrumWalletManager();

    /**
     * Create a new wallet.
     * @param wallet_id Optional client-provided ID. If empty, generates UUID.
     * @return Result with wallet_id on success, error message on failure.
     */
    WalletResult CreateWallet(const std::string& wallet_id = "");

    /**
     * Open/load an existing wallet.
     * @param wallet_id The wallet ID to load.
     * @return Result with wallet_id on success, error message on failure.
     */
    WalletResult OpenWallet(const std::string& wallet_id);

    /**
     * Close/unload a wallet.
     * @param wallet_id The wallet ID to unload.
     * @return Result indicating success or failure.
     */
    WalletResult CloseWallet(const std::string& wallet_id);

    /**
     * Delete a wallet permanently.
     * @param wallet_id The wallet ID to delete.
     * @return Result indicating success or failure.
     */
    WalletResult DeleteWallet(const std::string& wallet_id);

    /**
     * Check if a wallet exists (on disk).
     * @param wallet_id The wallet ID to check.
     * @return true if wallet exists.
     */
    bool WalletExists(const std::string& wallet_id) const;

    /**
     * Check if a wallet is currently loaded.
     * @param wallet_id The wallet ID to check.
     * @return true if wallet is loaded.
     */
    bool IsWalletLoaded(const std::string& wallet_id) const;

    /**
     * Import a descriptor into a wallet.
     * @param wallet_id The wallet ID.
     * @param descriptor The output descriptor string.
     * @param range_start Start of derivation range (for ranged descriptors).
     * @param range_end End of derivation range.
     * @param timestamp "now" or unix timestamp for rescan start.
     * @param internal Whether this is an internal (change) descriptor.
     * @return Result indicating success or failure.
     */
    WalletResult ImportDescriptor(const std::string& wallet_id,
                                   const std::string& descriptor,
                                   int range_start,
                                   int range_end,
                                   const std::string& timestamp,
                                   bool internal = false);

    /**
     * Get wallet balance.
     * @param wallet_id The wallet ID.
     * @return Balance info or error.
     */
    std::pair<ElectrumBalance, std::string> GetBalance(const std::string& wallet_id);

    /**
     * Get wallet transaction history.
     * @param wallet_id The wallet ID.
     * @param limit Maximum number of transactions to return.
     * @param offset Number of transactions to skip.
     * @return List of transactions or error string.
     */
    std::pair<std::vector<ElectrumTxInfo>, std::string> GetTransactions(
        const std::string& wallet_id,
        int limit = 100,
        int offset = 0);

    /**
     * Get a single transaction.
     * @param wallet_id The wallet ID.
     * @param txid The transaction ID.
     * @return Transaction info or error.
     */
    std::pair<std::optional<ElectrumTxInfo>, std::string> GetTransaction(
        const std::string& wallet_id,
        const std::string& txid);

    /**
     * Get unspent outputs.
     * @param wallet_id The wallet ID.
     * @param min_confirmations Minimum confirmations required.
     * @return List of UTXOs or error string.
     */
    std::pair<std::vector<ElectrumUTXO>, std::string> GetUTXOs(
        const std::string& wallet_id,
        int min_confirmations = 0);

    /**
     * Get a new receiving address.
     * @param wallet_id The wallet ID.
     * @param label Optional label for the address.
     * @return Address string or error.
     */
    std::pair<std::string, std::string> GetNewAddress(
        const std::string& wallet_id,
        const std::string& label = "");

    /**
     * Get wallet info summary.
     * @param wallet_id The wallet ID.
     * @return UniValue object with wallet info or error string.
     */
    std::pair<UniValue, std::string> GetWalletInfo(const std::string& wallet_id);

    /**
     * Check if a wallet is currently being rescanned.
     * @param wallet_id The wallet ID.
     * @return true if rescan is in progress.
     */
    bool IsRescanning(const std::string& wallet_id) const;

    /**
     * Callback for rescan progress notifications.
     * Parameters: wallet_id, current_height, total_height, progress (0.0-1.0)
     */
    using ScanProgressCallback = std::function<void(const std::string&, int, int, double)>;

    /**
     * Callback for rescan completion.
     * Parameters: wallet_id, success, error_message (empty if success)
     */
    using ScanCompleteCallback = std::function<void(const std::string&, bool, const std::string&)>;

    /**
     * Import a descriptor with async rescan.
     * Returns immediately after adding descriptor. Rescan runs in background.
     * @param wallet_id The wallet ID.
     * @param descriptor The output descriptor string.
     * @param range_start Start of derivation range.
     * @param range_end End of derivation range.
     * @param timestamp "now" or unix timestamp for rescan start.
     * @param internal Whether this is an internal descriptor.
     * @param progress_callback Called periodically with scan progress.
     * @param complete_callback Called when scan completes.
     * @return Result indicating if descriptor was added (rescan may still be running).
     */
    WalletResult ImportDescriptorAsync(const std::string& wallet_id,
                                        const std::string& descriptor,
                                        int range_start,
                                        int range_end,
                                        const std::string& timestamp,
                                        bool internal,
                                        ScanProgressCallback progress_callback,
                                        ScanCompleteCallback complete_callback);

private:
    node::NodeContext& m_node;

    /** Map of wallet_id -> loaded wallet interface */
    mutable Mutex m_wallets_mutex;
    std::map<std::string, std::unique_ptr<interfaces::Wallet>> m_wallets GUARDED_BY(m_wallets_mutex);

    /** Track wallets currently being rescanned */
    mutable Mutex m_rescan_mutex;
    std::set<std::string> m_rescanning_wallets GUARDED_BY(m_rescan_mutex);

    /** Get the internal wallet name from wallet_id */
    std::string GetInternalName(const std::string& wallet_id) const;

    /** Get wallet_id from internal wallet name */
    std::string GetWalletId(const std::string& internal_name) const;

    /** Generate a unique wallet ID */
    std::string GenerateWalletId() const;

    /** Get WalletLoader interface */
    interfaces::WalletLoader* GetWalletLoader() const;

    /** Get wallet interface by ID (must be loaded) */
    interfaces::Wallet* GetWallet(const std::string& wallet_id) const EXCLUSIVE_LOCKS_REQUIRED(m_wallets_mutex);

    /** Get underlying CWallet for operations not exposed through interfaces */
    wallet::CWallet* GetCWallet(const std::string& wallet_id) const;
};

} // namespace electrum

#endif // BITCOIN_ELECTRUM_WALLETMANAGER_H
