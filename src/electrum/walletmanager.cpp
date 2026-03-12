// Copyright (c) 2025 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <electrum/walletmanager.h>

#include <chain.h>
#include <core_io.h>
#include <index/blockfilterindex.h>
#include <interfaces/chain.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <logging.h>
#include <node/context.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <wallet/context.h>

#include <algorithm>

namespace electrum {

// Prefix for electrum-managed wallets
static const std::string WALLET_PREFIX = "electrum_";

ElectrumWalletManager::ElectrumWalletManager(node::NodeContext& node)
    : m_node(node)
{
}

ElectrumWalletManager::~ElectrumWalletManager()
{
    // Wallets will be unloaded when unique_ptrs are destroyed
}

std::string ElectrumWalletManager::GetInternalName(const std::string& wallet_id) const
{
    return WALLET_PREFIX + wallet_id;
}

std::string ElectrumWalletManager::GetWalletId(const std::string& internal_name) const
{
    if (internal_name.substr(0, WALLET_PREFIX.size()) == WALLET_PREFIX) {
        return internal_name.substr(WALLET_PREFIX.size());
    }
    return internal_name;
}

std::string ElectrumWalletManager::GenerateWalletId() const
{
    // Generate a random 16-byte ID and hex encode it
    uint256 random_bytes = GetRandHash();
    return HexStr(std::vector<unsigned char>(random_bytes.begin(), random_bytes.begin() + 16));
}

interfaces::WalletLoader* ElectrumWalletManager::GetWalletLoader() const
{
    return m_node.wallet_loader;
}

interfaces::Wallet* ElectrumWalletManager::GetWallet(const std::string& wallet_id) const
{
    auto it = m_wallets.find(wallet_id);
    if (it != m_wallets.end()) {
        return it->second.get();
    }
    return nullptr;
}

wallet::CWallet* ElectrumWalletManager::GetCWallet(const std::string& wallet_id) const
{
    interfaces::WalletLoader* loader = GetWalletLoader();
    if (!loader) return nullptr;

    wallet::WalletContext* context = loader->context();
    if (!context) return nullptr;

    std::string internal_name = GetInternalName(wallet_id);
    LOCK(context->wallets_mutex);
    for (const auto& wallet : context->wallets) {
        if (wallet->GetName() == internal_name) {
            return wallet.get();
        }
    }
    return nullptr;
}

WalletResult ElectrumWalletManager::CreateWallet(const std::string& wallet_id)
{
    interfaces::WalletLoader* loader = GetWalletLoader();
    if (!loader) {
        return WalletResult::Error("Wallet functionality not available");
    }

    // Generate ID if not provided
    std::string id = wallet_id.empty() ? GenerateWalletId() : wallet_id;
    std::string internal_name = GetInternalName(id);

    // Check if wallet already exists
    auto wallet_list = loader->listWalletDir();
    for (const auto& [name, path] : wallet_list) {
        if (name == internal_name) {
            return WalletResult::Error("Wallet already exists: " + id);
        }
    }

    // Create descriptor wallet (no passphrase, descriptor wallet flag)
    std::vector<bilingual_str> warnings;
    SecureString passphrase;
    uint64_t flags = wallet::WALLET_FLAG_DESCRIPTORS | wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;

    auto result = loader->createWallet(internal_name, passphrase, flags, warnings);
    if (!result) {
        return WalletResult::Error(util::ErrorString(result).original);
    }

    // Store the wallet interface
    {
        LOCK(m_wallets_mutex);
        m_wallets[id] = std::move(*result);
    }

    return WalletResult::Success(id);
}

WalletResult ElectrumWalletManager::OpenWallet(const std::string& wallet_id)
{
    if (wallet_id.empty()) {
        return WalletResult::Error("Wallet ID required");
    }

    // Check if already loaded
    {
        LOCK(m_wallets_mutex);
        if (m_wallets.count(wallet_id)) {
            return WalletResult::Success(wallet_id);
        }
    }

    interfaces::WalletLoader* loader = GetWalletLoader();
    if (!loader) {
        return WalletResult::Error("Wallet functionality not available");
    }

    std::string internal_name = GetInternalName(wallet_id);
    std::vector<bilingual_str> warnings;

    auto result = loader->loadWallet(internal_name, warnings);
    if (!result) {
        return WalletResult::Error(util::ErrorString(result).original);
    }

    // Store the wallet interface
    {
        LOCK(m_wallets_mutex);
        m_wallets[wallet_id] = std::move(*result);
    }

    return WalletResult::Success(wallet_id);
}

WalletResult ElectrumWalletManager::CloseWallet(const std::string& wallet_id)
{
    LOCK(m_wallets_mutex);
    auto it = m_wallets.find(wallet_id);
    if (it == m_wallets.end()) {
        return WalletResult::Error("Wallet not loaded: " + wallet_id);
    }

    // The Wallet::remove() call unloads the wallet
    it->second->remove();
    m_wallets.erase(it);

    return WalletResult::Success(wallet_id);
}

WalletResult ElectrumWalletManager::DeleteWallet(const std::string& wallet_id)
{
    // First close/unload if loaded
    {
        LOCK(m_wallets_mutex);
        auto it = m_wallets.find(wallet_id);
        if (it != m_wallets.end()) {
            it->second->remove();
            m_wallets.erase(it);
        }
    }

    // TODO: Delete wallet files from disk
    // For now, just unloading is sufficient - wallet remains on disk
    // Full deletion requires filesystem operations on the wallet directory

    return WalletResult::Success(wallet_id);
}

bool ElectrumWalletManager::WalletExists(const std::string& wallet_id) const
{
    interfaces::WalletLoader* loader = GetWalletLoader();
    if (!loader) return false;

    std::string internal_name = GetInternalName(wallet_id);
    auto wallet_list = loader->listWalletDir();
    for (const auto& [name, path] : wallet_list) {
        if (name == internal_name) {
            return true;
        }
    }
    return false;
}

bool ElectrumWalletManager::IsWalletLoaded(const std::string& wallet_id) const
{
    LOCK(m_wallets_mutex);
    return m_wallets.count(wallet_id) > 0;
}

WalletResult ElectrumWalletManager::ImportDescriptor(const std::string& wallet_id,
                                                      const std::string& descriptor,
                                                      int range_start,
                                                      int range_end,
                                                      const std::string& timestamp,
                                                      bool internal)
{
    wallet::CWallet* cwallet = GetCWallet(wallet_id);
    if (!cwallet) {
        return WalletResult::Error("Wallet not loaded: " + wallet_id);
    }

    // Parse timestamp
    int64_t ts;
    bool needs_rescan = false;
    if (timestamp == "now") {
        ts = GetTime();
    } else {
        if (!ParseInt64(timestamp, &ts)) {
            return WalletResult::Error("Invalid timestamp: " + timestamp);
        }
        needs_rescan = (ts < GetTime());
    }

    // If rescan is needed, check blockfilterindex availability
    if (needs_rescan) {
        BlockFilterIndex* filter_index = GetBlockFilterIndex(BlockFilterType::BASIC);
        if (!filter_index) {
            return WalletResult::Error("Block filter index not available. Enable with -blockfilterindex=1");
        }

        IndexSummary summary = filter_index->GetSummary();
        if (!summary.synced) {
            return WalletResult::Error("Block filter index not synced. Current height: " +
                                       std::to_string(summary.best_block_height) +
                                       ". Please wait for sync to complete.");
        }
    }

    LOCK(cwallet->cs_wallet);

    // Parse the descriptor
    FlatSigningProvider keys;
    std::string error;
    auto parsed_descs = Parse(descriptor, keys, error, false);
    if (parsed_descs.empty()) {
        return WalletResult::Error("Invalid descriptor: " + error);
    }

    // For ranged descriptors, expand the range
    std::unique_ptr<Descriptor>& desc = parsed_descs.at(0);
    if (!desc->IsRange() && (range_start != 0 || range_end != 0)) {
        return WalletResult::Error("Range specified for non-ranged descriptor");
    }

    // Create wallet descriptor and add to wallet
    wallet::WalletDescriptor w_desc(std::move(desc), ts, range_start, range_end, range_end);

    // Add to wallet's descriptor scriptPubKeyMan
    auto spk_manager = cwallet->AddWalletDescriptor(w_desc, keys, "", internal);
    if (spk_manager == nullptr) {
        return WalletResult::Error("Failed to add descriptor to wallet");
    }

    // Trigger rescan if timestamp indicates historical data
    if (needs_rescan) {
        // Find the block to start scanning from based on timestamp
        // We need to release the wallet lock before calling chain methods
        uint256 start_block;
        int start_height = 0;

        {
            // Get chain interface from wallet
            interfaces::Chain& chain = cwallet->chain();

            // Find first block at or after the timestamp
            chain.findFirstBlockWithTimeAndHeight(ts, 0,
                interfaces::FoundBlock().hash(start_block).height(start_height));
        }

        if (start_block.IsNull()) {
            // No block found, scan from genesis
            interfaces::Chain& chain = cwallet->chain();
            start_block = chain.getBlockHash(0);
            start_height = 0;
        }

        LogPrintf("Electrum: Starting wallet rescan from height %d for wallet %s\n",
                  start_height, wallet_id);

        // Reserve the wallet for scanning
        wallet::WalletRescanReserver reserver(*cwallet);
        if (!reserver.reserve()) {
            return WalletResult::Error("Wallet is currently rescanning. Please try again later.");
        }

        // Release the wallet lock for the rescan (it acquires its own locks)
        // The rescan is done outside the cs_wallet lock
        {
            LEAVE_CRITICAL_SECTION(cwallet->cs_wallet);

            auto result = cwallet->ScanForWalletTransactions(
                start_block,
                start_height,
                /*max_height=*/{},
                reserver,
                /*fUpdate=*/true,
                /*save_progress=*/true
            );

            ENTER_CRITICAL_SECTION(cwallet->cs_wallet);

            if (result.status == wallet::CWallet::ScanResult::FAILURE) {
                return WalletResult::Error("Rescan failed. Block " +
                                           result.last_failed_block.GetHex() +
                                           " may be pruned or corrupted.");
            }

            LogPrintf("Electrum: Wallet rescan completed for %s. Scanned to height %d\n",
                      wallet_id, result.last_scanned_height.value_or(-1));
        }
    }

    return WalletResult::Success(wallet_id);
}

std::pair<ElectrumBalance, std::string> ElectrumWalletManager::GetBalance(const std::string& wallet_id)
{
    LOCK(m_wallets_mutex);
    interfaces::Wallet* wallet = GetWallet(wallet_id);
    if (!wallet) {
        return {{}, "Wallet not loaded: " + wallet_id};
    }

    auto balances = wallet->getBalances();
    ElectrumBalance result;
    result.confirmed = balances.balance;
    result.unconfirmed = balances.unconfirmed_balance;

    return {result, ""};
}

std::pair<std::vector<ElectrumTxInfo>, std::string> ElectrumWalletManager::GetTransactions(
    const std::string& wallet_id,
    int limit,
    int offset)
{
    LOCK(m_wallets_mutex);
    interfaces::Wallet* wallet = GetWallet(wallet_id);
    if (!wallet) {
        return {{}, "Wallet not loaded: " + wallet_id};
    }

    std::vector<ElectrumTxInfo> results;
    auto txs = wallet->getWalletTxs();

    // Convert to vector for sorting and pagination
    std::vector<interfaces::WalletTx> tx_vec(txs.begin(), txs.end());

    // Sort by time descending (most recent first)
    std::sort(tx_vec.begin(), tx_vec.end(), [](const auto& a, const auto& b) {
        return a.time > b.time;
    });

    // Apply offset and limit
    int start = std::min(offset, static_cast<int>(tx_vec.size()));
    int end = std::min(offset + limit, static_cast<int>(tx_vec.size()));

    for (int i = start; i < end; ++i) {
        const auto& wtx = tx_vec[i];
        ElectrumTxInfo info;
        info.txid = wtx.tx->GetHash().GetHex();
        info.raw_hex = EncodeHexTx(*wtx.tx);
        info.timestamp = wtx.time;
        info.value = wtx.credit - wtx.debit;
        // TODO: Get height from wallet transaction status
        // info.height = ...;
        results.push_back(std::move(info));
    }

    return {results, ""};
}

std::pair<std::optional<ElectrumTxInfo>, std::string> ElectrumWalletManager::GetTransaction(
    const std::string& wallet_id,
    const std::string& txid)
{
    LOCK(m_wallets_mutex);
    interfaces::Wallet* wallet = GetWallet(wallet_id);
    if (!wallet) {
        return {std::nullopt, "Wallet not loaded: " + wallet_id};
    }

    auto hash_opt = uint256::FromHex(txid);
    if (!hash_opt) {
        return {std::nullopt, "Invalid txid: " + txid};
    }
    uint256 hash = *hash_opt;

    auto wtx = wallet->getWalletTx(hash);
    if (!wtx.tx) {
        return {std::nullopt, "Transaction not found: " + txid};
    }

    ElectrumTxInfo info;
    info.txid = wtx.tx->GetHash().GetHex();
    info.raw_hex = EncodeHexTx(*wtx.tx);
    info.timestamp = wtx.time;
    info.value = wtx.credit - wtx.debit;

    return {info, ""};
}

std::pair<std::vector<ElectrumUTXO>, std::string> ElectrumWalletManager::GetUTXOs(
    const std::string& wallet_id,
    int min_confirmations)
{
    LOCK(m_wallets_mutex);
    interfaces::Wallet* wallet = GetWallet(wallet_id);
    if (!wallet) {
        return {{}, "Wallet not loaded: " + wallet_id};
    }

    std::vector<ElectrumUTXO> results;
    auto coins = wallet->listCoins();

    for (const auto& [dest, coin_list] : coins) {
        for (const auto& [outpoint, txout] : coin_list) {
            // TODO: Check confirmations against min_confirmations
            ElectrumUTXO utxo;
            utxo.txid = outpoint.hash.GetHex();
            utxo.vout = outpoint.n;
            utxo.value = txout.txout.nValue;
            // TODO: Get height from txout
            // utxo.height = ...;
            results.push_back(std::move(utxo));
        }
    }

    return {results, ""};
}

std::pair<std::string, std::string> ElectrumWalletManager::GetNewAddress(
    const std::string& wallet_id,
    const std::string& label)
{
    LOCK(m_wallets_mutex);
    interfaces::Wallet* wallet = GetWallet(wallet_id);
    if (!wallet) {
        return {"", "Wallet not loaded: " + wallet_id};
    }

    auto result = wallet->getNewDestination(OutputType::BECH32, label);
    if (!result) {
        return {"", util::ErrorString(result).original};
    }

    return {EncodeDestination(*result), ""};
}

std::pair<UniValue, std::string> ElectrumWalletManager::GetWalletInfo(const std::string& wallet_id)
{
    LOCK(m_wallets_mutex);
    interfaces::Wallet* wallet = GetWallet(wallet_id);
    if (!wallet) {
        return {UniValue(), "Wallet not loaded: " + wallet_id};
    }

    UniValue info(UniValue::VOBJ);
    info.pushKV("wallet_id", wallet_id);
    info.pushKV("wallet_name", wallet->getWalletName());

    auto balances = wallet->getBalances();
    info.pushKV("balance", balances.balance);
    info.pushKV("unconfirmed_balance", balances.unconfirmed_balance);
    info.pushKV("immature_balance", balances.immature_balance);

    auto txs = wallet->getWalletTxs();
    info.pushKV("tx_count", static_cast<int64_t>(txs.size()));

    return {info, ""};
}

bool ElectrumWalletManager::IsRescanning(const std::string& wallet_id) const
{
    LOCK(m_rescan_mutex);
    return m_rescanning_wallets.count(wallet_id) > 0;
}

WalletResult ElectrumWalletManager::ImportDescriptorAsync(const std::string& wallet_id,
                                                           const std::string& descriptor,
                                                           int range_start,
                                                           int range_end,
                                                           const std::string& timestamp,
                                                           bool internal,
                                                           ScanProgressCallback progress_callback,
                                                           ScanCompleteCallback complete_callback)
{
    wallet::CWallet* cwallet = GetCWallet(wallet_id);
    if (!cwallet) {
        return WalletResult::Error("Wallet not loaded: " + wallet_id);
    }

    // Check if already rescanning
    {
        LOCK(m_rescan_mutex);
        if (m_rescanning_wallets.count(wallet_id)) {
            return WalletResult::Error("Wallet is already being rescanned");
        }
    }

    // Parse timestamp
    int64_t ts;
    bool needs_rescan = false;
    if (timestamp == "now") {
        ts = GetTime();
    } else {
        if (!ParseInt64(timestamp, &ts)) {
            return WalletResult::Error("Invalid timestamp: " + timestamp);
        }
        needs_rescan = (ts < GetTime());
    }

    // If rescan is needed, check blockfilterindex availability
    if (needs_rescan) {
        BlockFilterIndex* filter_index = GetBlockFilterIndex(BlockFilterType::BASIC);
        if (!filter_index) {
            return WalletResult::Error("Block filter index not available. Enable with -blockfilterindex=1");
        }

        IndexSummary summary = filter_index->GetSummary();
        if (!summary.synced) {
            return WalletResult::Error("Block filter index not synced. Current height: " +
                                       std::to_string(summary.best_block_height) +
                                       ". Please wait for sync to complete.");
        }
    }

    // Add the descriptor (synchronous part)
    {
        LOCK(cwallet->cs_wallet);

        FlatSigningProvider keys;
        std::string error;
        auto parsed_descs = Parse(descriptor, keys, error, false);
        if (parsed_descs.empty()) {
            return WalletResult::Error("Invalid descriptor: " + error);
        }

        std::unique_ptr<Descriptor>& desc = parsed_descs.at(0);
        if (!desc->IsRange() && (range_start != 0 || range_end != 0)) {
            return WalletResult::Error("Range specified for non-ranged descriptor");
        }

        wallet::WalletDescriptor w_desc(std::move(desc), ts, range_start, range_end, range_end);

        auto spk_manager = cwallet->AddWalletDescriptor(w_desc, keys, "", internal);
        if (spk_manager == nullptr) {
            return WalletResult::Error("Failed to add descriptor to wallet");
        }
    }

    // If no rescan needed, we're done
    if (!needs_rescan) {
        if (complete_callback) {
            complete_callback(wallet_id, true, "");
        }
        return WalletResult::Success(wallet_id);
    }

    // Mark wallet as rescanning
    {
        LOCK(m_rescan_mutex);
        m_rescanning_wallets.insert(wallet_id);
    }

    // Find start block for rescan
    uint256 start_block;
    int start_height = 0;
    int total_height = 0;
    {
        interfaces::Chain& chain = cwallet->chain();
        chain.findFirstBlockWithTimeAndHeight(ts, 0,
            interfaces::FoundBlock().hash(start_block).height(start_height));

        if (start_block.IsNull()) {
            start_block = chain.getBlockHash(0);
            start_height = 0;
        }

        // Get current tip height for progress calculation
        total_height = chain.getHeight().value_or(0);
    }

    LogPrintf("Electrum: Starting async wallet rescan from height %d to %d for wallet %s\n",
              start_height, total_height, wallet_id);

    // Spawn background thread for rescan
    std::thread rescan_thread([this, cwallet, wallet_id, start_block, start_height, total_height,
                               progress_callback, complete_callback]() {
        // Reserve the wallet for scanning
        wallet::WalletRescanReserver reserver(*cwallet);
        if (!reserver.reserve()) {
            LOCK(m_rescan_mutex);
            m_rescanning_wallets.erase(wallet_id);
            if (complete_callback) {
                complete_callback(wallet_id, false, "Failed to reserve wallet for scanning");
            }
            return;
        }

        // Progress monitoring - check periodically and send notifications
        std::atomic<bool> rescan_done{false};
        std::thread progress_thread([&]() {
            int last_reported_height = start_height;
            while (!rescan_done.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if (rescan_done.load()) break;

                double progress = cwallet->ScanningProgress();
                int current_height = start_height + static_cast<int>(progress * (total_height - start_height));

                // Only report if progress changed significantly
                if (current_height > last_reported_height + 10 || progress >= 0.99) {
                    last_reported_height = current_height;
                    if (progress_callback) {
                        progress_callback(wallet_id, current_height, total_height, progress);
                    }
                }
            }
        });

        // Run the rescan
        auto result = cwallet->ScanForWalletTransactions(
            start_block,
            start_height,
            /*max_height=*/{},
            reserver,
            /*fUpdate=*/true,
            /*save_progress=*/true
        );

        // Signal progress thread to stop
        rescan_done.store(true);
        progress_thread.join();

        // Remove from rescanning set
        {
            LOCK(m_rescan_mutex);
            m_rescanning_wallets.erase(wallet_id);
        }

        // Call completion callback
        if (result.status == wallet::CWallet::ScanResult::FAILURE) {
            LogPrintf("Electrum: Wallet rescan failed for %s at block %s\n",
                      wallet_id, result.last_failed_block.GetHex());
            if (complete_callback) {
                complete_callback(wallet_id, false, "Rescan failed at block " + result.last_failed_block.GetHex());
            }
        } else {
            LogPrintf("Electrum: Wallet rescan completed for %s. Scanned to height %d\n",
                      wallet_id, result.last_scanned_height.value_or(-1));
            if (complete_callback) {
                complete_callback(wallet_id, true, "");
            }
        }
    });

    // Detach the thread - it will clean up after itself
    rescan_thread.detach();

    return WalletResult::Success(wallet_id);
}

} // namespace electrum
