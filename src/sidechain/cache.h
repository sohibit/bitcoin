// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_CACHE_H
#define BITCOIN_SIDECHAIN_CACHE_H

#include <sidechain/enforcer_client.h>
#include <sidechain/validation.h>
#include <sync.h>
#include <uint256.h>

#include <atomic>
#include <functional>
#include <memory>
#include <map>
#include <set>
#include <optional>
#include <string>
#include <thread>

class ArgsManager;

namespace sidechain {

/**
 * A local mirror of the enforcer's view of the mainchain.
 *
 * Validation must never call the enforcer directly: Core holds cs_main across
 * block validation, and an HTTP round trip under that lock is a stall, not a
 * slow path. A background thread keeps this cache current, and validation reads
 * only from here.
 */
class MainchainCache final : public PegDataSource
{
public:
    explicit MainchainCache(std::unique_ptr<IEnforcerClient> client);
    ~MainchainCache();

    MainchainCache(const MainchainCache&) = delete;
    MainchainCache& operator=(const MainchainCache&) = delete;

    /**
     * Called after a poll advances the view, with no cache lock held.
     *
     * Validation takes cs_main and then this cache's mutex, so the callback must
     * never run under m_mutex or the two orders would deadlock.
     */
    void SetOnAdvance(std::function<void()> on_advance);

    void Start();
    void Stop();

    /**
     * Deposits in mainchain blocks after `start` up to and including `end`.
     *
     * Fails unless the whole range has actually been fetched. A height filter
     * over whatever happens to be cached would return a partial answer on a node
     * that started late and a complete one on a node that did not -- the two
     * would then require different coinbases and split.
     */
    DepositRangeResult GetDepositsBetween(const std::optional<uint256>& start,
                                          const uint256& end,
                                          std::vector<Deposit>& out) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Bundle events over the same range, under the same coverage rule.
    DepositRangeResult GetBundleEventsBetween(const std::optional<uint256>& start,
                                              const uint256& end,
                                              std::vector<WithdrawalBundleEvent>& out) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Height of a mainchain block we have seen, if known.
    std::optional<int32_t> GetHeight(const uint256& block_hash) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The mainchain block at this height, if the cache reaches it.
    std::optional<uint256> GetHashAtHeight(int32_t height) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The lowest mainchain height a cached header names, if any. That can sit
    //! below the range the peg data covers.
    std::optional<int32_t> GetLowestHeight() const override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The mainchain block committing to this sidechain block, if cached.
    std::optional<uint256> FindBmmAnchor(const uint256& block_hash) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The mainchain tip the enforcer had last time we polled.
    std::optional<uint256> GetSyncedTip() const override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! False until the first successful poll. Treat as IBD, never as invalid.
    bool IsSynced() const override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    std::string GetLastError() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Lowest height with resolved headers, or -1. Used to detect coverage growth.
    int32_t HeadersLow() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! True once any GetChainTip succeeded. Distinguishes an enforcer that is
    //! absent from one that is merely slow, which a completed-poll check cannot.
    bool IsReachable() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Test seam: populate without an enforcer.
    void SeedForTest(const BlockInfo& info, bool as_tip) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Test seam: declare the fetched height window.
    void SeedCoverageForTest(int32_t low, int32_t high) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    const IEnforcerClient& Client() const { return *m_client; }

    //! Poll once on the calling thread. Exposed for tests.
    bool Poll(std::string& error) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Note that validation needed history the cache does not yet have.
     *
     * The backward walk already runs unconditionally, so this is currently a
     * no-op; it exists so validation can express the need without depending on
     * how the cache schedules fetches. Takes no hash by design — any hash at the
     * call site comes from a block under validation and could name an abandoned
     * branch.
     */
    void RequestBackfill() const override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    void ThreadLoop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Shared coverage rule for both range queries.
    DepositRangeResult ResolveRange(const std::optional<uint256>& start,
                                    const uint256& end,
                                    int32_t& start_height_out,
                                    int32_t& end_height_out) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    std::unique_ptr<IEnforcerClient> m_client;

    mutable Mutex m_mutex;
    std::map<uint256, BlockInfo> m_blocks GUARDED_BY(m_mutex);
    //! Heights for mainchain blocks we have seen as a tip. GetTwoWayPegData
    //! omits blocks without events, so m_blocks alone cannot resolve a range.
    std::map<uint256, int32_t> m_heights GUARDED_BY(m_mutex);
    //! The same links the other way. The deposit range cut asks by height about
    //! twenty times per template, under cs_main, so a scan is too costly there.
    std::map<int32_t, uint256> m_by_height GUARDED_BY(m_mutex);
    std::optional<uint256> m_synced_tip GUARDED_BY(m_mutex);
    std::string m_last_error GUARDED_BY(m_mutex);
    int32_t m_tip_height GUARDED_BY(m_mutex){-1};
    //! Contiguous height window actually fetched from the enforcer. Ranges
    //! outside it are unanswerable, not empty.
    int32_t m_covered_low GUARDED_BY(m_mutex){-1};
    //! Lowest height for which headers are resolved, and its hash. The backward
    //! walk anchors on the hash: anchoring on the tip would re-fetch the same
    //! newest chunk every poll and never descend.
    int32_t m_headers_low GUARDED_BY(m_mutex){-1};  //!< -1 = not started, 0 = at genesis
    uint256 m_headers_low_hash GUARDED_BY(m_mutex);
    int32_t m_covered_high GUARDED_BY(m_mutex){-1};
    bool m_reachable GUARDED_BY(m_mutex){false};

    std::function<void()> m_on_advance;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
};

//! Process-wide cache, created in init. Null when not a sidechain network.
MainchainCache* GetMainchainCache();

//! Create and start the process-wide cache from -enforcerhost/-enforcerport.
void StartMainchainCache(const ArgsManager& args, uint8_t slot, std::function<void()> on_advance);
void StopMainchainCache();

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_CACHE_H
