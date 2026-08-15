// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/cache.h>

#include <common/args.h>
#include <sidechain/deposits.h>
#include <logging.h>
#include <util/thread.h>
#include <util/time.h>

#include <algorithm>
#include <set>
#include <memory>
#include <utility>

namespace sidechain {
namespace {
constexpr auto POLL_INTERVAL{std::chrono::seconds{1}};
//! Both windows are extended backwards in bounded chunks. Fetching to genesis
//! in one call exceeds MAX_HTTP_RESPONSE_BYTES on any long chain, and that
//! failure is unrecoverable because the retry is the same oversized request.
constexpr int32_t CHUNK{2000};
//! Distinct from 0, which means the walk reached genesis. Conflating the two
//! makes a cache that never started look finished.
constexpr int32_t HEADERS_LOW_UNKNOWN{-1};
constexpr int FAILURES_BEFORE_WARNING{30};
//! Deliberately leaked and published atomically. RPC and validation threads
//! read this concurrently with startup, and destroying it at shutdown would
//! dangle references held by in-flight RPCs.
std::atomic<MainchainCache*> g_cache{nullptr};
} // namespace

MainchainCache::MainchainCache(std::unique_ptr<IEnforcerClient> client) : m_client{std::move(client)} {}

MainchainCache::~MainchainCache() { Stop(); }

void MainchainCache::SetOnAdvance(std::function<void()> on_advance) { m_on_advance = std::move(on_advance); }

void MainchainCache::Start()
{
    if (m_thread.joinable()) return;
    m_stop = false;
    m_thread = std::thread(&util::TraceThread, "schaincache", [this] { ThreadLoop(); });
}

void MainchainCache::Stop()
{
    m_stop = true;
    if (m_thread.joinable()) m_thread.join();
}

void MainchainCache::ThreadLoop()
{
    int consecutive_failures{0};
    while (!m_stop) {
        const std::optional<uint256> before_tip{GetSyncedTip()};
        const int32_t before_low{HeadersLow()};
        std::string error;
        if (!Poll(error)) {
            LogDebug(BCLog::VALIDATION, "sidechain: enforcer poll failed: %s\n", error);
            // A persistently failing poll stops the node validating; surface it
            // at the default level rather than leaving a silent stall.
            if (++consecutive_failures % FAILURES_BEFORE_WARNING == 0) {
                LogPrintf("sidechain: enforcer poll has failed %d times: %s\n",
                          consecutive_failures, error);
            }
        } else {
            consecutive_failures = 0;
            // Blocks deferred with state.Error while the cache was behind are
            // still unconnected and nothing else retries them. Coverage can grow
            // for many polls with the tip unchanged, so a tip-only trigger would
            // leave them stalled until the next mainchain block. Invoked with no
            // lock held: validation takes cs_main before this cache's mutex.
            if (m_on_advance && (GetSyncedTip() != before_tip || HeadersLow() != before_low)) {
                m_on_advance();
            }
        }
        for (int i = 0; i < 10 && !m_stop; ++i) {
            UninterruptibleSleep(POLL_INTERVAL / 10);
        }
    }
}

bool MainchainCache::Poll(std::string& error)
{
    MainchainTip tip;
    if (!m_client->GetChainTip(tip, error)) {
        LOCK(m_mutex);
        m_last_error = error;
        return false;
    }
    {
        LOCK(m_mutex);
        m_reachable = true;
    }

    std::optional<uint256> known_tip;
    int32_t known_height{-1};
    int32_t headers_low{-1};
    uint256 headers_low_hash;
    {
        LOCK(m_mutex);
        known_tip = m_synced_tip;
        known_height = m_tip_height;
        headers_low = m_headers_low;
        headers_low_hash = m_headers_low_hash;
    }

    const bool tip_unchanged{known_tip && *known_tip == tip.block_hash};
    // Nothing to do only when the tip is unchanged AND the backward walk is
    // finished. Checking this before the resync predicate matters: folded into
    // it, the condition becomes unsatisfiable and every idle poll rebuilds the
    // whole cache under the lock validation waits on.
    if (tip_unchanged && headers_low == 0) {
        LOCK(m_mutex);
        m_last_error.clear();
        return true;
    }

    // Only a single-block extension with a matching parent link is provably a
    // simple advance. Anything else may be a reorg, and keeping abandoned-branch
    // blocks would make the cache a superset of the enforcer's canonical view.
    const bool provable_extension{known_tip && tip.prev_block_hash == *known_tip &&
                                  tip.height == known_height + 1};
    const bool resync{!known_tip || (!tip_unchanged && !provable_extension)};

    if (resync) {
        // Locals only. The members are cleared in the commit block below, so a
        // failed fetch cannot leave the cache half-updated.
        known_tip.reset();
        known_height = -1;
        headers_low = HEADERS_LOW_UNKNOWN;
        headers_low_hash.SetNull();
    }

    std::vector<MainchainTip> headers;
    std::vector<BlockInfo> blocks;
    std::optional<int32_t> new_covered_low;
    std::optional<int32_t> new_covered_high;
    int32_t new_headers_low{headers_low};
    uint256 new_headers_low_hash{headers_low_hash};

    // Forward: extend to the new tip. Bounded by how far the tip moved, so this
    // stays cheap in steady state instead of refetching a whole chunk.
    if (!resync && known_tip && !tip_unchanged) {
        std::vector<BlockInfo> forward;
        if (!m_client->GetTwoWayPegData(known_tip, tip.block_hash, forward, error)) {
            LOCK(m_mutex);
            m_last_error = error;
            return false;
        }
        blocks.insert(blocks.end(), forward.begin(), forward.end());
        new_covered_high = tip.height;
    }

    // Backward: extend one chunk. Headers first, because the peg range can only
    // be chunked once the hash at the target height is known.
    const bool extend_back{resync || headers_low != 0};
    if (extend_back) {
        const uint256 anchor{resync ? tip.block_hash : headers_low_hash};
        if (!m_client->GetBlockHeaderInfo(anchor, CHUNK, headers, error)) {
            LOCK(m_mutex);
            m_last_error = error;
            return false;
        }
        // An enforcer that does not know the block answers 200 with an empty
        // list; treating that as success would claim coverage we lack.
        if (headers.empty()) {
            LOCK(m_mutex);
            m_last_error = "enforcer returned no headers";
            return false;
        }
        if (headers.front().block_hash != anchor) {
            LOCK(m_mutex);
            m_last_error = "enforcer returned headers for the wrong block";
            return false;
        }
        // Verify the chunk is a contiguous chain, so the range it appears to
        // prove is the range it actually proves.
        for (size_t i = 1; i < headers.size(); ++i) {
            if (headers[i - 1].prev_block_hash != headers[i].block_hash ||
                headers[i - 1].height != headers[i].height + 1) {
                LOCK(m_mutex);
                m_last_error = "enforcer returned a non-contiguous header chain";
                return false;
            }
        }

        // A chunk that fails to descend would re-issue the identical request
        // every poll, forever, with nothing surfaced to the operator.
        if (!resync && headers_low > 0 && headers.back().height >= headers_low) {
            LOCK(m_mutex);
            m_last_error = "enforcer header chunk did not extend the window";
            return false;
        }

        // Peg payload size is driven by deposit addresses lifted from mainchain
        // OP_RETURNs, so a chunk-wide fetch can exceed the response cap on data
        // any mainchain user can produce. Halve the span until it fits rather
        // than re-issuing a request that can only fail identically.
        size_t low_index{headers.size() - 1};
        std::vector<BlockInfo> older;
        while (true) {
            const int32_t candidate_low{headers[low_index].height};
            const std::optional<uint256> peg_start{
                candidate_low > 0 ? std::optional<uint256>{headers[low_index].block_hash} : std::nullopt};
            older.clear();
            if (m_client->GetTwoWayPegData(peg_start, anchor, older, error)) {
                new_headers_low = candidate_low;
                new_headers_low_hash = headers[low_index].block_hash;
                // Exclusive of an explicit start; reaches genesis without one.
                new_covered_low = peg_start ? candidate_low + 1 : 0;
                break;
            }
            // Only an oversized response is worth narrowing for; every other
            // failure must stay atomic and be retried unchanged next poll.
            const bool can_narrow{error == ENFORCER_RESPONSE_TOO_LARGE && low_index > 1 &&
                                  (resync || headers_low <= 0 || headers[low_index / 2].height < headers_low)};
            if (!can_narrow) {
                LOCK(m_mutex);
                m_last_error = error;
                return false;
            }
            low_index /= 2;
        }
        // Headers past the span the peg fetch reached are not covered, so the
        // two windows must not be adopted independently.
        headers.resize(low_index + 1);
        blocks.insert(blocks.end(), older.begin(), older.end());

        if (resync) new_covered_high = tip.height;
    }

    LOCK(m_mutex);
    if (resync) {
        m_blocks.clear();
        m_heights.clear();
        m_by_height.clear();
        m_covered_low = -1;
        m_covered_high = -1;
        m_headers_low = HEADERS_LOW_UNKNOWN;
        m_headers_low_hash.SetNull();
    }
    for (const MainchainTip& header : headers) {
        m_heights[header.block_hash] = header.height;
        m_by_height[header.height] = header.block_hash;
    }
    for (BlockInfo& info : blocks) {
        m_heights[info.main_block_hash] = info.main_height;
        m_by_height[info.main_height] = info.main_block_hash;
        m_blocks[info.main_block_hash] = std::move(info);
    }
    m_heights[tip.block_hash] = tip.height;
    m_by_height[tip.height] = tip.block_hash;

    if (new_headers_low >= 0 && (m_headers_low == HEADERS_LOW_UNKNOWN || new_headers_low < m_headers_low)) {
        m_headers_low = new_headers_low;
        m_headers_low_hash = new_headers_low_hash;
    }

    if (new_covered_low) {
        m_covered_low = (m_covered_low < 0) ? *new_covered_low
                                            : std::min(m_covered_low, *new_covered_low);
    }
    // Only ever advance to a height a peg fetch actually reached. Adopting the
    // tip here while still backfilling would answer Ok for a range whose newest
    // blocks were never fetched, and a node mid-backfill would then disagree
    // with a synced one about which deposits exist.
    if (new_covered_high) {
        m_covered_high = (m_covered_high < 0) ? *new_covered_high
                                              : std::max(m_covered_high, *new_covered_high);
    }

    m_synced_tip = tip.block_hash;
    m_tip_height = tip.height;
    m_last_error.clear();
    return true;
}

void MainchainCache::RequestBackfill() const
{
    // Intentionally empty. The backward walk runs on every poll until it reaches
    // genesis, so a deferred block needs no prompting -- on_advance re-triggers
    // validation as coverage grows. Kept on the interface so validation can say
    // what it needs without knowing how the cache schedules work.
}

DepositRangeResult MainchainCache::ResolveRange(const std::optional<uint256>& start,
                                                const uint256& end,
                                                int32_t& start_height_out,
                                                int32_t& end_height_out) const
{
    AssertLockHeld(m_mutex);
    const auto end_it = m_heights.find(end);
    if (end_it == m_heights.end()) return DepositRangeResult::Unavailable;
    const int32_t end_height{end_it->second};

    int32_t start_height{-1};
    if (start) {
        const auto start_it = m_heights.find(*start);
        if (start_it == m_heights.end()) return DepositRangeResult::Unavailable;
        start_height = start_it->second;
    }
    // An inverted range must fail loudly. Returning an empty set would let a
    // block quietly credit nothing, and the next block would then re-credit
    // everything its grandparent already did.
    if (start_height > end_height) return DepositRangeResult::Invalid;
    // Only answer for a window we actually fetched. Anything else risks
    // reporting a partial deposit set as complete.
    if (m_covered_high < 0 || m_headers_low < 0) return DepositRangeResult::Unavailable;
    // Both the deposit window and the header window must cover the range: the
    // first proves no deposit is missing, the second that the endpoints resolve.
    const int32_t low{std::max(m_covered_low, m_headers_low)};
    if (start_height + 1 < low || end_height > m_covered_high) {
        return DepositRangeResult::Unavailable;
    }

    start_height_out = start_height;
    end_height_out = end_height;
    return DepositRangeResult::Ok;
}

DepositRangeResult MainchainCache::GetDepositsBetween(const std::optional<uint256>& start,
                                                      const uint256& end,
                                                      std::vector<Deposit>& out) const
{
    LOCK(m_mutex);
    int32_t start_height{-1};
    int32_t end_height{-1};
    if (const auto result{ResolveRange(start, end, start_height, end_height)};
        result != DepositRangeResult::Ok) {
        return result;
    }

    out.clear();
    for (const auto& [hash, info] : m_blocks) {
        if (info.main_height <= start_height || info.main_height > end_height) continue;
        out.insert(out.end(), info.deposits.begin(), info.deposits.end());
    }
    out = SortDeposits(std::move(out));
    return DepositRangeResult::Ok;
}

DepositRangeResult MainchainCache::GetBundleEventsBetween(const std::optional<uint256>& start,
                                                          const uint256& end,
                                                          std::vector<WithdrawalBundleEvent>& out) const
{
    LOCK(m_mutex);
    int32_t start_height{-1};
    int32_t end_height{-1};
    if (const auto result{ResolveRange(start, end, start_height, end_height)};
        result != DepositRangeResult::Ok) {
        return result;
    }

    // m_blocks is keyed by hash, so height alone leaves the order to the map,
    // which differs between nodes. A range can hold two verdicts for one m6id --
    // paid, re-proposed, expired -- and the last one read wins, so the order has
    // to be total, the way SortDeposits is.
    std::vector<std::pair<int32_t, WithdrawalBundleEvent>> in_range;
    for (const auto& [hash, info] : m_blocks) {
        if (info.main_height <= start_height || info.main_height > end_height) continue;
        for (const WithdrawalBundleEvent& event : info.bundle_events) {
            in_range.emplace_back(info.main_height, event);
        }
    }
    // A total order, so two nodes read one range the same way. Which verdict
    // wins is not decided here: CollectVerdicts keeps a payout whatever the
    // order, because a payout is final.
    const auto rank{[](WithdrawalBundleEvent::Status status) {
        return status == WithdrawalBundleEvent::Status::Succeeded ? 1 : 0;
    }};
    std::sort(in_range.begin(), in_range.end(), [&](const auto& a, const auto& b) {
        if (a.first != b.first) return a.first < b.first;
        if (a.second.m6id != b.second.m6id) return a.second.m6id < b.second.m6id;
        if (rank(a.second.status) != rank(b.second.status)) {
            return rank(a.second.status) < rank(b.second.status);
        }
        return a.second.status < b.second.status;
    });

    out.clear();
    for (auto& [height, event] : in_range) out.push_back(std::move(event));
    return DepositRangeResult::Ok;
}

void MainchainCache::SeedForTest(const BlockInfo& info, bool as_tip)
{
    LOCK(m_mutex);
    m_heights[info.main_block_hash] = info.main_height;
    m_by_height[info.main_height] = info.main_block_hash;
    m_blocks[info.main_block_hash] = info;
    if (as_tip) {
        m_synced_tip = info.main_block_hash;
        m_tip_height = info.main_height;
    }
}

void MainchainCache::SeedCoverageForTest(int32_t low, int32_t high)
{
    LOCK(m_mutex);
    m_covered_low = low;
    m_covered_high = high;
    m_headers_low = low;
}

bool MainchainCache::IsReachable() const
{
    LOCK(m_mutex);
    return m_reachable;
}

int32_t MainchainCache::HeadersLow() const
{
    LOCK(m_mutex);
    return m_headers_low;
}

std::optional<int32_t> MainchainCache::GetLowestHeight() const
{
    LOCK(m_mutex);
    if (m_by_height.empty()) return std::nullopt;
    return m_by_height.begin()->first;
}

std::optional<uint256> MainchainCache::GetHashAtHeight(int32_t height) const
{
    LOCK(m_mutex);
    const auto it{m_by_height.find(height)};
    if (it == m_by_height.end()) return std::nullopt;
    return it->second;
}

std::optional<int32_t> MainchainCache::GetHeight(const uint256& block_hash) const
{
    LOCK(m_mutex);
    const auto it = m_heights.find(block_hash);
    if (it == m_heights.end()) return std::nullopt;
    return it->second;
}

std::optional<uint256> MainchainCache::FindBmmAnchor(const uint256& block_hash) const
{
    LOCK(m_mutex);
    const BlockInfo* best{nullptr};
    for (const auto& [hash, info] : m_blocks) {
        if (!info.bmm_commitment || *info.bmm_commitment != block_hash) continue;
        // Two mainchain blocks on one chain may commit to the same sidechain
        // block: BIP301 forbids duplicate commitments only within a single
        // block. The earliest is the one the sidechain followed.
        if (best == nullptr || info.main_height < best->main_height) best = &info;
    }
    if (best == nullptr) return std::nullopt;
    return best->main_block_hash;
}

std::optional<uint256> MainchainCache::GetSyncedTip() const
{
    LOCK(m_mutex);
    return m_synced_tip;
}

bool MainchainCache::IsSynced() const
{
    LOCK(m_mutex);
    return m_synced_tip.has_value();
}

std::string MainchainCache::GetLastError() const
{
    LOCK(m_mutex);
    return m_last_error;
}

void StartMainchainCache(const ArgsManager& args, uint8_t slot, std::function<void()> on_advance)
{
    const std::string host{args.GetArg("-enforcerhost", "127.0.0.1")};
    const uint16_t port{static_cast<uint16_t>(args.GetIntArg("-enforcerport", 50051))};
    LogPrintf("sidechain: slot %d, enforcer at %s:%d\n", slot, host, port);

    auto cache{std::make_unique<MainchainCache>(std::make_unique<EnforcerClient>(host, port, slot))};
    cache->SetOnAdvance(std::move(on_advance));
    MainchainCache* raw{cache.release()};
    g_cache.store(raw, std::memory_order_release);
    SetPegDataSource(raw);
    RegisterPegCheck();
    // Started last: the first poll can fire on_advance straight into
    // ConnectBlock, which needs the peg check already registered.
    raw->Start();
}

void StopMainchainCache()
{
    // Stops the thread but does not destroy the object: an RPC may still be
    // reading it.
    if (MainchainCache* cache = g_cache.load(std::memory_order_acquire)) cache->Stop();
}

MainchainCache* GetMainchainCache() { return g_cache.load(std::memory_order_acquire); }

} // namespace sidechain
