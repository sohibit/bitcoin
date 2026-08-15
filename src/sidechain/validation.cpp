// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/validation.h>

#include <chain.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <sidechain/bmm.h>
#include <sidechain/deposits.h>
#include <sidechain/script.h>
#include <sidechain/withdrawal.h>
#include <sync.h>
#include <tinyformat.h>
#include <validation.h>

#include <atomic>
#include <map>
#include <vector>

namespace sidechain {

Mutex g_staged_mutex;
Mutex g_orphaned_mutex;
namespace {
std::atomic<PegDataSource*> g_peg_source{nullptr};
std::atomic<FindTxFn> g_find_tx{nullptr};
//! The mainchain tip `parent` was assembled against: the exclusive start of the
//! range its child credits. Shared by the validator and the miner, which must
//! derive it identically or a node rejects blocks it produced itself.
bool ReadPrevMainOf(const CBlockIndex* parent,
                    const ReadBlockFn& read_block,
                    std::optional<uint256>& out,
                    std::string& error)
{
    out.reset();
    // A parent that is genesis has no earlier prev_main, so the range is open.
    if (parent == nullptr || parent->nHeight <= 0) return true;

    CBlock parent_block;
    if (!read_block(parent_block, *parent)) {
        error = "cannot read parent block";
        return false;
    }
    if (parent_block.vtx.empty()) {
        error = "parent block has no coinbase";
        return false;
    }
    const std::optional<uint256> parent_prev_main{GetBmmCommitment(*parent_block.vtx[0])};
    if (!parent_prev_main) {
        // Failing open here would credit from genesis and re-mint every deposit
        // the parent already credited.
        error = "parent block has no BMM commitment";
        return false;
    }
    out = parent_prev_main;
    return true;
}

} // namespace

void SetTxLookup(FindTxFn lookup) { g_find_tx.store(lookup, std::memory_order_release); }
void SetPegDataSource(PegDataSource* source) { g_peg_source.store(source, std::memory_order_release); }
void RegisterPegCheck() { SetPegCheck(&CheckBlockPegRulesImpl); }
PegDataSource* GetPegDataSource() { return g_peg_source.load(std::memory_order_acquire); }


//! Which bundles a block opened and settled, and the settlement each one owes.
struct WithdrawalActivity {
    std::optional<LiveBundleRef> opened;
    std::vector<COutPoint> settled;
};

namespace {

//! m6id, and every sidechain block whose range carried the verdict. A competing
//! block at the same height carries it too, and only one of them survives -- so
//! one entry each would let a losing branch hide a real shortfall.
std::map<uint256, std::set<uint256>> g_orphaned_payouts GUARDED_BY(g_orphaned_mutex);
} // namespace

std::map<uint256, size_t> GetOrphanedPayouts(
    const std::function<bool(const uint256&)>& on_active_chain) EXCLUSIVE_LOCKS_REQUIRED(!g_orphaned_mutex)
{
    LOCK(g_orphaned_mutex);
    std::map<uint256, size_t> out;
    for (const auto& [m6id, blocks] : g_orphaned_payouts) {
        // Every block a node validates records here, losing branches included.
        // Only the chain the node settled on says anything about the peg.
        const size_t payouts{static_cast<size_t>(
            std::count_if(blocks.begin(), blocks.end(), on_active_chain))};
        if (payouts > 0) out[m6id] = payouts;
    }
    return out;
}

bool BundleAlreadyRuled(const uint256& m6id,
                        const std::map<uint256, BundleOutcome>& verdicts,
                        const std::vector<LiveBundleRef>& parent_live)
{
    if (!verdicts.contains(m6id)) return false;
    return !std::any_of(parent_live.begin(), parent_live.end(),
                        [&](const LiveBundleRef& ref) { return ref.m6id == m6id; });
}

std::map<uint256, BundleOutcome> CollectVerdicts(const std::vector<WithdrawalBundleEvent>& events)
{
    std::map<uint256, BundleOutcome> verdicts;
    for (const WithdrawalBundleEvent& event : events) {
        if (event.status == WithdrawalBundleEvent::Status::Succeeded) {
            verdicts[event.m6id] = BundleOutcome::Paid;
        } else if (event.status == WithdrawalBundleEvent::Status::Failed) {
            // A payout is final, whichever order the events arrive in. Anyone
            // may propose a paid m6id again, and that proposal can only expire,
            // because the treasury output it spends is gone. Reading the later
            // Failed would hand back coins the mainchain already paid.
            verdicts.emplace(event.m6id, BundleOutcome::Failed);
        }
    }
    return verdicts;
}

namespace {

/**
 * Record a payout for a bundle this chain never opened.
 *
 * Called for a connected block only. A template names a candidate hash that
 * changes with every call, and it says nothing about what the chain holds.
 */
void ReportOrphanedPayouts(const std::map<uint256, BundleOutcome>& verdicts,
                           const std::vector<LiveBundleRef>& live,
                           const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(!g_orphaned_mutex)
{
    for (const auto& [m6id, outcome] : verdicts) {
        if (outcome != BundleOutcome::Paid) continue;
        const bool ours{std::any_of(live.begin(), live.end(),
                                    [&](const LiveBundleRef& ref) { return ref.m6id == m6id; })};
        if (ours) continue;
        LogError("sidechain: the mainchain paid bundle %s, which this chain never opened; "
                 "the peg is short by that bundle\n", m6id.GetHex());
        LOCK(g_orphaned_mutex);
        g_orphaned_payouts[m6id].insert(block_hash);
    }
}

} // namespace

/**
 * Enforce the withdrawal lifecycle for a block.
 *
 * A block may open at most one bundle and settle any number. Every settlement
 * must match what the mainchain decided over the same range the deposits came
 * from, and the live set must account for all of it, so a payout cannot be
 * skipped and coins cannot be settled twice.
 */
static bool CheckWithdrawals(const CBlock& block,
                             const CBlockIndex& index,
                             const ReadBlockFn& read_block,
                             const SpentOutputsFn& spent_outputs,
                             const uint256& prev_main,
                             const std::optional<uint256>& parent_prev_main,
                             bool template_only,
                             PegDataSource& cache,
                             BlockValidationState& state)
    EXCLUSIVE_LOCKS_REQUIRED(!g_orphaned_mutex)
{
    const CTransaction& coinbase{*block.vtx[0]};
    const auto live{GetLiveBundles(coinbase)};
    if (!live) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-live-bundles",
                             "coinbase does not declare the bundles in flight");
    }

    // The parent's set is the baseline. Genesis has none, and neither does a
    // parent from before any withdrawal existed.
    std::vector<LiveBundleRef> parent_live;
    if (index.pprev != nullptr && index.pprev->nHeight > 0) {
        CBlock parent;
        if (!read_block(parent, *index.pprev) || parent.vtx.empty()) {
            return state.Error("sidechain-parent-unreadable: cannot read parent block");
        }
        const auto previous{GetLiveBundles(*parent.vtx[0])};
        if (!previous) {
            return state.Error("sidechain-parent-live-bundles-unreadable: cannot read parent live set");
        }
        parent_live = *previous;
    }

    // What the mainchain decided over this block's range. Bundle events ride the
    // same range as deposits, so each verdict is acted on in exactly one block.
    std::vector<WithdrawalBundleEvent> events;
    switch (cache.GetBundleEventsBetween(parent_prev_main, prev_main, events)) {
    case DepositRangeResult::Ok:
        break;
    case DepositRangeResult::Invalid:
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-bmm-prevmain-regressed",
                             "prev_main is earlier than the parent's");
    case DepositRangeResult::Unavailable:
        cache.RequestBackfill();
        return state.Error("sidechain-bundle-events-uncached");
    }
    const std::map<uint256, BundleOutcome> verdicts{CollectVerdicts(events)};
    // A template is a candidate, not a block. Its hash changes with every call,
    // so a record from here grows one entry per getblocktemplate.
    if (!template_only) ReportOrphanedPayouts(verdicts, parent_live, index.GetBlockHash());

    WithdrawalActivity activity;
    std::string reason;
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        const CTransaction& tx{*block.vtx[i]};
        std::vector<CTxOut> spent;
        if (!spent_outputs(i, spent) || spent.size() != tx.vin.size()) {
            return state.Error("sidechain-spent-outputs-unavailable");
        }

        // Classified by what it spends, exhaustively. Gating on the input count
        // would leave a transaction that spends a bundle alongside anything else
        // matching neither branch, and so validated by nothing at all: it would
        // pay the whole bundle wherever it liked.
        const bool spends_request{std::any_of(spent.begin(), spent.end(), IsWithdrawalRequestOutput)};
        uint256 bundle_m6id;
        const bool spends_bundle{std::any_of(spent.begin(), spent.end(), [](const CTxOut& out) {
            return IsBundleScript(out.scriptPubKey);
        })};

        if (spends_request && spends_bundle) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-peg-mixed-spend",
                                 "a transaction spends both a request and a bundle");
        }

        if (spends_request) {
            // Which of the two moves a request may make is read off the outputs:
            // a bundle makes exactly one bundle output, so anything else is an
            // abort. Both are checked, so neither can hide as the other.
            const bool opens_bundle{tx.vout.size() == 1 && IsBundleScript(tx.vout[0].scriptPubKey)};
            if (!opens_bundle) {
                if (!CheckAbortTransaction(tx, spent, reason)) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, reason,
                                         "invalid abort transaction");
                }
                continue;
            }
            uint256 m6id;
            if (!CheckBundleTransaction(tx, spent, m6id, reason)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, reason,
                                     "invalid bundle transaction");
            }
            // One at a time: concurrent bundles would race for the same treasury
            // on the mainchain, and only one of them could ever be paid.
            if (activity.opened) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-bundle-multiple",
                                     "more than one bundle opened in a block");
            }
            if (BundleAlreadyRuled(m6id, verdicts, parent_live)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-bundle-ruled",
                                     "opened a bundle the mainchain already ruled on");
            }
            activity.opened = LiveBundleRef{COutPoint{tx.GetHash(), 0}, m6id};
            continue;
        }

        if (spends_bundle) {
            // A settlement spends the bundle and nothing else, so its inputs are
            // exactly one and CheckSettlementTransaction can read the m6id off it.
            uint256 ignored_requests;
            if (spent.size() != 1 ||
                !IsBundleScript(spent[0].scriptPubKey, bundle_m6id, ignored_requests)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-settlement-inputs",
                                     "a bundle may only be spent by a settlement");
            }
            const auto verdict{verdicts.find(bundle_m6id)};
            // Settling before the mainchain has decided would either destroy
            // coins it has not paid for, or hand back coins it has.
            if (verdict == verdicts.end()) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-settlement-undecided",
                                     "settled a bundle the mainchain has not resolved");
            }
            uint256 m6id;
            if (!CheckSettlementTransaction(tx, spent, verdict->second, m6id, reason)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, reason,
                                     "invalid settlement transaction");
            }
            activity.settled.push_back(tx.vin[0].prevout);
        }
    }

    // What the mainchain ruled on, and which this block therefore has to settle.
    std::vector<COutPoint> owed;
    for (const LiveBundleRef& ref : parent_live) {
        if (verdicts.contains(ref.m6id)) owed.push_back(ref.outpoint);
    }

    if (!CheckLiveBundles(parent_live, activity.opened, activity.settled, owed, *live, reason)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, reason,
                             "live bundle set does not match what the block did");
    }
    return true;
}

bool CheckBlockPegRulesImpl(const CBlock& block,
                        const CBlockIndex& index,
                        const ReadBlockFn& read_block,
                        const SpentOutputsFn& spent_outputs,
                        bool template_only,
                        CAmount& deposit_credit,
                        BlockValidationState& state)
    EXCLUSIVE_LOCKS_REQUIRED(!g_orphaned_mutex)
{
    deposit_credit = 0;
    if (index.nHeight == 0) return true;

    PegDataSource* cache{GetPegDataSource()};
    if (cache == nullptr || !cache->IsSynced()) {
        return state.Error("sidechain-enforcer-unavailable");
    }

    const CTransaction& coinbase{*block.vtx[0]};

    const std::optional<uint256> prev_main{GetBmmCommitment(coinbase)};
    if (!prev_main) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-no-bmm",
                             "coinbase is missing the BMM commitment");
    }

    if (!template_only) {
        const std::optional<uint256> anchor{cache->FindBmmAnchor(block.GetHash())};
        if (!anchor) {
            // The commitment may simply not be mined yet, or the cache may be
            // behind. Neither makes the block bad.
            return state.Error("sidechain-bmm-not-found");
        }
        // prev_main must precede the block that BMM'd this one. Without this the
        // miner picks prev_main freely, and a block can name a range its
        // ancestors already credited -- minting the same deposits twice.
        const std::optional<int32_t> anchor_height{cache->GetHeight(*anchor)};
        const std::optional<int32_t> prev_height{cache->GetHeight(*prev_main)};
        if (!anchor_height || !prev_height) return state.Error("sidechain-height-uncached");
        if (*prev_height > *anchor_height) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-bmm-prevmain-after-anchor",
                                 "prev_main is later than the block that mined this one");
        }
    }

    // Deposits come from prev_main_hash, not from the anchor: the anchor is the
    // mainchain block that BMMs *this* block, so it does not exist at assembly.
    // The credited range starts at the parent's prev_main_hash, so deposits in
    // mainchain blocks the sidechain skipped over are not lost.
    std::optional<uint256> parent_prev_main;
    std::string parent_error;
    if (!ReadPrevMainOf(index.pprev, read_block, parent_prev_main, parent_error)) {
        // Deliberately NOT in the import path's deferrable set: an unreadable
        // parent means corruption or pruning, which waiting cannot fix.
        return state.Error(strprintf("sidechain-parent-unreadable: %s", parent_error));
    }

    // Monotonic by construction: an inverted or unknown range is rejected by
    // GetDepositsBetween rather than silently yielding an empty set.
    std::vector<Deposit> deposits;
    switch (cache->GetDepositsBetween(parent_prev_main, *prev_main, deposits)) {
    case DepositRangeResult::Ok:
        break;
    case DepositRangeResult::Invalid:
        // prev_main before the parent's is provably bad, so reject it. Deferring
        // instead would retry forever and refetch the chain on every attempt.
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-bmm-prevmain-regressed",
                             "prev_main is earlier than the parent's");
    case DepositRangeResult::Unavailable:
        cache->RequestBackfill();
        return state.Error("sidechain-prevmain-uncached");
    }

    std::string reason;
    if (!CheckCoinbaseDeposits(coinbase, deposits, deposit_credit, reason)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, reason,
                             "coinbase does not credit the reported deposits");
    }

    return CheckWithdrawals(block, index, read_block, spent_outputs, *prev_main,
                            parent_prev_main, template_only, *cache, state);
}

namespace {
//! The bundle the operator asked for, waiting for a block to carry it.
//!
//! Producer-side intent, not consensus: a bundle only becomes real when a block
//! containing it connects. Lost on restart, which costs nothing -- call
//! create_bundle again.
std::vector<COutPoint> g_staged_bundle GUARDED_BY(g_staged_mutex);
std::vector<COutPoint> g_staged_aborts GUARDED_BY(g_staged_mutex);
//! Aborts a staged bundle took over. They go back if that bundle is cancelled.
std::vector<COutPoint> g_bumped_aborts GUARDED_BY(g_staged_mutex);
} // namespace

namespace {
//! Give back the aborts the staged bundle took over.
void RestoreBumpedAborts() EXCLUSIVE_LOCKS_REQUIRED(g_staged_mutex)
{
    for (const COutPoint& outpoint : g_bumped_aborts) {
        if (std::find(g_staged_aborts.begin(), g_staged_aborts.end(), outpoint) ==
            g_staged_aborts.end()) {
            g_staged_aborts.push_back(outpoint);
        }
    }
    g_bumped_aborts.clear();
}
} // namespace

bool StageBundle(const std::vector<COutPoint>& outpoints) EXCLUSIVE_LOCKS_REQUIRED(!g_staged_mutex)
{
    LOCK(g_staged_mutex);
    if (!g_staged_bundle.empty()) return false;
    // Whatever the last stage took, it no longer holds. Giving it back before
    // this one claims its own is what stops a second call from stranding an
    // abort in neither queue.
    RestoreBumpedAborts();
    g_staged_bundle = outpoints;
    // A request cannot go two places at once. Both stages build a transaction
    // that spends it, and a block carrying both is invalid -- which the producer
    // only finds after it builds it, every time, forever.
    // Added to, never replaced. A second bundle over the same set finds the
    // abort queue already empty, so a reset here would lose the record and the
    // cancel would give nothing back.
    std::erase_if(g_staged_aborts, [&](const COutPoint& outpoint)
                      EXCLUSIVE_LOCKS_REQUIRED(g_staged_mutex) {
        const bool claimed{std::find(outpoints.begin(), outpoints.end(), outpoint) != outpoints.end()};
        if (claimed) g_bumped_aborts.push_back(outpoint);
        return claimed;
    });
    return true;
}

bool CancelStagedBundle() EXCLUSIVE_LOCKS_REQUIRED(!g_staged_mutex)
{
    LOCK(g_staged_mutex);
    const bool had_one{!g_staged_bundle.empty()};
    g_staged_bundle.clear();
    RestoreBumpedAborts();
    return had_one;
}

bool StageAbort(const std::vector<COutPoint>& outpoints) EXCLUSIVE_LOCKS_REQUIRED(!g_staged_mutex)
{
    LOCK(g_staged_mutex);
    for (const COutPoint& outpoint : outpoints) {
        if (std::find(g_staged_bundle.begin(), g_staged_bundle.end(), outpoint) !=
            g_staged_bundle.end()) {
            return false;
        }
    }
    for (const COutPoint& outpoint : outpoints) {
        if (std::find(g_staged_aborts.begin(), g_staged_aborts.end(), outpoint) ==
            g_staged_aborts.end()) {
            g_staged_aborts.push_back(outpoint);
        }
    }
    return true;
}

namespace {

//! A live bundle, resolved against the UTXO set.
struct LiveBundle {
    COutPoint outpoint;
    uint256 m6id;
    CAmount value{0};
};

/**
 * The requests a bundle swept, read back off the transaction that opened it.
 *
 * A failed bundle has to hand every request back exactly as it was, and the
 * only record of what "as it was" means is the bundle transaction's own inputs.
 * Needs -txindex to find that transaction; without it a node can still validate
 * settlements, it just cannot build one.
 */
static bool GetBundleMembers(const LiveBundle& bundle,
                      std::vector<CTxOut>& requests_out,
                      std::string& error)
{
    const FindTxFn find_tx{g_find_tx.load(std::memory_order_acquire)};
    const CTransactionRef opened{find_tx ? find_tx(bundle.outpoint.hash) : nullptr};
    if (!opened) {
        error = strprintf("cannot read the transaction that opened bundle %s; a synced -txindex is "
                          "required to settle one. Any node that builds a block needs it, not only "
                          "the node that opened the bundle.",
                          bundle.outpoint.hash.GetHex());
        return false;
    }

    requests_out.clear();
    for (const CTxIn& in : opened->vin) {
        // Spent by the bundle, so the live view no longer has them: read the
        // request straight out of the block that created it.
        const CTransactionRef source{find_tx(in.prevout.hash)};
        if (!source || in.prevout.n >= source->vout.size()) {
            error = strprintf("cannot read request %s", in.prevout.ToString());
            return false;
        }
        requests_out.push_back(source->vout[in.prevout.n]);
    }
    return true;
}

} // namespace

namespace {

/**
 * What a coinbase may spend on deposits.
 *
 * Half the block. One mainchain block of deposits has to fit, or the range
 * cannot move past it and the peg stops for good. A minimal M5 costs about 109
 * base bytes, so a 4 000 000 weight mainchain block holds about 9 100 of them.
 * Each earns one coinbase output of about 34 bytes, which is 136 weight, so
 * about 1 250 000 weight in all. Half a block clears that, and still leaves the
 * mempool half a block.
 */
constexpr size_t MAX_COINBASE_DEPOSIT_WEIGHT{MAX_BLOCK_WEIGHT / 2};

/**
 * What one abort may spend on signature operations.
 *
 * An owner script is the owner's to choose, and a block's signature-operation
 * limit does not move with its weight. Sixty-four bare multisig scripts cost
 * four times what a whole block may hold, so the count cap alone is not a
 * bound: the queue takes what fits and the rest waits.
 */
constexpr int64_t MAX_ABORT_SIGOPS_COST{MAX_BLOCK_SIGOPS_COST / 4};

// One request has to fit, or the first in the queue breaks the loop every time
// and nothing behind it ever moves. A bare OP_CHECKMULTISIG costs 20 signature
// operations per byte, which is the most any script can cost.
static_assert(WITNESS_SCALE_FACTOR * 20 * MAX_PEG_SCRIPT_SIZE <= MAX_ABORT_SIGOPS_COST,
              "one owner script can cost more than a whole abort may spend");

// A deposit output is what DecodeDepositPayload returns, so P2PKH is the worst
// case: one signature operation per 34 bytes, which is 136 weight.
static_assert(WITNESS_SCALE_FACTOR * (MAX_COINBASE_DEPOSIT_WEIGHT / 136) +
                      MAX_ABORT_SIGOPS_COST + 400 <=
                  MAX_BLOCK_SIGOPS_COST,
              "a full deposit budget and a full abort can cost more sigops than a block holds");

size_t DepositWeight(const std::vector<CTxOut>& outputs)
{
    size_t weight{0};
    for (const CTxOut& out : outputs) weight += WITNESS_SCALE_FACTOR * GetSerializeSize(out);
    return weight;
}

bool BuildDepositOutputs(PegDataSource& cache,
                         const std::optional<uint256>& start,
                         const uint256& end,
                         std::vector<CTxOut>& out,
                         std::string& error)
{
    std::vector<Deposit> deposits;
    if (cache.GetDepositsBetween(start, end, deposits) != DepositRangeResult::Ok) {
        error = "mainchain range not cached";
        return false;
    }
    out.clear();
    for (const Deposit& d : SortDeposits(deposits)) {
        const std::optional<CScript> script{DecodeDepositPayload(d.address)};
        // An undecodable payload still carries real mainchain value, so it is
        // credited to an unspendable output rather than dropped.
        out.emplace_back(d.value, script ? *script : UndecodableDepositScript());
    }
    return true;
}

} // namespace

bool CancelStagedAbort(const COutPoint& outpoint) EXCLUSIVE_LOCKS_REQUIRED(!g_staged_mutex)
{
    LOCK(g_staged_mutex);
    const size_t before{g_staged_aborts.size() + g_bumped_aborts.size()};
    std::erase(g_staged_aborts, outpoint);
    // Also the ones a staged bundle took over, or a cancel would bring back an
    // abort the operator already dropped.
    std::erase(g_bumped_aborts, outpoint);
    return g_staged_aborts.size() + g_bumped_aborts.size() != before;
}

size_t ComputeDepositBudget(size_t block_max_weight, size_t reserved_weight)
{
    // The two outputs the peg always adds to the coinbase. Both are fixed size,
    // so an empty hash prices them exactly.
    const size_t coinbase_peg{
        WITNESS_SCALE_FACTOR * GetSerializeSize(BuildBmmCommitmentOutput(uint256{})) +
        WITNESS_SCALE_FACTOR *
            GetSerializeSize(BuildLiveBundleOutput({LiveBundleRef{COutPoint{Txid{}, 0}, uint256{}}}))};
    const size_t taken{reserved_weight + coinbase_peg + PEG_RESERVE_WEIGHT};
    if (block_max_weight <= taken) return 0;
    return std::min(MAX_COINBASE_DEPOSIT_WEIGHT, block_max_weight - taken);
}

StageSnapshot TakeStageSnapshot() EXCLUSIVE_LOCKS_REQUIRED(!g_staged_mutex)
{
    LOCK(g_staged_mutex);
    return StageSnapshot{g_staged_bundle, g_staged_aborts, g_bumped_aborts};
}

size_t StagedBundleWeight(ChainstateManager& chainman) EXCLUSIVE_LOCKS_REQUIRED(!g_staged_mutex)
{
    std::vector<COutPoint> staged;
    {
        LOCK(g_staged_mutex);
        staged = g_staged_bundle;
    }
    if (staged.empty()) return 0;

    LOCK(cs_main);
    CCoinsViewCache& view{chainman.ActiveChainstate().CoinsTip()};
    CMutableTransaction bundle;
    CAmount total{0};
    std::vector<WithdrawalRequest> requests;
    for (const COutPoint& outpoint : staged) {
        const Coin& coin{view.AccessCoin(outpoint)};
        const auto request{coin.IsSpent() ? std::nullopt
                                          : ParseWithdrawalRequestOutput(coin.out)};
        if (!request) return 0;
        bundle.vin.emplace_back(outpoint);
        requests.push_back(*request);
        total += request->amount;
    }
    const auto m6id{BundleId(requests)};
    if (!m6id) return 0;
    bundle.vout.push_back(BuildBundleOutput(*m6id, RequestSetDigest(requests), total));
    return static_cast<size_t>(GetTransactionWeight(CTransaction{bundle}));
}

bool BuildPegTransactions(ChainstateManager& chainman,
                          const CBlockIndex& prev_index,
                          const uint256& prev_main,
                          const std::optional<uint256>& parent_prev_main,
                          const StageSnapshot& stage,
                          std::vector<CTransactionRef>& txs_out,
                          std::vector<LiveBundleRef>& live_out,
                          std::string& error)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main, !g_staged_mutex)
{
    PegDataSource* cache{GetPegDataSource()};
    if (cache == nullptr) {
        error = "no enforcer cache";
        return false;
    }

    std::vector<LiveBundleRef> parent_live;
    if (prev_index.nHeight > 0) {
        CBlock parent;
        if (!chainman.m_blockman.ReadBlock(parent, prev_index) || parent.vtx.empty()) {
            error = "cannot read parent block";
            return false;
        }
        const auto previous{GetLiveBundles(*parent.vtx[0])};
        if (!previous) {
            error = "parent declares an unreadable live bundle set";
            return false;
        }
        parent_live = *previous;
    }

    CCoinsViewCache& view{chainman.ActiveChainstate().CoinsTip()};
    std::vector<LiveBundle> live;
    for (const LiveBundleRef& ref : parent_live) {
        const Coin& coin{view.AccessCoin(ref.outpoint)};
        uint256 m6id;
        uint256 committed_requests;
        if (coin.IsSpent() || !IsBundleScript(coin.out.scriptPubKey, m6id, committed_requests) ||
            m6id != ref.m6id) {
            error = strprintf("live bundle %s is not in the UTXO set", ref.outpoint.ToString());
            return false;
        }
        live.push_back({ref.outpoint, m6id, coin.out.nValue});
    }

    std::vector<WithdrawalBundleEvent> events;
    if (cache->GetBundleEventsBetween(parent_prev_main, prev_main, events) != DepositRangeResult::Ok) {
        error = "mainchain range not cached";
        return false;
    }
    const std::map<uint256, BundleOutcome> verdicts{CollectVerdicts(events)};

    const auto add_tx{[&](CMutableTransaction&& tx) {
        const CTransactionRef ref{MakeTransactionRef(std::move(tx))};
        txs_out.push_back(ref);
        return ref;
    }};

    live_out.clear();
    for (const LiveBundle& bundle : live) {
        const auto verdict{verdicts.find(bundle.m6id)};
        if (verdict == verdicts.end()) {
            live_out.push_back(LiveBundleRef{bundle.outpoint, bundle.m6id});
            continue;
        }

        CMutableTransaction settlement;
        settlement.vin.emplace_back(bundle.outpoint);
        if (verdict->second == BundleOutcome::Paid) {
            // Paid on the mainchain, so the sidechain's copy stops existing.
            settlement.vout.emplace_back(bundle.value, CScript() << OP_RETURN);
        } else {
            // Not paid, so every request comes back exactly as it was. Recovered
            // from the block that opened the bundle, and checked by consensus
            // against the m6id that bundle committed to.
            std::vector<CTxOut> requests;
            if (!GetBundleMembers(bundle, requests, error)) return false;
            settlement.vout = requests;
        }
        add_tx(std::move(settlement));
    }

    // Aborts run whether or not a bundle is live: they touch only requests no
    // bundle holds, so they cannot disturb one the mainchain is voting on.
    {
        const std::vector<COutPoint>& aborting{stage.aborts};
        std::vector<COutPoint> outpoints;
        std::vector<COutPoint> spent_already;
        int64_t abort_sigops{0};
        std::vector<WithdrawalRequest> requests;
        for (const COutPoint& outpoint : aborting) {
            const Coin& coin{view.AccessCoin(outpoint)};
            const auto request{coin.IsSpent() ? std::nullopt
                                              : ParseWithdrawalRequestOutput(coin.out)};
            // Bundled or aborted already by the time a block is built. Nothing
            // left to do for it, so it leaves the queue.
            if (!request) {
                spent_already.push_back(outpoint);
                continue;
            }
            // Capped by count like a bundle, so one transaction does not outgrow
            // the block that carries it, and by signature operations because an
            // owner script is the owner's to choose. The weight needs no cap:
            // the reserve every block holds back covers an abort at its count.
            // The rest keeps its place and goes in the next block.
            const int64_t sigops{WITNESS_SCALE_FACTOR * request->owner.GetSigOpCount(false)};
            if (outpoints.size() == MAX_BUNDLE_WITHDRAWALS ||
                abort_sigops + sigops > MAX_ABORT_SIGOPS_COST) {
                break;
            }
            abort_sigops += sigops;
            outpoints.push_back(outpoint);
            requests.push_back(*request);
        }
        // Only what is gone is dropped. A template is not a block, so an abort
        // stays queued until the request it names is actually spent -- which is
        // what brings it back here as spent_already.
        {
            LOCK(g_staged_mutex);
            std::erase_if(g_staged_aborts, [&](const COutPoint& outpoint) {
                return std::find(spent_already.begin(), spent_already.end(), outpoint) !=
                       spent_already.end();
            });
        }
        if (!outpoints.empty()) {
            add_tx(BuildAbortTransaction(outpoints, requests));
        }
    }

    // One bundle at a time: concurrent bundles would race for the same treasury.
    if (live_out.empty()) {
        // The snapshot is the one taken with the abort queue. Two reads let
        // create_bundle move an outpoint between them, and the block would then
        // spend it twice.
        const std::vector<COutPoint>& staged{stage.bundle};
        if (!staged.empty()) {
            CMutableTransaction bundle;
            CAmount total{0};
            std::vector<Withdrawal> withdrawals;
            std::vector<WithdrawalRequest> staged_requests;
            for (const COutPoint& outpoint : staged) {
                const Coin& coin{view.AccessCoin(outpoint)};
                const auto request{coin.IsSpent() ? std::nullopt
                                                  : ParseWithdrawalRequestOutput(coin.out)};
                // A staged request can be spent by the time a block is built, so
                // a stale stage is dropped rather than failing the template.
                if (!request) {
                    // A bundle is a set: one member gone changes the m6id, so
                    // the whole stage goes. A live bundle means the block that
                    // carried this stage spent them, which is the ordinary path
                    // and no news. With none live, something else took them.
                    if (live.empty()) {
                        LogWarning("sidechain: dropped the staged bundle, because request %s went "
                                   "into no bundle of ours; call create_bundle again\n",
                                   outpoint.ToString());
                    }
                    LOCK(g_staged_mutex);
                    g_staged_bundle.clear();
                    // It took these from the abort queue and no longer holds
                    // them, so they go back with it.
                    RestoreBumpedAborts();
                    return true;
                }
                bundle.vin.emplace_back(outpoint);
                withdrawals.push_back(ToWithdrawal(*request));
                staged_requests.push_back(*request);
                total += request->amount;
            }
            const auto m6id{BundleId(staged_requests)};
            if (!m6id) {
                error = "staged withdrawals do not form a valid bundle";
                return false;
            }
            // The same test the validator applies. A block that opens such a
            // bundle is refused, and the producer would then fail its own
            // validation on every later template too.
            if (BundleAlreadyRuled(*m6id, verdicts, parent_live)) {
                // Dropped, not skipped. A block that opened it would strand the
                // verdict, and consensus refuses such a block -- so a stage kept
                // here would fail every later template until somebody noticed.
                // The requests stay pending, so create_bundle works again.
                LogWarning("sidechain: dropped the staged bundle %s, because the mainchain already "
                           "ruled on it over this block's range\n", m6id->GetHex());
                LOCK(g_staged_mutex);
                g_staged_bundle.clear();
                RestoreBumpedAborts();
                return true;
            }
            bundle.vout.push_back(BuildBundleOutput(*m6id, RequestSetDigest(staged_requests), total));

            const CTransactionRef ref{add_tx(std::move(bundle))};
            live_out.push_back(LiveBundleRef{COutPoint{ref->GetHash(), 0}, *m6id});
        }
    }
    return true;
}


bool ReadPegAnchors(const CBlockIndex* prev_index,
                    const ReadBlockFn& read_block,
                    uint256& tip_out,
                    std::optional<uint256>& parent_out,
                    std::string& error)
{
    PegDataSource* cache{GetPegDataSource()};
    if (cache == nullptr || !cache->IsSynced()) {
        error = "enforcer unavailable";
        return false;
    }
    const std::optional<uint256> tip{cache->GetSyncedTip()};
    if (!tip) {
        error = "enforcer unavailable";
        return false;
    }
    tip_out = *tip;
    return ReadPrevMainOf(prev_index, read_block, parent_out, error);
}

bool BuildCoinbasePegOutputs(const CBlockIndex* prev_index,
                             const ReadBlockFn& read_block,
                             const uint256& tip,
                             size_t max_deposit_weight,
                             CoinbasePeg& out,
                             std::string& error)
{
    // The cut has to target the budget the block is really built to, not a
    // constant. A smaller -blockmaxweight than the constant makes every cut
    // land above the budget, and the miner then throws on every block.
    // Already clamped by ComputeDepositBudget, and it does not move with what
    // the peg costs: the peg has a reserve of its own.
    const size_t budget{max_deposit_weight};
    PegDataSource* cache{GetPegDataSource()};
    if (cache == nullptr || !cache->IsSynced()) {
        error = "enforcer unavailable";
        return false;
    }

    if (!ReadPrevMainOf(prev_index, read_block, out.parent_prev_main, error)) return false;

    // A block credits every deposit in its mainchain range, so a long backlog
    // makes a coinbase no block can hold -- and it stays that way, because the
    // range comes from the chain and not from memory. The range is the
    // producer's to choose: it only has to end no earlier than the parent's
    // anchor, so a backlog drains over as many blocks as it takes.
    uint256 chosen{tip};
    if (!BuildDepositOutputs(*cache, out.parent_prev_main, chosen, out.deposits, error)) return false;
    if (DepositWeight(out.deposits) > budget) {
        const std::optional<int32_t> ceiling{cache->GetHeight(tip)};
        const std::optional<int32_t> lowest{cache->GetLowestHeight()};
        // The lowest end the producer may pick. With a parent, its own anchor,
        // which credits nothing. Without one this is the first sidechain block,
        // whose range starts at the mainchain genesis, so the floor is the
        // lowest block the cache reaches. That range holds every deposit the
        // slot ever took, which is the largest backlog there is.
        const std::optional<int32_t> floor{
            out.parent_prev_main ? cache->GetHeight(*out.parent_prev_main) : lowest};
        if (!ceiling || !floor || !lowest) {
            error = "mainchain range not cached";
            return false;
        }
        const auto hash_at{[&](int32_t height) -> std::optional<uint256> {
            if (out.parent_prev_main && height == *floor) return out.parent_prev_main;
            return cache->GetHashAtHeight(height);
        }};

        int32_t low{*floor};
        int32_t high{*ceiling};
        while (low < high) {
            const int32_t mid{low + (high - low + 1) / 2};
            // The cache holds a block only when it carried something for this
            // slot, so a height it does not reach is a gap and not a candidate.
            // Walked down, the way a heavy candidate is, because the range may
            // still end below it.
            const std::optional<uint256> at{hash_at(mid)};
            std::vector<CTxOut> outputs;
            if (at && !BuildDepositOutputs(*cache, out.parent_prev_main, *at, outputs, error)) {
                return false;
            }
            if (!at || DepositWeight(outputs) > budget) {
                high = mid - 1;
            } else {
                low = mid;
            }
        }
        // With a parent, the floor is the parent's own anchor, whose range is
        // empty. Landing there means the very next mainchain block does not fit
        // by itself, and the range can go nowhere. Blocks would then credit
        // nothing, block after block, and the verdicts that ride the same range
        // would stop with them -- both directions of the peg, silently. This
        // says so instead.
        //
        // Out of reach for deposits the peg can credit: those pay a decoded
        // destination of at most 34 bytes, which the budget above covers with
        // room to spare. A payload that decodes to nothing earns a 10-byte
        // output, which is smaller again. A -blockmaxweight far below the
        // default is what makes this reachable.
        if (out.parent_prev_main && low == *floor && *floor < *ceiling) {
            // The budget does not move with what the peg costs, so a floor
            // landing is about the block size and the deposits alone. No hold:
            // the next block computes the same thing, so a wait never ends.
            std::vector<CTxOut> next_block;
            const std::optional<uint256> next{cache->GetHashAtHeight(*floor + 1)};
            if (!next || !BuildDepositOutputs(*cache, out.parent_prev_main, *next, next_block, error)) {
                // The cache does not reach the block the range would end at.
                // Deferred, because the next poll may close the gap.
                error = "mainchain range not cached";
                return false;
            }
            if (DepositWeight(next_block) <= MAX_COINBASE_DEPOSIT_WEIGHT) {
                error = strprintf("mainchain block %d holds %u weight of deposits, and a block "
                                  "this size leaves them %u; raise -blockmaxweight",
                                  *floor + 1, DepositWeight(next_block), budget);
                return false;
            }
            error = strprintf("the deposits up to mainchain block %d need more than the %u weight "
                              "a coinbase may spend, so the range cannot move",
                              *floor + 1, MAX_COINBASE_DEPOSIT_WEIGHT);
            return false;
        }
        const std::optional<uint256> at{hash_at(low)};
        if (!at) {
            error = "mainchain range not cached";
            return false;
        }
        chosen = *at;
        if (!BuildDepositOutputs(*cache, out.parent_prev_main, chosen, out.deposits, error)) {
            return false;
        }
        // The first sidechain block has no parent anchor, so its floor is a
        // real block with deposits of its own. That one can be too large too.
        if (DepositWeight(out.deposits) > budget) {
            error = strprintf("the deposits in one mainchain block need %u weight, above the %u a "
                              "coinbase may spend",
                              DepositWeight(out.deposits), budget);
            return false;
        }
    }

    out.prev_main = chosen;
    out.bmm_commitment = BuildBmmCommitmentOutput(chosen);
    return true;
}

} // namespace sidechain
