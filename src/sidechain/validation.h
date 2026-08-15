// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_VALIDATION_H
#define BITCOIN_SIDECHAIN_VALIDATION_H

#include <consensus/amount.h>
#include <sync.h>
#include <consensus/consensus.h>
#include <sidechain/hook.h>
#include <sidechain/enforcer_client.h>
#include <sidechain/withdrawal.h>

class ChainstateManager;

#include <map>
#include <optional>
#include <string_view>
#include <primitives/transaction.h>

#include <functional>
#include <string>
#include <vector>

class CBlock;
class CBlockIndex;
class BlockValidationState;

namespace sidechain {

//! Guards the staged bundle and the staged aborts. Named here so a caller can
//! carry the annotation that says it does not hold them.
extern Mutex g_staged_mutex;
//! Guards the record of payouts this chain never opened.
extern Mutex g_orphaned_mutex;


class PegDataSource;

/**
 * Install the peg data source.
 *
 * validation.cpp is compiled into both bitcoin_node and bitcoinkernel, but the
 * enforcer client belongs only in the former. The kernel leaves this unset, and
 * an unset source refuses to validate a sidechain block rather than skipping the
 * peg rules -- silently skipping them would be a consensus hole.
 */
void SetPegDataSource(PegDataSource* source);

/**
 * What the mainchain ruled on over a range, indexed by m6id.
 *
 * A payout is final: anyone may propose a paid m6id again, and that proposal can
 * only expire, because the treasury output it spends is gone. So a later Failed
 * never overrides an earlier Paid, and the order the events arrive in cannot
 * change the answer.
 *
 * A shorter range can still give a different outcome, not merely fewer of them:
 * it may hold the Failed and not the Paid.
 */
std::map<uint256, BundleOutcome> CollectVerdicts(const std::vector<WithdrawalBundleEvent>& events);

/**
 * Whether opening this bundle would strand its own verdict.
 *
 * A verdict is visible over exactly one block's range. Opening a bundle this
 * range already ruled on consumes that verdict unseen, so no later block can
 * act on it and the bundle stays live forever. A bundle the parent already held
 * is a different case: this block settles it, and that is legal.
 *
 * The validator refuses such a block and the producer never builds one, so both
 * ask through here. Two copies of this test drifted apart once already.
 */
bool BundleAlreadyRuled(const uint256& m6id,
                        const std::map<uint256, BundleOutcome>& verdicts,
                        const std::vector<LiveBundleRef>& parent_live);

/**
 * Bundles the mainchain paid that this chain never opened.
 *
 * The peg is short by every one of them: the treasury handed out coins nothing
 * here destroyed. No rule can undo a mainchain payout, so this is a report, not
 * a recovery.
 *
 * Every payout for a bundle the parent did not hold reports, including one for
 * an m6id this chain settled earlier. A re-proposal that the mainchain pays a
 * second time really is a second payout, and this chain destroys the coins one
 * time. A report nobody owes beats a shortfall nobody sees.
 *
 * KNOWN LIMITATION: held in memory only. A shortfall is permanent, but this
 * report is not: a restart clears it and only a reindex brings it back, so a
 * node that restarts looks healthy while the peg still holds less than it owes.
 */
//! Each bundle, and how many payouts this chain saw for it. The mainchain may
//! pay one m6id twice, and this chain destroys the coins one time, so the count
//! is what the peg is short by.
std::map<uint256, size_t> GetOrphanedPayouts(
    const std::function<bool(const uint256&)>& on_active_chain);

//! Register CheckBlockPegRulesImpl with the dispatcher. Called from init.
void RegisterPegCheck();
PegDataSource* GetPegDataSource();

//! Reads a confirmed transaction by txid, or returns null.
using FindTxFn = CTransactionRef (*)(const uint256&);

//! Give the peg a transaction index to read. Called from init, before any
//! thread starts. A node without one still validates every block, it just
//! cannot build the settlement that gives a failed bundle's requests back.
void SetTxLookup(FindTxFn lookup);

//! Distinguishes "cannot answer yet" from "this block is provably bad".
enum class DepositRangeResult {
    Ok,
    //! Not cached yet. Defer, do not reject.
    Unavailable,
    //! start is after end. No honest block can name such a range.
    Invalid,
};

//! Everything CheckBlockPegRules needs from the mainchain view.
class PegDataSource
{
public:
    virtual ~PegDataSource() = default;
    virtual bool IsSynced() const = 0;
    virtual std::optional<uint256> GetSyncedTip() const = 0;
    virtual std::optional<int32_t> GetHeight(const uint256& block_hash) const = 0;
    //! The cached mainchain block at this height, if the cache reaches it.
    virtual std::optional<uint256> GetHashAtHeight(int32_t height) const = 0;
    //! The lowest mainchain height a cached header names, if any.
    virtual std::optional<int32_t> GetLowestHeight() const = 0;
    virtual std::optional<uint256> FindBmmAnchor(const uint256& block_hash) const = 0;
    virtual DepositRangeResult GetDepositsBetween(const std::optional<uint256>& start,
                                                  const uint256& end,
                                                  std::vector<Deposit>& out) const = 0;
    /**
     * Bundle events over the same range, and with the same coverage rule, as
     * GetDepositsBetween: a partial answer would let two nodes disagree about
     * which bundles failed, and so about which refunds a block owes.
     */
    virtual DepositRangeResult GetBundleEventsBetween(const std::optional<uint256>& start,
                                                      const uint256& end,
                                                      std::vector<WithdrawalBundleEvent>& out) const = 0;
    virtual void RequestBackfill() const = 0;
};


/**
 * Enforce the peg rules for a sidechain block.
 *
 * Reads only the cache, never the enforcer: this runs under cs_main, where an
 * HTTP round trip would be a stall rather than a slow path.
 *
 * KNOWN LIMITATION: a mainchain block whose peg payload exceeds the client's
 * response cap stalls the poll permanently, because the retry is the identical
 * request. Bounded chunking makes this unreachable for headers; the forward peg
 * fetch is bounded only by how far the tip moved between polls.
 *
 * KNOWN LIMITATION: nothing makes prev_main advance. A block whose range is
 * empty is valid, so a producer may hold its anchor forever. No deposit is
 * credited and no verdict becomes actionable, so a live bundle never settles.
 * The cut makes a short range ordinary, so this rests on the producer alone.
 *
 * KNOWN LIMITATION: a reorg that takes back the block which opened a bundle
 * does not bring the stage back. The template cleared it once the requests read
 * as spent, so the operator calls create_bundle again.
 *
 * KNOWN LIMITATION: a reorg drops a staged abort. The abort leaves the queue
 * once the request it names is spent. A reorg that removes the block carrying it
 * makes the request unspent again, with nothing staged. The owner calls
 * abort_withdrawal again.
 *
 * KNOWN LIMITATION: a mainchain reorg does not reorg the sidechain. Sidechain
 * blocks already connected against a now-orphaned prev_main stay connected,
 * while a node syncing afterwards cannot resolve that prev_main and stalls.
 * That is a permanent split condition and must be fixed before this carries
 * value.
 *
 * When the cache cannot answer — no enforcer, or one still catching up — this
 * fails with state.Error() rather than state.Invalid(). The distinction is
 * load-bearing: Invalid marks the block permanently bad and would have a node
 * with a lagging enforcer reject good blocks and ban itself off the network.
 * Error just stops the connection attempt and lets it retry.
 *
 * `template_only` skips the BMM check. A block being assembled has not been
 * blind-merge-mined yet — that is precisely what the caller does next — so
 * requiring it here would make block production impossible. Deposit rules are
 * still enforced, since those are knowable at assembly.
 */
bool CheckBlockPegRulesImpl(const CBlock& block,
                        const CBlockIndex& index,
                        const ReadBlockFn& read_block,
                        const SpentOutputsFn& spent_outputs,
                        bool template_only,
                        CAmount& deposit_credit,
                        BlockValidationState& state);

/**
 * Ask the next block to sweep these requests into a bundle.
 *
 * Producer-side intent, not consensus: a bundle only becomes real when a block
 * carrying it connects, and a restart drops this.
 *
 * False when one already waits for a block. The test and the claim are one step
 * here, because two callers that each test first would both pass, and the
 * second would replace the first -- whose m6id then reaches no block and no RPC.
 */
[[nodiscard]] bool StageBundle(const std::vector<COutPoint>& outpoints);

/**
 * Drop a staged bundle. False when nothing was staged.
 *
 * The requests go back to the pending queue, and any abort the bundle took over
 * goes back to the abort queue with them.
 */
bool CancelStagedBundle();

/**
 * Ask the next block to return these requests to their owners.
 *
 * False when a staged bundle already claims one of them. Both stages build a
 * transaction that spends the request, so a block carrying both is invalid.
 */
[[nodiscard]] bool StageAbort(const std::vector<COutPoint>& outpoints);

//! What the operator asked the next block to carry. Taken one time, so two
//! reads cannot see a request move from one queue to the other.
struct StageSnapshot {
    std::vector<COutPoint> bundle;
    std::vector<COutPoint> aborts;
    //! Aborts a staged bundle took over. They come back if it is cancelled.
    std::vector<COutPoint> bumped_aborts;
};

StageSnapshot TakeStageSnapshot();

//! What a block has to hold to carry the staged bundle. Zero when none waits.
size_t StagedBundleWeight(ChainstateManager& chainman);

//! Drop a staged abort. False when neither queue held it.
bool CancelStagedAbort(const COutPoint& outpoint);

/**
 * What a block holds back for the peg, whatever the peg turns out to cost.
 *
 * Every peg transaction is bounded by MAX_BUNDLE_WITHDRAWALS and
 * MAX_PEG_SCRIPT_SIZE, so one constant covers the worst block: a failed
 * settlement of 64 requests, an abort of 64, and one bundle open. A number the
 * producer measures instead would have to agree with itself across two passes
 * over two ranges, and it can only differ from this below a -blockmaxweight no
 * operator sets.
 */
constexpr size_t PEG_RESERVE_WEIGHT{
    WITNESS_SCALE_FACTOR *
    (3 * 100 + MAX_BUNDLE_WITHDRAWALS *
                   (2 * (41 + 9 + MAX_WITHDRAWAL_PAYLOAD_SIZE) + (41 + 9 + MAX_PEG_SCRIPT_SIZE)))};

//! What the deposits may spend in one block, after that reserve.
size_t ComputeDepositBudget(size_t block_max_weight, size_t reserved_weight);

/**
 * The peg transactions a block owes, and the live bundle set that results.
 *
 * Settlements are not optional -- consensus requires one for every live bundle
 * the mainchain has ruled on -- so this produces them whether or not anyone
 * asked. Opening a bundle is the operator's call, staged by create_bundle.
 *
 * What it costs is bounded by PEG_RESERVE_WEIGHT, which every block holds back,
 * so the deposits and the peg never compete for one byte.
 */
bool BuildPegTransactions(ChainstateManager& chainman,
                          const CBlockIndex& prev_index,
                          const uint256& prev_main,
                          const std::optional<uint256>& parent_prev_main,
                          const StageSnapshot& stage,
                          std::vector<CTransactionRef>& txs_out,
                          std::vector<LiveBundleRef>& live_out,
                          std::string& error);

//! Everything the coinbase owes the peg, and the mainchain range it covers.
struct CoinbasePeg {
    std::vector<CTxOut> deposits;
    CTxOut bmm_commitment;
    //! The mainchain block this sidechain block anchors to.
    uint256 prev_main;
    //! The parent's anchor. Absent at the first sidechain block.
    std::optional<uint256> parent_prev_main;
};

/**
 * The two ends of the widest range a block may credit.
 *
 * The mainchain tip the cache knows, and the parent's own anchor. Reads no
 * deposits, so a producer can price the peg transactions before it decides how
 * much of the range the deposits may have.
 */
bool ReadPegAnchors(const CBlockIndex* prev_index,
                    const ReadBlockFn& read_block,
                    uint256& tip_out,
                    std::optional<uint256>& parent_out,
                    std::string& error);

/**
 * Build the peg outputs a sidechain coinbase must carry, and the range they
 * cover.
 *
 * Leading outputs credit the deposits in the range since the parent, followed
 * by the commitment to the mainchain block the range ends at. Ordering matches
 * what CheckBlockPegRules expects.
 *
 * The range is the producer's to choose, and it ends earlier than the mainchain
 * tip when the deposits would not fit. A block credits every deposit in its
 * range, so an unbounded range is a coinbase no block can hold -- and it stays
 * that way, because the range comes from the chain and not from memory.
 *
 * KNOWN LIMITATION: one mainchain block can carry more deposits than a sidechain
 * block can credit, because a block credits its whole range or none of it. The
 * producer reports that state and makes no block at all -- so no BMM auction,
 * no withdrawal and no user transaction either, not only no deposit. A partial
 * credit needs a cursor the coinbase commits to, which this does not have.
 *
 * The enforcer's own wallet cannot reach that state: each M5 spends the treasury
 * output the last one made, and an unconfirmed one is replaced rather than
 * chained, so it puts one deposit in a mainchain block. Other software can chain
 * them, so the branch stays. It has unit coverage and no functional coverage.
 *
 * The tip comes from the caller, not from a second read of the cache: a poll
 * between the two would widen the range past the one the caller priced.
 *
 * The search for that earlier end reads the cache about twenty times, and the
 * cache can resync between two of those reads. The producer then builds a block
 * its own validation refuses, so this costs liveness, never a split. It only
 * runs when a backlog is larger than a quarter of a block.
 */
bool BuildCoinbasePegOutputs(const CBlockIndex* prev_index,
                             const ReadBlockFn& read_block,
                             const uint256& tip,
                             //! What ComputeDepositBudget gives them.
                             size_t max_deposit_weight,
                             CoinbasePeg& out,
                             std::string& error);

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_VALIDATION_H
