// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_WITHDRAWAL_H
#define BITCOIN_SIDECHAIN_WITHDRAWAL_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sidechain/bundle.h>
#include <sidechain/script.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace sidechain {

/**
 * A pending withdrawal, held by an encumbered output on the sidechain.
 *
 * The coins are not destroyed here. They are destroyed only once the mainchain
 * has actually paid the bundle carrying this request out, so a request that is
 * merely queued -- or whose bundle loses the vote -- is still the owner's money,
 * sitting in the UTXO set where double-spend prevention, reorg undo and identity
 * already work. Burning at request time is what forces a status database and a
 * minting refund path, and both are where the reference sidechain's inflation
 * bugs live.
 */
struct WithdrawalRequest {
    //! Mainchain destination scriptPubKey, paid by the M6.
    CScript dest;
    //! Sidechain scriptPubKey the coins return to on abort or bundle failure.
    //! Committed in the output because the request is spent without a signature.
    CScript owner;
    CAmount amount{0};
    CAmount mainchain_fee{0};
};

/**
 * Cap on how many requests one bundle may carry.
 *
 * A settlement spends every request in the bundle, so an unbounded bundle would
 * be an unbounded transaction.
 */
constexpr size_t MAX_BUNDLE_WITHDRAWALS{64};

/**
 * Cap on a destination or owner script.
 *
 * Comfortably above every standard output script (P2TR and P2WSH are the largest
 * at 34 bytes). Without it, a bundle of attacker-chosen scripts yields an M6 the
 * mainchain cannot carry and a settlement that can outgrow its own block.
 */
constexpr size_t MAX_PEG_SCRIPT_SIZE{64};

/**
 * Build the request output.
 *
 * Anyone-can-spend at script level, and non-relayable by policy. The producer
 * has to sweep and settle these without every withdrawer being online to sign,
 * so no signature can be required; block-only movement is what stops anyone
 * else touching them, since every block costs a BMM bid. Where the coins may go
 * is pinned by consensus, not by script.
 */
CTxOut BuildWithdrawalRequestOutput(const WithdrawalRequest& request);

//! nullopt if the output is not a well-formed withdrawal request.
std::optional<WithdrawalRequest> ParseWithdrawalRequestOutput(const CTxOut& out);

bool IsWithdrawalRequestOutput(const CTxOut& out);

/**
 * A bundle in flight: where its coins sit, and what the mainchain votes on.
 *
 * The m6id travels with the outpoint so a validator can tell which verdict
 * belongs to which bundle without looking the transaction up, which would
 * otherwise make -txindex a consensus requirement.
 */
struct LiveBundleRef {
    COutPoint outpoint;
    uint256 m6id;

    friend bool operator==(const LiveBundleRef&, const LiveBundleRef&) = default;
    friend bool operator<(const LiveBundleRef& a, const LiveBundleRef& b)
    {
        if (a.outpoint != b.outpoint) return a.outpoint < b.outpoint;
        return a.m6id < b.m6id;
    }
};

/**
 * Coinbase output naming the bundles this block leaves in flight.
 *
 * Carried block to block and checked against the parent's, the way prev_main
 * already is, so a node knows which bundles are live without an index. That is
 * what makes settlement mandatory: a payout cannot be quietly skipped, which
 * would leave the sidechain holding coins the mainchain has already handed out.
 *
 * Naming outpoints rather than m6ids is deliberate. An outpoint has to exist,
 * so a bundle nobody built can never enter the set and oblige a block to settle
 * something unsettleable.
 */
CTxOut BuildLiveBundleOutput(const std::vector<LiveBundleRef>& live);

//! Read the live set back. An absent output means nothing is in flight; nullopt
//! means the block declared one and it could not be read.
std::optional<std::vector<LiveBundleRef>> GetLiveBundles(const CTransaction& coinbase);

//! The output a bundle transaction creates, holding the bundled coins.
CTxOut BuildBundleOutput(const uint256& m6id, const uint256& requests, CAmount value);

/**
 * Digest of a request set, in order, covering everything the m6id does not.
 *
 * The blinded M6 carries only the mainchain destination and the payout, so
 * without this a settlement could rewrite who a request returns to, or move the
 * mainchain fee between requests, and still hash to the same m6id.
 */
uint256 RequestSetDigest(const std::vector<WithdrawalRequest>& requests);

/**
 * The m6id a set of requests would produce.
 *
 * nullopt when the set could not be a bundle at all, which includes being over
 * the cap. Both the producer and the validator go through here, so a bundle the
 * producer can build is one the validator can accept.
 */
std::optional<uint256> BundleId(const std::vector<WithdrawalRequest>& requests);

/**
 * Validate a bundle transaction: it sweeps pending requests into one bundle.
 *
 * Every input must be a request output, and the single output must commit to
 * the m6id computed from exactly those requests. Nothing is created or
 * destroyed, so the coins stay backed while the mainchain votes.
 */
bool CheckBundleTransaction(const CTransaction& tx,
                            const std::vector<CTxOut>& spent_outputs,
                            uint256& m6id_out,
                            std::string& reason);

/**
 * Check a block's live set against its parent's, given what it did.
 *
 * `opened` is the bundle this block created, if any; `settled` are the bundles
 * it resolved; `owed` are those the mainchain has ruled on, which it must.
 *
 * A verdict is visible over exactly one block's mainchain range, so a block
 * that declines to act on one strands that bundle forever -- and since a new
 * bundle can only open when none is live, it strands every future withdrawal
 * with it. Only one bundle may be in flight, because the mainchain votes on one
 * per slot and a second could never be paid.
 */
bool CheckLiveBundles(const std::vector<LiveBundleRef>& parent_live,
                      const std::optional<LiveBundleRef>& opened,
                      const std::vector<COutPoint>& settled,
                      const std::vector<COutPoint>& owed,
                      const std::vector<LiveBundleRef>& live,
                      std::string& reason);

//! What the mainchain decided about a bundle, and so which settlement is owed.
enum class BundleOutcome {
    Paid,
    Failed,
};

/**
 * Validate a settlement transaction: it resolves one bundle.
 *
 * Paid means the mainchain has handed the coins over, so the sidechain's copy
 * is destroyed. Failed means it has not, so the requests come back exactly as
 * they were -- recovered from the settlement's own outputs and checked against
 * the m6id the spent bundle committed to, which is only trustworthy because
 * that bundle output has to exist to be spent.
 */
bool CheckSettlementTransaction(const CTransaction& tx,
                                const std::vector<CTxOut>& spent_outputs,
                                BundleOutcome outcome,
                                uint256& m6id_out,
                                std::string& reason);

/**
 * Validate an abort transaction: it gives requests back to their owners.
 *
 * Every input is a request that no bundle holds, and every output pays the
 * script that request committed to, for what that request was worth. This is
 * the only way coins leave the peg without the mainchain, and it is what stops
 * a queued withdrawal from being a one-way door when no bundle ever wins.
 *
 * Owners are paid one output each, in input order, so a validator needs nothing
 * but the spent outputs to check it. No fee is taken: the request pays no
 * signature and cannot be relayed, so the block that carries it is already paid
 * for by its BMM bid.
 */
bool CheckAbortTransaction(const CTransaction& tx,
                           const std::vector<CTxOut>& spent_outputs,
                           std::string& reason);

//! Build the abort that returns these requests to their owners.
CMutableTransaction BuildAbortTransaction(const std::vector<COutPoint>& outpoints,
                                          const std::vector<WithdrawalRequest>& requests);

//! The M6 view of a request. Refunds are sidechain-side and not carried here.
Withdrawal ToWithdrawal(const WithdrawalRequest& request);

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_WITHDRAWAL_H
