// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/txindex.h>
#include <interfaces/mining.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <policy/policy.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <sidechain/bmm.h>
#include <sidechain/bundle.h>
#include <sidechain/cache.h>
#include <sidechain/enforcer_client.h>
#include <sidechain/withdrawal.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <limits>
#include <map>

using interfaces::BlockTemplate;
using interfaces::Mining;
using node::NodeContext;

using sidechain::IEnforcerClient;

namespace {

//! Every enforcer-backed RPC goes through the configured client, so
//! -enforcerhost/-enforcerport are honoured rather than assumed.
const IEnforcerClient& Client()
{
    sidechain::MainchainCache* cache{sidechain::GetMainchainCache()};
    if (cache == nullptr) {
        throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
    }
    return cache->Client();
}

RPCHelpMan getsidechaininfo()
{
    return RPCHelpMan{
        "getsidechaininfo",
        "State of the local mirror of the enforcer's mainchain view.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "synced", "whether the mainchain view is complete"},
            {RPCResult::Type::STR_HEX, "mainchaintip", /*optional=*/true, "the mainchain tip the enforcer reports"},
            {RPCResult::Type::STR, "lasterror", /*optional=*/true, "what the last poll failed with"},
            {RPCResult::Type::BOOL, "has_txindex",
             "whether this node has the index a failed bundle's settlement reads; a producer "
             "without it builds no block at all once a bundle fails. Presence only, so an index "
             "still building reads true"},
            {RPCResult::Type::STR_HEX, "prevmain", /*optional=*/true,
             "the mainchain block this sidechain's tip credits up to"},
            {RPCResult::Type::NUM, "prevmain_lag", /*optional=*/true,
             "how many mainchain blocks that is behind mainchaintip; a number that "
             "only grows means the deposit peg stopped, and a live bundle with it"},
            {RPCResult::Type::ARR, "orphaned_payouts", /*optional=*/true,
             "bundles the mainchain paid that this chain never opened; the peg is short by them",
             {{RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "m6id", "what the mainchain voted on"},
                {RPCResult::Type::NUM, "payouts", "how many times it paid this one"},
             }}}},
        }},
        RPCExamples{HelpExampleCli("getsidechaininfo", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            sidechain::MainchainCache* cache{sidechain::GetMainchainCache()};
            if (cache == nullptr) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            UniValue result{UniValue::VOBJ};
            result.pushKV("synced", cache->IsSynced());
            if (const auto tip{cache->GetSyncedTip()}) {
                result.pushKV("mainchaintip", tip->GetHex());
            }
            const std::string error{cache->GetLastError()};
            if (!error.empty()) result.pushKV("lasterror", error);
            // Settling a failed bundle reads the requests it swept, so a
            // producer without the index can build no block at all once one
            // fails -- whether or not this node opened it. Presence only: a
            // sync test blocks, and this is a status call.
            result.pushKV("has_txindex", g_txindex != nullptr);
            // Which mainchain block the sidechain tip credits up to, and how far
            // that lags. A tip that stops moving while mainchaintip goes on is
            // the deposit peg at a stop, and it strands a live bundle with it:
            // a verdict rides the same range, so it never becomes actionable.
            ChainstateManager& chainman{EnsureChainman(EnsureAnyNodeContext(request.context))};
            LOCK(cs_main);
            const CBlockIndex* chain_tip{chainman.ActiveChain().Tip()};
            CBlock block;
            if (chain_tip != nullptr && chain_tip->nHeight > 0 &&
                chainman.m_blockman.ReadBlock(block, *chain_tip) && !block.vtx.empty()) {
                if (const auto anchor{sidechain::GetBmmCommitment(*block.vtx[0])}) {
                    result.pushKV("prevmain", anchor->GetHex());
                    const auto at{cache->GetHeight(*anchor)};
                    const auto top{cache->GetSyncedTip()};
                    const auto top_height{top ? cache->GetHeight(*top) : std::nullopt};
                    if (at && top_height) {
                        result.pushKV("prevmain_lag", *top_height - *at);
                    }
                }
            }
            // The peg is short by these: the mainchain paid a bundle this chain
            // never opened, so nothing here destroyed the coins it handed out.
            const std::map<uint256, size_t> orphaned{sidechain::GetOrphanedPayouts(
                [&chainman](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                    AssertLockHeld(cs_main);
                    const CBlockIndex* at{chainman.m_blockman.LookupBlockIndex(hash)};
                    return at != nullptr && chainman.ActiveChain().Contains(at);
                })};
            if (!orphaned.empty()) {
                UniValue short_by{UniValue::VARR};
                for (const auto& [m6id, payouts] : orphaned) {
                    UniValue entry{UniValue::VOBJ};
                    entry.pushKV("m6id", m6id.GetHex());
                    entry.pushKV("payouts", static_cast<uint64_t>(payouts));
                    short_by.push_back(std::move(entry));
                }
                result.pushKV("orphaned_payouts", std::move(short_by));
            }
            return result;
        }};
}

RPCHelpMan getmainchaintip()
{
    return RPCHelpMan{
        "getmainchaintip",
        "Return the mainchain tip as reported by the BIP300/301 enforcer.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "blockhash", "mainchain tip block hash"},
                {RPCResult::Type::STR_HEX, "prevblockhash", "previous block hash"},
                {RPCResult::Type::NUM_TIME, "timestamp", "block timestamp"},
            }},
        RPCExamples{HelpExampleCli("getmainchaintip", "")},
        [](const RPCHelpMan&, const JSONRPCRequest&) -> UniValue {
            sidechain::MainchainTip tip;
            std::string error;
            if (!Client().GetChainTip(tip, error)) {
                throw JSONRPCError(RPC_MISC_ERROR, error);
            }
            UniValue result{UniValue::VOBJ};
            result.pushKV("blockhash", tip.block_hash.GetHex());
            result.pushKV("prevblockhash", tip.prev_block_hash.GetHex());
            result.pushKV("timestamp", tip.timestamp);
            return result;
        }};
}

RPCHelpMan getmainchainblockinfo()
{
    return RPCHelpMan{
        "getmainchainblockinfo",
        "Return two-way peg data for our slot, from genesis up to the given mainchain block.\n"
        "Blocks with no events are omitted. Queries the enforcer directly and may be slow.\n",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "mainchain block hash"},
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{HelpExampleCli("getmainchainblockinfo", "\"<blockhash>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const auto block_hash{uint256::FromHex(request.params[0].get_str())};
            if (!block_hash) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "blockhash must be a hex string");
            }

            std::vector<sidechain::BlockInfo> blocks;
            std::string error;
            if (!Client().GetTwoWayPegData(std::nullopt, *block_hash, blocks, error)) {
                throw JSONRPCError(RPC_MISC_ERROR, error);
            }

            UniValue result{UniValue::VARR};
            for (const sidechain::BlockInfo& info : blocks) {
                UniValue entry{UniValue::VOBJ};
                entry.pushKV("blockhash", info.main_block_hash.GetHex());
                entry.pushKV("height", info.main_height);
                if (info.bmm_commitment) {
                    entry.pushKV("bmmcommitment", info.bmm_commitment->GetHex());
                }
                UniValue deposits{UniValue::VARR};
                for (const sidechain::Deposit& d : info.deposits) {
                    UniValue dv{UniValue::VOBJ};
                    dv.pushKV("sequencenumber", d.sequence_number);
                    dv.pushKV("outpoint", d.outpoint.ToString());
                    dv.pushKV("address", HexStr(d.address));
                    dv.pushKV("value", d.value);
                    deposits.push_back(std::move(dv));
                }
                entry.pushKV("deposits", std::move(deposits));

                UniValue events{UniValue::VARR};
                for (const sidechain::WithdrawalBundleEvent& e : info.bundle_events) {
                    UniValue ev{UniValue::VOBJ};
                    ev.pushKV("m6id", e.m6id.GetHex());
                    switch (e.status) {
                    case sidechain::WithdrawalBundleEvent::Status::Succeeded:
                        ev.pushKV("status", "succeeded");
                        break;
                    case sidechain::WithdrawalBundleEvent::Status::Failed:
                        ev.pushKV("status", "failed");
                        break;
                    case sidechain::WithdrawalBundleEvent::Status::Submitted:
                        ev.pushKV("status", "submitted");
                        break;
                    }
                    events.push_back(std::move(ev));
                }
                entry.pushKV("withdrawalbundleevents", std::move(events));
                result.push_back(std::move(entry));
            }
            return result;
        }};
}

RPCHelpMan getbmmcommitment()
{
    return RPCHelpMan{
        "getbmmcommitment",
        "Return the BMM commitment our slot made in a mainchain block, if any.\n",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "mainchain block hash"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "", "commitment, or null if none"},
        RPCExamples{HelpExampleCli("getbmmcommitment", "\"<blockhash>\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const auto block_hash{uint256::FromHex(request.params[0].get_str())};
            if (!block_hash) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "blockhash must be a hex string");
            }
            std::optional<uint256> commitment;
            std::string error;
            if (!Client().GetBmmHStarCommitment(*block_hash, commitment, error)) {
                throw JSONRPCError(RPC_MISC_ERROR, error);
            }
            if (!commitment) return UniValue{UniValue::VNULL};
            return commitment->GetHex();
        }};
}

//! Mainchain blocks committing to a sidechain block.
//!
//! The orchestrator's BMM engine polls this between CreateBid and ConnectBid to
//! learn whether a miner took the bid, so the name and shape follow
//! sidechain-orchestrator/sidechain/jsonrpc_proxy.go.
RPCHelpMan get_bmm_inclusions()
{
    return RPCHelpMan{
        "get_bmm_inclusions",
        "Mainchain blocks whose BMM commitment names this sidechain block.\n",
        {
            {"critical_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "critical_hash from get_block_template, in internal byte order"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::STR_HEX, "", "mainchain block hash"}}},
        RPCExamples{HelpExampleCli("get_bmm_inclusions", "\"<critical_hash>\"")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            // critical_hash is what get_block_template emitted: the raw bytes
            // committed on the mainchain, not a display-order block hash.
            const auto bytes{TryParseHex<unsigned char>(request.params[0].get_str())};
            if (!bytes || bytes->size() != uint256::size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "critical_hash must be 32 bytes of hex");
            }
            sidechain::MainchainCache* cache{sidechain::GetMainchainCache()};
            if (cache == nullptr) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            // An unpolled cache holds no mainchain blocks, so an empty result
            // would be indistinguishable from "no miner took the bid" -- and the
            // caller drops a paid-for block on that answer.
            if (!cache->IsSynced()) {
                throw JSONRPCError(RPC_MISC_ERROR, "enforcer not synced");
            }
            UniValue out{UniValue::VARR};
            if (const auto anchor{cache->FindBmmAnchor(uint256{*bytes})}) {
                out.push_back(anchor->GetHex());
            }
            return out;
        }};
}

//! One pending withdrawal, as found in the UTXO set.
struct PendingRequest {
    COutPoint outpoint;
    sidechain::WithdrawalRequest request;
};

//! The bundle the tip leaves in flight, if any. One at a time, so at most one.
std::optional<sidechain::LiveBundleRef> LiveBundleAtTip(ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const CBlockIndex* tip{chainman.ActiveChain().Tip()};
    if (tip == nullptr || tip->nHeight == 0) return std::nullopt;
    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *tip) || block.vtx.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "cannot read the tip block");
    }
    const auto live{sidechain::GetLiveBundles(*block.vtx[0])};
    if (!live || live->empty()) return std::nullopt;
    return live->front();
}

/**
 * Every unspent withdrawal request, oldest first.
 *
 * A full UTXO scan. Producer-side only and never consensus, so an index here
 * would be an optimisation rather than a correctness requirement -- and getting
 * it wrong could only cost a worse bundle, never a bad one.
 */
std::vector<PendingRequest> ScanPendingRequests(ChainstateManager& chainman, NodeContext& node)
{
    std::unique_ptr<CCoinsViewCursor> cursor;
    {
        LOCK(cs_main);
        Chainstate& active{chainman.ActiveChainstate()};
        active.ForceFlushStateToDisk();
        cursor = CHECK_NONFATAL(active.CoinsDB().Cursor());
    }

    // Ordered by (height, outpoint) so every node building from the same chain
    // selects the same bundle. std::sort on the amount alone would leave ties to
    // the implementation, and two producers could then disagree.
    std::vector<std::pair<std::pair<uint32_t, COutPoint>, sidechain::WithdrawalRequest>> found;
    for (; cursor->Valid(); cursor->Next()) {
        node.rpc_interruption_point();
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) continue;
        if (const auto request{sidechain::ParseWithdrawalRequestOutput(coin.out)}) {
            found.push_back({{uint32_t{coin.nHeight}, key}, *request});
        }
    }
    std::sort(found.begin(), found.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::vector<PendingRequest> out;
    out.reserve(found.size());
    for (auto& [key, request] : found) out.push_back({key.second, std::move(request)});
    return out;
}

UniValue RequestToJSON(const PendingRequest& pending)
{
    UniValue entry{UniValue::VOBJ};
    entry.pushKV("txid", pending.outpoint.hash.GetHex());
    entry.pushKV("vout", static_cast<uint64_t>(pending.outpoint.n));
    entry.pushKV("amount_sats", pending.request.amount);
    entry.pushKV("mainchain_fee_sats", pending.request.mainchain_fee);
    entry.pushKV("payout_sats", pending.request.amount - pending.request.mainchain_fee);
    entry.pushKV("dest", HexStr(pending.request.dest));
    entry.pushKV("owner", HexStr(pending.request.owner));
    return entry;
}

RPCHelpMan list_withdrawal_requests()
{
    return RPCHelpMan{
        "list_withdrawal_requests",
        "Withdrawals waiting to be bundled, oldest first.\n"
        "This is the order create_bundle selects in.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "txid", "transaction holding the request"},
                    {RPCResult::Type::NUM, "vout", "output index"},
                    {RPCResult::Type::NUM, "amount_sats", "encumbered total"},
                    {RPCResult::Type::NUM, "mainchain_fee_sats", "left to mainchain miners"},
                    {RPCResult::Type::NUM, "payout_sats", "what the mainchain would pay"},
                    {RPCResult::Type::STR_HEX, "dest", "mainchain scriptPubKey to pay"},
                    {RPCResult::Type::STR_HEX, "owner", "sidechain scriptPubKey the coins return to"},
                }}}},
        RPCExamples{HelpExampleCli("list_withdrawal_requests", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            UniValue out{UniValue::VARR};
            for (const PendingRequest& pending : ScanPendingRequests(chainman, node)) {
                out.push_back(RequestToJSON(pending));
            }
            return out;
        }};
}

RPCHelpMan create_bundle()
{
    return RPCHelpMan{
        "create_bundle",
        "Sweep pending withdrawals into a bundle for the next block.\n"
        "A bundle wins over a staged abort: a request this takes stops being\n"
        "aborted, and goes to the mainchain.\n"
        "The bundle only becomes real once a block carrying it is connected. Read\n"
        "the blinded M6 off pending_withdrawal_bundle after that, and hand it to the\n"
        "enforcer's BroadcastWithdrawalBundle then.\n",
        {
            {"max_requests", RPCArg::Type::NUM, RPCArg::Default{static_cast<int64_t>(sidechain::MAX_BUNDLE_WITHDRAWALS)},
             "how many of the oldest pending withdrawals to take"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "m6id", "identifier the mainchain votes on"},
                {RPCResult::Type::NUM, "payout_sats", "total the mainchain would pay out"},
                {RPCResult::Type::NUM, "mainchain_fee_sats", "total left to mainchain miners"},
                {RPCResult::Type::NUM, "requests", "how many withdrawals it swept"},
            }},
        RPCExamples{HelpExampleCli("create_bundle", "")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }

            size_t limit{sidechain::MAX_BUNDLE_WITHDRAWALS};
            if (!request.params[0].isNull()) {
                const int64_t requested{request.params[0].getInt<int64_t>()};
                if (requested < 1 || static_cast<size_t>(requested) > sidechain::MAX_BUNDLE_WITHDRAWALS) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       strprintf("max_requests must be 1..%d", sidechain::MAX_BUNDLE_WITHDRAWALS));
                }
                limit = static_cast<size_t>(requested);
            }

            // Settling a failed bundle means reading the requests back off the
            // transaction that opened it, which needs the index. Opening one
            // without it strands the chain: the settlement is mandatory, the
            // producer cannot build it, and so no block can be built at all.
            // Synced, not merely present: the index builds behind the chain, and
            // a settlement reads a transaction from any earlier block.
            if (!g_txindex || !g_txindex->BlockUntilSyncedToCurrentChain()) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "a synced -txindex is required to open a bundle, because "
                                   "settling a failed one reads the requests it swept");
            }

            // A second bundle can never be paid: the mainchain votes on one per
            // slot, and the block that would carry it is refused.
            if (WITH_LOCK(cs_main, return LiveBundleAtTip(chainman))) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "a bundle is already in flight; wait for the mainchain to rule on it");
            }

            // Before the scan, which flushes the chainstate and walks every
            // coin. A refusal should not pay for that.
            if (WITH_LOCK(cs_main, return !sidechain::TakeStageSnapshot().bundle.empty())) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "a bundle is already staged; call cancel_bundle to replace it");
            }

            std::vector<PendingRequest> pending{ScanPendingRequests(chainman, node)};
            // A request output is standard on a sidechain, so anyone can make
            // one by hand. One whose payout the mainchain would never confirm
            // holds back every request behind it: selection takes the oldest
            // first, so the bundle it joins ages out and forms again with the
            // same request at its head. Skipped here, where the set is chosen.
            std::erase_if(pending, [](const PendingRequest& p) {
                const CAmount payout{p.request.amount - p.request.mainchain_fee};
                // The mainchain's own default, not this node's -dustrelayfee:
                // the output this measures is one the mainchain has to confirm.
                return IsDust(CTxOut{payout, p.request.dest}, CFeeRate{DUST_RELAY_TX_FEE});
            });
            if (pending.empty()) {
                throw JSONRPCError(RPC_MISC_ERROR, "no withdrawals are waiting to be bundled");
            }
            if (pending.size() > limit) pending.resize(limit);

            std::vector<sidechain::WithdrawalRequest> selected;
            CAmount payout{0};
            CAmount fees{0};
            for (const PendingRequest& p : pending) {
                selected.push_back(p.request);
                payout += p.request.amount - p.request.mainchain_fee;
                fees += p.request.mainchain_fee;
            }

            const auto m6id{sidechain::BundleId(selected)};
            if (!m6id) {
                throw JSONRPCError(RPC_MISC_ERROR, "the selected withdrawals do not form a valid bundle");
            }

            std::vector<COutPoint> staged;
            staged.reserve(pending.size());
            for (const PendingRequest& p : pending) staged.push_back(p.outpoint);
            // One that waits for a block counts too, and the claim is what
            // tests it: two callers that each tested first would both pass.
            if (!sidechain::StageBundle(staged)) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "a bundle is already staged; call cancel_bundle to replace it");
            }

            UniValue result{UniValue::VOBJ};
            // Internal byte order, like critical_hash: this is what the enforcer
            // reports back as the verdict's m6id.
            result.pushKV("m6id", HexStr(*m6id));
            result.pushKV("payout_sats", payout);
            result.pushKV("mainchain_fee_sats", fees);
            // Not the requests themselves: an M6 is a function of exactly those
            // fields, so handing them out here publishes the bundle before any
            // block commits to it. pending_withdrawal_bundle does that, at depth.
            result.pushKV("requests", static_cast<uint64_t>(pending.size()));
            return result;
        }};
}

RPCHelpMan cancel_bundle()
{
    return RPCHelpMan{
        "cancel_bundle",
        "Drop a bundle that no block carries yet.\n"
        "The withdrawals go back to the pending queue, and so does any abort this\n"
        "bundle took over. This drops the intent, not the chain: a bundle a block\n"
        "already carries stays with the mainchain, and a bid this node already\n"
        "paid can still carry it after this succeeds.\n",
        {},
        RPCResult{RPCResult::Type::BOOL, "", "whether a staged bundle was dropped"},
        RPCExamples{HelpExampleCli("cancel_bundle", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            // No guard on what the chain carries. A bundle a block already took
            // spent its requests, so the next template drops the stage by
            // itself, and a live bundle of somebody else's is not this stage --
            // refusing there would leave the operator no way back at all.
            return sidechain::CancelStagedBundle();
        }};
}

RPCHelpMan list_staged()
{
    return RPCHelpMan{
        "list_staged",
        "What the operator asked the next block to carry.\n"
        "Intent, not chain: a restart clears it, and a block that never comes\n"
        "leaves it here. Nothing here is committed until a block carries it.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ARR, "bundle", "requests a staged bundle would sweep",
             {{RPCResult::Type::STR, "outpoint", "txid:vout"}}},
            {RPCResult::Type::ARR, "aborts", "requests a staged abort would return",
             {{RPCResult::Type::STR, "outpoint", "txid:vout"}}},
            {RPCResult::Type::ARR, "bumped_aborts",
             "aborts the staged bundle took over; cancel_bundle gives them back",
             {{RPCResult::Type::STR, "outpoint", "txid:vout"}}},
            {RPCResult::Type::NUM, "bundle_weight", "what a block has to hold to carry it"},
            {RPCResult::Type::NUM, "peg_reserve",
             "the weight every block holds back for the peg, whatever it costs"},
        }},
        RPCExamples{HelpExampleCli("list_staged", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            const sidechain::StageSnapshot stage{sidechain::TakeStageSnapshot()};
            const auto to_array{[](const std::vector<COutPoint>& outpoints) {
                UniValue out{UniValue::VARR};
                for (const COutPoint& outpoint : outpoints) {
                    out.push_back(strprintf("%s:%d", outpoint.hash.GetHex(), outpoint.n));
                }
                return out;
            }};
            UniValue result{UniValue::VOBJ};
            result.pushKV("bundle", to_array(stage.bundle));
            result.pushKV("aborts", to_array(stage.aborts));
            result.pushKV("bumped_aborts", to_array(stage.bumped_aborts));
            // What a block has to hold to carry it. A bundle larger than the
            // share -blockmaxweight leaves for one waits for a block that never
            // comes, so the operator compares this against the log warning.
            // Zero for nothing staged, and for a stage the chain can no longer
            // read. The bundle array beside it tells the two apart.
            result.pushKV("bundle_weight", static_cast<uint64_t>(
                sidechain::StagedBundleWeight(chainman)));
            // What a block holds back for the peg, whatever it costs. A bundle
            // is capped by its request count, not by weight, so there is one
            // number and it does not move with -blockmaxweight.
            result.pushKV("peg_reserve", static_cast<uint64_t>(sidechain::PEG_RESERVE_WEIGHT));
            return result;
        }};
}

RPCHelpMan cancel_abort()
{
    return RPCHelpMan{
        "cancel_abort",
        "Drop a staged abort that no block carries yet.\n"
        "The withdrawal stays pending, and a bundle may sweep it again.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "transaction holding the request"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "output index"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "whether the queue held it"},
        RPCExamples{HelpExampleCli("cancel_abort", "\"<txid>\" 0")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            const auto txid{Txid::FromHex(request.params[0].get_str())};
            if (!txid) throw JSONRPCError(RPC_INVALID_PARAMETER, "txid must be hexadecimal");
            const int64_t vout{request.params[1].getInt<int64_t>()};
            if (vout < 0 || vout > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout is out of range");
            }
            return sidechain::CancelStagedAbort(COutPoint{*txid, static_cast<uint32_t>(vout)});
        }};
}

RPCHelpMan abort_withdrawal()
{
    return RPCHelpMan{
        "abort_withdrawal",
        "Give a pending withdrawal back to its owner.\n"
        "The coins go to the owner named by the request, so this cannot take them.\n"
        "Any caller may abort any request, so on a shared node one caller can\n"
        "cancel another's withdrawal.\n"
        "The coins return to the sidechain address the request committed to. Only\n"
        "a withdrawal no bundle holds can be aborted; one already in flight has to\n"
        "wait for the mainchain to rule on it. A later create_bundle takes the\n"
        "request back and the abort stops.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "transaction holding the request"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "output index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "amount_sats", "what returns to the owner"},
            {RPCResult::Type::STR_HEX, "owner", "sidechain scriptPubKey the coins return to"},
        }},
        RPCExamples{HelpExampleCli("abort_withdrawal", "\"<txid>\" 0")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }

            const auto txid{Txid::FromHex(request.params[0].get_str())};
            if (!txid) throw JSONRPCError(RPC_INVALID_PARAMETER, "txid must be hexadecimal");
            const int64_t vout{request.params[1].getInt<int64_t>()};
            if (vout < 0 || vout > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout is out of range");
            }
            const COutPoint outpoint{*txid, static_cast<uint32_t>(vout)};
            // Resolved straight out of the UTXO set. A full scan would flush
            // the chainstate to disk and walk every coin to answer one outpoint.
            const Coin& coin{WITH_LOCK(cs_main, return chainman.ActiveChainstate().CoinsTip().AccessCoin(outpoint))};
            const auto parsed{coin.IsSpent()
                                  ? std::nullopt
                                  : sidechain::ParseWithdrawalRequestOutput(coin.out)};
            if (!parsed) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "no pending withdrawal request at that outpoint");
            }
            if (!sidechain::StageAbort({outpoint})) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "a bundle already claims this withdrawal; it goes to the "
                                   "mainchain in the next block");
            }
            UniValue result{UniValue::VOBJ};
            result.pushKV("amount_sats", parsed->amount);
            result.pushKV("owner", HexStr(parsed->owner));
            return result;
        }};
}

/**
 * How deep the block that opened a bundle has to be before its M6 goes out.
 *
 * The mainchain cannot un-see an M6. If the sidechain reorgs the bundle away
 * afterwards, the treasury may still pay it, and nothing here destroys the
 * coins.
 *
 * This guards the operator, not the chain. list_withdrawal_requests publishes
 * every field an M6 is built from, and create_bundle takes the oldest first, so
 * anyone can build and broadcast the same M6 before any block carries it. The
 * depth only keeps the honest path from doing it by accident.
 */
constexpr int BUNDLE_PUBLISH_DEPTH{6};

RPCHelpMan pending_withdrawal_bundle()
{
    return RPCHelpMan{
        "pending_withdrawal_bundle",
        "The bundle currently waiting on a mainchain verdict, if any.\n"
        "blinded_m6 and requests appear once the block that opened the bundle is 6\n"
        "deep. The mainchain cannot un-see an M6, so a shallower one risks a payout\n"
        "for a bundle a sidechain reorg took away.\n",
        {},
        RPCResult{RPCResult::Type::ANY, "", "null when none is in flight, else an object with:\n"
                  "m6id, txid, vout, value_sats, requests_readable, and -- once the opening\n"
                  "block is 6 deep and the index can read it -- height_created,\n"
                  "confirmations, blinded_m6 and requests"},
        RPCExamples{HelpExampleCli("pending_withdrawal_bundle", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }

            LOCK(cs_main);
            const auto live{LiveBundleAtTip(chainman)};
            if (!live) return UniValue{UniValue::VNULL};
            const COutPoint& outpoint{live->outpoint};
            const Coin& coin{chainman.ActiveChainstate().CoinsTip().AccessCoin(outpoint)};
            uint256 m6id;
            uint256 committed_requests;
            if (coin.IsSpent() ||
                !sidechain::IsBundleScript(coin.out.scriptPubKey, m6id, committed_requests)) {
                throw JSONRPCError(RPC_MISC_ERROR, "the live bundle is not in the UTXO set");
            }

            // Every request, or none. A partial set still builds a valid M6,
            // for a different bundle -- and an operator that broadcasts it puts
            // the mainchain to work on an m6id this chain never opened, while
            // the real one waits for a verdict that never comes.
            uint256 block_hash;
            const CTransactionRef opened{node::GetTransaction(nullptr, nullptr, outpoint.hash,
                                                              block_hash, chainman.m_blockman)};
            UniValue result{UniValue::VOBJ};
            result.pushKV("m6id", HexStr(m6id));
            result.pushKV("txid", outpoint.hash.GetHex());
            result.pushKV("vout", static_cast<uint64_t>(outpoint.n));
            result.pushKV("value_sats", coin.out.nValue);

            // The m6id, the outpoint and the value all come off the tip, so a
            // node with no index still sees what is in flight. Only the requests
            // and the M6 built from them need the index.
            if (!opened) {
                result.pushKV("requests_readable", false);
                return result;
            }

            // The depth gates a step nothing can take back, so a lookup it
            // cannot answer has to refuse, never publish.
            const CBlockIndex* at{chainman.m_blockman.LookupBlockIndex(block_hash)};
            if (at == nullptr || !chainman.ActiveChain().Contains(at)) {
                result.pushKV("requests_readable", false);
                return result;
            }
            const int height{at->nHeight};
            UniValue requests{UniValue::VARR};
            std::vector<sidechain::WithdrawalRequest> members;
            for (const CTxIn& in : opened->vin) {
                uint256 request_block;
                const CTransactionRef source{node::GetTransaction(nullptr, nullptr, in.prevout.hash,
                                                                  request_block, chainman.m_blockman)};
                const auto parsed{source && in.prevout.n < source->vout.size()
                                      ? sidechain::ParseWithdrawalRequestOutput(source->vout[in.prevout.n])
                                      : std::nullopt};
                if (!parsed) {
                    throw JSONRPCError(RPC_MISC_ERROR,
                                       strprintf("cannot read request %s of the live bundle",
                                                 in.prevout.ToString()));
                }
                requests.push_back(RequestToJSON({in.prevout, *parsed}));
                members.push_back(*parsed);
            }
            // The set has to be the set the chain committed to, or the M6 and
            // the m6id beside it describe different bundles.
            const auto rebuilt{sidechain::BundleId(members)};
            if (!rebuilt || *rebuilt != m6id) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "the requests read back do not match the bundle the chain opened");
            }
            std::vector<sidechain::Withdrawal> withdrawals;
            withdrawals.reserve(members.size());
            for (const sidechain::WithdrawalRequest& r : members) {
                withdrawals.push_back(sidechain::ToWithdrawal(r));
            }

            result.pushKV("requests_readable", true);
            result.pushKV("height_created", height);
            const int depth{chainman.ActiveChain().Height() - height + 1};
            result.pushKV("confirmations", depth);
            // The only place the blinded M6 is published, and it exists only
            // once a block commits to this bundle. Handing one out at stage time
            // lets a second create_bundle produce a second broadcastable M6 for
            // the same slot, and the mainchain may pay the one this chain
            // dropped.
            const auto blinded{sidechain::BuildBlindedM6(withdrawals)};
            if (!blinded) {
                throw JSONRPCError(RPC_MISC_ERROR, "the live bundle does not form a valid M6");
            }
            // Held back until the block that opened the bundle is buried. The
            // M6 cannot be taken back once the enforcer has it: a sidechain
            // reorg that drops the bundle leaves the mainchain free to pay a
            // bundle this chain no longer holds, and the peg goes short by it.
            // The requests are the M6: it is a function of exactly these
            // fields, so publishing them early publishes the M6 early.
            if (depth >= BUNDLE_PUBLISH_DEPTH) {
                result.pushKV("blinded_m6", HexStr(sidechain::SerializeBlindedM6(*blinded)));
                result.pushKV("requests", std::move(requests));
            }
            return result;
        }};
}

//! How far back to look for a failed settlement. Display only, so a bounded
//! scan is preferable to an index that consensus would never read.
constexpr int FAILED_BUNDLE_SCAN_DEPTH{2000};

RPCHelpMan latest_failed_withdrawal_bundle_height()
{
    return RPCHelpMan{
        "latest_failed_withdrawal_bundle_height",
        "Height of the most recent block that handed a failed bundle back.\n"
        "Looks back a bounded distance, so an older failure reads as null.\n",
        {},
        RPCResult{RPCResult::Type::ANY, "", "height, or null"},
        RPCExamples{HelpExampleCli("latest_failed_withdrawal_bundle_height", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }

            LOCK(cs_main);
            const CBlockIndex* at{chainman.ActiveChain().Tip()};
            for (int scanned = 0; at != nullptr && at->nHeight > 0 && scanned < FAILED_BUNDLE_SCAN_DEPTH;
                 at = at->pprev, ++scanned) {
                CBlock block;
                if (!chainman.m_blockman.ReadBlock(block, *at)) break;
                for (size_t i = 1; i < block.vtx.size(); ++i) {
                    // A failed settlement is the only thing that turns one input
                    // back into request outputs.
                    const CTransaction& tx{*block.vtx[i]};
                    if (tx.vin.size() != 1 || tx.vout.empty()) continue;
                    if (std::all_of(tx.vout.begin(), tx.vout.end(), sidechain::IsWithdrawalRequestOutput)) {
                        return at->nHeight;
                    }
                }
            }
            return UniValue{UniValue::VNULL};
        }};
}

//! Assemble a block for blind merge mining.
//!
//! Matches the `get_block_template` shape in
//! sidechain-orchestrator/sidechain/jsonrpc_proxy.go, so the orchestrator's BMM
//! engine drives this chain with no Go-side changes. The caller bids for
//! `critical_hash` on the mainchain itself and hands `block` back to
//! connect_block once its bid is mined.
RPCHelpMan get_block_template()
{
    return RPCHelpMan{
        "get_block_template",
        "Assemble a sidechain block to blind merge mine.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "critical_hash", "hash to commit to on the mainchain"},
                {RPCResult::Type::OBJ, "block", "passed back to connect_block untouched",
                 {
                     {RPCResult::Type::OBJ, "header", "what the bid builder reads",
                      {
                          {RPCResult::Type::STR_HEX, "prev_main_hash", "the mainchain block this one anchors to"},
                      }},
                     {RPCResult::Type::STR_HEX, "hex", "the serialized block"},
                 }},
                {RPCResult::Type::NUM, "fees_sats", "fees collected by this block"},
            }},
        RPCExamples{HelpExampleCli("get_block_template", "")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            // Settling a failed bundle reads the requests it swept, and a
            // settlement is mandatory. Without the index this node builds no
            // block from the moment any bundle fails -- including one it never
            // opened -- so it says so before it takes a bid.
            // Synced, not merely present: GetTransaction never waits for the
            // index, so a node still building one reads nothing and every
            // template throws until it catches up.
            if (!g_txindex || !g_txindex->BlockUntilSyncedToCurrentChain()) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "a synced -txindex is required to build a sidechain block, "
                                   "because settling a failed bundle reads the requests it swept");
            }
            Mining& miner{EnsureMining(node)};

            CBlock block;
            CAmount fees{0};
            std::optional<uint256> prev_main;
            {
                LOCK(chainman.GetMutex());
                std::unique_ptr<BlockTemplate> tmpl{miner.createNewBlock()};
                if (!tmpl) throw JSONRPCError(RPC_INTERNAL_ERROR, "could not assemble a block");
                block = tmpl->getBlock();
                for (const CAmount fee : tmpl->getTxFees()) {
                    if (fee > 0) fees += fee;
                }
            }

            if (block.vtx.empty()) throw JSONRPCError(RPC_INTERNAL_ERROR, "assembled block has no coinbase");
            prev_main = sidechain::GetBmmCommitment(*block.vtx[0]);
            // Without an anchor the caller cannot build the M8 request, so the
            // template is unusable; say so here rather than emit an empty hash.
            if (!prev_main) throw JSONRPCError(RPC_INTERNAL_ERROR, "assembled block has no BMM commitment");

            // createNewBlock leaves the merkle root for the caller to set.
            block.hashMerkleRoot = BlockMerkleRoot(block);

            // BMM is the real gate on this chain, but the PoW check still runs
            // and the assembled block has an unground nonce. Regtest difficulty
            // makes this a handful of tries; the bid on the mainchain is what
            // actually costs anything.
            while (!CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())) {
                ++block.nNonce;
                if (block.nNonce == 0) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "could not satisfy proof of work");
                }
            }

            UniValue result{UniValue::VOBJ};
            // Internal byte order, not GetHex(): this feeds the enforcer's
            // ConsensusHex critical_hash field, and display order would commit
            // to the reversed hash.
            //
            // The hash must also be final before the bid is placed -- nothing
            // learned from BMM can be folded back into the block.
            const uint256 critical_hash{block.GetHash()};
            result.pushKV("critical_hash", HexStr(critical_hash));
            DataStream serialized;
            serialized << TX_WITH_WITNESS(block);

            // Shaped for the orchestrator's BMM engine, which reads
            // header.prev_main_hash to build the M8 request script and hands the
            // whole object back to connect_block untouched. prev_main_hash is
            // display order there -- the script builder reverses it.
            UniValue header{UniValue::VOBJ};
            header.pushKV("prev_main_hash", prev_main->GetHex());
            UniValue block_json{UniValue::VOBJ};
            block_json.pushKV("header", header);
            block_json.pushKV("hex", HexStr(serialized));
            result.pushKV("block", block_json);
            result.pushKV("fees_sats", fees);
            return result;
        }};
}

//! Submit a block whose BMM bid was mined in `main_block_hash`.
RPCHelpMan connect_block()
{
    return RPCHelpMan{
        "connect_block",
        "Submit a sidechain block that was blind merge mined.\n",
        {
            {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "block object from get_block_template",
             {{"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "serialized block"}}, RPCArgOptions{.skip_type_check = true}},
            {"main_block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "mainchain block containing the BMM commitment"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "whether the block became the new tip"},
        RPCExamples{HelpExampleCli("connect_block", "\"<blockhex>\" \"<mainblockhash>\"")},
        [](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node{EnsureAnyNodeContext(request.context)};
            ChainstateManager& chainman{EnsureChainman(node)};
            if (!chainman.GetParams().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }

            const UniValue& block_json{request.params[0]};
            if (!block_json.isObject() || !block_json.find_value("hex").isStr()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "block must be the object get_block_template returned");
            }
            std::shared_ptr<CBlock> block{std::make_shared<CBlock>()};
            if (!DecodeHexBlk(*block, block_json.find_value("hex").get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "block decode failed");
            }
            const auto main_block_hash{uint256::FromHex(request.params[1].get_str())};
            if (!main_block_hash) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "main_block_hash must be a hex string");
            }

            // Fail here rather than let validation defer: the caller told us
            // which mainchain block carries the bid, so a mismatch is its bug.
            sidechain::MainchainCache* cache{sidechain::GetMainchainCache()};
            if (cache == nullptr) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }
            if (!cache->IsSynced()) {
                throw JSONRPCError(RPC_MISC_ERROR, "enforcer not synced");
            }
            const std::optional<uint256> anchor{cache->FindBmmAnchor(block->GetHash())};
            if (!anchor) {
                throw JSONRPCError(RPC_VERIFY_REJECTED, "no mainchain block commits to this block");
            }
            if (*anchor != *main_block_hash) {
                throw JSONRPCError(RPC_VERIFY_REJECTED, "BMM commitment is in a different mainchain block");
            }

            bool new_block{false};
            if (!chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block)) {
                throw JSONRPCError(RPC_VERIFY_REJECTED, "block was not accepted");
            }
            return new_block;
        }};
}

} // namespace

void RegisterSidechainRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"sidechain", &getsidechaininfo},
        {"sidechain", &getmainchaintip},
        {"sidechain", &getmainchainblockinfo},
        {"sidechain", &getbmmcommitment},
        {"sidechain", &get_bmm_inclusions},
        {"sidechain", &list_withdrawal_requests},
        {"sidechain", &create_bundle},
        {"sidechain", &abort_withdrawal},
        {"sidechain", &cancel_bundle},
        {"sidechain", &cancel_abort},
        {"sidechain", &list_staged},
        {"sidechain", &pending_withdrawal_bundle},
        {"sidechain", &latest_failed_withdrawal_bundle_height},
        {"sidechain", &get_block_template},
        {"sidechain", &connect_block},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
