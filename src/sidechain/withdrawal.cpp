// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/withdrawal.h>

#include <hash.h>
#include <serialize.h>
#include <util/check.h>
#include <set>
#include <streams.h>

namespace sidechain {
namespace {

//! Payload layout: version, fee, dest, owner. Amount lives in nValue.
struct RequestPayload {
    unsigned char version{WITHDRAWAL_MARKER_V0};
    CAmount mainchain_fee{0};
    CScript dest;
    CScript owner;

    SERIALIZE_METHODS(RequestPayload, obj)
    {
        READWRITE(obj.version, obj.mainchain_fee, obj.dest, obj.owner);
    }
};

} // namespace

CTxOut BuildWithdrawalRequestOutput(const WithdrawalRequest& request)
{
    RequestPayload payload;
    payload.mainchain_fee = request.mainchain_fee;
    payload.dest = request.dest;
    payload.owner = request.owner;

    DataStream stream;
    stream << payload;
    const std::vector<unsigned char> bytes{UCharCast(stream.data()),
                                           UCharCast(stream.data() + stream.size())};

    // `<payload> OP_DROP OP_TRUE`: carries the request and evaluates true with an
    // empty scriptSig, so the producer can sweep it into a bundle without the
    // owner's signature. Policy keeps it out of the mempool; consensus decides
    // where the coins may go.
    return CTxOut{request.amount, CScript() << bytes << OP_DROP << OP_TRUE};
}

std::optional<WithdrawalRequest> ParseWithdrawalRequestOutput(const CTxOut& out)
{
    const CScript& spk{out.scriptPubKey};
    CScript::const_iterator it{spk.begin()};
    opcodetype opcode;

    std::vector<unsigned char> bytes;
    if (!spk.GetOp(it, opcode, bytes) || bytes.empty()) return std::nullopt;
    if (!spk.GetOp(it, opcode) || opcode != OP_DROP) return std::nullopt;
    if (!spk.GetOp(it, opcode) || opcode != OP_TRUE) return std::nullopt;
    if (it != spk.end()) return std::nullopt;

    RequestPayload payload;
    try {
        DataStream stream{bytes};
        stream >> payload;
        if (!stream.empty()) return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }

    if (payload.version != WITHDRAWAL_MARKER_V0) return std::nullopt;
    if (payload.mainchain_fee < 0 || out.nValue < 0) return std::nullopt;
    // The mainchain payout is amount - fee, so a request that cannot pay its own
    // fee would produce a negative M6 output.
    if (payload.mainchain_fee >= out.nValue) return std::nullopt;
    // An empty script pays nobody. The abort would then destroy the coins it
    // exists to give back, and the M6 would carry a mainchain output nobody can
    // spend.
    if (payload.dest.empty() || payload.owner.empty()) return std::nullopt;
    if (payload.dest.size() > MAX_PEG_SCRIPT_SIZE || payload.owner.size() > MAX_PEG_SCRIPT_SIZE) {
        return std::nullopt;
    }

    WithdrawalRequest request;
    request.amount = out.nValue;
    request.mainchain_fee = payload.mainchain_fee;
    request.dest = payload.dest;
    request.owner = payload.owner;
    return request;
}

bool IsWithdrawalRequestOutput(const CTxOut& out)
{
    return ParseWithdrawalRequestOutput(out).has_value();
}

namespace {
//! Marker for the coinbase output carrying the live set.
constexpr unsigned char LIVE_BUNDLES_MARKER_V0{0x03};

//! Serialized as parallel vectors so the payload stays a plain pair of fields.
struct LiveBundlePayload {
    unsigned char version{LIVE_BUNDLES_MARKER_V0};
    std::vector<COutPoint> outpoints;
    std::vector<uint256> m6ids;

    SERIALIZE_METHODS(LiveBundlePayload, obj) { READWRITE(obj.version, obj.outpoints, obj.m6ids); }
};
} // namespace

CTxOut BuildLiveBundleOutput(const std::vector<LiveBundleRef>& live)
{
    LiveBundlePayload payload;
    for (const LiveBundleRef& ref : live) {
        payload.outpoints.push_back(ref.outpoint);
        payload.m6ids.push_back(ref.m6id);
    }

    DataStream stream;
    stream << payload;
    const std::vector<unsigned char> bytes{UCharCast(stream.data()),
                                           UCharCast(stream.data() + stream.size())};
    return CTxOut{CAmount{0}, CScript() << OP_RETURN << bytes};
}

std::optional<std::vector<LiveBundleRef>> GetLiveBundles(const CTransaction& coinbase)
{
    std::optional<std::vector<LiveBundleRef>> found;
    for (const CTxOut& out : coinbase.vout) {
        if (out.nValue != 0) continue;

        CScript::const_iterator it{out.scriptPubKey.begin()};
        opcodetype opcode;
        std::vector<unsigned char> bytes;
        if (!out.scriptPubKey.GetOp(it, opcode) || opcode != OP_RETURN) continue;
        if (!out.scriptPubKey.GetOp(it, opcode, bytes) || bytes.empty()) continue;
        if (it != out.scriptPubKey.end()) continue;
        if (bytes[0] != LIVE_BUNDLES_MARKER_V0) continue;

        LiveBundlePayload payload;
        try {
            DataStream stream{bytes};
            stream >> payload;
            if (!stream.empty()) return std::nullopt;
        } catch (const std::exception&) {
            return std::nullopt;
        }
        // Two live sets are ambiguous, so neither counts -- the same rule the
        // BMM commitment uses, and for the same reason.
        if (payload.outpoints.size() != payload.m6ids.size()) return std::nullopt;
        std::vector<LiveBundleRef> refs;
        refs.reserve(payload.outpoints.size());
        for (size_t i = 0; i < payload.outpoints.size(); ++i) {
            refs.push_back(LiveBundleRef{payload.outpoints[i], payload.m6ids[i]});
        }
        if (found) return std::nullopt;
        found = std::move(refs);
    }
    // No output at all means nothing is in flight, so most blocks carry none.
    // Safe because a block that does have live bundles and omits it declares an
    // empty set, which cannot match what its parent left behind.
    return found.value_or(std::vector<LiveBundleRef>{});
}

uint256 RequestSetDigest(const std::vector<WithdrawalRequest>& requests)
{
    HashWriter writer;
    writer << static_cast<uint32_t>(requests.size());
    for (const WithdrawalRequest& r : requests) {
        writer << r.dest << r.owner << r.amount << r.mainchain_fee;
    }
    return writer.GetHash();
}

CTxOut BuildBundleOutput(const uint256& m6id, const uint256& requests, CAmount value)
{
    std::vector<unsigned char> payload;
    payload.reserve(1 + 2 * uint256::size());
    payload.push_back(BUNDLE_MARKER_V0);
    payload.insert(payload.end(), m6id.begin(), m6id.end());
    payload.insert(payload.end(), requests.begin(), requests.end());
    return CTxOut{value, CScript() << payload << OP_DROP << OP_TRUE};
}

std::optional<uint256> BundleId(const std::vector<WithdrawalRequest>& requests)
{
    if (requests.empty() || requests.size() > MAX_BUNDLE_WITHDRAWALS) return std::nullopt;
    std::vector<Withdrawal> withdrawals;
    withdrawals.reserve(requests.size());
    for (const WithdrawalRequest& r : requests) withdrawals.push_back(ToWithdrawal(r));
    return ComputeM6id(withdrawals);
}

bool CheckBundleTransaction(const CTransaction& tx,
                            const std::vector<CTxOut>& spent_outputs,
                            uint256& m6id_out,
                            std::string& reason)
{
    if (spent_outputs.size() != tx.vin.size()) {
        reason = "bad-bundle-inputs";
        return false;
    }

    std::vector<WithdrawalRequest> requests;
    CAmount total{0};
    for (const CTxOut& spent : spent_outputs) {
        const auto request{ParseWithdrawalRequestOutput(spent)};
        // Sweeping anything else would let a bundle carry coins nobody asked to
        // withdraw, and the settlement would then pay them out or destroy them.
        if (!request) {
            reason = "bad-bundle-input-not-request";
            return false;
        }
        if (!MoneyRange(total + request->amount)) {
            reason = "bad-bundle-amount";
            return false;
        }
        total += request->amount;
        requests.push_back(*request);
    }

    const std::optional<uint256> m6id{BundleId(requests)};
    if (!m6id) {
        reason = "bad-bundle-size";
        return false;
    }

    if (tx.vout.size() != 1) {
        reason = "bad-bundle-outputs";
        return false;
    }
    uint256 committed;
    uint256 committed_requests;
    if (!IsBundleScript(tx.vout[0].scriptPubKey, committed, committed_requests)) {
        reason = "bad-bundle-output-script";
        return false;
    }
    // The commitment is what a settlement later checks itself against, so a
    // bundle that commits to anything but its own contents is worthless.
    if (committed != *m6id) {
        reason = "bad-bundle-m6id";
        return false;
    }
    if (committed_requests != RequestSetDigest(requests)) {
        reason = "bad-bundle-requests";
        return false;
    }
    // Zero fee: the bundle moves coins between forms, it does not spend them.
    if (tx.vout[0].nValue != total) {
        reason = "bad-bundle-value";
        return false;
    }

    m6id_out = *m6id;
    return true;
}

bool CheckLiveBundles(const std::vector<LiveBundleRef>& parent_live,
                      const std::optional<LiveBundleRef>& opened,
                      const std::vector<COutPoint>& settled,
                      const std::vector<COutPoint>& owed,
                      const std::vector<LiveBundleRef>& live,
                      std::string& reason)
{
    std::set<LiveBundleRef> expected{parent_live.begin(), parent_live.end()};
    if (expected.size() != parent_live.size()) {
        reason = "bad-live-bundles-duplicate";
        return false;
    }

    for (const COutPoint& done : settled) {
        // Settling something that was never in flight would let a block claim
        // credit for work no block opened.
        const auto it = std::find_if(expected.begin(), expected.end(),
                                     [&](const LiveBundleRef& ref) { return ref.outpoint == done; });
        if (it == expected.end()) {
            reason = "bad-live-bundles-unknown-settlement";
            return false;
        }
        expected.erase(it);
    }
    // Every verdict the mainchain handed down over this block's range has to be
    // acted on here, because no later block can see it.
    const std::set<COutPoint> done{settled.begin(), settled.end()};
    for (const COutPoint& must : owed) {
        if (!done.contains(must)) {
            reason = "bad-live-bundles-unsettled";
            return false;
        }
    }

    if (opened) {
        // One at a time: the mainchain votes on one bundle per slot, so a second
        // could never be paid and would occupy the slot forever.
        if (!expected.empty()) {
            reason = "bad-bundle-multiple";
            return false;
        }
        if (!expected.insert(*opened).second) {
            reason = "bad-live-bundles-duplicate";
            return false;
        }
    }

    const std::set<LiveBundleRef> claimed{live.begin(), live.end()};
    if (claimed.size() != live.size()) {
        reason = "bad-live-bundles-duplicate";
        return false;
    }
    if (claimed != expected) {
        reason = "bad-live-bundles-mismatch";
        return false;
    }
    return true;
}

bool CheckSettlementTransaction(const CTransaction& tx,
                                const std::vector<CTxOut>& spent_outputs,
                                BundleOutcome outcome,
                                uint256& m6id_out,
                                std::string& reason)
{
    if (spent_outputs.size() != 1 || tx.vin.size() != 1) {
        reason = "bad-settlement-inputs";
        return false;
    }
    uint256 m6id;
    uint256 committed_requests;
    if (!IsBundleScript(spent_outputs[0].scriptPubKey, m6id, committed_requests)) {
        reason = "bad-settlement-input-not-bundle";
        return false;
    }
    const CAmount value{spent_outputs[0].nValue};

    if (outcome == BundleOutcome::Paid) {
        // The mainchain has paid these coins out, so the sidechain's copy stops
        // existing. Destroyed explicitly rather than left implicit: value left
        // unclaimed becomes fee, which hands it to the miner instead.
        if (tx.vout.size() != 1 || !tx.vout[0].scriptPubKey.IsUnspendable()) {
            reason = "bad-settlement-not-destroyed";
            return false;
        }
        if (tx.vout[0].nValue != value) {
            reason = "bad-settlement-value";
            return false;
        }
        m6id_out = m6id;
        return true;
    }

    // Failed: every request comes back exactly as it was. Which requests those
    // are is read off this transaction's own outputs, which is only believable
    // because they have to hash to the m6id the spent bundle committed to.
    std::vector<WithdrawalRequest> requests;
    CAmount total{0};
    for (const CTxOut& out : tx.vout) {
        const auto request{ParseWithdrawalRequestOutput(out)};
        if (!request) {
            reason = "bad-settlement-not-requests";
            return false;
        }
        total += request->amount;
        requests.push_back(*request);
    }
    if (total != value) {
        reason = "bad-settlement-value";
        return false;
    }
    const std::optional<uint256> rebuilt{BundleId(requests)};
    if (!rebuilt || *rebuilt != m6id) {
        reason = "bad-settlement-m6id";
        return false;
    }
    // The m6id binds the mainchain destination and payout only. This binds the
    // rest: who each request returns to, and how the fee is split between them.
    if (RequestSetDigest(requests) != committed_requests) {
        reason = "bad-settlement-requests";
        return false;
    }

    m6id_out = m6id;
    return true;
}

// An abort of one request makes one output paying an attacker-chosen script,
// and the block rule tells an abort from a bundle by output shape. A bundle
// script must therefore be too large to appear as an owner script.
static_assert(MAX_PEG_SCRIPT_SIZE < 1 + 65 + 1 + 1,
              "an owner script could be bundle-shaped, and an abort could hide as a bundle");

// The script predicate bounds what may relay; the parser bounds what is real.
// The first has to be at least as wide as the second, or a valid request stops
// relaying.
static_assert(1 + 2 * (1 + MAX_PEG_SCRIPT_SIZE) + 8 <= MAX_WITHDRAWAL_PAYLOAD_SIZE,
              "a valid request payload does not fit the script predicate's bound");

bool CheckAbortTransaction(const CTransaction& tx,
                           const std::vector<CTxOut>& spent_outputs,
                           std::string& reason)
{
    if (spent_outputs.empty() || spent_outputs.size() != tx.vout.size()) {
        reason = "bad-abort-shape";
        return false;
    }
    // Capped like a bundle. An owner script is attacker-chosen, so an uncapped
    // abort is an uncapped count of attacker-chosen scripts in one transaction.
    if (spent_outputs.size() > MAX_BUNDLE_WITHDRAWALS) {
        reason = "bad-abort-too-many";
        return false;
    }
    for (size_t i{0}; i < spent_outputs.size(); ++i) {
        const auto request{ParseWithdrawalRequestOutput(spent_outputs[i])};
        if (!request) {
            reason = "bad-abort-input-not-request";
            return false;
        }
        if (tx.vout[i].scriptPubKey != request->owner || tx.vout[i].nValue != request->amount) {
            reason = "bad-abort-payout";
            return false;
        }
    }
    return true;
}

CMutableTransaction BuildAbortTransaction(const std::vector<COutPoint>& outpoints,
                                          const std::vector<WithdrawalRequest>& requests)
{
    // The block rule pairs input i with output i, so the caller's two lists have
    // to be the same request in the same order.
    Assert(outpoints.size() == requests.size());
    CMutableTransaction tx;
    for (const COutPoint& outpoint : outpoints) {
        tx.vin.emplace_back(outpoint);
    }
    for (const WithdrawalRequest& request : requests) {
        tx.vout.emplace_back(request.amount, request.owner);
    }
    return tx;
}

Withdrawal ToWithdrawal(const WithdrawalRequest& request)
{
    Withdrawal w;
    w.dest = request.dest;
    w.amount = request.amount - request.mainchain_fee;
    w.mainchain_fee = request.mainchain_fee;
    return w;
}

} // namespace sidechain
