// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/bundle.h>
#include <sidechain/bmm.h>
#include <sidechain/cache.h>
#include <sidechain/hook.h>
#include <sidechain/script.h>
#include <sidechain/validation.h>

#include <chain.h>
#include <consensus/validation.h>
#include <sidechain/enforcer_client.h>
#include <sidechain/deposits.h>
#include <sidechain/withdrawal.h>

#include <key_io.h>

#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

using namespace sidechain;

BOOST_FIXTURE_TEST_SUITE(sidechain_tests, BasicTestingSetup)

static Withdrawal MakeWithdrawal(CAmount amount, CAmount fee, unsigned char tag)
{
    Withdrawal w;
    w.amount = amount;
    w.mainchain_fee = fee;
    w.dest = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag)
                       << OP_EQUALVERIFY << OP_CHECKSIG;
    return w;
}

//! A blinded M6 has no inputs. The real M6 spends the treasury UTXO; blinding
//! drops it so a bundle can be proposed before that UTXO exists.
//! The treasury script the enforcer builds: OP_DRIVECHAIN <slot> OP_TRUE.
static CScript TreasuryScript(uint8_t slot)
{
    CScript script;
    script << sidechain::OP_DRIVECHAIN;
    script.push_back(0x01);
    script.push_back(slot);
    script << OP_TRUE;
    return script;
}

BOOST_AUTO_TEST_CASE(treasury_script_matches_enforcer_bytes)
{
    BOOST_CHECK_EQUAL(HexStr(TreasuryScript(119)), "b4017751");
    uint8_t slot{0};
    BOOST_CHECK(sidechain::IsDrivechainTreasury(TreasuryScript(119), slot));
    BOOST_CHECK_EQUAL(slot, 119);
}

//! The enforcer emits OP_PUSHBYTES_1 even where a minimal push would do, so a
//! minimal-encoding parse would miss every treasury on slots 0 through 16.
BOOST_AUTO_TEST_CASE(treasury_accepts_non_minimal_push)
{
    for (const uint8_t slot : {uint8_t{0}, uint8_t{1}, uint8_t{16}, uint8_t{255}}) {
        uint8_t parsed{200};
        BOOST_CHECK(sidechain::IsDrivechainTreasury(TreasuryScript(slot), parsed));
        BOOST_CHECK_EQUAL(parsed, slot);
    }
    // What a minimal encoder would have produced for slot 1: OP_1, not a push.
    BOOST_CHECK(!sidechain::IsDrivechainTreasury(CScript() << sidechain::OP_DRIVECHAIN << OP_1 << OP_TRUE));
}

BOOST_AUTO_TEST_CASE(treasury_rejects_near_misses)
{
    uint8_t slot{0};
    // Right shape, wrong opcode.
    BOOST_CHECK(!sidechain::IsDrivechainTreasury(CScript() << OP_NOP4 << std::vector<unsigned char>{119} << OP_TRUE, slot));
    // Trailing byte.
    CScript trailing{TreasuryScript(119)};
    trailing << OP_TRUE;
    BOOST_CHECK(!sidechain::IsDrivechainTreasury(trailing, slot));
    // Truncated.
    const CScript full{TreasuryScript(119)};
    BOOST_CHECK(!sidechain::IsDrivechainTreasury(CScript(full.begin(), full.end() - 1), slot));
    // Two-byte push of the slot.
    CScript wide;
    wide << sidechain::OP_DRIVECHAIN;
    wide.push_back(0x02);
    wide.push_back(119);
    wide.push_back(0);
    wide << OP_TRUE;
    BOOST_CHECK(!sidechain::IsDrivechainTreasury(wide, slot));
    BOOST_CHECK(!sidechain::IsDrivechainTreasury(CScript(), slot));
}

//! Standardness is the whole point: without it an M5 never reaches a mempool.
BOOST_AUTO_TEST_CASE(treasury_solves_as_drivechain_and_is_standard)
{
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(TreasuryScript(119), solutions) == TxoutType::DRIVECHAIN);
    BOOST_REQUIRE_EQUAL(solutions.size(), 1U);
    BOOST_CHECK_EQUAL(solutions[0].size(), 1U);
    BOOST_CHECK_EQUAL(solutions[0][0], 119);

    TxoutType type;
    BOOST_CHECK(::IsStandard(TreasuryScript(119), type));
    BOOST_CHECK(type == TxoutType::DRIVECHAIN);
    BOOST_CHECK_EQUAL(GetTxnOutputType(TxoutType::DRIVECHAIN), "drivechain");
}

BOOST_AUTO_TEST_CASE(blinded_m6_has_no_inputs)
{
    const auto m6{BuildBlindedM6({MakeWithdrawal(1000, 10, 0x01)})};
    BOOST_REQUIRE(m6.has_value());
    BOOST_CHECK(m6->vin.empty());
}

//! bip300.md:859 claims the fee output is last. The enforcer replaces index 0
//! (lib/messages.rs:937). Index 0 is what interoperates.
BOOST_AUTO_TEST_CASE(fee_output_is_first_not_last)
{
    const auto m6{BuildBlindedM6({MakeWithdrawal(1000, 10, 0x01), MakeWithdrawal(2000, 20, 0x02)})};
    BOOST_REQUIRE(m6.has_value());
    BOOST_REQUIRE_EQUAL(m6->vout.size(), 3U);

    BOOST_CHECK(m6->vout[0].scriptPubKey.IsUnspendable());
    BOOST_CHECK_EQUAL(m6->vout[0].nValue, 0);
    BOOST_CHECK_EQUAL(m6->vout[1].nValue, 1000);
    BOOST_CHECK_EQUAL(m6->vout[2].nValue, 2000);
}

//! F_total is the summed mainchain fee, big-endian, 8 bytes.
BOOST_AUTO_TEST_CASE(fee_total_is_big_endian_64)
{
    const auto m6{BuildBlindedM6({MakeWithdrawal(1000, 0x0102, 0x01), MakeWithdrawal(2000, 0x0304, 0x02)})};
    BOOST_REQUIRE(m6.has_value());
    const CScript& spk{m6->vout[0].scriptPubKey};

    // OP_RETURN, then an 8-byte push.
    std::vector<unsigned char> expected{OP_RETURN, 0x08, 0, 0, 0, 0, 0, 0, 0x04, 0x06};
    BOOST_CHECK_EQUAL(HexStr(spk), HexStr(expected));
}

BOOST_AUTO_TEST_CASE(empty_bundle_still_carries_fee_output)
{
    const auto m6{BuildBlindedM6({})};
    BOOST_REQUIRE(m6.has_value());
    BOOST_REQUIRE_EQUAL(m6->vout.size(), 1U);
    BOOST_CHECK(m6->vout[0].scriptPubKey.IsUnspendable());
}

//! Determinism is what lets every node derive the same m6id with no stored
//! state, so identical inputs must always give an identical id.
BOOST_AUTO_TEST_CASE(m6id_is_deterministic)
{
    const std::vector<Withdrawal> ws{MakeWithdrawal(1000, 10, 0x01), MakeWithdrawal(2000, 20, 0x02)};
    BOOST_CHECK(ComputeM6id(ws) == ComputeM6id(ws));
    BOOST_CHECK(ComputeM6id(ws).has_value());
}

BOOST_AUTO_TEST_CASE(m6id_changes_with_order)
{
    const Withdrawal a{MakeWithdrawal(1000, 10, 0x01)};
    const Withdrawal b{MakeWithdrawal(2000, 20, 0x02)};
    BOOST_CHECK(ComputeM6id({a, b}) != ComputeM6id({b, a}));
}

//! A wrapped fee total would hash differently on a different compiler, which is
//! a consensus split in a value every node must agree on.
BOOST_AUTO_TEST_CASE(m6id_rejects_out_of_range_totals)
{
    BOOST_CHECK(!ComputeM6id({MakeWithdrawal(MAX_MONEY, 1, 0x01), MakeWithdrawal(MAX_MONEY, 1, 0x02)}).has_value());
    BOOST_CHECK(!ComputeM6id({MakeWithdrawal(1000, MAX_MONEY, 0x01), MakeWithdrawal(1000, MAX_MONEY, 0x02)}).has_value());
    BOOST_CHECK(!ComputeM6id({MakeWithdrawal(-1, 10, 0x01)}).has_value());
}

BOOST_AUTO_TEST_CASE(m6id_changes_with_fee)
{
    BOOST_CHECK(ComputeM6id({MakeWithdrawal(1000, 10, 0x01)}) !=
                ComputeM6id({MakeWithdrawal(1000, 11, 0x01)}));
}

//! The enforcer decodes with a legacy fallback because a zero-input tx in
//! segwit encoding is misparsed as a witness marker. Ours must be legacy: no
//! 0x0001 marker after the version.
BOOST_AUTO_TEST_CASE(serialization_is_legacy_not_segwit)
{
    const auto m6{BuildBlindedM6({MakeWithdrawal(1000, 10, 0x01)})};
    BOOST_REQUIRE(m6.has_value());
    const auto bytes{SerializeBlindedM6(*m6)};

    BOOST_REQUIRE(bytes.size() > 6);
    // version(4) then the input count, which must be 0 rather than a marker.
    BOOST_CHECK_EQUAL(bytes[4], 0x00);
    BOOST_CHECK(bytes[5] != 0x01);
}

//! Fixed vector, cross-checked against an independent implementation built
//! from bip300.md. Guards the exact bytes the enforcer will hash.
BOOST_AUTO_TEST_CASE(m6id_matches_reference_vector)
{
    const std::vector<Withdrawal> ws{MakeWithdrawal(1000, 10, 0x01)};
    BOOST_CHECK_EQUAL(
        HexStr(SerializeBlindedM6(*BuildBlindedM6(ws))),
        "02000000000200000000000000000a6a08000000000000000ae803000000000000"
        "1976a914010101010101010101010101010101010101010188ac00000000");
    BOOST_CHECK_EQUAL(
        ComputeM6id(ws)->GetHex(),
        "61a9589b94367fe2299447a0007987bf0541b4e354f37c87d831e7349cd034b1");
}

static WithdrawalRequest MakeRequest(CAmount amount, CAmount fee)
{
    WithdrawalRequest r;
    r.amount = amount;
    r.mainchain_fee = fee;
    r.dest = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xaa)
                       << OP_EQUALVERIFY << OP_CHECKSIG;
    r.owner = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xbb)
                         << OP_EQUALVERIFY << OP_CHECKSIG;
    return r;
}

//! A request output as the producer would find it in the UTXO set.
static CTxOut RequestOut(unsigned char tag, CAmount amount = 10'000, CAmount fee = 1'000)
{
    WithdrawalRequest r;
    r.amount = amount;
    r.mainchain_fee = fee;
    r.dest = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag)
                       << OP_EQUALVERIFY << OP_CHECKSIG;
    r.owner = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag ^ 0xff)
                        << OP_EQUALVERIFY << OP_CHECKSIG;
    return BuildWithdrawalRequestOutput(r);
}

static std::vector<WithdrawalRequest> RequestsOf(const std::vector<CTxOut>& outs)
{
    std::vector<WithdrawalRequest> parsed;
    for (const CTxOut& out : outs) {
        // A caller may pass an output that is not a request, to check that the
        // bundle rules reject it. Only a request belongs in the digest.
        if (const auto request{ParseWithdrawalRequestOutput(out)}) parsed.push_back(*request);
    }
    return parsed;
}

static CMutableTransaction SweepInto(const std::vector<CTxOut>& requests, CAmount value, const uint256& m6id)
{
    CMutableTransaction tx;
    tx.vin.resize(requests.size());
    tx.vout.push_back(BuildBundleOutput(m6id, RequestSetDigest(RequestsOf(requests)), value));
    return tx;
}

static uint256 M6idOf(const std::vector<CTxOut>& requests)
{
    std::vector<Withdrawal> ws;
    ws.reserve(requests.size());
    for (const CTxOut& out : requests) ws.push_back(ToWithdrawal(*ParseWithdrawalRequestOutput(out)));
    return *ComputeM6id(ws);
}

static COutPoint Point(unsigned char tag)
{
    return COutPoint{Txid::FromUint256(uint256{std::vector<unsigned char>(32, tag)}), 0};
}

//! A live bundle at `tag`, voting under m6id `tag`.
static LiveBundleRef Ref(unsigned char tag)
{
    return LiveBundleRef{Point(tag), uint256{std::vector<unsigned char>(32, tag)}};
}

BOOST_AUTO_TEST_CASE(live_bundles_roundtrip)
{
    const std::vector<LiveBundleRef> live{Ref(1), Ref(2)};
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout.push_back(BuildLiveBundleOutput(live));

    const auto parsed{GetLiveBundles(CTransaction{cb})};
    BOOST_REQUIRE(parsed);
    BOOST_CHECK(*parsed == live);

    // An empty set is a statement -- nothing is in flight -- not an absence.
    CMutableTransaction empty;
    empty.vin.resize(1);
    empty.vout.push_back(BuildLiveBundleOutput({}));
    const auto none{GetLiveBundles(CTransaction{empty})};
    BOOST_REQUIRE(none);
    BOOST_CHECK(none->empty());

    // A coinbase that declares nothing has nothing in flight.
    CMutableTransaction silent;
    silent.vin.resize(1);
    const auto absent{GetLiveBundles(CTransaction{silent})};
    BOOST_REQUIRE(absent);
    BOOST_CHECK(absent->empty());

    // Two sets are ambiguous, so neither counts.
    cb.vout.push_back(BuildLiveBundleOutput({Ref(3)}));
    BOOST_CHECK(!GetLiveBundles(CTransaction{cb}));
}

BOOST_AUTO_TEST_CASE(live_bundles_track_what_a_block_did)
{
    std::string reason;
    // Opening one.
    BOOST_CHECK(CheckLiveBundles({}, Ref(1), {}, {}, {Ref(1)}, reason));
    // Settling it empties the set.
    BOOST_CHECK(CheckLiveBundles({Ref(1)}, std::nullopt, {Point(1)}, {}, {}, reason));
    // Settling one and opening the next in the same block.
    BOOST_CHECK(CheckLiveBundles({Ref(1)}, Ref(2), {Point(1)}, {}, {Ref(2)}, reason));
}

//! A verdict is visible over exactly one block's mainchain range, so a block
//! that ignores one strands that bundle -- and every withdrawal behind it.
BOOST_AUTO_TEST_CASE(live_bundles_must_settle_what_the_mainchain_ruled_on)
{
    std::string reason;
    BOOST_CHECK(!CheckLiveBundles({Ref(1)}, std::nullopt, {}, {Point(1)}, {Ref(1)}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-live-bundles-unsettled");

    // Acting on it is what makes the block valid.
    BOOST_CHECK(CheckLiveBundles({Ref(1)}, std::nullopt, {Point(1)}, {Point(1)}, {}, reason));
}

//! The mainchain votes on one bundle per slot, so a second could never be paid
//! and would occupy the slot for good.
BOOST_AUTO_TEST_CASE(only_one_bundle_may_be_live)
{
    std::string reason;
    BOOST_CHECK(!CheckLiveBundles({Ref(1)}, Ref(2), {}, {}, {Ref(1), Ref(2)}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-bundle-multiple");
}

//! Dropping a bundle from the set is how a payout would get skipped, which
//! would leave the sidechain holding coins the mainchain already handed out.
BOOST_AUTO_TEST_CASE(live_bundles_cannot_be_forgotten_or_invented)
{
    std::string reason;

    BOOST_CHECK(!CheckLiveBundles({Ref(1)}, std::nullopt, {}, {}, {}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-live-bundles-mismatch");

    // Nor may one appear that no block opened.
    BOOST_CHECK(!CheckLiveBundles({}, std::nullopt, {}, {}, {Ref(9)}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-live-bundles-mismatch");

    // Nor may a block claim to settle something never in flight.
    BOOST_CHECK(!CheckLiveBundles({}, std::nullopt, {Point(9)}, {}, {}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-live-bundles-unknown-settlement");

    // Nor may it rewrite the m6id a live bundle votes under, which is what a
    // validator matches verdicts against.
    BOOST_CHECK(!CheckLiveBundles({Ref(1)}, std::nullopt, {}, {},
                                  {LiveBundleRef{Point(1), uint256::ONE}}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-live-bundles-mismatch");

    // Duplicates would let one settlement clear two entries.
    BOOST_CHECK(!CheckLiveBundles({}, Ref(1), {}, {}, {Ref(1), Ref(1)}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-live-bundles-duplicate");
}

BOOST_AUTO_TEST_CASE(bundle_sweeps_requests_and_commits_to_them)
{
    const std::vector<CTxOut> requests{RequestOut(1), RequestOut(2, 25'000, 500)};
    const CAmount total{10'000 + 25'000};
    const CMutableTransaction tx{SweepInto(requests, total, M6idOf(requests))};

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(CheckBundleTransaction(CTransaction{tx}, requests, m6id, reason));
    BOOST_CHECK(m6id == M6idOf(requests));
}

//! Sweeping anything else would let a bundle carry coins nobody asked to
//! withdraw, which the settlement would then pay out or destroy.
BOOST_AUTO_TEST_CASE(bundle_rejects_a_non_request_input)
{
    std::vector<CTxOut> spent{RequestOut(1)};
    spent.emplace_back(50'000, CScript() << OP_TRUE);
    CMutableTransaction tx{SweepInto(spent, 60'000, uint256::ONE)};

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(!CheckBundleTransaction(CTransaction{tx}, spent, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-bundle-input-not-request");
}

BOOST_AUTO_TEST_CASE(bundle_must_commit_to_its_own_contents)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    CMutableTransaction tx{SweepInto(requests, 10'000, uint256::ONE)};

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(!CheckBundleTransaction(CTransaction{tx}, requests, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-bundle-m6id");
}

//! ToWithdrawal drops `owner`, so a bundle can carry the right m6id while
//! committing to a request set that refunds someone else. Only the digest catches
//! it, and a failed bundle would otherwise restore the coins to the attacker.
BOOST_AUTO_TEST_CASE(bundle_cannot_redirect_the_refund)
{
    const std::vector<CTxOut> requests{RequestOut(1)};

    std::vector<WithdrawalRequest> hijacked{RequestsOf(requests)};
    hijacked[0].owner = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x99)
                                  << OP_EQUALVERIFY << OP_CHECKSIG;

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.push_back(BuildBundleOutput(M6idOf(requests), RequestSetDigest(hijacked), 10'000));

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(!CheckBundleTransaction(CTransaction{tx}, requests, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-bundle-requests");
}

//! No fee and no mint: a bundle changes the form of the coins, not the amount.
BOOST_AUTO_TEST_CASE(bundle_preserves_value)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    uint256 m6id;
    std::string reason;
    for (const CAmount wrong : {CAmount{9'999}, CAmount{10'001}}) {
        CMutableTransaction tx{SweepInto(requests, wrong, M6idOf(requests))};
        BOOST_CHECK(!CheckBundleTransaction(CTransaction{tx}, requests, m6id, reason));
        BOOST_CHECK_EQUAL(reason, "bad-bundle-value");
    }
}

BOOST_AUTO_TEST_CASE(bundle_is_bounded)
{
    std::vector<CTxOut> requests;
    for (size_t i = 0; i <= MAX_BUNDLE_WITHDRAWALS; ++i) {
        requests.push_back(RequestOut(static_cast<unsigned char>(i)));
    }
    CMutableTransaction tx{SweepInto(requests, 10'000 * requests.size(), uint256::ONE)};

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(!CheckBundleTransaction(CTransaction{tx}, requests, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-bundle-size");
}

BOOST_AUTO_TEST_CASE(paid_settlement_destroys_the_coins)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    const std::vector<CTxOut> bundle{BuildBundleOutput(M6idOf(requests), RequestSetDigest(RequestsOf(requests)), 10'000)};

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.emplace_back(10'000, CScript() << OP_RETURN);

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(CheckSettlementTransaction(CTransaction{tx}, bundle, BundleOutcome::Paid, m6id, reason));
    BOOST_CHECK(m6id == M6idOf(requests));
}

//! The mainchain already paid these out, so a settlement that keeps them
//! spendable would be a second payment.
BOOST_AUTO_TEST_CASE(paid_settlement_cannot_keep_the_coins)
{
    const std::vector<CTxOut> bundle{BuildBundleOutput(uint256::ONE, uint256::ONE, 10'000)};

    CMutableTransaction stolen;
    stolen.vin.resize(1);
    stolen.vout.emplace_back(10'000, CScript() << OP_TRUE);

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(!CheckSettlementTransaction(CTransaction{stolen}, bundle, BundleOutcome::Paid, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-settlement-not-destroyed");

    // Nor may it destroy less than it spent and pocket the difference as fee.
    CMutableTransaction skimmed;
    skimmed.vin.resize(1);
    skimmed.vout.emplace_back(9'000, CScript() << OP_RETURN);
    BOOST_CHECK(!CheckSettlementTransaction(CTransaction{skimmed}, bundle, BundleOutcome::Paid, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-settlement-value");
}

BOOST_AUTO_TEST_CASE(failed_settlement_restores_the_requests)
{
    const std::vector<CTxOut> requests{RequestOut(1), RequestOut(2, 25'000, 500)};
    const std::vector<CTxOut> bundle{BuildBundleOutput(M6idOf(requests), RequestSetDigest(RequestsOf(requests)), 35'000)};

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout = requests;

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(CheckSettlementTransaction(CTransaction{tx}, bundle, BundleOutcome::Failed, m6id, reason));
    BOOST_CHECK(m6id == M6idOf(requests));
}

//! The producer builds the settlement, so it must not be able to redirect a
//! failed withdrawal to itself. The m6id rehash is what stops it.
BOOST_AUTO_TEST_CASE(failed_settlement_cannot_redirect_the_coins)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    const std::vector<CTxOut> bundle{BuildBundleOutput(M6idOf(requests), RequestSetDigest(RequestsOf(requests)), 10'000)};

    uint256 m6id;
    std::string reason;

    // Same destination, same payout, same fee -- only the owner differs, so the
    // m6id has to be what rejects it. Changing the destination too would make
    // this pass for the wrong reason.
    const auto original{*ParseWithdrawalRequestOutput(requests[0])};
    WithdrawalRequest hijacked{original};
    hijacked.owner = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x99)
                               << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK(hijacked.dest == original.dest);
    BOOST_CHECK_EQUAL(hijacked.amount, original.amount);
    BOOST_CHECK_EQUAL(hijacked.mainchain_fee, original.mainchain_fee);

    CMutableTransaction rewritten;
    rewritten.vin.resize(1);
    rewritten.vout = {BuildWithdrawalRequestOutput(hijacked)};
    BOOST_CHECK(!CheckSettlementTransaction(CTransaction{rewritten}, bundle, BundleOutcome::Failed, m6id, reason));
    // The m6id cannot catch this -- the blinded M6 carries no owner -- so it is
    // the request digest that has to.
    BOOST_CHECK_EQUAL(reason, "bad-settlement-requests");

    // Nor may it pay a plain address, which would put the coins beyond the peg.
    CMutableTransaction plain;
    plain.vin.resize(1);
    plain.vout.emplace_back(10'000, CScript() << OP_TRUE);
    BOOST_CHECK(!CheckSettlementTransaction(CTransaction{plain}, bundle, BundleOutcome::Failed, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-settlement-not-requests");
}

//! The blinded M6 commits to the fee TOTAL, not to each request's share, so a
//! producer could otherwise move fee sats between users and still match.
BOOST_AUTO_TEST_CASE(failed_settlement_cannot_reshuffle_the_fee)
{
    const std::vector<CTxOut> requests{RequestOut(1, 10'000, 1'000), RequestOut(2, 10'000, 1'000)};
    const std::vector<CTxOut> bundle{
        BuildBundleOutput(M6idOf(requests), RequestSetDigest(RequestsOf(requests)), 20'000)};

    // Every payout (amount - fee) and the fee total are preserved, so the blinded
    // M6 is unchanged and the m6id cannot be what rejects this. Moving the fee
    // alone would change a payout and be caught for the wrong reason.
    std::vector<WithdrawalRequest> shuffled{RequestsOf(requests)};
    shuffled[0].amount = 10'500;
    shuffled[0].mainchain_fee = 1'500;
    shuffled[1].amount = 9'500;
    shuffled[1].mainchain_fee = 500;

    CMutableTransaction tx;
    tx.vin.resize(1);
    for (const WithdrawalRequest& r : shuffled) tx.vout.push_back(BuildWithdrawalRequestOutput(r));

    BOOST_REQUIRE(M6idOf(tx.vout) == M6idOf(requests));

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(!CheckSettlementTransaction(CTransaction{tx}, bundle, BundleOutcome::Failed, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-settlement-requests");
}

BOOST_AUTO_TEST_CASE(settlement_must_spend_a_bundle)
{
    const std::vector<CTxOut> not_a_bundle{RequestOut(1)};
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.emplace_back(10'000, CScript() << OP_RETURN);

    uint256 m6id;
    std::string reason;
    BOOST_CHECK(!CheckSettlementTransaction(CTransaction{tx}, not_a_bundle, BundleOutcome::Paid, m6id, reason));
    BOOST_CHECK_EQUAL(reason, "bad-settlement-input-not-bundle");
}

BOOST_AUTO_TEST_CASE(abort_pays_every_owner_what_it_committed_to)
{
    const std::vector<WithdrawalRequest> requests{MakeRequest(10'000, 1'000), MakeRequest(7'000, 500)};
    std::vector<CTxOut> spent;
    std::vector<COutPoint> outpoints;
    for (size_t i{0}; i < requests.size(); ++i) {
        spent.push_back(BuildWithdrawalRequestOutput(requests[i]));
        outpoints.emplace_back(Txid::FromUint256(uint256{static_cast<uint8_t>(i + 1)}), 0);
    }

    std::string reason;
    const CMutableTransaction tx{BuildAbortTransaction(outpoints, requests)};
    BOOST_CHECK(CheckAbortTransaction(CTransaction{tx}, spent, reason));

    // Paying somewhere else is the whole attack: a request carries no signature,
    // so only this rule keeps it its owner's.
    CMutableTransaction stolen{tx};
    stolen.vout[1].scriptPubKey = CScript() << OP_TRUE;
    BOOST_CHECK(!CheckAbortTransaction(CTransaction{stolen}, spent, reason));
    BOOST_CHECK_EQUAL(reason, "bad-abort-payout");

    // Skimming is the same attack, quieter.
    CMutableTransaction skimmed{tx};
    skimmed.vout[0].nValue -= 1;
    BOOST_CHECK(!CheckAbortTransaction(CTransaction{skimmed}, spent, reason));
    BOOST_CHECK_EQUAL(reason, "bad-abort-payout");

    // One output per input, so the pairing a validator reads off is the only one.
    CMutableTransaction short_tx{tx};
    short_tx.vout.pop_back();
    BOOST_CHECK(!CheckAbortTransaction(CTransaction{short_tx}, spent, reason));
    BOOST_CHECK_EQUAL(reason, "bad-abort-shape");

    // Ordinary coins may not ride along: they have no owner to check against.
    std::vector<CTxOut> mixed{spent};
    mixed[1] = CTxOut{7'000, CScript() << OP_TRUE};
    BOOST_CHECK(!CheckAbortTransaction(CTransaction{tx}, mixed, reason));
    BOOST_CHECK_EQUAL(reason, "bad-abort-input-not-request");
}

BOOST_AUTO_TEST_CASE(withdrawal_request_roundtrips)
{
    const auto request{MakeRequest(5000, 100)};
    const auto parsed{ParseWithdrawalRequestOutput(BuildWithdrawalRequestOutput(request))};
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK_EQUAL(parsed->amount, 5000);
    BOOST_CHECK_EQUAL(parsed->mainchain_fee, 100);
    BOOST_CHECK(parsed->dest == request.dest);
    BOOST_CHECK(parsed->owner == request.owner);
}

//! The coins are encumbered, not destroyed. An unspendable output would put
//! them beyond the producer's reach and force a minting refund path to undo it.
BOOST_AUTO_TEST_CASE(withdrawal_request_output_is_spendable)
{
    const CScript spk{BuildWithdrawalRequestOutput(MakeRequest(5000, 100)).scriptPubKey};
    BOOST_CHECK(!spk.IsUnspendable());

    // Spendable with an empty scriptSig: the producer sweeps it into a bundle
    // without the owner's signature, and the stack is left clean.
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err;
    BOOST_CHECK(EvalScript(stack, spk, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(CastToBool(stack.back()));
}

BOOST_AUTO_TEST_CASE(plain_op_return_is_not_a_request)
{
    CTxOut out{0, CScript() << OP_RETURN << std::vector<unsigned char>{0xde, 0xad}};
    BOOST_CHECK(!IsWithdrawalRequestOutput(out));
}

BOOST_AUTO_TEST_CASE(payment_output_is_not_a_request)
{
    CTxOut out{5000, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x01)
                               << OP_EQUALVERIFY << OP_CHECKSIG};
    BOOST_CHECK(!IsWithdrawalRequestOutput(out));
}

//! A fee at or above the amount would make the M6 payout zero or negative.
BOOST_AUTO_TEST_CASE(fee_must_be_less_than_amount)
{
    BOOST_CHECK(!ParseWithdrawalRequestOutput(BuildWithdrawalRequestOutput(MakeRequest(100, 100))).has_value());
    BOOST_CHECK(!ParseWithdrawalRequestOutput(BuildWithdrawalRequestOutput(MakeRequest(100, 200))).has_value());
    BOOST_CHECK(ParseWithdrawalRequestOutput(BuildWithdrawalRequestOutput(MakeRequest(100, 99))).has_value());
}

//! The mainchain is paid amount - fee; the fee accrues to mainchain miners.
BOOST_AUTO_TEST_CASE(to_withdrawal_deducts_mainchain_fee)
{
    const auto w{ToWithdrawal(MakeRequest(5000, 100))};
    BOOST_CHECK_EQUAL(w.amount, 4900);
    BOOST_CHECK_EQUAL(w.mainchain_fee, 100);
}

BOOST_AUTO_TEST_CASE(trailing_bytes_rejected)
{
    auto out{BuildWithdrawalRequestOutput(MakeRequest(5000, 100))};
    out.scriptPubKey << std::vector<unsigned char>{0x01};
    BOOST_CHECK(!IsWithdrawalRequestOutput(out));
}

static std::vector<unsigned char> Bytes(const std::string& s)
{
    return std::vector<unsigned char>{s.begin(), s.end()};
}

static std::string SampleAddress()
{
    return EncodeDestination(PKHash{uint160{std::vector<unsigned char>(20, 0x07)}});
}

//! All three forms BitWindow can emit must decode to the same script, since
//! nothing normalizes between them on the way through the enforcer.
BOOST_AUTO_TEST_CASE(deposit_payload_accepts_all_three_forms)
{
    const std::string addr{SampleAddress()};
    const auto bare{DecodeDepositPayload(Bytes(addr))};
    BOOST_REQUIRE(bare.has_value());

    const auto with_slot{DecodeDepositPayload(Bytes("s119_" + addr))};
    BOOST_REQUIRE(with_slot.has_value());

    const auto full{DecodeDepositPayload(Bytes(EncodeDepositAddress(119, addr)))};
    BOOST_REQUIRE(full.has_value());

    BOOST_CHECK(*bare == *with_slot);
    BOOST_CHECK(*bare == *full);
}

//! Checksum is 3 bytes rendered as 6 hex chars. The enforcer proto comment says
//! "first 6 bytes"; bitwindow's Go uses hash[:3]. The Go code is authoritative.
BOOST_AUTO_TEST_CASE(deposit_checksum_is_three_bytes_six_hex)
{
    BOOST_CHECK_EQUAL(DepositAddressChecksum(119, SampleAddress()).size(), 6U);
    // Fixed vector matching bitwindow/server/drivechain/utils.go:56 —
    // hex(sha256("s119_TESTADDR_")[:3]).
    BOOST_CHECK_EQUAL(DepositAddressChecksum(119, "TESTADDR"), "a71ad2");
}

BOOST_AUTO_TEST_CASE(deposit_payload_rejects_bad_checksum)
{
    const std::string addr{SampleAddress()};
    BOOST_CHECK(!DecodeDepositPayload(Bytes("s119_" + addr + "_000000")).has_value());
}

BOOST_AUTO_TEST_CASE(deposit_payload_rejects_malformed)
{
    BOOST_CHECK(!DecodeDepositPayload(Bytes("")).has_value());
    BOOST_CHECK(!DecodeDepositPayload(Bytes("not-an-address")).has_value());
    BOOST_CHECK(!DecodeDepositPayload(Bytes("s119_")).has_value());
    BOOST_CHECK(!DecodeDepositPayload(Bytes("x119_" + SampleAddress())).has_value());
    BOOST_CHECK(!DecodeDepositPayload(Bytes("s999_" + SampleAddress())).has_value());
    BOOST_CHECK(!DecodeDepositPayload(Bytes("a_b_c_d")).has_value());
}

static Deposit MakeDeposit(uint64_t seq, CAmount value, const std::string& payload)
{
    Deposit d;
    d.sequence_number = seq;
    d.value = value;
    d.address = Bytes(payload);
    return d;
}

//! Sequence number is the canonical order; the enforcer may report otherwise.
BOOST_AUTO_TEST_CASE(deposits_sort_by_sequence_number)
{
    const auto sorted{SortDeposits({MakeDeposit(3, 1, "c"), MakeDeposit(1, 1, "a"), MakeDeposit(2, 1, "b")})};
    BOOST_CHECK_EQUAL(sorted[0].sequence_number, 1U);
    BOOST_CHECK_EQUAL(sorted[1].sequence_number, 2U);
    BOOST_CHECK_EQUAL(sorted[2].sequence_number, 3U);
}

static CMutableTransaction CoinbaseWith(const std::vector<CTxOut>& outs)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vout = outs;
    return tx;
}

BOOST_AUTO_TEST_CASE(coinbase_credits_deposits_in_order)
{
    const std::string addr{SampleAddress()};
    const CScript spk{*DecodeDepositPayload(Bytes(addr))};
    const std::vector<Deposit> deposits{MakeDeposit(1, 1000, addr), MakeDeposit(2, 2000, addr)};

    std::string reason;
    CAmount credited{0};
    const auto cb{CoinbaseWith({CTxOut{1000, spk}, CTxOut{2000, spk}})};
    BOOST_CHECK(CheckCoinbaseDeposits(CTransaction{cb}, deposits, credited, reason));
    BOOST_CHECK(reason.empty());
}

BOOST_AUTO_TEST_CASE(coinbase_rejects_wrong_deposit_amount)
{
    const std::string addr{SampleAddress()};
    const CScript spk{*DecodeDepositPayload(Bytes(addr))};
    std::string reason;
    CAmount credited{0};
    const auto cb{CoinbaseWith({CTxOut{999, spk}})};
    BOOST_CHECK(!CheckCoinbaseDeposits(CTransaction{cb}, {MakeDeposit(1, 1000, addr)}, credited, reason));
    BOOST_CHECK_EQUAL(reason, "bad-cb-deposit-amount");
}

BOOST_AUTO_TEST_CASE(coinbase_rejects_missing_deposit_output)
{
    std::string reason;
    CAmount credited{0};
    const auto cb{CoinbaseWith({})};
    BOOST_CHECK(!CheckCoinbaseDeposits(CTransaction{cb}, {MakeDeposit(1, 1000, SampleAddress())}, credited, reason));
    BOOST_CHECK_EQUAL(reason, "bad-cb-missing-deposit");
}

//! An undecodable payload still has real mainchain coins behind it, so it is
//! credited to an unspendable output rather than dropped. Dropping it would
//! break the coinbase value equation.
BOOST_AUTO_TEST_CASE(undecodable_deposit_credits_unspendable)
{
    const std::vector<Deposit> deposits{MakeDeposit(1, 1000, "garbage-not-an-address")};
    std::string reason;
    CAmount credited{0};

    const auto burned{CoinbaseWith({CTxOut{1000, CScript() << OP_RETURN}})};
    BOOST_CHECK(CheckCoinbaseDeposits(CTransaction{burned}, deposits, credited, reason));

    const auto stolen{CoinbaseWith({CTxOut{1000, CScript() << OP_TRUE}})};
    BOOST_CHECK(!CheckCoinbaseDeposits(CTransaction{stolen}, deposits, credited, reason));
    BOOST_CHECK_EQUAL(reason, "bad-cb-deposit-script");
}

//! The payload is an arbitrary-length string lifted from a mainchain OP_RETURN
//! and fed to a consensus decoder. The bound has to exist before mainnet, not
//! after: adding one later is a fork.
BOOST_AUTO_TEST_CASE(deposit_payload_is_length_bounded)
{
    const std::string address{SampleAddress()};
    const std::vector<unsigned char> ok{address.begin(), address.end()};
    BOOST_REQUIRE(DecodeDepositPayload(ok).has_value());

    std::vector<unsigned char> too_long(MAX_DEPOSIT_PAYLOAD_SIZE + 1, 'a');
    BOOST_CHECK(!DecodeDepositPayload(too_long).has_value());

    // The split used to run to completion before the part count was checked,
    // so a payload of separators allocated one string per byte.
    std::vector<unsigned char> separators(MAX_DEPOSIT_PAYLOAD_SIZE, '_');
    BOOST_CHECK(!DecodeDepositPayload(separators).has_value());

    // The longest well-formed payload still fits, so the cap cannot reject a
    // deposit anyone can actually make.
    const std::string longest{EncodeDepositAddress(119, address)};
    BOOST_CHECK_LE(longest.size(), MAX_DEPOSIT_PAYLOAD_SIZE);
    const std::vector<unsigned char> longest_bytes{longest.begin(), longest.end()};
    BOOST_CHECK(DecodeDepositPayload(longest_bytes).has_value());
}

//! Heights are uint32 on the wire. A negative one is adopted as the window's
//! low, leaves the cache without an anchor, and no later poll can recover.
BOOST_AUTO_TEST_CASE(peg_response_rejects_a_negative_height)
{
    const std::string hash(64, 'a');
    UniValue response{UniValue::VOBJ};
    UniValue blocks{UniValue::VARR};
    UniValue item{UniValue::VOBJ};
    UniValue header{UniValue::VOBJ};
    UniValue block_hash{UniValue::VOBJ};
    block_hash.pushKV("hex", hash);
    header.pushKV("blockHash", block_hash);
    header.pushKV("height", -1);
    item.pushKV("blockHeaderInfo", header);
    item.pushKV("blockInfo", UniValue{UniValue::VOBJ});
    blocks.push_back(item);
    response.pushKV("blocks", blocks);

    std::vector<BlockInfo> out;
    std::string error;
    BOOST_CHECK(!ParseTwoWayPegResponse(response, out, error));
    BOOST_CHECK_EQUAL(error, "GetTwoWayPegData: invalid height");

    // The same response with a valid height parses, so it is the sign that is
    // rejected and not the shape.
    UniValue positive{UniValue::VOBJ};
    UniValue positive_header{UniValue::VOBJ};
    positive_header.pushKV("blockHash", block_hash);
    positive_header.pushKV("height", 7);
    positive.pushKV("blockHeaderInfo", positive_header);
    positive.pushKV("blockInfo", UniValue{UniValue::VOBJ});
    UniValue positive_blocks{UniValue::VARR};
    positive_blocks.push_back(positive);
    UniValue positive_response{UniValue::VOBJ};
    positive_response.pushKV("blocks", positive_blocks);

    BOOST_CHECK_MESSAGE(ParseTwoWayPegResponse(positive_response, out, error), error);
    BOOST_CHECK_EQUAL(out.size(), 1U);
    BOOST_CHECK_EQUAL(out[0].main_height, 7);
}

BOOST_AUTO_TEST_CASE(bmm_commitment_roundtrips)
{
    const uint256 prev{uint256::FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").value()};
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout.emplace_back(5000, CScript() << OP_TRUE);
    cb.vout.push_back(BuildBmmCommitmentOutput(prev));

    const auto found{GetBmmCommitment(CTransaction{cb})};
    BOOST_REQUIRE(found.has_value());
    BOOST_CHECK(*found == prev);
}

BOOST_AUTO_TEST_CASE(bmm_commitment_absent_when_not_present)
{
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout.emplace_back(5000, CScript() << OP_TRUE);
    BOOST_CHECK(!GetBmmCommitment(CTransaction{cb}).has_value());
}

//! A foreign OP_RETURN must not be mistaken for a BMM commitment.
//! GenerateCoinbaseCommitment appends the segwit witness commitment after ours,
//! so the BMM output is never last. Keying on position made the chain incapable
//! of producing a single block.
BOOST_AUTO_TEST_CASE(bmm_commitment_found_before_witness_commitment)
{
    const uint256 prev{uint256::FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").value()};
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout.emplace_back(5000, CScript() << OP_TRUE);
    cb.vout.push_back(BuildBmmCommitmentOutput(prev));
    // Shape of a real witness commitment: OP_RETURN + 36-byte push.
    cb.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(36, 0xaa));

    const auto found{GetBmmCommitment(CTransaction{cb})};
    BOOST_REQUIRE(found.has_value());
    BOOST_CHECK(*found == prev);
}

//! Two BMM-shaped outputs are ambiguous; picking one would let a miner shadow
//! the real commitment with a decoy and choose prev_main freely.
BOOST_AUTO_TEST_CASE(bmm_commitment_rejects_duplicates)
{
    const uint256 a{uint256::FromHex("11" "11111111111111111111111111111111111111111111111111111111111111").value()};
    const uint256 b{uint256::FromHex("22" "22222222222222222222222222222222222222222222222222222222222222").value()};
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout.push_back(BuildBmmCommitmentOutput(a));
    cb.vout.push_back(BuildBmmCommitmentOutput(b));
    BOOST_CHECK(!GetBmmCommitment(CTransaction{cb}).has_value());
}

BOOST_AUTO_TEST_CASE(bmm_commitment_ignores_other_op_returns)
{
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(33, 0xff));
    BOOST_CHECK(!GetBmmCommitment(CTransaction{cb}).has_value());
}

//! The enforcer is unauthenticated plaintext HTTP on an operator-configured
//! host, so its framing is untrusted input.
BOOST_AUTO_TEST_CASE(chunked_decoder_accepts_valid_framing)
{
    std::string out;
    BOOST_REQUIRE(DecodeChunkedForTest("4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n", out));
    BOOST_CHECK_EQUAL(out, "abcdefg");

    BOOST_REQUIRE(DecodeChunkedForTest("0\r\n\r\n", out));
    BOOST_CHECK_EQUAL(out, "");

    // Chunk extensions after ';' are legal and must be ignored.
    BOOST_REQUIRE(DecodeChunkedForTest("4;ext=1\r\nabcd\r\n0\r\n\r\n", out));
    BOOST_CHECK_EQUAL(out, "abcd");
}

//! std::stoul would take "-1" as ULONG_MAX and the old bounds check could wrap.
BOOST_AUTO_TEST_CASE(chunked_decoder_rejects_hostile_sizes)
{
    std::string out;
    BOOST_CHECK(!DecodeChunkedForTest("-1\r\nabcd\r\n0\r\n\r\n", out));
    BOOST_CHECK(!DecodeChunkedForTest("ffffffffffffffff\r\nabcd\r\n", out));
    BOOST_CHECK(!DecodeChunkedForTest("fffffffffffffffff\r\nabcd\r\n", out));
    BOOST_CHECK(!DecodeChunkedForTest("  4\r\nabcd\r\n0\r\n\r\n", out));
    BOOST_CHECK(!DecodeChunkedForTest("zz\r\nabcd\r\n0\r\n\r\n", out));
    BOOST_CHECK(!DecodeChunkedForTest("\r\n", out));
}

BOOST_AUTO_TEST_CASE(chunked_decoder_rejects_truncated_body)
{
    std::string out;
    BOOST_CHECK(!DecodeChunkedForTest("10\r\nshort\r\n0\r\n\r\n", out));
    BOOST_CHECK(!DecodeChunkedForTest("4\r\nabcd", out));
    BOOST_CHECK(!DecodeChunkedForTest("", out));
}

static BlockInfo MakeBlockInfo(int32_t height, unsigned char tag, const std::vector<Deposit>& deposits)
{
    BlockInfo info;
    info.main_block_hash = uint256{std::vector<unsigned char>(32, tag)};
    info.main_height = height;
    info.deposits = deposits;
    return info;
}

//! Models a real mainchain: a linear chain of blocks, some carrying deposits.
//! Mirrors the enforcer's actual contract -- try_get_header_infos returns
//! max_ancestors + 1 newest-first, and the peg range is exclusive of start.
class FakeEnforcer final : public IEnforcerClient
{
public:
    //! height -> (hash, optional deposit)
    std::vector<uint256> chain;
    std::map<int32_t, Deposit> deposits;

    mutable int peg_calls{0};
    mutable int header_calls{0};
    mutable int fail_next_header{0};
    mutable int fail_next_peg{0};
    //! Reject any peg fetch spanning more than this many blocks, to model a
    //! response that exceeds the read cap on deposit-heavy ranges.
    mutable int32_t oversize_peg_span{0};
    //! Refuse every peg fetch as oversized, whatever its span.
    mutable bool reject_every_peg_fetch{false};
    //! Return at most this many headers, to model a truncating enforcer.
    mutable int truncate_headers_to{0};
    //! Corrupt the prev-hash link at this index, to model a broken chain.
    mutable int break_link_at{-1};
    //! Report a tip the enforcer does not actually know about.
    std::optional<uint256> unknown_tip;

    void BuildChain(int32_t height, unsigned char branch)
    {
        chain.clear();
        for (int32_t h = 0; h <= height; ++h) {
            std::vector<unsigned char> raw(32, branch);
            raw[0] = static_cast<unsigned char>(h & 0xff);
            raw[1] = static_cast<unsigned char>((h >> 8) & 0xff);
            chain.emplace_back(raw);
        }
    }

    std::optional<int32_t> HeightOf(const uint256& hash) const
    {
        for (size_t i = 0; i < chain.size(); ++i) {
            if (chain[i] == hash) return static_cast<int32_t>(i);
        }
        return std::nullopt;
    }

    bool GetChainTip(MainchainTip& out, std::string&) const override
    {
        out.block_hash = unknown_tip ? *unknown_tip : chain.back();
        out.height = static_cast<int32_t>(chain.size()) - 1;
        if (chain.size() > 1) out.prev_block_hash = chain[chain.size() - 2];
        return true;
    }

    bool GetTwoWayPegData(const std::optional<uint256>& start, const uint256& end,
                          std::vector<BlockInfo>& out, std::string& error) const override
    {
        ++peg_calls;
        if (fail_next_peg > 0) {
            --fail_next_peg;
            error = "connection refused";
            return false;
        }
        const auto end_height{HeightOf(end)};
        if (!end_height) {
            error = "end block not found";
            return false;
        }
        int32_t low{-1};
        if (start) {
            const auto start_height{HeightOf(*start)};
            if (!start_height) {
                error = "start block is not an ancestor";
                return false;
            }
            low = *start_height;
        }
        if (reject_every_peg_fetch || (oversize_peg_span > 0 && *end_height - low > oversize_peg_span)) {
            error = ENFORCER_RESPONSE_TOO_LARGE;
            return false;
        }
        out.clear();
        // Exclusive of start, inclusive of end. Blocks with no events are
        // omitted, exactly as the enforcer's filter_map does.
        for (int32_t h = low + 1; h <= *end_height; ++h) {
            const auto it = deposits.find(h);
            if (it == deposits.end()) continue;
            BlockInfo info;
            info.main_block_hash = chain[h];
            info.main_height = h;
            info.deposits = {it->second};
            out.push_back(info);
        }
        return true;
    }

    bool GetBlockHeaderInfo(const uint256& block_hash, uint32_t max_ancestors,
                            std::vector<MainchainTip>& out, std::string& error) const override
    {
        ++header_calls;
        if (fail_next_header > 0) {
            --fail_next_header;
            error = "connection refused";
            return false;
        }
        const auto height{HeightOf(block_hash)};
        if (!height) return true; // unknown block: empty list, HTTP 200
        out.clear();
        // The enforcer returns max_ancestors + 1 entries, newest first.
        for (int32_t h = *height; h >= 0 && out.size() <= max_ancestors; --h) {
            if (truncate_headers_to > 0 && static_cast<int>(out.size()) >= truncate_headers_to) break;
            MainchainTip header;
            header.block_hash = chain[h];
            header.height = h;
            if (h > 0) header.prev_block_hash = chain[h - 1];
            out.push_back(header);
        }
        if (break_link_at >= 0 && break_link_at < static_cast<int>(out.size())) {
            out[break_link_at].prev_block_hash = uint256{std::vector<unsigned char>(32, 0x7f)};
        }
        return true;
    }

    bool GetBmmHStarCommitment(const uint256&, std::optional<uint256>& commitment,
                               std::string&) const override
    {
        commitment = std::nullopt;
        return true;
    }

    std::optional<Ctip> ctip;
    ChainInfo chain_info{.withdrawal_bundle_max_age = 26'300,
                         .withdrawal_bundle_inclusion_threshold = 13'150};
    mutable std::vector<std::vector<unsigned char>> broadcast_bundles;

    bool GetCtip(std::optional<Ctip>& out, std::string&) const override
    {
        out = ctip;
        return true;
    }

    bool GetChainInfo(ChainInfo& out, std::string&) const override
    {
        out = chain_info;
        return true;
    }

    bool BroadcastWithdrawalBundle(const std::vector<unsigned char>& blinded_m6,
                                   std::string&) const override
    {
        broadcast_bundles.push_back(blinded_m6);
        return true;
    }
};

static MainchainCache MakeCache()
{
    auto fake{std::make_unique<FakeEnforcer>()};
    fake->BuildChain(0, 0x00);
    return MainchainCache{std::move(fake)};
}

static Deposit Dep(uint64_t seq, CAmount value)
{
    Deposit d;
    d.sequence_number = seq;
    d.value = value;
    d.address = Bytes("a");
    return d;
}

BOOST_AUTO_TEST_CASE(poll_first_sync_populates_dense_heights)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(3, 0xaa);
    f->deposits[2] = Dep(1, 100);
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE(cache.Poll(error));
    BOOST_CHECK(cache.IsSynced());
    // Heights resolve for ordinary blocks, not only event-bearing ones.
    BOOST_CHECK(cache.GetHeight(f->chain[1]).has_value());

    std::vector<Deposit> deposits;
    BOOST_CHECK(cache.GetDepositsBetween(std::nullopt, f->chain[3], deposits) == DepositRangeResult::Ok);
    BOOST_CHECK_EQUAL(deposits.size(), 1U);
}

//! An idle poll must not refetch. The fast path was previously unsatisfiable,
//! so every poll rebuilt the entire cache under the lock validation takes.
BOOST_AUTO_TEST_CASE(poll_idle_does_not_refetch)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(3, 0xaa);
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE(cache.Poll(error));
    const int peg_after_first{f->peg_calls};
    const int headers_after_first{f->header_calls};

    BOOST_REQUIRE(cache.Poll(error));
    BOOST_CHECK_EQUAL(f->peg_calls, peg_after_first);
    BOOST_CHECK_EQUAL(f->header_calls, headers_after_first);
}

//! The backward walk must descend. Anchoring each chunk at the tip re-fetches
//! the newest window forever, so history older than one chunk is never
//! resolvable and a fresh node can never validate block 1.
BOOST_AUTO_TEST_CASE(poll_walks_backwards_to_genesis)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(5000, 0xaa);
    f->deposits[10] = Dep(1, 100);
    MainchainCache cache{std::move(fake)};

    std::string error;
    // Far more polls than chunks needed; asserts convergence, not a count.
    bool reached{false};
    for (int i = 0; i < 20 && !reached; ++i) {
        BOOST_REQUIRE(cache.Poll(error));
        std::vector<Deposit> deposits;
        reached = cache.GetDepositsBetween(std::nullopt, f->chain[5000], deposits) == DepositRangeResult::Ok;
    }
    BOOST_CHECK(reached);

    std::vector<Deposit> deposits;
    BOOST_REQUIRE(cache.GetDepositsBetween(std::nullopt, f->chain[5000], deposits) == DepositRangeResult::Ok);
    BOOST_CHECK_EQUAL(deposits.size(), 1U);
}

//! A from-genesis refetch must REPLACE the maps. Merging it into a cache still
//! holding an abandoned branch credits both branches' deposits, and the node
//! then rejects honest blocks and bans the peers serving them.
//! Once the walk is complete, a one-block advance must cost a one-block fetch,
//! not a whole chunk. Re-fetching CHUNK blocks per mainchain block would put the
//! response cap on the steady-state path, where failure is unrecoverable.
BOOST_AUTO_TEST_CASE(poll_steady_state_advance_is_incremental)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(2500, 0xaa);
    MainchainCache cache{std::move(fake)};

    std::string error;
    for (int i = 0; i < 10; ++i) BOOST_REQUIRE(cache.Poll(error));
    BOOST_REQUIRE_EQUAL(cache.HeadersLow(), 0);

    const int peg_before{f->peg_calls};
    const int headers_before{f->header_calls};

    f->BuildChain(2501, 0xaa);
    BOOST_REQUIRE(cache.Poll(error));

    // One forward peg fetch, and no header chunk: the walk is already done.
    BOOST_CHECK_EQUAL(f->peg_calls, peg_before + 1);
    BOOST_CHECK_EQUAL(f->header_calls, headers_before);
}

BOOST_AUTO_TEST_CASE(poll_reorg_replaces_rather_than_merges)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(3, 0xaa);
    f->deposits[2] = Dep(1, 100);
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE(cache.Poll(error));
    const uint256 old_block{f->chain[2]};
    BOOST_CHECK(cache.GetHeight(old_block).has_value());

    // Reorg to a different branch carrying a different deposit.
    f->BuildChain(4, 0xbb);
    f->deposits.clear();
    f->deposits[2] = Dep(2, 200);
    BOOST_REQUIRE(cache.Poll(error));

    BOOST_CHECK(!cache.GetHeight(old_block).has_value());
    std::vector<Deposit> deposits;
    BOOST_REQUIRE(cache.GetDepositsBetween(std::nullopt, f->chain[4], deposits) == DepositRangeResult::Ok);
    BOOST_REQUIRE_EQUAL(deposits.size(), 1U);
    BOOST_CHECK_EQUAL(deposits[0].sequence_number, 2U);
}

//! Same, but with a backfill pending -- the path that skipped the reorg clear.
BOOST_AUTO_TEST_CASE(poll_reorg_with_backfill_pending_still_replaces)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(3, 0xaa);
    f->deposits[2] = Dep(1, 100);
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE(cache.Poll(error));
    const uint256 old_block{f->chain[2]};

    cache.RequestBackfill();

    f->BuildChain(4, 0xbb);
    f->deposits.clear();
    f->deposits[2] = Dep(2, 200);
    BOOST_REQUIRE(cache.Poll(error));

    BOOST_CHECK(!cache.GetHeight(old_block).has_value());
    std::vector<Deposit> deposits;
    BOOST_REQUIRE(cache.GetDepositsBetween(std::nullopt, f->chain[4], deposits) == DepositRangeResult::Ok);
    BOOST_CHECK_EQUAL(deposits.size(), 1U);
}

BOOST_AUTO_TEST_CASE(poll_rejects_empty_header_response)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(3, 0xaa);
    MainchainCache cache{std::move(fake)};
    // Tip the enforcer does not know: 200 with an empty header list.
    f->unknown_tip = uint256{std::vector<unsigned char>(32, 0xee)};

    std::string error;
    BOOST_CHECK(!cache.Poll(error));
    BOOST_CHECK(!cache.IsSynced());
}

//! THE consensus invariant: two honest nodes at different sync depths must
//! never both answer Ok with different deposits. A partially-synced node may
//! say Unavailable, but it may never say Ok and be wrong.
//!
//! This is a property over the whole state machine, so it catches the whole bug
//! class rather than one reorg shape at a time.
//! A fetch failing part-way through a resync must not commit anything. Clearing
//! the maps first left m_headers_low at the "not started" sentinel, which the
//! idle and extend-back predicates then read as "walk complete" -- the cache
//! stopped validating forever while still reporting healthy.
BOOST_AUTO_TEST_CASE(poll_failure_during_resync_does_not_wedge)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(100, 0xaa);
    f->deposits[50] = Dep(1, 500);
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE(cache.Poll(error));
    BOOST_REQUIRE_EQUAL(cache.HeadersLow(), 0);

    // Force a resync (multi-block jump), then fail it mid-flight.
    f->BuildChain(103, 0xaa);
    f->deposits[50] = Dep(1, 500);
    f->fail_next_header = 1;
    BOOST_CHECK(!cache.Poll(error));

    // Recovery must be possible without a restart.
    bool recovered{false};
    for (int i = 0; i < 10 && !recovered; ++i) {
        cache.Poll(error);
        std::vector<Deposit> deposits;
        recovered = cache.GetDepositsBetween(std::nullopt, f->chain[103], deposits) == DepositRangeResult::Ok;
    }
    BOOST_CHECK(recovered);
}

//! A chunk-wide peg fetch can exceed the read cap on deposit-heavy ranges. The
//! retry has to be a smaller request, or the node re-issues the same oversized
//! one every poll and never syncs.
BOOST_AUTO_TEST_CASE(poll_narrows_an_oversized_peg_fetch)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(5000, 0xaa);
    f->deposits[4900] = Dep(1, 100);
    // Well under CHUNK, so the first attempt of every backward walk is refused.
    f->oversize_peg_span = 100;
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE_MESSAGE(cache.Poll(error), error);
    BOOST_CHECK(cache.HeadersLow() < 5000);

    // And it keeps descending rather than stalling at the narrowed span.
    const int32_t low_after_first{cache.HeadersLow()};
    BOOST_REQUIRE_MESSAGE(cache.Poll(error), error);
    BOOST_CHECK_LT(cache.HeadersLow(), low_after_first);

    std::vector<Deposit> probe;
    BOOST_CHECK(cache.GetDepositsBetween(f->chain[4899], f->chain[5000], probe) == DepositRangeResult::Ok);
    BOOST_CHECK_EQUAL(probe.size(), 1U);
}

//! An oversized response that cannot be narrowed any further must fail, not spin.
BOOST_AUTO_TEST_CASE(poll_gives_up_when_narrowing_cannot_help)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(500, 0xaa);
    // Even a single-block span is refused, so no narrowing can succeed.
    f->oversize_peg_span = 0;
    f->reject_every_peg_fetch = true;
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_CHECK(!cache.Poll(error));
    BOOST_CHECK_EQUAL(error, ENFORCER_RESPONSE_TOO_LARGE);
    BOOST_CHECK_EQUAL(cache.HeadersLow(), -1);
}

//! A failed peg fetch must leave coverage exactly as it was.
BOOST_AUTO_TEST_CASE(poll_partial_commit_is_atomic)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    // Longer than CHUNK, so the walk is mid-flight and HeadersLow() is not 0 --
    // a short chain makes the assertion trivially 0 == 0.
    f->BuildChain(5000, 0xaa);
    f->deposits[4900] = Dep(1, 100);
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE(cache.Poll(error));
    const int32_t low_before{cache.HeadersLow()};
    const auto tip_before{cache.GetSyncedTip()};
    BOOST_REQUIRE(low_before > 0);

    // Probe a range inside the covered window; a from-genesis probe is
    // Unavailable on a chain this long and would assert nothing.
    std::vector<Deposit> probe_before;
    const auto probe_result_before{cache.GetDepositsBetween(f->chain[4899], f->chain[5000], probe_before)};
    BOOST_REQUIRE(probe_result_before == DepositRangeResult::Ok);
    BOOST_REQUIRE_EQUAL(probe_before.size(), 1U);

    f->BuildChain(5004, 0xaa);
    f->deposits[4900] = Dep(1, 100);
    f->fail_next_peg = 1;
    BOOST_CHECK(!cache.Poll(error));

    // The entire observable state must be unchanged, not just one field.
    BOOST_CHECK_EQUAL(cache.HeadersLow(), low_before);
    BOOST_CHECK(cache.GetSyncedTip() == tip_before);
    std::vector<Deposit> probe_after;
    BOOST_CHECK(cache.GetDepositsBetween(f->chain[4899], f->chain[5000], probe_after) == probe_result_before);
    BOOST_CHECK_EQUAL(probe_after.size(), probe_before.size());
}

//! A chunk that does not descend would re-issue the identical request forever
//! with nothing surfaced; it must fail loudly instead.
BOOST_AUTO_TEST_CASE(poll_rejects_non_descending_chunk)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(5000, 0xaa);
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_REQUIRE(cache.Poll(error));
    BOOST_REQUIRE(cache.HeadersLow() > 0);

    // Enforcer now returns only the anchor itself: no progress.
    f->truncate_headers_to = 1;
    BOOST_CHECK(!cache.Poll(error));
    BOOST_CHECK(!cache.GetLastError().empty());
}

//! A non-contiguous chunk claims to prove a range it does not.
BOOST_AUTO_TEST_CASE(poll_rejects_non_contiguous_chunk)
{
    auto fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* f{fake.get()};
    f->BuildChain(100, 0xaa);
    f->break_link_at = 2;
    MainchainCache cache{std::move(fake)};

    std::string error;
    BOOST_CHECK(!cache.Poll(error));
    BOOST_CHECK(!cache.IsSynced());
}

BOOST_AUTO_TEST_CASE(poll_partial_sync_never_answers_differently)
{
    auto full_fake{std::make_unique<FakeEnforcer>()};
    auto partial_fake{std::make_unique<FakeEnforcer>()};
    FakeEnforcer* ff{full_fake.get()};
    FakeEnforcer* pf{partial_fake.get()};

    for (FakeEnforcer* f : {ff, pf}) {
        f->BuildChain(5000, 0xaa);
        for (int32_t h = 100; h <= 5000; h += 250) f->deposits[h] = Dep(h, 100 + h);
    }

    MainchainCache full{std::move(full_fake)};
    MainchainCache partial{std::move(partial_fake)};

    std::string error;
    // Fully sync one; give the other only enough polls to be mid-backfill.
    for (int i = 0; i < 20; ++i) BOOST_REQUIRE(full.Poll(error));
    BOOST_REQUIRE(partial.Poll(error));

    // Advance the tip under both, carrying a deposit, mid-backfill for `partial`.
    for (FakeEnforcer* f : {ff, pf}) {
        f->BuildChain(5001, 0xaa);
        for (int32_t h = 100; h <= 5000; h += 250) f->deposits[h] = Dep(h, 100 + h);
        f->deposits[5001] = Dep(9999, 4242);
    }
    BOOST_REQUIRE(full.Poll(error));
    BOOST_REQUIRE(partial.Poll(error));

    int compared{0};
    for (int32_t start_h = 0; start_h <= 5000; start_h += 97) {
        for (int32_t end_h : {start_h + 1, start_h + 500, 5001}) {
            if (end_h > 5001 || end_h <= start_h) continue;

            std::vector<Deposit> a, b;
            const auto ra{full.GetDepositsBetween(ff->chain[start_h], ff->chain[end_h], a)};
            const auto rb{partial.GetDepositsBetween(pf->chain[start_h], pf->chain[end_h], b)};
            if (ra != DepositRangeResult::Ok || rb != DepositRangeResult::Ok) continue;

            ++compared;
            BOOST_REQUIRE_MESSAGE(a.size() == b.size(),
                                  strprintf("range (%d,%d]: full=%d partial=%d",
                                            start_h, end_h, a.size(), b.size()));
            for (size_t i = 0; i < a.size(); ++i) {
                BOOST_CHECK_EQUAL(a[i].sequence_number, b[i].sequence_number);
                BOOST_CHECK_EQUAL(a[i].value, b[i].value);
            }
        }
    }
    BOOST_CHECK_GT(compared, 20);
}

/**
 * A request goes to one stage or the other, never both.
 *
 * Both stages build a transaction that spends it, and a block carrying both is
 * invalid -- which the producer only finds after it builds it, every time.
 */
BOOST_AUTO_TEST_CASE(staging_keeps_one_claim_per_request)
{
    const COutPoint a{Txid::FromUint256(uint256{1}), 0};
    const COutPoint b{Txid::FromUint256(uint256{2}), 0};

    // Whichever comes first, the bundle keeps the request.
    CancelStagedBundle();
    BOOST_CHECK(StageAbort({a}));
    BOOST_CHECK(StageBundle({a}));
    BOOST_CHECK(!StageAbort({a}));
    BOOST_CHECK(StageAbort({b}));

    // Cancel reports whether it dropped anything, and frees the request. That
    // it also gives the abort back is what the functional test proves, because
    // only a block shows where the coins went.
    // A second claim is refused while one waits for a block.
    BOOST_CHECK(!StageBundle({b}));
    BOOST_CHECK(CancelStagedBundle());
    BOOST_CHECK(!CancelStagedBundle());
    BOOST_CHECK(StageAbort({a}));

    // The stages are process-global, so leaving one set would reach the next
    // test in this binary.
    CancelStagedBundle();
    BOOST_CHECK(CancelStagedAbort(a));
    BOOST_CHECK(CancelStagedAbort(b));
}

/**
 * A shorter range can give a different verdict, not merely fewer.
 *
 * The reader keeps the last event per m6id, and the spec lets a failed bundle be
 * proposed again. So the same bundle reads Failed over one range and Paid over a
 * longer one. A failed settlement rebuilds every request; a paid one writes a
 * single OP_RETURN. That is why the producer prices every verdict as Failed
 * before it decides how much of the range the deposits may have.
 */
BOOST_AUTO_TEST_CASE(cache_shorter_range_can_flip_a_verdict)
{
    const uint256 m6id{std::vector<unsigned char>(32, 0xee)};
    const auto with_event{[&](int32_t height, unsigned char tag,
                              WithdrawalBundleEvent::Status status) {
        BlockInfo info{MakeBlockInfo(height, tag, {})};
        info.bundle_events.push_back(WithdrawalBundleEvent{m6id, status});
        return info;
    }};

    MainchainCache cache{MakeCache()};
    cache.SeedForTest(MakeBlockInfo(1, 0x11, {}), false);
    cache.SeedForTest(with_event(2, 0x22, WithdrawalBundleEvent::Status::Failed), false);
    cache.SeedForTest(with_event(3, 0x33, WithdrawalBundleEvent::Status::Succeeded), true);
    cache.SeedCoverageForTest(0, 3);

    const uint256 h1{std::vector<unsigned char>(32, 0x11)};
    const uint256 h2{std::vector<unsigned char>(32, 0x22)};
    const uint256 h3{std::vector<unsigned char>(32, 0x33)};

    std::vector<WithdrawalBundleEvent> wide;
    BOOST_REQUIRE(cache.GetBundleEventsBetween(h1, h3, wide) == DepositRangeResult::Ok);
    std::vector<WithdrawalBundleEvent> narrow;
    BOOST_REQUIRE(cache.GetBundleEventsBetween(h1, h2, narrow) == DepositRangeResult::Ok);

    BOOST_CHECK(CollectVerdicts(wide).at(m6id) == BundleOutcome::Paid);
    BOOST_CHECK(CollectVerdicts(narrow).at(m6id) == BundleOutcome::Failed);

    // A payout is final, whichever order the events arrive in. A re-proposal of
    // a paid m6id can only expire, because the treasury output it spends is
    // gone -- and reading that Failed would hand back coins already paid.
    std::vector<WithdrawalBundleEvent> paid_then_failed{
        {m6id, WithdrawalBundleEvent::Status::Succeeded},
        {m6id, WithdrawalBundleEvent::Status::Failed}};
    BOOST_CHECK(CollectVerdicts(paid_then_failed).at(m6id) == BundleOutcome::Paid);
    std::vector<WithdrawalBundleEvent> failed_then_paid{
        {m6id, WithdrawalBundleEvent::Status::Failed},
        {m6id, WithdrawalBundleEvent::Status::Succeeded}};
    BOOST_CHECK(CollectVerdicts(failed_then_paid).at(m6id) == BundleOutcome::Paid);

    // The same across two mainchain heights, which the sort orders by height.
    MainchainCache across{MakeCache()};
    across.SeedForTest(MakeBlockInfo(1, 0x11, {}), false);
    across.SeedForTest(with_event(2, 0x22, WithdrawalBundleEvent::Status::Succeeded), false);
    across.SeedForTest(with_event(3, 0x33, WithdrawalBundleEvent::Status::Failed), true);
    across.SeedCoverageForTest(0, 3);
    std::vector<WithdrawalBundleEvent> spanning;
    BOOST_REQUIRE(across.GetBundleEventsBetween(h1, h3, spanning) == DepositRangeResult::Ok);
    BOOST_CHECK(CollectVerdicts(spanning).at(m6id) == BundleOutcome::Paid);

    // Both in one mainchain block, where height cannot order them.
    MainchainCache tie{MakeCache()};
    BlockInfo both{MakeBlockInfo(2, 0x22, {})};
    both.bundle_events.push_back(WithdrawalBundleEvent{m6id, WithdrawalBundleEvent::Status::Succeeded});
    both.bundle_events.push_back(WithdrawalBundleEvent{m6id, WithdrawalBundleEvent::Status::Failed});
    tie.SeedForTest(MakeBlockInfo(1, 0x11, {}), false);
    tie.SeedForTest(both, true);
    tie.SeedCoverageForTest(0, 2);

    std::vector<WithdrawalBundleEvent> tied;
    BOOST_REQUIRE(tie.GetBundleEventsBetween(h1, h2, tied) == DepositRangeResult::Ok);
    BOOST_CHECK(CollectVerdicts(tied).at(m6id) == BundleOutcome::Paid);
}

BOOST_AUTO_TEST_CASE(cache_range_is_exclusive_of_start)
{
    MainchainCache cache{MakeCache()};
    cache.SeedForTest(MakeBlockInfo(1, 0x11, {MakeDeposit(1, 100, "a")}), false);
    cache.SeedForTest(MakeBlockInfo(2, 0x22, {MakeDeposit(2, 200, "b")}), false);
    cache.SeedForTest(MakeBlockInfo(3, 0x33, {MakeDeposit(3, 300, "c")}), true);
    cache.SeedCoverageForTest(0, 3);

    const uint256 h1{std::vector<unsigned char>(32, 0x11)};
    const uint256 h3{std::vector<unsigned char>(32, 0x33)};

    std::vector<Deposit> deposits;
    BOOST_REQUIRE(cache.GetDepositsBetween(h1, h3, deposits) == DepositRangeResult::Ok);
    BOOST_REQUIRE_EQUAL(deposits.size(), 2U);
    BOOST_CHECK_EQUAL(deposits[0].sequence_number, 2U);
    BOOST_CHECK_EQUAL(deposits[1].sequence_number, 3U);

    BOOST_REQUIRE(cache.GetDepositsBetween(std::nullopt, h3, deposits) == DepositRangeResult::Ok);
    BOOST_CHECK_EQUAL(deposits.size(), 3U);
}

//! An inverted range must fail loudly. Silently returning nothing would let one
//! block credit no deposits and the next re-credit what its grandparent already
//! did -- unbounded inflation.
BOOST_AUTO_TEST_CASE(cache_rejects_inverted_range)
{
    MainchainCache cache{MakeCache()};
    cache.SeedForTest(MakeBlockInfo(1, 0x11, {MakeDeposit(1, 100, "a")}), false);
    cache.SeedForTest(MakeBlockInfo(5, 0x55, {MakeDeposit(2, 200, "b")}), true);
    cache.SeedCoverageForTest(0, 5);

    const uint256 low{std::vector<unsigned char>(32, 0x11)};
    const uint256 high{std::vector<unsigned char>(32, 0x55)};

    std::vector<Deposit> deposits;
    BOOST_CHECK_EQUAL(static_cast<int>(cache.GetDepositsBetween(high, low, deposits)),
                      static_cast<int>(DepositRangeResult::Invalid));
}

//! A node that started late has heights for its endpoints but never fetched the
//! interior. Answering "no deposits" there would make it require a different
//! coinbase than a fully synced node -- a chain split.
BOOST_AUTO_TEST_CASE(cache_refuses_range_outside_fetched_window)
{
    MainchainCache cache{MakeCache()};
    cache.SeedForTest(MakeBlockInfo(1500, 0x11, {}), false);
    cache.SeedForTest(MakeBlockInfo(2000, 0x22, {MakeDeposit(1, 100, "a")}), true);
    // Only the top of the chain was actually fetched.
    cache.SeedCoverageForTest(1999, 2000);

    const uint256 old_block{std::vector<unsigned char>(32, 0x11)};
    const uint256 tip{std::vector<unsigned char>(32, 0x22)};

    std::vector<Deposit> deposits;
    BOOST_CHECK(cache.GetDepositsBetween(old_block, tip, deposits) != DepositRangeResult::Ok);

    cache.SeedCoverageForTest(0, 2000);
    BOOST_CHECK(cache.GetDepositsBetween(old_block, tip, deposits) == DepositRangeResult::Ok);
}

//! A first poll fetches with no start, which the enforcer walks back to
//! genesis, so coverage legitimately begins at 0. Deriving it from the tip
//! height instead would make block 1 unvalidatable and the chain unsyncable.
BOOST_AUTO_TEST_CASE(cache_first_sync_covers_from_genesis)
{
    MainchainCache cache{MakeCache()};
    cache.SeedForTest(MakeBlockInfo(2000, 0x22, {MakeDeposit(1, 100, "a")}), true);
    cache.SeedCoverageForTest(0, 2000);

    std::vector<Deposit> deposits;
    BOOST_CHECK(cache.GetDepositsBetween(std::nullopt, uint256{std::vector<unsigned char>(32, 0x22)}, deposits) == DepositRangeResult::Ok);
    BOOST_CHECK_EQUAL(deposits.size(), 1U);
}

//! An inverted range is provably invalid, not merely uncached. Conflating the
//! two made it retry forever and refetch the whole chain on each attempt.
BOOST_AUTO_TEST_CASE(cache_distinguishes_invalid_from_unavailable)
{
    MainchainCache cache{MakeCache()};
    cache.SeedForTest(MakeBlockInfo(1, 0x11, {}), false);
    cache.SeedForTest(MakeBlockInfo(5, 0x55, {}), true);
    cache.SeedCoverageForTest(0, 5);

    const uint256 low{std::vector<unsigned char>(32, 0x11)};
    const uint256 high{std::vector<unsigned char>(32, 0x55)};
    const uint256 unknown{std::vector<unsigned char>(32, 0xee)};

    std::vector<Deposit> deposits;
    BOOST_CHECK(cache.GetDepositsBetween(high, low, deposits) == DepositRangeResult::Invalid);
    BOOST_CHECK(cache.GetDepositsBetween(unknown, high, deposits) == DepositRangeResult::Unavailable);
    BOOST_CHECK(cache.GetDepositsBetween(low, high, deposits) == DepositRangeResult::Ok);
}

BOOST_AUTO_TEST_CASE(cache_reports_unknown_blocks)
{
    MainchainCache cache{MakeCache()};
    const uint256 unknown{std::vector<unsigned char>(32, 0xee)};
    std::vector<Deposit> deposits;
    BOOST_CHECK(cache.GetDepositsBetween(std::nullopt, unknown, deposits) != DepositRangeResult::Ok);
    BOOST_CHECK(!cache.GetHeight(unknown).has_value());
    BOOST_CHECK(!cache.IsSynced());
}

BOOST_AUTO_TEST_CASE(cache_deposits_sorted_by_sequence_across_blocks)
{
    MainchainCache cache{MakeCache()};
    cache.SeedForTest(MakeBlockInfo(1, 0x11, {MakeDeposit(9, 100, "a")}), false);
    cache.SeedForTest(MakeBlockInfo(2, 0x22, {MakeDeposit(4, 200, "b")}), true);
    cache.SeedCoverageForTest(0, 2);

    std::vector<Deposit> deposits;
    BOOST_REQUIRE(cache.GetDepositsBetween(std::nullopt, uint256{std::vector<unsigned char>(32, 0x22)}, deposits) == DepositRangeResult::Ok);
    BOOST_REQUIRE_EQUAL(deposits.size(), 2U);
    BOOST_CHECK_EQUAL(deposits[0].sequence_number, 4U);
    BOOST_CHECK_EQUAL(deposits[1].sequence_number, 9U);
}

//! Fake mainchain view, so the consensus function can be tested without a
//! cache or an enforcer.
class FakePegSource final : public PegDataSource
{
public:
    bool synced{true};
    std::map<uint256, int32_t> heights;
    std::optional<int32_t> GetLowestHeight() const override
    {
        std::optional<int32_t> lowest;
        for (const auto& [hash, at] : heights) {
            if (!lowest || at < *lowest) lowest = at;
        }
        return lowest;
    }
    std::optional<uint256> GetHashAtHeight(int32_t height) const override
    {
        for (const auto& [hash, at] : heights) {
            if (at == height) return hash;
        }
        return std::nullopt;
    }
    std::optional<uint256> anchor;
    DepositRangeResult range_result{DepositRangeResult::Ok};
    std::vector<Deposit> range_deposits;
    mutable bool backfill_requested{false};
    //! Recorded so the endpoint selection can be asserted. Ignoring these left
    //! the one expression whose failure mode is unbounded inflation untested.
    mutable std::optional<uint256> asked_start;
    mutable uint256 asked_end;
    mutable bool asked{false};

    uint256 synced_tip;
    bool IsSynced() const override { return synced; }
    std::optional<uint256> GetSyncedTip() const override { return synced_tip; }
    std::optional<int32_t> GetHeight(const uint256& h) const override
    {
        const auto it = heights.find(h);
        if (it == heights.end()) return std::nullopt;
        return it->second;
    }
    std::optional<uint256> FindBmmAnchor(const uint256&) const override { return anchor; }
    //! Deposits by the mainchain height that carried them. Set this instead of
    //! range_deposits when the test cares which range the producer picks.
    std::map<int32_t, std::vector<Deposit>> deposits_by_height;
    DepositRangeResult GetDepositsBetween(const std::optional<uint256>& start, const uint256& end,
                                          std::vector<Deposit>& out) const override
    {
        asked_start = start;
        asked_end = end;
        asked = true;
        if (deposits_by_height.empty()) {
            out = range_deposits;
            return range_result;
        }
        const std::optional<int32_t> low{start ? GetHeight(*start) : std::optional<int32_t>{-1}};
        const std::optional<int32_t> high{GetHeight(end)};
        if (!low || !high) return DepositRangeResult::Unavailable;
        out.clear();
        for (const auto& [height, deposits] : deposits_by_height) {
            if (height <= *low || height > *high) continue;
            out.insert(out.end(), deposits.begin(), deposits.end());
        }
        return range_result;
    }
    DepositRangeResult bundle_result{DepositRangeResult::Ok};
    std::vector<WithdrawalBundleEvent> range_bundle_events;
    DepositRangeResult GetBundleEventsBetween(const std::optional<uint256>&, const uint256&,
                                              std::vector<WithdrawalBundleEvent>& out) const override
    {
        out = range_bundle_events;
        return bundle_result;
    }
    void RequestBackfill() const override { backfill_requested = true; }
};

namespace {
//! These blocks carry no withdrawal transactions, so there is nothing to spend.
const sidechain::SpentOutputsFn NoSpends{[](size_t, std::vector<CTxOut>&) { return false; }};

//! BasicTestingSetup, because SampleAddress needs chain parameters. Without it
//! a case passes only when an earlier case in the same binary sets them up.
struct PegFixture : public BasicTestingSetup {
    FakePegSource source;
    CBlockIndex parent;
    CBlockIndex index;
    uint256 prev_main{uint256::FromHex("11" + std::string(62, '1')).value()};
    uint256 anchor_hash{uint256::FromHex("22" + std::string(62, '2')).value()};

    uint256 parent_prev_main{uint256::FromHex("33" + std::string(62, '3')).value()};
    CBlockIndex grandparent;

    uint256 index_hash{uint256::FromHex("a1" + std::string(62, '1')).value()};
    uint256 parent_hash{uint256::FromHex("a2" + std::string(62, '2')).value()};
    uint256 grandparent_hash{uint256::FromHex("a3" + std::string(62, '3')).value()};

    //! What the parent block left in flight, declared in its coinbase.
    std::vector<LiveBundleRef> parent_live;
    //! Spent outputs by transaction index, as ConnectBlock reads them off the undo.
    std::map<size_t, std::vector<CTxOut>> spends;

    //! Supplies the parent block, so the range start actually comes from the
    //! parent's commitment rather than being skipped as it is at height 1.
    bool ReadParent(CBlock& out, const CBlockIndex& at) const
    {
        // Guards against being handed the block's own index instead of its parent.
        BOOST_CHECK_EQUAL(at.nHeight, 1);
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vout.push_back(BuildBmmCommitmentOutput(parent_prev_main));
        if (!parent_live.empty()) cb.vout.push_back(BuildLiveBundleOutput(parent_live));
        out.vtx.clear();
        out.vtx.push_back(MakeTransactionRef(std::move(cb)));
        return true;
    }

    sidechain::SpentOutputsFn Spends() const
    {
        return [this](size_t index, std::vector<CTxOut>& out) {
            const auto it = spends.find(index);
            if (it == spends.end()) return false;
            out = it->second;
            return true;
        };
    }

    //! A block carrying real transactions, so the loop the peg rules run over
    //! each one is actually entered.
    CBlock BlockWithTxs(const std::vector<LiveBundleRef>& live,
                        const std::vector<CMutableTransaction>& txs)
    {
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vout.push_back(BuildBmmCommitmentOutput(prev_main));
        if (!live.empty()) cb.vout.push_back(BuildLiveBundleOutput(live));
        CBlock block;
        block.vtx.push_back(MakeTransactionRef(std::move(cb)));
        for (const CMutableTransaction& tx : txs) block.vtx.push_back(MakeTransactionRef(tx));
        return block;
    }

    void RuleOn(const uint256& m6id, WithdrawalBundleEvent::Status status)
    {
        WithdrawalBundleEvent event;
        event.m6id = m6id;
        event.status = status;
        source.range_bundle_events.push_back(event);
    }

    PegFixture()
    {
        grandparent.nHeight = 0;
        parent.nHeight = 1;
        parent.pprev = &grandparent;
        index.nHeight = 2;
        index.pprev = &parent;
        // GetBlockHash asserts on this, and the peg records which block a
        // verdict came from.
        index.phashBlock = &index_hash;
        parent.phashBlock = &parent_hash;
        grandparent.phashBlock = &grandparent_hash;
        source.heights[parent_prev_main] = 5;
        source.anchor = anchor_hash;
        source.heights[prev_main] = 10;
        source.heights[anchor_hash] = 11;
        SetPegDataSource(&source);
    }
    ~PegFixture() { SetPegDataSource(nullptr); }

    //! Genesis parent, so no parent block read is attempted.
    static bool NeverRead(CBlock&, const CBlockIndex&) { return false; }

    CBlock BlockWith(const std::vector<CTxOut>& extra, bool with_commitment, const uint256& commitment)
    {
        CMutableTransaction cb;
        cb.vin.resize(1);
        for (const CTxOut& out : extra) cb.vout.push_back(out);
        if (with_commitment) cb.vout.push_back(BuildBmmCommitmentOutput(commitment));
        CBlock block;
        block.vtx.push_back(MakeTransactionRef(std::move(cb)));
        return block;
    }
};
} // namespace

//! A missing commitment is provably bad; an unavailable cache is not. Conflating
//! them would have a node with a lagging enforcer ban itself off the network.
//! The credited range must be (parent's prev_main, this block's prev_main].
//! Using this block's prev_main as both endpoints credits nothing and lets the
//! next block re-credit its grandparent's range; using the anchor credits
//! deposits that did not exist when the block was assembled.
BOOST_FIXTURE_TEST_CASE(peg_rules_credits_range_since_parent, PegFixture)
{
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};

    BOOST_REQUIRE(CheckBlockPegRulesImpl(block, index, read, NoSpends, false, credit, state));
    BOOST_REQUIRE(source.asked);
    BOOST_REQUIRE(source.asked_start.has_value());
    BOOST_CHECK(*source.asked_start == parent_prev_main);
    BOOST_CHECK(source.asked_end == prev_main);
}

//! A block whose parent is genesis has no earlier prev_main, so the range is
//! open at the bottom rather than anchored on a block that does not exist.
BOOST_FIXTURE_TEST_CASE(peg_rules_first_block_has_open_range_start, PegFixture)
{
    index.pprev = &grandparent; // parent is genesis
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;

    BOOST_REQUIRE(CheckBlockPegRulesImpl(block, index, NeverRead, NoSpends, false, credit, state));
    BOOST_REQUIRE(source.asked);
    BOOST_CHECK(!source.asked_start.has_value());
    BOOST_CHECK(source.asked_end == prev_main);
}

//! An unreadable parent must defer, not reject: the block may be fine and the
//! read may succeed later.
BOOST_FIXTURE_TEST_CASE(peg_rules_unreadable_parent_defers, PegFixture)
{
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, NeverRead, NoSpends, false, credit, state));
    BOOST_CHECK(!state.IsInvalid());
}

BOOST_FIXTURE_TEST_CASE(peg_rules_missing_commitment_is_invalid, PegFixture)
{
    CBlock block{BlockWith({CTxOut{0, CScript() << OP_TRUE}}, false, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, NeverRead, NoSpends, false, credit, state));
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-no-bmm");
}

BOOST_FIXTURE_TEST_CASE(peg_rules_unsynced_defers_rather_than_rejects, PegFixture)
{
    source.synced = false;
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, NeverRead, NoSpends, false, credit, state));
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK(state.IsError());
}

//! prev_main after the block that mined this one lets a miner name a range its
//! ancestors already credited, minting the same deposits twice.
BOOST_FIXTURE_TEST_CASE(peg_rules_prevmain_after_anchor_is_invalid, PegFixture)
{
    source.heights[prev_main] = 12; // later than the anchor at 11
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, NoSpends, false, credit, state));
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bmm-prevmain-after-anchor");
}

//! An inverted range is provably invalid. Deferring instead retries forever and
//! refetches history on every attempt.
BOOST_FIXTURE_TEST_CASE(peg_rules_inverted_range_is_invalid, PegFixture)
{
    source.range_result = DepositRangeResult::Invalid;
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, NoSpends, false, credit, state));
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK(!source.backfill_requested);
}

BOOST_FIXTURE_TEST_CASE(peg_rules_uncached_range_defers_and_asks_for_backfill, PegFixture)
{
    source.range_result = DepositRangeResult::Unavailable;
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, NoSpends, false, credit, state));
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK(source.backfill_requested);
}

//! The credited total must reach the caller: ConnectBlock adds it to the reward
//! ceiling, and without it every block crediting a deposit is rejected.
BOOST_FIXTURE_TEST_CASE(peg_rules_reports_deposit_credit, PegFixture)
{
    const std::string addr{SampleAddress()};
    const CScript spk{*DecodeDepositPayload(Bytes(addr))};
    source.range_deposits = {MakeDeposit(1, 1000, addr), MakeDeposit(2, 2000, addr)};

    CBlock block{BlockWith({CTxOut{1000, spk}, CTxOut{2000, spk}}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(CheckBlockPegRulesImpl(block, index, read, NoSpends, false, credit, state));
    BOOST_CHECK_EQUAL(credit, 3000);
}

BOOST_FIXTURE_TEST_CASE(peg_rules_wrong_deposit_amount_is_invalid, PegFixture)
{
    const std::string addr{SampleAddress()};
    const CScript spk{*DecodeDepositPayload(Bytes(addr))};
    source.range_deposits = {MakeDeposit(1, 1000, addr)};

    CBlock block{BlockWith({CTxOut{999, spk}}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, NoSpends, false, credit, state));
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-deposit-amount");
}

//! Every case below carries real transactions. Without them the loop that
//! classifies and validates withdrawal activity never runs, and the rules it
//! enforces are covered by nothing.

BOOST_FIXTURE_TEST_CASE(peg_rules_reject_ambiguous_live_set, PegFixture)
{
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vout.push_back(BuildBmmCommitmentOutput(prev_main));
    // Two live sets are ambiguous, so the coinbase declares nothing readable.
    cb.vout.push_back(BuildLiveBundleOutput({Ref(1)}));
    cb.vout.push_back(BuildLiveBundleOutput({Ref(2)}));
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(cb)));

    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-live-bundles");
}

BOOST_FIXTURE_TEST_CASE(peg_rules_reject_missing_spent_outputs, PegFixture)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    CBlock block{BlockWithTxs({}, {tx})};
    // `spends` deliberately left empty: the undo data is unavailable.

    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "sidechain-spent-outputs-unavailable");
}

//! Spending both in one transaction matches neither branch's rules, so it would
//! otherwise be validated by nothing at all.
BOOST_FIXTURE_TEST_CASE(peg_rules_reject_mixed_spend, PegFixture)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vout.emplace_back(20'000, CScript() << OP_TRUE);
    CBlock block{BlockWithTxs({}, {tx})};
    spends[1] = {requests[0], BuildBundleOutput(M6idOf(requests), RequestSetDigest(RequestsOf(requests)), 10'000)};

    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-peg-mixed-spend");
}

//! A block author picks the transactions, and a request output carries no
//! signature. The block rule is the only thing that keeps it its owner's.
BOOST_FIXTURE_TEST_CASE(peg_rules_reject_bad_abort, PegFixture)
{
    const std::vector<CTxOut> requests{RequestOut(1), RequestOut(2)};
    const std::vector<WithdrawalRequest> parsed{RequestsOf(requests)};

    CMutableTransaction tx;
    tx.vin.resize(2);
    for (const WithdrawalRequest& r : parsed) tx.vout.emplace_back(r.amount, r.owner);
    // Paid to the author instead of the second owner.
    tx.vout[1].scriptPubKey = CScript() << OP_TRUE;

    CBlock block{BlockWithTxs({}, {tx})};
    spends[1] = requests;

    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-abort-payout");

    // The same block with every owner paid is valid, so the rule refuses the
    // theft and nothing else.
    CMutableTransaction honest{tx};
    honest.vout[1].scriptPubKey = parsed[1].owner;
    CBlock good{BlockWithTxs({}, {honest})};
    BlockValidationState ok;
    BOOST_CHECK(CheckBlockPegRulesImpl(good, index, read, Spends(), false, credit, ok));
}

/**
 * A block may not open a bundle its own range already ruled on.
 *
 * A verdict is visible over exactly one block's range. Opening such a bundle
 * consumes that verdict unseen, and no later block can act on it, so the bundle
 * stays live forever. Anyone can propose an m6id on the mainchain first: the
 * pending requests and the selection order are both public.
 */
BOOST_FIXTURE_TEST_CASE(peg_rules_reject_opening_a_ruled_bundle, PegFixture)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    const uint256 m6id{M6idOf(requests)};
    CMutableTransaction tx{SweepInto(requests, 10'000, m6id)};

    // The coinbase declares what the block leaves in flight, which an opened
    // bundle is.
    const std::vector<LiveBundleRef> live{{COutPoint{Txid::FromUint256(tx.GetHash()), 0}, m6id}};
    CBlock block{BlockWithTxs(live, {tx})};
    spends[1] = requests;
    // The mainchain ruled on this m6id over this block's own range, and the
    // parent never held it.
    source.range_bundle_events = {WithdrawalBundleEvent{m6id, WithdrawalBundleEvent::Status::Failed}};

    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bundle-ruled");

    // With no verdict in range the same block is fine, so the rule refuses the
    // stranded case and nothing else.
    source.range_bundle_events.clear();
    BlockValidationState ok;
    BOOST_CHECK_MESSAGE(CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, ok),
                        ok.ToString());
}

/**
 * What a block leaves the deposits, after the reserve it holds for the peg.
 *
 * One number, and it does not move with what the peg turns out to cost. The
 * peg has a reserve that covers it at its hard caps, so the two never compete
 * for a byte and a block never has to choose between them.
 */
BOOST_AUTO_TEST_CASE(deposit_budget_comes_after_the_peg_reserve)
{
    // A default block: the deposits reach their own cap with room to spare.
    BOOST_CHECK_EQUAL(ComputeDepositBudget(MAX_BLOCK_WEIGHT, 8'000), MAX_BLOCK_WEIGHT / 2);

    // A smaller one: what is left after the reserve and the coinbase outputs.
    const size_t small{ComputeDepositBudget(200'000, 8'000)};
    BOOST_CHECK(small > 0);
    BOOST_CHECK(small < MAX_BLOCK_WEIGHT / 2);
    BOOST_CHECK(small < 200'000 - 8'000 - PEG_RESERVE_WEIGHT + 1);

    // A block that cannot hold the reserve leaves the deposits nothing, and
    // says so by the number rather than by a guess.
    BOOST_CHECK_EQUAL(ComputeDepositBudget(8'000 + PEG_RESERVE_WEIGHT, 8'000), 0U);
    BOOST_CHECK_EQUAL(ComputeDepositBudget(8'000, 8'000), 0U);

    // The reserve covers the peg at its caps. Measured on the three worst
    // transactions, not on the constant's own formula, so a change to any cap
    // it depends on fails here.
    std::vector<WithdrawalRequest> full;
    std::vector<COutPoint> outpoints;
    for (size_t i{0}; i < MAX_BUNDLE_WITHDRAWALS; ++i) {
        WithdrawalRequest r;
        r.amount = 100'000;
        r.mainchain_fee = 1'000;
        const std::vector<unsigned char> filler(MAX_PEG_SCRIPT_SIZE, 0x51);
        r.dest = CScript(filler.begin(), filler.end());
        r.owner = CScript(filler.begin(), filler.end());
        full.push_back(r);
        outpoints.emplace_back(Txid::FromUint256(uint256{static_cast<uint8_t>(i + 1)}), 0);
    }

    // A failed settlement rebuilds every request it swept.
    CMutableTransaction settlement;
    settlement.vin.emplace_back(outpoints.front());
    for (const WithdrawalRequest& r : full) settlement.vout.push_back(BuildWithdrawalRequestOutput(r));

    // A bundle sweeps them all into one output.
    CMutableTransaction bundle;
    for (const COutPoint& outpoint : outpoints) bundle.vin.emplace_back(outpoint);
    bundle.vout.push_back(BuildBundleOutput(uint256{}, uint256{}, 6'400'000));

    const size_t worst{static_cast<size_t>(GetTransactionWeight(CTransaction{settlement})) +
                       static_cast<size_t>(GetTransactionWeight(
                           CTransaction{BuildAbortTransaction(outpoints, full)})) +
                       static_cast<size_t>(GetTransactionWeight(CTransaction{bundle}))};
    BOOST_CHECK_MESSAGE(worst <= PEG_RESERVE_WEIGHT,
                        strprintf("the peg can weigh %u, above the %u a block holds back", worst,
                                  PEG_RESERVE_WEIGHT));
}

/**
 * The one test both the validator and the producer ask.
 *
 * Two copies of it drifted apart once: consensus refused a block the producer
 * still built, and the producer then failed its own validation on every later
 * template.
 */
BOOST_AUTO_TEST_CASE(bundle_already_ruled_covers_both_sides)
{
    const uint256 m6id{std::vector<unsigned char>(32, 0xab)};
    const uint256 other{std::vector<unsigned char>(32, 0xcd)};
    const std::map<uint256, BundleOutcome> ruled{{m6id, BundleOutcome::Failed}};
    const std::vector<LiveBundleRef> held{{COutPoint{Txid::FromUint256(uint256{7}), 0}, m6id}};

    // Ruled over this range, and the parent never held it: opening it strands
    // the verdict.
    BOOST_CHECK(BundleAlreadyRuled(m6id, ruled, {}));
    // The parent held it, so this block settles it. That is legal.
    BOOST_CHECK(!BundleAlreadyRuled(m6id, ruled, held));
    // No verdict over this range at all.
    BOOST_CHECK(!BundleAlreadyRuled(other, ruled, {}));
    BOOST_CHECK(!BundleAlreadyRuled(m6id, {}, {}));
}

/**
 * A payout for a bundle this chain never opened is reported, not hidden.
 *
 * The treasury hands out coins and nothing here destroys them, so the peg holds
 * less than it owes. Consensus cannot undo a mainchain payout, and refusing the
 * block would let anyone with mainchain vote power stop the sidechain -- so the
 * block connects and the node says what it costs.
 */
BOOST_FIXTURE_TEST_CASE(peg_reports_a_payout_it_never_opened, PegFixture)
{
    const uint256 stranger{uint256::FromHex("dd" + std::string(62, 'd')).value()};
    source.range_bundle_events = {
        WithdrawalBundleEvent{stranger, WithdrawalBundleEvent::Status::Succeeded}};

    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};

    // The block is valid. Nothing here can settle a bundle this chain never
    // opened, so refusing it would stop the chain over a fact outside it.
    BOOST_REQUIRE_MESSAGE(
        CheckBlockPegRulesImpl(block, index, read, NoSpends, /*template_only=*/false, credit, state),
        state.ToString());

    const auto on_chain{[](const uint256&) { return true; }};
    const auto off_chain{[](const uint256&) { return false; }};
    const std::map<uint256, size_t> reported{GetOrphanedPayouts(on_chain)};
    BOOST_REQUIRE(reported.count(stranger) == 1);
    BOOST_CHECK_EQUAL(reported.at(stranger), 1U);

    // A losing branch says nothing about what this chain holds.
    BOOST_CHECK(GetOrphanedPayouts(off_chain).count(stranger) == 0);

    // A template is a candidate, not a block, so it records nothing. Every call
    // names a new candidate hash, which would grow the report per poll.
    const uint256 candidate{uint256::FromHex("ee" + std::string(62, 'e')).value()};
    index.phashBlock = &candidate;
    source.range_bundle_events = {
        WithdrawalBundleEvent{stranger, WithdrawalBundleEvent::Status::Succeeded}};
    BlockValidationState again;
    BOOST_REQUIRE(CheckBlockPegRulesImpl(block, index, read, NoSpends, /*template_only=*/true,
                                         credit, again));
    index.phashBlock = &index_hash;
    BOOST_CHECK_EQUAL(GetOrphanedPayouts(on_chain).at(stranger), 1U);
}

//! Settling before the mainchain has ruled either destroys coins it has not paid
//! for, or hands back coins it has.
BOOST_FIXTURE_TEST_CASE(peg_rules_reject_undecided_settlement, PegFixture)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    const CTxOut bundle{BuildBundleOutput(M6idOf(requests), RequestSetDigest(RequestsOf(requests)), 10'000)};

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout = requests;
    CBlock block{BlockWithTxs({}, {tx})};
    spends[1] = {bundle};
    // No verdict published for this m6id.

    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-settlement-undecided");
}

//! Concurrent bundles would race for the same treasury on the mainchain, and
//! only one of them could ever be paid.
BOOST_FIXTURE_TEST_CASE(peg_rules_reject_two_bundles_in_a_block, PegFixture)
{
    const std::vector<CTxOut> first{RequestOut(1)};
    const std::vector<CTxOut> second{RequestOut(2)};
    CMutableTransaction a{SweepInto(first, 10'000, M6idOf(first))};
    CMutableTransaction b{SweepInto(second, 10'000, M6idOf(second))};
    CBlock block{BlockWithTxs({}, {a, b})};
    spends[1] = first;
    spends[2] = second;

    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-bundle-multiple");
}

//! `owed` is derived here, not handed in: a block must settle every bundle its
//! parent left in flight that the mainchain has since ruled on. Deriving it from
//! the block's own set instead of the parent's would silently make settlement
//! optional and strand every peg-out.
BOOST_FIXTURE_TEST_CASE(peg_rules_require_settling_a_ruled_bundle, PegFixture)
{
    const std::vector<CTxOut> requests{RequestOut(1)};
    const uint256 m6id{M6idOf(requests)};
    const CTxOut bundle{BuildBundleOutput(m6id, RequestSetDigest(RequestsOf(requests)), 10'000)};
    const COutPoint bundle_point{Point(7)};

    parent_live = {LiveBundleRef{bundle_point, m6id}};
    RuleOn(m6id, WithdrawalBundleEvent::Status::Failed);

    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};

    // Carrying the bundle forward untouched, as if nothing had been decided.
    {
        CBlock block{BlockWithTxs(parent_live, {})};
        CAmount credit{0};
        BlockValidationState state;
        BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-live-bundles-unsettled");
    }

    // Settling it, and dropping it from the live set, is what the rule demands.
    {
        CMutableTransaction settlement;
        settlement.vin.resize(1);
        settlement.vin[0].prevout = bundle_point;
        settlement.vout = requests;
        CBlock block{BlockWithTxs({}, {settlement})};
        spends[1] = {bundle};

        CAmount credit{0};
        BlockValidationState state;
        BOOST_CHECK_MESSAGE(CheckBlockPegRulesImpl(block, index, read, Spends(), false, credit, state),
                            state.GetRejectReason());
    }
}

//! Template assembly happens before BMM by definition, so the anchor check must
//! be skipped there or no block could ever be produced.
BOOST_FIXTURE_TEST_CASE(peg_rules_template_skips_bmm_check, PegFixture)
{
    source.anchor = std::nullopt;
    CBlock block{BlockWith({}, true, prev_main)};
    CAmount credit{0};
    BlockValidationState state;
    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    BOOST_CHECK(CheckBlockPegRulesImpl(block, index, read, NoSpends, /*template_only=*/true, credit, state));

    BlockValidationState mined;
    BOOST_CHECK(!CheckBlockPegRulesImpl(block, index, read, NoSpends, /*template_only=*/false, credit, mined));
    BOOST_CHECK(!mined.IsInvalid());
}

//! The miner and the validator must derive the credited range identically. They
//! hold different indexes -- the validator has the block being connected, the
//! miner already has its parent -- so a shared helper that walks ->pprev itself
//! reads the grandparent from one of them, and the node rejects blocks it made.
BOOST_FIXTURE_TEST_CASE(miner_and_validator_agree_on_range, PegFixture)
{
    const std::string addr{SampleAddress()};
    source.range_deposits = {MakeDeposit(1, 1000, addr), MakeDeposit(2, 2000, addr)};
    source.synced_tip = prev_main;

    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};

    // Miner: prev_index is the parent of the block being assembled.
    std::vector<CTxOut> deposit_outputs;
    CTxOut commitment;
    std::string error;
    CoinbasePeg peg;
    BOOST_REQUIRE_MESSAGE(BuildCoinbasePegOutputs(&parent, read, source.synced_tip, ComputeDepositBudget(MAX_BLOCK_WEIGHT, 8'000), peg, error), error);
    deposit_outputs = peg.deposits;
    commitment = peg.bmm_commitment;

    const auto miner_start{source.asked_start};
    const auto miner_end{source.asked_end};

    // Validator: index is the block itself, whose pprev is that same parent.
    source.asked = false;
    CMutableTransaction cb;
    cb.vin.resize(1);
    for (const CTxOut& out : deposit_outputs) cb.vout.push_back(out);
    cb.vout.push_back(commitment);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(cb)));

    CAmount credit{0};
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(CheckBlockPegRulesImpl(block, index, read, NoSpends, false, credit, state),
                          state.ToString());

    // Same range, and the coinbase the miner built satisfies the validator.
    BOOST_REQUIRE(source.asked);
    BOOST_CHECK(source.asked_start == miner_start);
    BOOST_CHECK(source.asked_end == miner_end);
    BOOST_REQUIRE(miner_start.has_value());
    BOOST_CHECK(*miner_start == parent_prev_main);
    BOOST_CHECK_EQUAL(credit, 3000);
}

//! Deposits that fill one mainchain block. A deposit costs about 136 weight in
//! the coinbase, and the budget is half a block. One block of these fits, and
//! two do not.
constexpr size_t DEPOSITS_PER_MAIN_BLOCK{MAX_BLOCK_WEIGHT / 500};

//! Deposits that no coinbase can hold, whatever the block weight is.
constexpr size_t DEPOSITS_PAST_ANY_BLOCK{MAX_BLOCK_WEIGHT / 200};

/**
 * A backlog drains over several blocks instead of halting the chain.
 *
 * A block credits every deposit in its range, so a range that carries more than
 * a coinbase can hold is a block nobody can build. The range comes from the
 * chain, not from memory, so that state does not clear on restart. The producer
 * ends the range earlier and takes the rest next block.
 */
BOOST_FIXTURE_TEST_CASE(deposit_backlog_drains_over_blocks, PegFixture)
{
    const std::string addr{SampleAddress()};
    // Three mainchain blocks, each holding more than half a block of deposits.
    const uint256 first{uint256::FromHex("44" + std::string(62, '4')).value()};
    const uint256 second{uint256::FromHex("55" + std::string(62, '5')).value()};
    // Contiguous, and above the fixture's own anchor at 11, so no two hashes
    // share a height and the cache has no gap.
    source.heights[parent_prev_main] = 12;
    source.heights[first] = 13;
    source.heights[second] = 14;
    source.heights[prev_main] = 15;
    source.synced_tip = prev_main;

    uint64_t sequence{0};
    for (const int32_t height : {13, 14, 15}) {
        std::vector<Deposit> deposits;
        for (size_t i{0}; i < DEPOSITS_PER_MAIN_BLOCK; ++i) deposits.push_back(MakeDeposit(++sequence, 1000, addr));
        source.deposits_by_height[height] = std::move(deposits);
    }

    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    CoinbasePeg peg;
    std::string error;
    BOOST_REQUIRE_MESSAGE(BuildCoinbasePegOutputs(&parent, read, source.synced_tip, ComputeDepositBudget(MAX_BLOCK_WEIGHT, 8'000), peg, error), error);

    // It stopped short of the tip, and what it took fits.
    BOOST_CHECK(peg.prev_main != prev_main);
    BOOST_CHECK(peg.prev_main == first);
    size_t weight{0};
    for (const CTxOut& out : peg.deposits) weight += WITNESS_SCALE_FACTOR * GetSerializeSize(out);
    BOOST_CHECK(weight <= MAX_BLOCK_WEIGHT / 2);
    BOOST_CHECK_EQUAL(peg.deposits.size(), DEPOSITS_PER_MAIN_BLOCK);

    // The first sidechain block has no parent anchor, so its range starts at
    // the lowest block the cache reaches. That is the largest backlog there is,
    // so it is the one case the cut may not skip.
    CoinbasePeg first_block;
    BOOST_REQUIRE_MESSAGE(
        BuildCoinbasePegOutputs(&grandparent, read, source.synced_tip, ComputeDepositBudget(MAX_BLOCK_WEIGHT, 8'000), first_block, error), error);
    BOOST_CHECK(first_block.prev_main == first);
    BOOST_CHECK_EQUAL(first_block.deposits.size(), DEPOSITS_PER_MAIN_BLOCK);

    // A budget too small for the next mainchain block leaves the range nowhere
    // to go. The producer says so and makes no block. A wait would never end:
    // the budget does not move with what the peg costs, so the next block
    // computes the same thing.
    CoinbasePeg tight;
    BOOST_CHECK(!BuildCoinbasePegOutputs(&parent, read, source.synced_tip,
                                         ComputeDepositBudget(200'000, 8'000), tight, error));
    BOOST_CHECK(error.find("raise -blockmaxweight") != std::string::npos);


    // The next block starts where this one stopped, so the rest is not lost.
    // Last, because it moves the parent's anchor forward for every later read.
    parent_prev_main = peg.prev_main;
    CoinbasePeg later;
    BOOST_REQUIRE_MESSAGE(BuildCoinbasePegOutputs(&parent, read, source.synced_tip, ComputeDepositBudget(MAX_BLOCK_WEIGHT, 8'000), later, error), error);
    BOOST_CHECK(later.prev_main == second);
    BOOST_CHECK_EQUAL(later.deposits.size(), DEPOSITS_PER_MAIN_BLOCK);
}

/**
 * One mainchain block that fits in no coinbase stops the range for good.
 *
 * A block credits its whole range or none of it, so a mainchain block whose
 * deposits outgrow what any coinbase may spend leaves the range nowhere to go.
 * The producer says so and makes no block. Holding the anchor instead would
 * stall both directions of the peg without a word.
 */
BOOST_FIXTURE_TEST_CASE(deposits_that_fit_no_block_are_reported, PegFixture)
{
    const std::string addr{SampleAddress()};
    source.heights[parent_prev_main] = 12;
    source.heights[prev_main] = 13;
    source.synced_tip = prev_main;

    std::vector<Deposit> huge;
    for (size_t i{0}; i < DEPOSITS_PAST_ANY_BLOCK; ++i) huge.push_back(MakeDeposit(i + 1, 1000, addr));
    source.deposits_by_height[13] = std::move(huge);

    const auto read{[this](CBlock& out, const CBlockIndex& at) { return ReadParent(out, at); }};
    CoinbasePeg peg;
    std::string error;
    BOOST_CHECK(!BuildCoinbasePegOutputs(&parent, read, source.synced_tip, ComputeDepositBudget(MAX_BLOCK_WEIGHT, 8'000), peg, error));
    BOOST_CHECK(error.find("the range cannot move") != std::string::npos);
}

//! Every reason, both directions. The import path defers on these and aborts on
//! everything else, so a reason moving between the two sets is a silent change
//! from "node stalls and retries" to "node dies", or worse the reverse.
BOOST_AUTO_TEST_CASE(deferrable_reasons_are_exactly_the_transient_ones)
{
    BOOST_CHECK(IsDeferrableSidechainReason("sidechain-enforcer-unavailable"));
    BOOST_CHECK(IsDeferrableSidechainReason("sidechain-bmm-not-found"));
    BOOST_CHECK(IsDeferrableSidechainReason("sidechain-height-uncached"));
    BOOST_CHECK(IsDeferrableSidechainReason("sidechain-prevmain-uncached"));

    // Corruption or a pruned parent: waiting cannot fix either.
    BOOST_CHECK(!IsDeferrableSidechainReason("sidechain-parent-unreadable"));
    // The peg check was never registered -- a programming error, not a wait.
    BOOST_CHECK(!IsDeferrableSidechainReason("sidechain-peg-unavailable"));

    // The reason carries a suffix, so prefix matching would wrongly defer it.
    BOOST_CHECK(!IsDeferrableSidechainReason("sidechain-parent-unreadable: cannot read parent block"));

    // Consensus failures and anything unrecognised must abort.
    BOOST_CHECK(!IsDeferrableSidechainReason("bad-cb-no-bmm"));
    BOOST_CHECK(!IsDeferrableSidechainReason("sidechain-something-new"));
    BOOST_CHECK(!IsDeferrableSidechainReason(""));
}

BOOST_AUTO_TEST_SUITE_END()
