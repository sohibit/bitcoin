// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/bundle.h>

#include <consensus/amount.h>
#include <streams.h>

namespace sidechain {

std::optional<CMutableTransaction> BuildBlindedM6(const std::vector<Withdrawal>& withdrawals)
{
    CAmount fee_total{0};
    CAmount amount_total{0};
    for (const Withdrawal& w : withdrawals) {
        if (!MoneyRange(w.mainchain_fee) || !MoneyRange(w.amount)) return std::nullopt;
        fee_total += w.mainchain_fee;
        amount_total += w.amount;
        if (!MoneyRange(fee_total) || !MoneyRange(amount_total)) return std::nullopt;
    }

    // F_total as a 64-bit big-endian push, replacing the treasury output.
    std::vector<unsigned char> fee_be(8);
    for (int i = 0; i < 8; ++i) {
        fee_be[i] = static_cast<unsigned char>((static_cast<uint64_t>(fee_total) >> (8 * (7 - i))) & 0xff);
    }

    CMutableTransaction m6;
    m6.vin.clear();
    m6.vout.emplace_back(CAmount{0}, CScript() << OP_RETURN << fee_be);
    for (const Withdrawal& w : withdrawals) {
        m6.vout.emplace_back(w.amount, w.dest);
    }
    return m6;
}

std::optional<uint256> ComputeM6id(const std::vector<Withdrawal>& withdrawals)
{
    const std::optional<CMutableTransaction> m6{BuildBlindedM6(withdrawals)};
    if (!m6) return std::nullopt;
    return CTransaction{*m6}.GetHash();
}

std::vector<unsigned char> SerializeBlindedM6(const CMutableTransaction& tx)
{
    DataStream stream;
    stream << TX_NO_WITNESS(tx);
    return std::vector<unsigned char>{UCharCast(stream.data()), UCharCast(stream.data() + stream.size())};
}

} // namespace sidechain
