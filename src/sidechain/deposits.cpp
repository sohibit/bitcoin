// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/deposits.h>

#include <crypto/sha256.h>
#include <key_io.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdlib>

namespace sidechain {
namespace {

//! Checksum covers the prefix including its trailing underscore.
std::string Sha256Prefix3Hex(const std::string& input)
{
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(input.data()), input.size()).Finalize(hash);
    return HexStr(std::span<const unsigned char>{hash, 3});
}

bool ParseSlotPrefix(const std::string& part, uint8_t& slot)
{
    if (part.size() < 2 || part[0] != 's') return false;
    uint16_t parsed{0};
    if (!ParseUInt16(part.substr(1), &parsed)) return false;
    if (parsed > 255) return false;
    slot = static_cast<uint8_t>(parsed);
    return true;
}

} // namespace

std::string DepositAddressChecksum(uint8_t slot, const std::string& address)
{
    return Sha256Prefix3Hex(strprintf("s%d_%s_", int{slot}, address));
}

std::string EncodeDepositAddress(uint8_t slot, const std::string& address)
{
    return strprintf("s%d_%s_%s", int{slot}, address, DepositAddressChecksum(slot, address));
}

std::optional<CScript> DecodeDepositPayload(const std::vector<unsigned char>& payload)
{
    if (payload.empty()) return std::nullopt;
    if (payload.size() > MAX_DEPOSIT_PAYLOAD_SIZE) return std::nullopt;
    const std::string text{payload.begin(), payload.end()};

    std::vector<std::string> parts;
    size_t start{0};
    while (true) {
        const size_t sep{text.find('_', start)};
        if (sep == std::string::npos) {
            parts.push_back(text.substr(start));
            break;
        }
        parts.push_back(text.substr(start, sep - start));
        if (parts.size() > 3) return std::nullopt;
        start = sep + 1;
    }

    std::string address;
    switch (parts.size()) {
    case 1:
        address = parts[0];
        break;
    case 2: {
        uint8_t slot{0};
        if (!ParseSlotPrefix(parts[0], slot)) return std::nullopt;
        address = parts[1];
        break;
    }
    case 3: {
        uint8_t slot{0};
        if (!ParseSlotPrefix(parts[0], slot)) return std::nullopt;
        address = parts[1];
        if (parts[2] != DepositAddressChecksum(slot, address)) return std::nullopt;
        break;
    }
    default:
        return std::nullopt;
    }

    if (address.empty()) return std::nullopt;
    const CTxDestination dest{DecodeDestination(address)};
    if (!IsValidDestination(dest)) return std::nullopt;
    return GetScriptForDestination(dest);
}

CScript UndecodableDepositScript() { return CScript() << OP_RETURN; }

CAmount DepositFee(CAmount value)
{
    if (value <= 0) return 0;
    return std::min<CAmount>(value / DEPOSIT_FEE_DIVISOR, MAX_DEPOSIT_FEE);
}

CScript DepositFeeScript()
{
    // The development fund: a 2-of-3 P2WSH at
    // bc1q0lr5zfexu2wghjhlfyh7f0448fcgtw06tnd0pt27yutm239eq4ls8ne40h
    static const std::vector<unsigned char> hash{
        ParseHex("7fc7412726e29c8bcaff492fe4beb53a7085b9fa5cdaf0ad5e2717b544b9057f")};
    return CScript() << OP_0 << hash;
}

std::vector<Deposit> SortDeposits(std::vector<Deposit> deposits)
{
    std::sort(deposits.begin(), deposits.end(), [](const Deposit& a, const Deposit& b) {
        if (a.sequence_number != b.sequence_number) return a.sequence_number < b.sequence_number;
        if (a.outpoint.hash != b.outpoint.hash) return a.outpoint.hash < b.outpoint.hash;
        return a.outpoint.n < b.outpoint.n;
    });
    return deposits;
}

bool CheckCoinbaseDeposits(const CTransaction& coinbase,
                           const std::vector<Deposit>& deposits,
                           CAmount& credited,
                           std::string& reason)
{
    credited = 0;
    const std::vector<Deposit> sorted{SortDeposits(deposits)};

    if (coinbase.vout.size() < sorted.size()) {
        reason = "bad-cb-missing-deposit";
        return false;
    }

    CAmount fee_total{0};
    CAmount paid{0};
    for (size_t i = 0; i < sorted.size(); ++i) {
        const std::optional<CScript> script{DecodeDepositPayload(sorted[i].address)};
        if (!script) {
            // A payload we cannot decode still has real mainchain coins behind
            // it, so it is credited to an unspendable output rather than
            // silently dropped. Deterministic either way; this keeps the
            // coinbase value equation identical on every node.
            // Pinned exactly: accepting any unspendable script would let a
            // miner stuff arbitrary bytes into a consensus-mandated output.
            if (coinbase.vout[i].scriptPubKey != UndecodableDepositScript()) {
                reason = "bad-cb-deposit-script";
                return false;
            }
        } else if (coinbase.vout[i].scriptPubKey != *script) {
            reason = "bad-cb-deposit-script";
            return false;
        }

        if (!MoneyRange(sorted[i].value) || !MoneyRange(credited + sorted[i].value)) {
            reason = "bad-cb-deposit-amount";
            return false;
        }
        const CAmount fee{DepositFee(sorted[i].value)};
        if (coinbase.vout[i].nValue != sorted[i].value - fee) {
            reason = "bad-cb-deposit-amount";
            return false;
        }
        credited += sorted[i].value;
        fee_total += fee;
        paid += coinbase.vout[i].nValue;
    }

    // The fee output follows the deposits. Without this check the value
    // equation alone would let a miner drop it and take the difference.
    if (fee_total > 0) {
        if (coinbase.vout.size() <= sorted.size()) {
            reason = "bad-cb-missing-fee";
            return false;
        }
        const CTxOut& fee_out{coinbase.vout[sorted.size()]};
        if (fee_out.scriptPubKey != DepositFeeScript()) {
            reason = "bad-cb-fee-script";
            return false;
        }
        if (fee_out.nValue != fee_total) {
            reason = "bad-cb-fee-amount";
            return false;
        }
        paid += fee_out.nValue;
    }

    // What the block mints for deposits is exactly what these outputs pay.
    if (paid != credited) {
        reason = "bad-cb-deposit-total";
        return false;
    }
    return true;
}

} // namespace sidechain
