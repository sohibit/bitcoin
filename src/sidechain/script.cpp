// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/script.h>

#include <atomic>

namespace sidechain {
namespace {
//! Policy reads this for every output of every transaction, so it stays atomic.
std::atomic<bool> g_sidechain_policy{false};
} // namespace

void SetSidechainScriptPolicy(bool enabled) { g_sidechain_policy.store(enabled, std::memory_order_release); }

bool SidechainScriptPolicy() { return g_sidechain_policy.load(std::memory_order_acquire); }

bool IsDrivechainTreasury(const CScript& script, uint8_t& slot_out)
{
    if (script.size() != TREASURY_SCRIPT_SIZE) return false;
    if (script[0] != OP_DRIVECHAIN) return false;
    if (script[1] != 0x01) return false;
    if (script[3] != OP_TRUE) return false;
    slot_out = script[2];
    return true;
}

bool IsDrivechainTreasury(const CScript& script)
{
    uint8_t slot;
    return IsDrivechainTreasury(script, slot);
}

bool IsBundleScript(const CScript& script, uint256& m6id_out, uint256& requests_out)
{
    CScript::const_iterator it{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> payload;

    if (!script.GetOp(it, opcode, payload)) return false;
    if (payload.size() != 1 + 2 * uint256::size()) return false;
    if (payload[0] != BUNDLE_MARKER_V0) return false;
    if (!script.GetOp(it, opcode) || opcode != OP_DROP) return false;
    if (!script.GetOp(it, opcode) || opcode != OP_TRUE) return false;
    if (it != script.end()) return false;

    const std::span<const unsigned char> body{payload};
    m6id_out = uint256{body.subspan(1, uint256::size())};
    requests_out = uint256{body.subspan(1 + uint256::size(), uint256::size())};
    return true;
}

bool IsBundleScript(const CScript& script)
{
    uint256 m6id;
    uint256 requests;
    return IsBundleScript(script, m6id, requests);
}

bool IsWithdrawalRequestScript(const CScript& script)
{
    CScript::const_iterator it{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> payload;

    if (!script.GetOp(it, opcode, payload)) return false;
    if (payload.empty() || payload.size() > MAX_WITHDRAWAL_PAYLOAD_SIZE) return false;
    if (payload[0] != WITHDRAWAL_MARKER_V0) return false;
    if (!script.GetOp(it, opcode) || opcode != OP_DROP) return false;
    if (!script.GetOp(it, opcode) || opcode != OP_TRUE) return false;
    return it == script.end();
}

} // namespace sidechain

