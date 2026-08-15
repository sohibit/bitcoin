// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/bmm.h>


namespace sidechain {

CTxOut BuildBmmCommitmentOutput(const uint256& prev_main_hash)
{
    std::vector<unsigned char> payload;
    payload.reserve(1 + 32);
    payload.push_back(BMM_MARKER_V0);
    payload.insert(payload.end(), prev_main_hash.begin(), prev_main_hash.end());
    return CTxOut{CAmount{0}, CScript() << OP_RETURN << payload};
}

std::optional<uint256> GetBmmCommitment(const CTransaction& coinbase)
{
    // Identified by uniqueness rather than position. The last output cannot be
    // used: GenerateCoinbaseCommitment appends the segwit witness commitment
    // after ours. Taking the *first* match would instead let a miner shadow the
    // real commitment with a BMM-shaped output in a deposit slot, choosing
    // prev_main freely. Requiring exactly one is position-independent and
    // leaves no room for a decoy.
    std::optional<uint256> found;
    for (const CTxOut& out : coinbase.vout) {
        CScript::const_iterator it{out.scriptPubKey.begin()};
        opcodetype opcode;
        if (!out.scriptPubKey.GetOp(it, opcode) || opcode != OP_RETURN) continue;

        std::vector<unsigned char> payload;
        if (!out.scriptPubKey.GetOp(it, opcode, payload)) continue;
        if (it != out.scriptPubKey.end()) continue;
        if (payload.size() != 33 || payload[0] != BMM_MARKER_V0) continue;
        if (out.nValue != 0) continue;

        if (found) return std::nullopt; // ambiguous: reject rather than pick
        found = uint256{std::span<const unsigned char>{payload.data() + 1, 32}};
    }
    return found;
}

} // namespace sidechain
