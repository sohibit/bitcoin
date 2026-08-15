// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_HOOK_H
#define BITCOIN_SIDECHAIN_HOOK_H

#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <functional>
#include <vector>
#include <string_view>

class CBlock;
class CBlockIndex;
class BlockValidationState;

namespace sidechain {

using ReadBlockFn = std::function<bool(CBlock&, const CBlockIndex&)>;

/**
 * The outputs a block's transaction spends, by index into block.vtx.
 *
 * Sourced from the block's undo data, because by the time the peg check runs
 * the coins view has already had them removed. False for the coinbase, and for
 * an index the block does not have.
 */
using SpentOutputsFn = std::function<bool(size_t, std::vector<CTxOut>&)>;

using PegCheckFn = bool (*)(const CBlock&, const CBlockIndex&, const ReadBlockFn&, const SpentOutputsFn&, bool, CAmount&, BlockValidationState&);

/**
 * Peg rules for a sidechain block.
 *
 * validation.cpp is compiled into both bitcoin_node and bitcoinkernel, but the
 * peg implementation needs key_io and an HTTP client, neither of which belongs
 * in the kernel. This dispatches to whatever bitcoin_node registered. With
 * nothing registered it fails with state.Error rather than returning true --
 * silently skipping consensus rules would be a hole.
 */
[[nodiscard]] bool CheckBlockPegRules(const CBlock& block,
                        const CBlockIndex& index,
                        const ReadBlockFn& read_block,
                        const SpentOutputsFn& spent_outputs,
                        bool template_only,
                        CAmount& deposit_credit,
                        BlockValidationState& state);

void SetPegCheck(PegCheckFn fn);

/**
 * Whether a rejection reason means "come back later" rather than "this is bad".
 *
 * Deliberately an allowlist: sidechain-parent-unreadable means corruption or
 * pruning, and sidechain-peg-unavailable means the peg check was never
 * registered. Neither resolves by waiting, and a reason added later fails safe.
 */
bool IsDeferrableSidechainReason(std::string_view reason);

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_HOOK_H
