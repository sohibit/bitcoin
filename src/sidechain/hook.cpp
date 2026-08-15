// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/hook.h>

#include <consensus/validation.h>

#include <atomic>

namespace sidechain {
namespace {
std::atomic<PegCheckFn> g_peg_check{nullptr};
} // namespace

//! sidechain-parent-unreadable is absent deliberately, and stays correct only
//! because -prune and assumeutxo are both refused in sidechain mode (init.cpp).
bool IsDeferrableSidechainReason(std::string_view reason)
{
    return reason == "sidechain-enforcer-unavailable" ||
           reason == "sidechain-bmm-not-found" ||
           reason == "sidechain-height-uncached" ||
           reason == "sidechain-prevmain-uncached";
}

void SetPegCheck(PegCheckFn fn) { g_peg_check.store(fn, std::memory_order_release); }

bool CheckBlockPegRules(const CBlock& block,
                        const CBlockIndex& index,
                        const ReadBlockFn& read_block,
                        const SpentOutputsFn& spent_outputs,
                        bool template_only,
                        CAmount& deposit_credit,
                        BlockValidationState& state)
{
    const PegCheckFn fn{g_peg_check.load(std::memory_order_acquire)};
    if (fn == nullptr) return state.Error("sidechain-peg-unavailable");
    return fn(block, index, read_block, spent_outputs, template_only, deposit_credit, state);
}

} // namespace sidechain
