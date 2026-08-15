// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <core_io.h>
#include <key_io.h>
#include <rpc/util.h>
#include <sidechain/withdrawal.h>
#include <util/strencodings.h>
#include <wallet/rpc/util.h>
#include <wallet/coincontrol.h>
#include <policy/policy.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

namespace wallet {

/**
 * Peg out.
 *
 * The coins are not destroyed here. They move into an output that only a bundle
 * or a settlement may spend, so they stay the owner's until the mainchain
 * actually pays them out -- and come back untouched if it never does.
 *
 * Named and shaped to match the `withdraw` the orchestrator already calls, so
 * the frontends need no change.
 */
RPCHelpMan withdraw()
{
    return RPCHelpMan{
        "withdraw",
        "Request a withdrawal to a mainchain address.\n"
        "The coins are held in an unspendable-by-you output until the mainchain\n"
        "either pays the bundle carrying this request out, or declines to.\n"
        "Call abort_withdrawal to take a request back before a bundle carries it.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "mainchain address to pay"},
            {"amount_sats", RPCArg::Type::NUM, RPCArg::Optional::NO, "what the mainchain should pay out"},
            {"sidechain_fee_rate", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "fee rate for this sidechain transaction, in satoshis per 1000 vbytes"},
            {"mainchain_fee_sats", RPCArg::Type::NUM, RPCArg::Optional::NO, "left to mainchain miners by the bundle"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "the request transaction"},
        RPCExamples{HelpExampleCli("withdraw", "\"bcrt1q...\" 100000 1000 2000")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<CWallet> pwallet{GetWalletForJSONRPCRequest(request)};
            if (!pwallet) return UniValue::VNULL;
            CWallet& wallet{*pwallet};

            if (!Params().GetConsensus().IsSidechain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "not running as a sidechain; set -sidechainslot");
            }

            // Decoded with this node's parameters. The sidechain and the
            // mainchain share an address format today; a deployment where they
            // differ needs the mainchain's parameters here instead.
            const CTxDestination dest{DecodeDestination(request.params[0].get_str())};
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid mainchain address");
            }

            const CAmount amount{request.params[1].getInt<int64_t>()};
            const CAmount sidechain_fee_rate{request.params[2].getInt<int64_t>()};
            const CAmount mainchain_fee{request.params[3].getInt<int64_t>()};
            if (amount <= 0 || sidechain_fee_rate <= 0 || mainchain_fee <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amounts must be positive");
            }

            sidechain::WithdrawalRequest peg_out;
            peg_out.dest = GetScriptForDestination(dest);
            // The whole sum is encumbered: the mainchain fee is paid out of it
            // by the bundle, so it has to be here to be paid with.
            peg_out.amount = amount + mainchain_fee;
            peg_out.mainchain_fee = mainchain_fee;
            if (!MoneyRange(peg_out.amount)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amount out of range");
            }
            // Below the dust rule the M6 never confirms, the bundle ages out,
            // and every request in it comes back. create_bundle skips such a
            // request as well, because anyone can make one without this wallet.
            if (IsDust(CTxOut{amount, peg_out.dest}, CFeeRate{DUST_RELAY_TX_FEE})) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "the payout is below the dust threshold, so the mainchain would "
                                   "never confirm it");
            }
            if (peg_out.dest.size() > sidechain::MAX_PEG_SCRIPT_SIZE) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "mainchain address script is too large");
            }

            // Where the coins land if the bundle fails, or if the request is
            // aborted. Ours, so the owner gets them back without doing anything.
            EnsureWalletIsUnlocked(wallet);
            auto owner{wallet.GetNewDestination(wallet.m_default_address_type, "withdrawal refund")};
            if (!owner) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(owner).original);
            }
            peg_out.owner = GetScriptForDestination(*owner);
            if (peg_out.owner.size() > sidechain::MAX_PEG_SCRIPT_SIZE) {
                throw JSONRPCError(RPC_WALLET_ERROR, "the refund address script is too large");
            }

            const CTxOut out{sidechain::BuildWithdrawalRequestOutput(peg_out)};
            std::vector<CRecipient> recipients{{CNoDestination{out.scriptPubKey}, out.nValue, false}};

            // A rate, not a total. An exact fee is not reachable with coin
            // selection: raising the rate can pull in another input, which grows
            // the size and the fee with it.
            CCoinControl coin_control;
            // Not overridden: a rate too small to relay has to be refused, not
            // quietly built into a transaction that never confirms.
            coin_control.m_feerate = CFeeRate{sidechain_fee_rate, 1000};
            auto created{CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt,
                                           coin_control, true)};
            if (!created) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(created).original);
            }
            const CTransactionRef best{created->tx};

            wallet.CommitTransaction(best, {}, /*orderForm=*/{});
            return best->GetHash().GetHex();
        }};
}

} // namespace wallet
