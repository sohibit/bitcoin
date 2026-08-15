// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_BUNDLE_H
#define BITCOIN_SIDECHAIN_BUNDLE_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <optional>
#include <vector>

namespace sidechain {

//! One pending withdrawal, as committed to by a withdrawal request output.
struct Withdrawal {
    //! Mainchain destination scriptPubKey.
    CScript dest;
    CAmount amount{0};
    CAmount mainchain_fee{0};
};

/**
 * Build the blinded M6 for a bundle.
 *
 * Per BIP300 the real M6 spends the treasury UTXO and carries the new treasury
 * UTXO at vout[0]. The blinded form drops the input and replaces vout[0] with
 * an OP_RETURN carrying the total mainchain fee, so a bundle can be proposed
 * before the treasury UTXO it will eventually spend exists.
 *
 * Beware: bip300.md:859 says the fee output is the *last* output. The enforcer
 * replaces index 0 in place (lib/messages.rs:937). Index 0 is correct; following
 * the prose yields m6ids every bundle is rejected for.
 */
//! The 8-byte fee is written as OP_RETURN OP_PUSHBYTES_8 <fee>. The spec gives
//! the bytes but not the framing, and argues elsewhere that data after an
//! OP_RETURN carries no script meaning; the enforcer emits the push, and the
//! push is inside the txid, so the enforcer is what this matches.
std::optional<CMutableTransaction> BuildBlindedM6(const std::vector<Withdrawal>& withdrawals);

//! m6id is the txid of the blinded M6. nullopt if any amount is out of range,
//! since a wrapped total would produce a different id on a different compiler.
std::optional<uint256> ComputeM6id(const std::vector<Withdrawal>& withdrawals);

/**
 * Serialize a blinded M6 for BroadcastWithdrawalBundle.
 *
 * Must be legacy (no-witness) encoding: a zero-input transaction in segwit
 * encoding is misparsed as a witness marker by standard decoders.
 */
std::vector<unsigned char> SerializeBlindedM6(const CMutableTransaction& tx);

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_BUNDLE_H
