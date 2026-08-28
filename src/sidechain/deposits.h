// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_DEPOSITS_H
#define BITCOIN_SIDECHAIN_DEPOSITS_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sidechain/enforcer_client.h>

#include <optional>
#include <string>
#include <vector>

namespace sidechain {

/**
 * Decode a deposit payload into the script to credit.
 *
 * The payload is whatever the depositor handed the enforcer: it pushes the
 * string verbatim into an OP_RETURN and never parses it
 * (bip300301_enforcer/lib/wallet/mod.rs:1023). BitWindow emits three forms —
 * a bare address, `s<slot>_<address>`, and `s<slot>_<address>_<checksum>` —
 * and nothing normalizes between them, so all three are accepted here.
 *
 * This is consensus-critical: every node must derive an identical script from
 * identical bytes, and a payload that fails to decode must fail identically
 * everywhere.
 */
std::optional<CScript> DecodeDepositPayload(const std::vector<unsigned char>& payload);

//! Longest deposit payload that can decode. The longest well-formed form is
//! `s<slot>_<address>_<checksum>`, bounded by BIP173's 90-character address
//! limit. Anything longer is credited to UndecodableDepositScript(); this bound
//! is consensus-critical and cannot be widened without a fork.
static constexpr size_t MAX_DEPOSIT_PAYLOAD_SIZE{128};

//! Checksum is hex of the first 3 bytes of sha256("s<slot>_<address>_").
std::string DepositAddressChecksum(uint8_t slot, const std::string& address);

//! Full deposit address string as presented to a depositor.
std::string EncodeDepositAddress(uint8_t slot, const std::string& address);

//! One part in 400 of a deposit, which is 0.25%.
static constexpr CAmount DEPOSIT_FEE_DIVISOR{400};

//! The most one deposit pays, whatever its size.
static constexpr CAmount MAX_DEPOSIT_FEE{1'000'000'000};

//! What one deposit pays the development fund. Never more than the deposit.
CAmount DepositFee(CAmount value);

//! The script the deposit fees pay. One output per block carries their total.
CScript DepositFeeScript();

/**
 * Verify the coinbase credits exactly the deposits reported for this block.
 *
 * Deposits occupy the leading outputs in sequence-number order, each paying its
 * value less DepositFee(). The output after them pays those fees to
 * DepositFeeScript(), and it is absent only when the block credits nothing.
 * `credited` returns the deposit total, which the caller adds to the block
 * reward ceiling.
 *
 * The fee ceiling is deliberately not checked here: ConnectBlock already
 * enforces GetValueOut() <= nFees + subsidy + credited, with the real fee total.
 */
bool CheckCoinbaseDeposits(const CTransaction& coinbase,
                           const std::vector<Deposit>& deposits,
                           CAmount& credited,
                           std::string& reason);

//! The exact script an undecodable deposit payload is credited to.
CScript UndecodableDepositScript();

//! Deposits sorted into the canonical order used by the coinbase rule.
std::vector<Deposit> SortDeposits(std::vector<Deposit> deposits);

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_DEPOSITS_H
