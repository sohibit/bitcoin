// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_BMM_H
#define BITCOIN_SIDECHAIN_BMM_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <optional>
#include <string>

namespace sidechain {

class MainchainCache;

/**
 * The mainchain block a sidechain block is anchored to.
 *
 * The anchor cannot live inside the block: the BMM request commits to the
 * block hash, so the hash is final before BMM is requested and nothing learned
 * from BMM can be folded back in.
 *
 * What the block *can* carry is the mainchain tip as of assembly, which is
 * known beforehand. Validation then scans forward from there for the first
 * mainchain block committing to this block's hash. That keeps the anchor
 * derivable at every later revalidation — reindex included — without storing
 * anything alongside the block index.
 */
constexpr unsigned char BMM_MARKER_V0{0x02};

//! Coinbase commitment carrying the mainchain tip as of block assembly.
CTxOut BuildBmmCommitmentOutput(const uint256& prev_main_hash);

//! Read the commitment back out of a coinbase. nullopt if absent or malformed.
std::optional<uint256> GetBmmCommitment(const CTransaction& coinbase);

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_BMM_H
