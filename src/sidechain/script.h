// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_SCRIPT_H
#define BITCOIN_SIDECHAIN_SCRIPT_H

#include <script/script.h>
#include <uint256.h>

#include <cstdint>

namespace sidechain {

//! BIP300 spells its treasury opcode OP_DRIVECHAIN; it is OP_NOP5 on the wire.
static constexpr opcodetype OP_DRIVECHAIN{OP_NOP5};

//! Serialized length of a treasury scriptPubKey.
static constexpr unsigned int TREASURY_SCRIPT_SIZE{4};

/**
 * Whether a scriptPubKey is a BIP300 sidechain treasury output.
 *
 * The form is `OP_DRIVECHAIN OP_PUSHBYTES_1 <slot> OP_TRUE`. Compared bytewise
 * rather than through an interpreter: the enforcer emits a literal
 * OP_PUSHBYTES_1 even for slots that would fit a minimal push, so a
 * minimal-encoding parse would miss every treasury on slots 0 through 16,
 * and on slot 129.
 */
bool IsDrivechainTreasury(const CScript& script, uint8_t& slot_out);

//! Whether a scriptPubKey is a treasury output for any slot.
bool IsDrivechainTreasury(const CScript& script);

//! Marker distinguishing a withdrawal request from any other script.
static constexpr unsigned char WITHDRAWAL_MARKER_V0{0x01};

/**
 * Largest payload a valid request carries: a version byte, two capped scripts
 * with their length bytes, and the mainchain fee.
 *
 * Without this bound a request-shaped script of any size is standard, so it
 * relays and is mined -- and nothing can then sweep it, because the parser
 * rejects it and no bundle or abort may take it.
 */
static constexpr size_t MAX_WITHDRAWAL_PAYLOAD_SIZE{139};

/**
 * True for a request-shaped output script.
 *
 * `<payload> OP_DROP OP_TRUE`, where the payload starts with the marker and
 * fits MAX_WITHDRAWAL_PAYLOAD_SIZE. Shape and size only, because this has to
 * stay callable from the kernel.
 *
 * Whether the payload is a real request also depends on the output's value,
 * which a script alone does not carry. A script that passes here can still fail
 * ParseWithdrawalRequestOutput -- a mainchain fee at or above the value, for
 * one. Such an output matches no peg rule, and its script ends in OP_TRUE, so
 * any block author takes it. Policy refuses to relay one: IsStandardTx checks
 * the whole output, not the script alone.
 */
bool IsWithdrawalRequestScript(const CScript& script);

/**
 * Tell the policy layer that this node runs as a sidechain.
 *
 * A peg output means nothing on a chain with no peg. Off a sidechain it stays
 * non-standard, so it cannot become a cheap way to put attacker bytes into the
 * UTXO set of a chain that can never spend them.
 */
void SetSidechainScriptPolicy(bool enabled);

//! Whether the node runs as a sidechain. Policy only, never consensus.
bool SidechainScriptPolicy();

//! Marker distinguishing a bundle output from a request output.
static constexpr unsigned char BUNDLE_MARKER_V0{0x02};

/**
 * Whether a scriptPubKey holds a bundle, and what it commits to.
 *
 * `<marker || m6id || requests> OP_DROP OP_TRUE`. Deliberately not a standard
 * output type: both creating and spending one is then non-relayable, which is
 * what confines the whole bundle lifecycle to blocks without any further policy
 * rule.
 *
 * Two digests, because the m6id cannot carry the whole truth. It is the txid of
 * the blinded M6, whose shape BIP300 fixes, and that shape holds only the
 * mainchain destination and the payout -- not the owner a request returns to,
 * and not how the mainchain fee is split between requests. Committing to the
 * requests separately is what stops a settlement rewriting either.
 */
bool IsBundleScript(const CScript& script, uint256& m6id_out, uint256& requests_out);

//! Whether a scriptPubKey holds a bundle at all.
bool IsBundleScript(const CScript& script);

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_SCRIPT_H
