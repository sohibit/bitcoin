// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_ENFORCER_CLIENT_H
#define BITCOIN_SIDECHAIN_ENFORCER_CLIENT_H

#include <primitives/transaction.h>
#include <uint256.h>
#include <univalue.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sidechain {

//! Error reported when a response exceeds the read cap. Callers narrow the
//! request and retry on this and only this, so it must stay an exact match.
inline constexpr const char* ENFORCER_RESPONSE_TOO_LARGE{"enforcer response too large"};

//! Exposed for testing. Strips HTTP chunked transfer framing.
bool DecodeChunkedForTest(const std::string& in, std::string& out);

struct BlockInfo;

//! Exposed for testing. Decodes a GetTwoWayPegData response body.
bool ParseTwoWayPegResponse(const UniValue& response, std::vector<BlockInfo>& out, std::string& error);


struct MainchainTip {
    uint256 block_hash;
    uint256 prev_block_hash;
    int32_t height{0};
    int64_t timestamp{0};
};

struct Deposit {
    uint64_t sequence_number{0};
    COutPoint outpoint;
    //! Opaque payload from the deposit OP_RETURN. Interpretation is ours alone.
    std::vector<unsigned char> address;
    CAmount value{0};
};

struct WithdrawalBundleEvent {
    enum class Status { Submitted, Succeeded, Failed };

    uint256 m6id;
    Status status{Status::Submitted};
};

//! The sidechain's treasury output on the mainchain, which an M6 spends.
struct Ctip {
    COutPoint outpoint;
    CAmount value{0};
    uint64_t sequence_number{0};
};

//! BIP300 parameters, read from the enforcer rather than hardcoded: a bundle's
//! fate depends on the same numbers the mainchain is enforcing.
struct ChainInfo {
    uint32_t withdrawal_bundle_max_age{0};
    uint32_t withdrawal_bundle_inclusion_threshold{0};
};

//! Everything the enforcer reports about one mainchain block, scoped to our slot.
struct BlockInfo {
    uint256 main_block_hash;
    int32_t main_height{0};
    std::optional<uint256> bmm_commitment;
    std::vector<Deposit> deposits;
    std::vector<WithdrawalBundleEvent> bundle_events;
};

/**
 * What MainchainCache needs from the enforcer.
 *
 * Exists so Poll can be driven by a fake through reorgs and truncated
 * responses. Every consensus bug found in review so far has lived in code that
 * only a real enforcer could reach.
 */
class IEnforcerClient
{
public:
    virtual ~IEnforcerClient() = default;
    virtual bool GetChainTip(MainchainTip& tip, std::string& error) const = 0;
    virtual bool GetTwoWayPegData(const std::optional<uint256>& start_block_hash,
                                  const uint256& end_block_hash,
                                  std::vector<BlockInfo>& out,
                                  std::string& error) const = 0;
    virtual bool GetBlockHeaderInfo(const uint256& block_hash,
                                    uint32_t max_ancestors,
                                    std::vector<MainchainTip>& out,
                                    std::string& error) const = 0;
    virtual bool GetBmmHStarCommitment(const uint256& main_block_hash,
                                       std::optional<uint256>& commitment,
                                       std::string& error) const = 0;
    virtual bool GetCtip(std::optional<Ctip>& ctip, std::string& error) const = 0;
    virtual bool GetChainInfo(ChainInfo& info, std::string& error) const = 0;

    /**
     * Propose a withdrawal bundle (M3).
     *
     * The only write in this interface. Takes the serialized blinded M6, and
     * answers nothing useful -- the enforcer stores it and computes the m6id
     * itself without returning it, so callers correlate with ComputeM6id.
     */
    virtual bool BroadcastWithdrawalBundle(const std::vector<unsigned char>& blinded_m6,
                                           std::string& error) const = 0;
};

/**
 * Connect RPC client for bip300301_enforcer.
 *
 * Connect is HTTP POST with a JSON body over HTTP/1.1, so this needs no
 * protobuf or gRPC. Calls block, and must only ever run on the poll thread —
 * never under cs_main.
 */
class EnforcerClient final : public IEnforcerClient
{
public:
    EnforcerClient(std::string host, uint16_t port, uint8_t slot);

    bool GetChainTip(MainchainTip& tip, std::string& error) const override;

    /**
     * Walk from `end_block_hash` back to `start_block_hash`, EXCLUSIVE of
     * `start` and inclusive of `end`.
     *
     * An empty start walks all the way to genesis, so it yields the complete
     * history up to `end`. The enforcer errors if `start` is not an ancestor of
     * `end`, which is what lets a caller detect a reorg.
     *
     * Blocks with no events for our slot are omitted, so the result is sparse.
     * That is sound: an omitted block provably has no deposits to credit.
     */
    bool GetTwoWayPegData(const std::optional<uint256>& start_block_hash,
                          const uint256& end_block_hash,
                          std::vector<BlockInfo>& out,
                          std::string& error) const override;

    /**
     * Dense header chain ending at `block_hash`, newest first.
     *
     * Unlike GetTwoWayPegData this is not filtered by slot, so it resolves
     * heights for ordinary mainchain blocks too. Peg data alone yields only
     * event-bearing blocks, which would make a node's ability to validate
     * depend on which tips it happened to observe while polling.
     */
    bool GetBlockHeaderInfo(const uint256& block_hash,
                            uint32_t max_ancestors,
                            std::vector<MainchainTip>& out,
                            std::string& error) const override;

    //! nullopt commitment means the block is known but committed nothing for us.
    bool GetBmmHStarCommitment(const uint256& main_block_hash,
                               std::optional<uint256>& commitment,
                               std::string& error) const override;

    //! nullopt means nobody has ever deposited, so there is no treasury yet.
    bool GetCtip(std::optional<Ctip>& ctip, std::string& error) const override;

    bool GetChainInfo(ChainInfo& info, std::string& error) const override;

    bool BroadcastWithdrawalBundle(const std::vector<unsigned char>& blinded_m6,
                                   std::string& error) const override;

private:
    std::string m_host;
    uint16_t m_port;
    uint8_t m_slot;
};

} // namespace sidechain

#endif // BITCOIN_SIDECHAIN_ENFORCER_CLIENT_H
