// Copyright (c) 2026 The Bitcoin Inquisition developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain/enforcer_client.h>

#include <compat/compat.h>
#include <consensus/amount.h>
#include <netbase.h>
#include <util/sock.h>

#include <chrono>
#include <limits>
#include <memory>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <cstring>
#include <string>
#include <string_view>

namespace sidechain {
namespace {

//! Whole-exchange deadline. Without it a peer dripping bytes would keep the
//! poll thread alive indefinitely, and shutdown joins that thread.
constexpr auto HTTP_DEADLINE{std::chrono::seconds{30}};
//! The enforcer is unauthenticated plaintext HTTP on an operator-configured
//! host, so treat its responses as untrusted and bounded.
constexpr size_t MAX_HTTP_RESPONSE_BYTES{8 * 1024 * 1024};

//! Strip chunked transfer framing. The enforcer serves HTTP/1.1 chunked, so the
//! body is a series of `<hex length>CRLF<data>CRLF` runs ending in a zero chunk.
bool DecodeChunked(const std::string& in, std::string& out)
{
    out.clear();
    size_t pos{0};
    while (true) {
        const size_t line_end{in.find("\r\n", pos)};
        if (line_end == std::string::npos) return false;

        // Chunk-extensions are legal after a ';'. std::stoul would also accept
        // "-1" (wrapping to ULONG_MAX) and leading whitespace, so parse strictly.
        std::string size_field{in.substr(pos, line_end - pos)};
        const size_t semi{size_field.find(';')};
        if (semi != std::string::npos) size_field.resize(semi);
        if (size_field.empty() || size_field.size() > 16) return false;

        uint64_t size{0};
        for (const char c : size_field) {
            const int digit{HexDigit(c)};
            if (digit < 0) return false;
            size = size * 16 + static_cast<uint64_t>(digit);
        }

        if (size == 0) return true;
        if (out.size() + size > MAX_HTTP_RESPONSE_BYTES) return false;

        const size_t data_start{line_end + 2};
        // Subtract rather than add, so a huge size cannot wrap past the check.
        if (data_start > in.size() || size > in.size() - data_start) return false;
        out.append(in, data_start, size);
        pos = data_start + size;
        if (pos + 2 > in.size() || in.compare(pos, 2, "\r\n") != 0) return false;
        pos += 2;
    }
}

/**
 * Blocking HTTP/1.1 POST against the enforcer.
 *
 * A plain socket rather than libevent: this only runs on the poll thread, where
 * blocking is what we want, and an event loop here brings callback lifetime
 * hazards for no benefit. ConnectDirectly gives us SO_NOSIGPIPE (without which
 * a closed enforcer connection kills bitcoind on macOS), a bounded connect, and
 * hostname/IPv6 resolution.
 */
bool HttpPostJson(const std::string& host, uint16_t port, const std::string& path,
                  const std::string& request_body, std::string& response_body,
                  std::string& error)
{
    const auto deadline{std::chrono::steady_clock::now() + HTTP_DEADLINE};

    const std::optional<CService> dest{Lookup(host, port, /*fAllowLookup=*/true)};
    if (!dest) {
        error = strprintf("cannot resolve enforcer host `%s`", host);
        return false;
    }

    std::unique_ptr<Sock> sock{ConnectDirectly(*dest, /*manual_connection=*/true)};
    if (!sock) {
        error = strprintf("cannot reach enforcer at %s", dest->ToStringAddrPort());
        return false;
    }

    // Connection: close means the server ends the body at EOF, so there is no
    // keep-alive framing to track. It may still answer chunked.
    const std::string request{strprintf(
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
        path, host, request_body.size(), request_body)};

    size_t sent{0};
    while (sent < request.size()) {
        if (std::chrono::steady_clock::now() > deadline) {
            error = "enforcer send exceeded deadline";
            return false;
        }
        const ssize_t n{sock->Send(request.data() + sent, request.size() - sent, MSG_NOSIGNAL)};
        if (n < 0) {
            const int err{WSAGetLastError()};
            if (err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS) {
                (void)sock->Wait(std::chrono::milliseconds{100}, Sock::SEND);
                continue;
            }
            error = strprintf("failed sending to enforcer: %s", NetworkErrorString(err));
            return false;
        }
        sent += static_cast<size_t>(n);
    }

    std::string raw;
    char buf[4096];
    while (true) {
        if (std::chrono::steady_clock::now() > deadline) {
            error = "enforcer response exceeded deadline";
            return false;
        }
        const ssize_t n{sock->Recv(buf, sizeof(buf), 0)};
        if (n < 0) {
            const int err{WSAGetLastError()};
            if (err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS) {
                (void)sock->Wait(std::chrono::milliseconds{100}, Sock::RECV);
                continue;
            }
            error = strprintf("failed reading from enforcer: %s", NetworkErrorString(err));
            return false;
        }
        if (n == 0) break;
        if (raw.size() + static_cast<size_t>(n) > MAX_HTTP_RESPONSE_BYTES) {
            error = ENFORCER_RESPONSE_TOO_LARGE;
            return false;
        }
        raw.append(buf, static_cast<size_t>(n));
    }

    const size_t header_end{raw.find("\r\n\r\n")};
    if (header_end == std::string::npos) {
        error = "malformed HTTP response from enforcer";
        return false;
    }
    const std::string headers{raw.substr(0, header_end)};
    const std::string body{raw.substr(header_end + 4)};
    const std::string status_line{raw.substr(0, raw.find("\r\n"))};
    // Match the status code positionally; a reason phrase could contain " 200".
    static constexpr std::string_view OK_STATUS{"HTTP/1.1 200"};
    const bool ok{status_line.starts_with(OK_STATUS) &&
                  (status_line.size() == OK_STATUS.size() ||
                   status_line[OK_STATUS.size()] == ' ')};
    if (!ok) {
        error = strprintf("enforcer returned `%s`", status_line);
        return false;
    }
    if (ToLower(headers).find("transfer-encoding: chunked") != std::string::npos) {
        if (!DecodeChunked(body, response_body)) {
            error = "malformed chunked response from enforcer";
            return false;
        }
        return true;
    }
    response_body = body;
    return true;
}

} // namespace
} // namespace sidechain

namespace sidechain {
namespace {

//! ReverseHex fields carry display-order hashes.
bool ParseReverseHex(const UniValue& v, uint256& out)
{
    if (!v.isObject()) return false;
    const UniValue& hex = v.find_value("hex");
    if (!hex.isStr()) return false;
    const auto parsed = uint256::FromHex(hex.get_str());
    if (!parsed) return false;
    out = *parsed;
    return true;
}

//! ConsensusHex fields carry internal-order bytes.
bool ParseConsensusHex(const UniValue& v, uint256& out)
{
    if (!v.isObject()) return false;
    const UniValue& hex = v.find_value("hex");
    if (!hex.isStr()) return false;
    const auto bytes = TryParseHex<unsigned char>(hex.get_str());
    if (!bytes || bytes->size() != 32) return false;
    std::memcpy(out.begin(), bytes->data(), 32);
    return true;
}

bool ParseHexBytes(const UniValue& v, std::vector<unsigned char>& out)
{
    if (!v.isObject()) return false;
    const UniValue& hex = v.find_value("hex");
    if (!hex.isStr()) return false;
    const auto bytes = TryParseHex<unsigned char>(hex.get_str());
    if (!bytes) return false;
    out = *bytes;
    return true;
}

//! Protobuf JSON renders 64-bit integers as strings, 32-bit as numbers.
bool ParseUint64(const UniValue& v, uint64_t& out)
{
    if (v.isNum()) {
        int64_t signed_value{0};
        try {
            signed_value = v.getInt<int64_t>();
        } catch (const std::exception&) {
            return false;
        }
        if (signed_value < 0) return false;
        out = static_cast<uint64_t>(signed_value);
        return true;
    }
    if (!v.isStr()) return false;
    return ParseUInt64(v.get_str(), &out);
}

bool ParseInt32(const UniValue& v, int32_t& out)
{
    if (!v.isNum()) return false;
    int32_t parsed{0};
    try {
        parsed = v.getInt<int32_t>();
    } catch (const std::exception&) {
        return false;
    }
    // Every field parsed through here is a uint32 on the wire. A negative value
    // would be adopted as a height and leave the cache with no usable anchor.
    if (parsed < 0) return false;
    out = parsed;
    return true;
}

//! Proto3 omits zero-valued scalars, so an absent plain field means 0. This is
//! only correct for bare scalars -- an absent wrapper type (UInt64Value) means
//! "unset" and must stay an error.
bool ParseScalarInt32(const UniValue& v, int32_t& out)
{
    if (v.isNull()) {
        out = 0;
        return true;
    }
    return ParseInt32(v, out);
}

bool ParseScalarUint64(const UniValue& v, uint64_t& out)
{
    if (v.isNull()) {
        out = 0;
        return true;
    }
    return ParseUint64(v, out);
}


//! Amounts from the enforcer are untrusted; an out-of-range value would become
//! a negative CAmount and produce blocks that fail CheckTransaction.
bool ParseAmount(const UniValue& v, CAmount& out)
{
    uint64_t sats{0};
    if (!ParseUint64(v, sats)) return false;
    if (sats > static_cast<uint64_t>(MAX_MONEY)) return false;
    out = static_cast<CAmount>(sats);
    return true;
}

} // namespace

bool DecodeChunkedForTest(const std::string& in, std::string& out) { return DecodeChunked(in, out); }

EnforcerClient::EnforcerClient(std::string host, uint16_t port, uint8_t slot)
    : m_host{std::move(host)}, m_port{port}, m_slot{slot} {}

namespace {
bool Call(const std::string& host, uint16_t port, const std::string& method,
          const UniValue& request, UniValue& response, std::string& error)
{
    const std::string path = "/cusf.mainchain.v1." + method;
    std::string body;
    if (!HttpPostJson(host, port, path, request.write(), body, error)) return false;
    if (!response.read(body)) {
        error = "malformed JSON from enforcer for " + method;
        return false;
    }
    return true;
}
} // namespace

bool EnforcerClient::GetChainTip(MainchainTip& tip, std::string& error) const
{
    try {
    UniValue response;
    if (!Call(m_host, m_port, "ValidatorService/GetChainTip", UniValue{UniValue::VOBJ}, response, error)) {
        return false;
    }
    const UniValue& info = response.find_value("blockHeaderInfo");
    if (!ParseReverseHex(info.find_value("blockHash"), tip.block_hash)) {
        error = "GetChainTip: missing blockHash";
        return false;
    }
    if (!ParseReverseHex(info.find_value("prevBlockHash"), tip.prev_block_hash)) {
        error = "GetChainTip: missing prevBlockHash";
        return false;
    }
    if (!ParseScalarInt32(info.find_value("height"), tip.height)) {
        error = "GetChainTip: invalid height";
        return false;
    }
    uint64_t timestamp{0};
    if (!ParseScalarUint64(info.find_value("timestamp"), timestamp) ||
        timestamp > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        error = "GetChainTip: missing or invalid timestamp";
        return false;
    }
    tip.timestamp = static_cast<int64_t>(timestamp);
    return true;
    } catch (const std::exception& e) {
        error = strprintf("GetChainTip: %s", e.what());
        return false;
    }
}

bool EnforcerClient::GetBlockHeaderInfo(const uint256& block_hash,
                                        uint32_t max_ancestors,
                                        std::vector<MainchainTip>& out,
                                        std::string& error) const
{
    try {
    UniValue hash{UniValue::VOBJ};
    hash.pushKV("hex", block_hash.GetHex());
    UniValue request{UniValue::VOBJ};
    request.pushKV("blockHash", hash);
    request.pushKV("maxAncestors", static_cast<uint64_t>(max_ancestors));

    UniValue response;
    if (!Call(m_host, m_port, "ValidatorService/GetBlockHeaderInfo", request, response, error)) {
        return false;
    }

    out.clear();
    const UniValue& infos = response.find_value("headerInfos");
    if (infos.isNull()) return true;
    if (!infos.isArray()) {
        error = "GetBlockHeaderInfo: malformed headerInfos";
        return false;
    }
    for (size_t i = 0; i < infos.size(); ++i) {
        const UniValue& info = infos[i];
        MainchainTip header;
        if (!ParseReverseHex(info.find_value("blockHash"), header.block_hash)) {
            error = "GetBlockHeaderInfo: missing blockHash";
            return false;
        }
        // Genesis has no parent, so an absent prevBlockHash is not an error.
        ParseReverseHex(info.find_value("prevBlockHash"), header.prev_block_hash);
        if (!ParseScalarInt32(info.find_value("height"), header.height)) {
            error = "GetBlockHeaderInfo: invalid height";
            return false;
        }
        out.push_back(header);
    }
    return true;
    } catch (const std::exception& e) {
        error = strprintf("GetBlockHeaderInfo: %s", e.what());
        return false;
    }
}

bool EnforcerClient::GetBmmHStarCommitment(const uint256& main_block_hash,
                                           std::optional<uint256>& commitment,
                                           std::string& error) const
{
    try {
    UniValue block_hash{UniValue::VOBJ};
    block_hash.pushKV("hex", main_block_hash.GetHex());
    UniValue request{UniValue::VOBJ};
    request.pushKV("blockHash", block_hash);
    request.pushKV("sidechainId", static_cast<uint64_t>(m_slot));

    UniValue response;
    if (!Call(m_host, m_port, "ValidatorService/GetBmmHStarCommitment", request, response, error)) {
        return false;
    }
    if (!response.find_value("blockNotFound").isNull()) {
        error = "GetBmmHStarCommitment: mainchain block unknown to enforcer";
        return false;
    }
    const UniValue& result = response.find_value("commitment");
    if (!result.isObject()) {
        error = "GetBmmHStarCommitment: malformed response";
        return false;
    }
    uint256 parsed;
    // An empty `commitment` object means the block committed nothing for our slot.
    commitment = ParseConsensusHex(result.find_value("commitment"), parsed)
                     ? std::optional<uint256>{parsed}
                     : std::nullopt;
    return true;
    } catch (const std::exception& e) {
        error = strprintf("GetBmmHStarCommitment: %s", e.what());
        return false;
    }
}

bool EnforcerClient::GetCtip(std::optional<Ctip>& ctip, std::string& error) const
{
    try {
    UniValue request{UniValue::VOBJ};
    request.pushKV("sidechainNumber", static_cast<uint64_t>(m_slot));

    UniValue response;
    if (!Call(m_host, m_port, "ValidatorService/GetCtip", request, response, error)) {
        return false;
    }

    const UniValue& result = response.find_value("ctip");
    // Absent until the first deposit: there is no treasury to spend yet.
    if (!result.isObject()) {
        ctip = std::nullopt;
        return true;
    }

    Ctip parsed;
    uint256 txid;
    if (!ParseReverseHex(result.find_value("txid"), txid)) {
        error = "GetCtip: malformed txid";
        return false;
    }
    uint64_t vout{0};
    if (!ParseUint64(result.find_value("vout"), vout) ||
        vout > std::numeric_limits<uint32_t>::max()) {
        error = "GetCtip: malformed vout";
        return false;
    }
    parsed.outpoint = COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)};
    if (!ParseAmount(result.find_value("value"), parsed.value)) {
        error = "GetCtip: missing or out-of-range value";
        return false;
    }
    ParseUint64(result.find_value("sequenceNumber"), parsed.sequence_number);
    ctip = parsed;
    return true;
    } catch (const std::exception& e) {
        error = strprintf("GetCtip: %s", e.what());
        return false;
    }
}

bool EnforcerClient::GetChainInfo(ChainInfo& info, std::string& error) const
{
    try {
    UniValue response;
    if (!Call(m_host, m_port, "ValidatorService/GetChainInfo", UniValue{UniValue::VOBJ}, response, error)) {
        return false;
    }
    const UniValue& constants = response.find_value("bip300Constants");
    if (!constants.isObject()) {
        error = "GetChainInfo: malformed bip300Constants";
        return false;
    }
    uint64_t max_age{0};
    uint64_t threshold{0};
    if (!ParseUint64(constants.find_value("withdrawalBundleMaxAge"), max_age) ||
        !ParseUint64(constants.find_value("withdrawalBundleInclusionThreshold"), threshold)) {
        error = "GetChainInfo: missing withdrawal bundle constants";
        return false;
    }
    if (max_age == 0 || threshold == 0 || threshold > max_age ||
        max_age > std::numeric_limits<uint32_t>::max()) {
        error = "GetChainInfo: nonsensical withdrawal bundle constants";
        return false;
    }
    info.withdrawal_bundle_max_age = static_cast<uint32_t>(max_age);
    info.withdrawal_bundle_inclusion_threshold = static_cast<uint32_t>(threshold);
    return true;
    } catch (const std::exception& e) {
        error = strprintf("GetChainInfo: %s", e.what());
        return false;
    }
}

bool EnforcerClient::BroadcastWithdrawalBundle(const std::vector<unsigned char>& blinded_m6,
                                               std::string& error) const
{
    try {
    UniValue request{UniValue::VOBJ};
    request.pushKV("sidechainId", static_cast<uint64_t>(m_slot));
    // A BytesValue is base64 in proto3 JSON, unlike the hex-wrapped
    // ConsensusHex/ReverseHex fields everywhere else in this API.
    request.pushKV("transaction", EncodeBase64(blinded_m6));

    UniValue response;
    return Call(m_host, m_port, "WalletService/BroadcastWithdrawalBundle", request, response, error);
    } catch (const std::exception& e) {
        error = strprintf("BroadcastWithdrawalBundle: %s", e.what());
        return false;
    }
}

bool EnforcerClient::GetTwoWayPegData(const std::optional<uint256>& start_block_hash,
                                      const uint256& end_block_hash,
                                      std::vector<BlockInfo>& out,
                                      std::string& error) const
{
    try {
    UniValue end{UniValue::VOBJ};
    end.pushKV("hex", end_block_hash.GetHex());
    UniValue request{UniValue::VOBJ};
    request.pushKV("sidechainId", static_cast<uint64_t>(m_slot));
    request.pushKV("endBlockHash", end);
    if (start_block_hash) {
        UniValue start{UniValue::VOBJ};
        start.pushKV("hex", start_block_hash->GetHex());
        request.pushKV("startBlockHash", start);
    }

    UniValue response;
    if (!Call(m_host, m_port, "ValidatorService/GetTwoWayPegData", request, response, error)) {
        return false;
    }
    return ParseTwoWayPegResponse(response, out, error);
    } catch (const std::exception& e) {
        error = strprintf("GetTwoWayPegData: %s", e.what());
        return false;
    }
}

bool ParseTwoWayPegResponse(const UniValue& response, std::vector<BlockInfo>& out, std::string& error)
{
    try {
    out.clear();
    const UniValue& blocks = response.find_value("blocks");
    if (blocks.isNull()) return true;
    if (!blocks.isArray()) {
        error = "GetTwoWayPegData: malformed blocks";
        return false;
    }

    for (size_t i = 0; i < blocks.size(); ++i) {
        const UniValue& item = blocks[i];
        const UniValue& header = item.find_value("blockHeaderInfo");
        BlockInfo info;
        if (!ParseReverseHex(header.find_value("blockHash"), info.main_block_hash)) {
            error = "GetTwoWayPegData: missing blockHash";
            return false;
        }
        if (!ParseScalarInt32(header.find_value("height"), info.main_height)) {
            error = "GetTwoWayPegData: invalid height";
            return false;
        }

        const UniValue& block_info = item.find_value("blockInfo");
        // An absent or empty commitment means the block committed nothing for
        // our slot. A present but unparseable one is a different thing entirely:
        // treating it as absent would defer the sidechain block forever on
        // sidechain-bmm-not-found with nothing logged anywhere.
        const UniValue& bmm = block_info.find_value("bmmCommitment");
        if (bmm.isObject() && !bmm.find_value("hex").isNull()) {
            uint256 commitment;
            if (!ParseConsensusHex(bmm, commitment)) {
                error = "GetTwoWayPegData: malformed bmmCommitment";
                return false;
            }
            info.bmm_commitment = commitment;
        }

        const UniValue& events = block_info.find_value("events");
        if (events.isArray()) {
            for (size_t j = 0; j < events.size(); ++j) {
                const UniValue& event = events[j];

                const UniValue& deposit = event.find_value("deposit");
                if (deposit.isObject()) {
                    Deposit d;
                    if (!ParseUint64(deposit.find_value("sequenceNumber"), d.sequence_number)) {
                        error = "GetTwoWayPegData: deposit has missing or invalid sequenceNumber";
                        return false;
                    }
                    const UniValue& outpoint = deposit.find_value("outpoint");
                    uint256 txid;
                    if (!ParseReverseHex(outpoint.find_value("txid"), txid)) {
                        error = "GetTwoWayPegData: deposit has no outpoint txid";
                        return false;
                    }
                    uint64_t vout{0};
                    if (!ParseUint64(outpoint.find_value("vout"), vout) ||
                        vout > std::numeric_limits<uint32_t>::max()) {
                        error = "GetTwoWayPegData: deposit has invalid outpoint vout";
                        return false;
                    }
                    d.outpoint = COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)};
                    const UniValue& output = deposit.find_value("output");
                    if (!ParseHexBytes(output.find_value("address"), d.address)) {
                        error = "GetTwoWayPegData: deposit missing address";
                        return false;
                    }
                    if (!ParseAmount(output.find_value("valueSats"), d.value)) {
                        error = "GetTwoWayPegData: deposit has missing or out-of-range valueSats";
                        return false;
                    }
                    info.deposits.push_back(std::move(d));
                    continue;
                }

                const UniValue& bundle = event.find_value("withdrawalBundle");
                if (bundle.isObject()) {
                    WithdrawalBundleEvent e;
                    if (!ParseConsensusHex(bundle.find_value("m6id"), e.m6id)) {
                        error = "GetTwoWayPegData: bundle event missing m6id";
                        return false;
                    }
                    const UniValue& inner = bundle.find_value("event");
                    if (inner.find_value("succeeded").isObject()) {
                        e.status = WithdrawalBundleEvent::Status::Succeeded;
                    } else if (inner.find_value("failed").isObject()) {
                        e.status = WithdrawalBundleEvent::Status::Failed;
                    } else {
                        e.status = WithdrawalBundleEvent::Status::Submitted;
                    }
                    info.bundle_events.push_back(e);
                }
            }
        }
        out.push_back(std::move(info));
    }
    return true;
    } catch (const std::exception& e) {
        error = strprintf("GetTwoWayPegData: %s", e.what());
        return false;
    }
}

} // namespace sidechain
