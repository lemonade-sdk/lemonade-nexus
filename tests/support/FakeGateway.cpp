#include "support/FakeGateway.hpp"

#include <algorithm>
#include <cstring>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
using socket_t = SOCKET;
static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
static void close_socket(socket_t s) { closesocket(s); }
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
using socket_t = int;
static constexpr socket_t kInvalidSocket = -1;
static void close_socket(socket_t s) { close(s); }
#endif

namespace test_support {

namespace {

constexpr uint8_t kNatPmpVersion = 0;
constexpr uint8_t kNatPmpOpExternalAddress = 0;
constexpr uint8_t kNatPmpOpMapUdp = 1;
constexpr uint8_t kNatPmpResponseBit = 128;
constexpr size_t kNatPmpMapRequestLen = 12;

void put16(std::vector<uint8_t>& pkt, size_t at, uint16_t value) {
    pkt[at] = static_cast<uint8_t>(value >> 8);
    pkt[at + 1] = static_cast<uint8_t>(value & 0xFF);
}

void put32(std::vector<uint8_t>& pkt, size_t at, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) {
        pkt[at + i] = static_cast<uint8_t>(value >> (8 * (3 - i)));
    }
}

uint16_t get16(const std::vector<uint8_t>& pkt, size_t at) {
    return static_cast<uint16_t>((uint16_t{pkt[at]} << 8) | pkt[at + 1]);
}

uint32_t get32(const std::vector<uint8_t>& pkt, size_t at) {
    uint32_t value = 0;
    for (size_t i = 0; i < 4; ++i) value = (value << 8) | pkt[at + i];
    return value;
}

}  // namespace

std::vector<uint8_t> FakeGateway::encode_pcp_map_response(const PcpMapResponse& f) {
    std::vector<uint8_t> pkt(kPcpMapResponseLen, 0);
    pkt[0] = f.version;
    pkt[1] = static_cast<uint8_t>(f.opcode | kPcpResponseBit);
    pkt[3] = f.result_code;
    put32(pkt, 4, f.lifetime_sec);
    put32(pkt, 8, f.epoch_sec);
    std::copy(f.mapping_nonce.begin(), f.mapping_nonce.end(), pkt.begin() + kPcpHeaderLen);
    pkt[36] = f.protocol;
    put16(pkt, 40, f.internal_port);
    put16(pkt, 42, f.assigned_external_port);
    std::copy(f.assigned_external_address.begin(), f.assigned_external_address.end(),
              pkt.begin() + 44);
    return pkt;
}

std::array<uint8_t, 16> FakeGateway::ipv4_mapped(const std::string& dotted) {
    std::array<uint8_t, 16> out{};
    in_addr addr{};
    if (inet_pton(AF_INET, dotted.c_str(), &addr) != 1) return out;
    out[10] = 0xFF;
    out[11] = 0xFF;
    std::memcpy(out.data() + 12, &addr.s_addr, 4);
    return out;
}

FakeGateway::FakeGateway() : start_(std::chrono::steady_clock::now()) {
#ifdef _WIN32
    static std::once_flag wsa_once;
    std::call_once(wsa_once, [] {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    });
#endif
    socket_t sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == kInvalidSocket) return;
#ifdef _WIN32
    DWORD timeout_ms = 100;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    timeval tv{};
    tv.tv_usec = 100 * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port = 0;
    if (bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
        close_socket(sock);
        return;
    }
    sockaddr_in bound{};
    socklen_t bound_len = sizeof(bound);
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0) {
        close_socket(sock);
        return;
    }
    socket_ = static_cast<intptr_t>(sock);
    port_ = ntohs(bound.sin_port);
    running_ = true;
    thread_ = std::thread([this] { run(); });
}

FakeGateway::~FakeGateway() { stop(); }

void FakeGateway::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    if (socket_ != static_cast<intptr_t>(kInvalidSocket)) {
        close_socket(static_cast<socket_t>(socket_));
        socket_ = static_cast<intptr_t>(kInvalidSocket);
    }
}

void FakeGateway::restart() {
    std::lock_guard<std::mutex> lock(mutex_);
    start_ = std::chrono::steady_clock::now();
    mappings_.clear();
}

void FakeGateway::advance_epoch(uint32_t seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    start_ -= std::chrono::seconds(seconds);
}

std::vector<FakeGateway::Request> FakeGateway::requests() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return requests_;
}

std::optional<uint16_t> FakeGateway::mapped_external_port(uint16_t internal_port,
                                                          uint8_t protocol) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = mappings_.find({protocol, internal_port});
    if (it == mappings_.end()) return std::nullopt;
    return it->second;
}

void FakeGateway::set_external_address(const std::string& dotted) {
    std::lock_guard<std::mutex> lock(mutex_);
    external_address_ = dotted;
}

std::string FakeGateway::external_address() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return external_address_;
}

void FakeGateway::run() {
    const socket_t sock = static_cast<socket_t>(socket_);
    std::vector<uint8_t> buf(1500);
    std::vector<uint8_t> reply;
    while (running_) {
        sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        const auto n = recvfrom(sock, reinterpret_cast<char*>(buf.data()),
                                static_cast<int>(buf.size()), 0,
                                reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n <= 0) continue;
        const std::vector<uint8_t> datagram(buf.begin(), buf.begin() + n);
        reply.clear();
        handle(datagram, reply);
        if (reply.empty()) continue;
        sendto(sock, reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()),
               0, reinterpret_cast<const sockaddr*>(&from), from_len);
    }
}

uint32_t FakeGateway::epoch_sec_locked() const {
    return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::steady_clock::now() - start_)
                                     .count());
}

bool FakeGateway::external_port_free_locked(uint16_t external_port) const {
    return std::none_of(mappings_.begin(), mappings_.end(),
                        [&](const auto& entry) { return entry.second == external_port; });
}

std::pair<uint16_t, uint32_t> FakeGateway::apply_mapping_locked(uint8_t protocol,
                                                                uint16_t internal_port,
                                                                uint16_t suggested_port,
                                                                uint32_t lifetime_sec) {
    const auto key = std::make_pair(protocol, internal_port);
    if (lifetime_sec == 0) {
        mappings_.erase(key);
        return {0, 0};
    }
    const uint32_t granted = std::min(lifetime_sec, max_lifetime_sec.load());
    if (const auto it = mappings_.find(key); it != mappings_.end()) return {it->second, granted};
    uint16_t external_port = suggested_port;
    if (external_port == 0 || !external_port_free_locked(external_port)) {
        while (!external_port_free_locked(next_external_port_)) ++next_external_port_;
        external_port = next_external_port_++;
    }
    mappings_[key] = external_port;
    return {external_port, granted};
}

void FakeGateway::handle(const std::vector<uint8_t>& datagram, std::vector<uint8_t>& reply) {
    if (datagram.empty()) return;
    switch (datagram[0]) {
        case kNatPmpVersion: handle_natpmp(datagram, reply); break;
        case kPcpVersion: handle_pcp(datagram, reply); break;
        default: break;
    }
}

void FakeGateway::handle_natpmp(const std::vector<uint8_t>& datagram,
                                std::vector<uint8_t>& reply) {
    if (datagram.size() < 2) return;
    Request req;
    req.protocol = kNatPmpVersion;
    req.opcode = datagram[1];
    if (req.opcode == kNatPmpOpMapUdp) {
        if (datagram.size() != kNatPmpMapRequestLen) return;
        req.internal_port = get16(datagram, 4);
        req.suggested_port = get16(datagram, 6);
        req.lifetime_sec = get32(datagram, 8);
    } else if (req.opcode == kNatPmpOpExternalAddress && datagram.size() != 2) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    requests_.push_back(req);
    if (drop_requests || !natpmp_enabled) return;

    const uint16_t configured = natpmp_result.load();
    const uint16_t result =
        configured != kNatPmpSuccess ? configured
        : (req.opcode == kNatPmpOpExternalAddress || req.opcode == kNatPmpOpMapUdp)
            ? kNatPmpSuccess
            : kNatPmpUnsupportedOpcode;

    if (req.opcode == kNatPmpOpExternalAddress) {
        reply.assign(12, 0);
        put16(reply, 2, result);
        put32(reply, 4, epoch_sec_locked());
        in_addr addr{};
        if (result == kNatPmpSuccess && inet_pton(AF_INET, external_address_.c_str(), &addr) == 1) {
            std::memcpy(reply.data() + 8, &addr.s_addr, 4);
        }
    } else if (req.opcode == kNatPmpOpMapUdp) {
        reply.assign(16, 0);
        put16(reply, 2, result);
        put32(reply, 4, epoch_sec_locked());
        put16(reply, 8, req.internal_port);
        if (result == kNatPmpSuccess) {
            const auto [external_port, granted] = apply_mapping_locked(
                kProtocolUdp, req.internal_port, req.suggested_port, req.lifetime_sec);
            put16(reply, 10, external_port);
            put32(reply, 12, granted);
        }
    } else {
        reply.assign(8, 0);
        put16(reply, 2, result);
        put32(reply, 4, epoch_sec_locked());
    }
    reply[0] = kNatPmpVersion;
    reply[1] = static_cast<uint8_t>(req.opcode + kNatPmpResponseBit);
}

void FakeGateway::handle_pcp(const std::vector<uint8_t>& datagram, std::vector<uint8_t>& reply) {
    if (datagram.size() < kPcpHeaderLen) return;
    Request req;
    req.protocol = kPcpVersion;
    req.opcode = static_cast<uint8_t>(datagram[1] & 0x7F);
    req.lifetime_sec = get32(datagram, 4);
    PcpMapResponse fields;
    fields.opcode = req.opcode;
    const bool is_map = req.opcode == kPcpOpcodeMap && datagram.size() == kPcpMapRequestLen;
    if (is_map) {
        std::copy_n(datagram.begin() + kPcpHeaderLen, 12, req.nonce.begin());
        fields.protocol = datagram[36];
        req.internal_port = get16(datagram, 40);
        req.suggested_port = get16(datagram, 42);
        fields.mapping_nonce = req.nonce;
        fields.internal_port = req.internal_port;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    requests_.push_back(req);
    if (drop_requests) return;
    fields.epoch_sec = epoch_sec_locked();

    if (!pcp_enabled) {
        // A NAT-PMP-only gateway answers any other version with the RFC 6886
        // unsupported-version response: version 0, opcode 0, result 1, epoch.
        reply.assign(8, 0);
        put16(reply, 2, kNatPmpUnsupportedVersion);
        put32(reply, 4, fields.epoch_sec);
        return;
    }

    if (req.opcode != kPcpOpcodeMap) {
        fields.result_code = kPcpUnsuppOpcode;
    } else if (!is_map) {
        fields.result_code = kPcpMalformedRequest;
    } else {
        fields.result_code = pcp_result.load();
    }
    if (fields.result_code != kPcpSuccess) {
        reply = encode_pcp_map_response(fields);
        if (!is_map) reply.resize(kPcpHeaderLen);
        return;
    }

    const auto [external_port, granted] = apply_mapping_locked(
        fields.protocol, req.internal_port, req.suggested_port, req.lifetime_sec);
    fields.lifetime_sec = granted;
    fields.assigned_external_port = external_port;
    fields.assigned_external_address = ipv4_mapped(external_address_);
    reply = encode_pcp_map_response(fields);
}

}  // namespace test_support
