#pragma once

/// A stand-in home gateway on 127.0.0.1 that answers NAT-PMP (RFC 6886) and
/// PCP (RFC 6887) port-mapping requests, so the port-mapping clients can be
/// tested without a router. Switches select which protocol it speaks, which
/// result code it answers, and whether it answers at all; a request log
/// shows what the client sent.

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace test_support {

class FakeGateway {
public:
    /// NAT-PMP result codes (RFC 6886 section 3.5) for `natpmp_result`.
    static constexpr uint16_t kNatPmpSuccess = 0;
    static constexpr uint16_t kNatPmpUnsupportedVersion = 1;
    static constexpr uint16_t kNatPmpNotAuthorized = 2;
    static constexpr uint16_t kNatPmpUnsupportedOpcode = 5;

    /// PCP result codes (RFC 6887 section 7.4) for `pcp_result`.
    static constexpr uint8_t kPcpSuccess = 0;
    static constexpr uint8_t kPcpUnsuppVersion = 1;
    static constexpr uint8_t kPcpNotAuthorized = 2;
    static constexpr uint8_t kPcpMalformedRequest = 3;
    static constexpr uint8_t kPcpUnsuppOpcode = 4;

    static constexpr uint8_t kPcpVersion = 2;
    static constexpr uint8_t kPcpOpcodeMap = 1;
    static constexpr uint8_t kPcpResponseBit = 0x80;
    static constexpr size_t kPcpHeaderLen = 24;
    static constexpr size_t kPcpMapRequestLen = 60;
    static constexpr size_t kPcpMapResponseLen = 60;
    static constexpr uint8_t kProtocolUdp = 17;

    /// One request the gateway received. `protocol` is the version byte: 0
    /// for NAT-PMP, 2 for PCP. `nonce` is the PCP mapping nonce, zero for
    /// NAT-PMP.
    struct Request {
        uint8_t protocol{0};
        uint8_t opcode{0};
        uint16_t internal_port{0};
        uint16_t suggested_port{0};
        uint32_t lifetime_sec{0};
        std::array<uint8_t, 12> nonce{};
    };

    /// The fields of a PCP MAP response (RFC 6887 sections 7.2 and 11.1), in
    /// wire order. `assigned_external_address` is 16 bytes; an IPv4 address
    /// goes in as an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
    struct PcpMapResponse {
        uint8_t version{kPcpVersion};
        uint8_t opcode{kPcpOpcodeMap};  ///< Without the R bit; the encoder sets it.
        uint8_t result_code{kPcpSuccess};
        uint32_t lifetime_sec{0};
        uint32_t epoch_sec{0};
        std::array<uint8_t, 12> mapping_nonce{};
        uint8_t protocol{0};
        uint16_t internal_port{0};
        uint16_t assigned_external_port{0};
        std::array<uint8_t, 16> assigned_external_address{};
    };

    /// The 60-byte PCP MAP response for `fields`: version, R bit | opcode,
    /// reserved, result code, lifetime, epoch, 12 reserved bytes, then the
    /// MAP data.
    static std::vector<uint8_t> encode_pcp_map_response(const PcpMapResponse& fields);

    /// The 16-byte IPv4-mapped IPv6 form of a dotted IPv4 address; all zero
    /// when the text does not parse.
    static std::array<uint8_t, 16> ipv4_mapped(const std::string& dotted);

    /// Binds 127.0.0.1 on an ephemeral UDP port and starts the receive
    /// thread. port() is 0 when the bind failed.
    FakeGateway();
    ~FakeGateway();
    FakeGateway(const FakeGateway&) = delete;
    FakeGateway& operator=(const FakeGateway&) = delete;

    /// The bound UDP port, 0 when the bind failed.
    uint16_t port() const noexcept { return port_; }

    /// Stops the receive thread and closes the socket. Idempotent.
    void stop();

    /// Simulates a gateway reboot: the epoch restarts at 0 and every mapping
    /// is lost.
    void restart();

    /// Moves the epoch forward by `seconds`, as if the gateway had been up
    /// that much longer.
    void advance_epoch(uint32_t seconds);

    /// A copy of every request received so far, including dropped ones.
    std::vector<Request> requests() const;

    /// The external port mapped for (`protocol`, `internal_port`), nullopt
    /// when there is no mapping. NAT-PMP UDP mappings use kProtocolUdp.
    std::optional<uint16_t> mapped_external_port(uint16_t internal_port,
                                                 uint8_t protocol = kProtocolUdp) const;

    /// Answer NAT-PMP requests. When false they are dropped, as a gateway
    /// without NAT-PMP does.
    std::atomic<bool> natpmp_enabled{true};
    /// Answer PCP requests. When false a PCP request gets the NAT-PMP
    /// unsupported-version response (version 0), so a PCP client falls back
    /// to NAT-PMP.
    std::atomic<bool> pcp_enabled{false};
    /// Log every request and answer none of them.
    std::atomic<bool> drop_requests{false};
    /// Result code of every NAT-PMP response.
    std::atomic<uint16_t> natpmp_result{kNatPmpSuccess};
    /// Result code of every PCP MAP response. An error response carries
    /// lifetime 0 and the request's nonce, protocol, and internal port.
    std::atomic<uint8_t> pcp_result{kPcpSuccess};
    /// The longest lifetime granted; a longer request is cut to it.
    std::atomic<uint32_t> max_lifetime_sec{7200};

    /// The public IPv4 address the gateway reports (default 203.0.113.5).
    void set_external_address(const std::string& dotted);
    std::string external_address() const;

private:
    void run();
    void handle(const std::vector<uint8_t>& datagram, std::vector<uint8_t>& reply);
    void handle_natpmp(const std::vector<uint8_t>& datagram, std::vector<uint8_t>& reply);
    void handle_pcp(const std::vector<uint8_t>& datagram, std::vector<uint8_t>& reply);
    uint32_t epoch_sec_locked() const;
    /// The mapping for (protocol, internal_port) after applying a request
    /// with `suggested_port` and `lifetime_sec`: the granted external port
    /// (0 after a release) and the granted lifetime.
    std::pair<uint16_t, uint32_t> apply_mapping_locked(uint8_t protocol, uint16_t internal_port,
                                                       uint16_t suggested_port,
                                                       uint32_t lifetime_sec);
    bool external_port_free_locked(uint16_t external_port) const;

    intptr_t socket_{-1};
    uint16_t port_{0};
    std::atomic<bool> running_{false};
    std::thread thread_;

    mutable std::mutex mutex_;
    std::chrono::steady_clock::time_point start_;
    std::string external_address_{"203.0.113.5"};
    std::vector<Request> requests_;
    /// (protocol, internal port) -> external port.
    std::map<std::pair<uint8_t, uint16_t>, uint16_t> mappings_;
    uint16_t next_external_port_{40000};
};

}  // namespace test_support
