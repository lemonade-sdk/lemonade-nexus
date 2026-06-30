#pragma once

/// In-process traffic termination for the virtual mesh planes.
///
/// The boringtun dataplane decrypts and routes IP packets in userspace; packets
/// addressed to one of the server's own virtual IPs (its tunnel IP on the
/// client plane, its backbone IP on the server plane) are handed here. This
/// service owns the embedded smoltcp netstack (crates/virtual-netstack) and
/// byte-pipes virtual TCP connections to the unchanged httplib private API
/// server listening on a loopback or Unix-domain socket. No kernel network
/// interface is involved, so host root cannot observe tunnel traffic and no
/// CAP_NET_ADMIN is required.

#include <LemonadeNexus/Core/IService.hpp>

#include <cstdint>
#include <functional>
#include <span>
#include <string>

struct NsHandle;  // virtual_netstack.h

namespace nexus::network {

struct VirtualNetConfig {
    /// MTU for the virtual stack (clients use ~1420).
    uint32_t mtu{1420};
};

class VirtualNetService : public core::IService<VirtualNetService> {
    friend class core::IService<VirtualNetService>;
public:
    /// Sink for outbound IP packets the netstack emits (locally-originated
    /// traffic that must be routed and encrypted by the dataplane).
    using OutboundSink = std::function<void(std::span<const uint8_t>)>;

    explicit VirtualNetService(VirtualNetConfig config = {});
    ~VirtualNetService();

    VirtualNetService(const VirtualNetService&)            = delete;
    VirtualNetService& operator=(const VirtualNetService&) = delete;

    // ---- dataplane handoff (both directions) -------------------------------

    /// Feed a decrypted inbound IP packet (called from dataplane rx threads).
    void deliver_inbound_ip_packet(std::span<const uint8_t> packet);

    /// Where the netstack sends locally-originated IP packets.
    void set_outbound_sink(OutboundSink sink);

    // ---- topology ----------------------------------------------------------

    /// Register a virtual address plane the stack answers for, e.g.
    /// "10.64.0.1/10" (client plane) or "172.16.0.7/22" (backbone).
    bool add_local_ip(const std::string& ip_cidr);

    /// Ingress: virtual `vip:vport` -> bridge `target`
    /// ("tcp:127.0.0.1:PORT" or "unix:/path").
    bool add_tcp_forward(const std::string& vip, uint16_t vport,
                         const std::string& target);

    /// Egress: bind a real loopback TCP listener bridged to a virtual TCP
    /// connection toward `dst_ip:dst_port` sourced from `src_ip`. Returns the
    /// bound loopback port, or 0 on failure. (For future server-to-server
    /// backend calls; no caller yet.)
    uint16_t add_tcp_egress(const std::string& dst_ip, uint16_t dst_port,
                            const std::string& src_ip);

    // ---- IService ----------------------------------------------------------

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "VirtualNetService"; }

    /// Internal: invoked by the C output callback. Public so the free function
    /// trampoline can reach it; not part of the intended API.
    void emit_outbound(std::span<const uint8_t> packet);

private:
    VirtualNetConfig config_;
    NsHandle*        stack_{nullptr};
    OutboundSink     sink_;
};

} // namespace nexus::network
