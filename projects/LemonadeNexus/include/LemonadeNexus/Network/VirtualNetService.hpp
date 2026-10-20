#pragma once

/// In-process traffic termination for the virtual mesh planes.
///
/// The boringtun dataplane decrypts and routes IP packets in userspace; packets
/// addressed to one of the server's own virtual IPs (its tunnel IP on the
/// client plane, its backbone IP on the server plane) are handed here. This
/// service owns the embedded smoltcp netstack (crates/virtual-netstack) and
/// byte-pipes virtual TCP connections to the unchanged httplib private API
/// server listening on a loopback or Unix-domain socket. Virtual UDP ports
/// deliver datagrams to an in-process callback (bind_udp / send_udp). No
/// kernel network interface is involved, so host root cannot observe tunnel
/// traffic and no CAP_NET_ADMIN is required.

#include <LemonadeNexus/Core/IService.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
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

    /// Receiver for datagrams on a bound virtual UDP port. `src_ip` is IPv4 in
    /// host byte order. Runs on the netstack thread; `data` is valid only for
    /// the call, so copy it and hand off to your own thread.
    using UdpReceiver =
        std::function<void(uint32_t src_ip, uint16_t src_port, std::span<const uint8_t> data)>;

    /// Bind virtual UDP `vip:vport` (an address registered with add_local_ip)
    /// and deliver every datagram addressed to it to `receiver`. The receiver
    /// lives until on_stop. Returns false when the stack is down or the
    /// arguments are invalid.
    bool bind_udp(const std::string& vip, uint16_t vport, UdpReceiver receiver);

    /// Send one datagram from bound virtual `src_ip:src_port`. Thread-safe;
    /// never blocks. Like a kernel UDP socket, a datagram larger than the MTU
    /// is sent as IPv4 fragments, and any number may be sent in series.
    /// Returns false on a parameter error, including a payload larger than
    /// max_udp_payload(). Delivery is not guaranteed, as with any UDP.
    bool send_udp(const std::string& src_ip, uint16_t src_port,
                  const std::string& dst_ip, uint16_t dst_port,
                  std::span<const uint8_t> data);

    /// Largest datagram send_udp accepts: the IPv4 UDP maximum (65507 bytes).
    [[nodiscard]] static constexpr std::size_t max_udp_payload() { return 65507; }

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
    // The C callback context points into these, so each receiver needs a
    // stable address for the stack's lifetime.
    std::list<std::unique_ptr<UdpReceiver>> udp_receivers_;
};

} // namespace nexus::network
