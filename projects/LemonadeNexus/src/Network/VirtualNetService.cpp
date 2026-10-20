#include <LemonadeNexus/Network/VirtualNetService.hpp>

#include <virtual_netstack.h>

#include <spdlog/spdlog.h>

namespace nexus::network {

namespace {

/// C ABI trampoline: the netstack hands every outbound packet here with the
/// VirtualNetService pointer as context.
void output_trampoline(void* ctx, const uint8_t* pkt, size_t len) {
    if (!ctx) return;
    static_cast<VirtualNetService*>(ctx)->emit_outbound({pkt, len});
}

/// C ABI trampoline for virtual UDP: `ctx` is the bound UdpReceiver.
void udp_trampoline(void* ctx, uint32_t src_ip, uint16_t src_port,
                    uint32_t /*dst_ip*/, uint16_t /*dst_port*/,
                    const uint8_t* data, size_t len) {
    if (!ctx || !data) return;
    // An exception must not unwind into the Rust stack thread.
    try {
        (*static_cast<VirtualNetService::UdpReceiver*>(ctx))(src_ip, src_port, {data, len});
    } catch (const std::exception& e) {
        spdlog::error("[VirtualNetService] udp receiver threw: {}", e.what());
    } catch (...) {
        spdlog::error("[VirtualNetService] udp receiver threw");
    }
}

} // namespace

VirtualNetService::VirtualNetService(VirtualNetConfig config)
    : config_(config) {}

VirtualNetService::~VirtualNetService() {
    on_stop();
}

void VirtualNetService::on_start() {
    if (stack_) return;
    stack_ = ns_create(config_.mtu, &output_trampoline, this);
    if (!stack_) {
        spdlog::error("[{}] failed to create virtual netstack", name());
        return;
    }
    spdlog::info("[{}] in-process netstack up (mtu {}, no kernel interface)",
                 name(), config_.mtu);
}

void VirtualNetService::on_stop() {
    if (!stack_) return;
    ns_destroy(stack_);  // joins the stack thread: no receiver runs after this
    stack_ = nullptr;
    udp_receivers_.clear();
}

void VirtualNetService::deliver_inbound_ip_packet(std::span<const uint8_t> packet) {
    if (stack_ && !packet.empty())
        ns_feed_inbound(stack_, packet.data(), packet.size());
}

void VirtualNetService::set_outbound_sink(OutboundSink sink) {
    sink_ = std::move(sink);
}

void VirtualNetService::emit_outbound(std::span<const uint8_t> packet) {
    if (sink_) sink_(packet);
}

bool VirtualNetService::add_local_ip(const std::string& ip_cidr) {
    if (!stack_) return false;
    if (ns_add_local_ip(stack_, ip_cidr.c_str()) != 0) {
        spdlog::warn("[{}] add_local_ip failed for '{}'", name(), ip_cidr);
        return false;
    }
    return true;
}

bool VirtualNetService::add_tcp_forward(const std::string& vip, uint16_t vport,
                                        const std::string& target) {
    if (!stack_) return false;
    if (ns_add_tcp_forward(stack_, vip.c_str(), vport, target.c_str()) != 0) {
        spdlog::warn("[{}] add_tcp_forward {}:{} -> {} failed", name(), vip, vport, target);
        return false;
    }
    spdlog::info("[{}] ingress {}:{} -> {}", name(), vip, vport, target);
    return true;
}

uint16_t VirtualNetService::add_tcp_egress(const std::string& dst_ip, uint16_t dst_port,
                                           const std::string& src_ip) {
    if (!stack_) return 0;
    return ns_add_tcp_egress(stack_, dst_ip.c_str(), dst_port, src_ip.c_str());
}

bool VirtualNetService::bind_udp(const std::string& vip, uint16_t vport,
                                 UdpReceiver receiver) {
    if (!stack_ || !receiver) return false;
    auto& slot = udp_receivers_.emplace_back(std::make_unique<UdpReceiver>(std::move(receiver)));
    if (ns_udp_bind(stack_, vip.c_str(), vport, &udp_trampoline, slot.get()) != 0) {
        udp_receivers_.pop_back();
        spdlog::warn("[{}] bind_udp {}:{} failed", name(), vip, vport);
        return false;
    }
    spdlog::info("[{}] udp bound on virtual {}:{}", name(), vip, vport);
    return true;
}

bool VirtualNetService::send_udp(const std::string& src_ip, uint16_t src_port,
                                 const std::string& dst_ip, uint16_t dst_port,
                                 std::span<const uint8_t> data) {
    if (!stack_ || data.empty() || data.size() > max_udp_payload()) return false;
    return ns_udp_send(stack_, src_ip.c_str(), src_port, dst_ip.c_str(), dst_port,
                       data.data(), data.size()) == 0;
}

} // namespace nexus::network
