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
    ns_destroy(stack_);
    stack_ = nullptr;
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

} // namespace nexus::network
