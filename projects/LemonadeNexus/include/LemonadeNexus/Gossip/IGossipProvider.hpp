#pragma once

#include <array>
#include <concepts>
#include <cstdint>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include <LemonadeNexus/Gossip/GossipTypes.hpp>

namespace nexus::gossip {

/// CRTP interface for GossipService.
///
/// Contract:
///   void do_add_peer(std::string_view endpoint, std::string_view pubkey)
///   void do_remove_peer(std::string_view pubkey)
///   void do_send_digest(const GossipPeer& peer)
///   void do_handle_digest(const GossipPeer& peer, uint64_t their_pos,
///                         const std::string& their_generation)
///   std::vector<GossipPeer> do_get_peers() const
template <typename Derived>
class IGossipProvider {
public:
    void add_peer(std::string_view endpoint, std::string_view pubkey) {
        self().do_add_peer(endpoint, pubkey);
    }

    void remove_peer(std::string_view pubkey) {
        self().do_remove_peer(pubkey);
    }

    void send_digest(const GossipPeer& peer) {
        self().do_send_digest(peer);
    }

    void handle_digest(const GossipPeer& peer, uint64_t their_pos,
                       const std::string& their_generation) {
        self().do_handle_digest(peer, their_pos, their_generation);
    }

    [[nodiscard]] std::vector<GossipPeer> get_peers() const {
        return self().do_get_peers();
    }

protected:
    ~IGossipProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IGossipProvider implementation.
template <typename T>
concept GossipProviderType = requires(T t, const T ct,
                                      std::string_view sv,
                                      const GossipPeer& peer) {
    { t.do_add_peer(sv, sv) } -> std::same_as<void>;
    { t.do_remove_peer(sv) } -> std::same_as<void>;
    { t.do_send_digest(peer) } -> std::same_as<void>;
    { t.do_handle_digest(peer, 0u, std::string{}) } -> std::same_as<void>;
    { ct.do_get_peers() } -> std::same_as<std::vector<GossipPeer>>;
};

} // namespace nexus::gossip
