#pragma once

#include <LemonadeNexus/Gossip/GossipTypes.hpp>

#include <nlohmann/json.hpp>

#include <concepts>
#include <string_view>
#include <vector>

namespace nexus::gossip {

/// CRTP base for gossip protocol operations.
/// Derived must implement:
///   void do_add_peer(std::string_view endpoint, std::string_view pubkey)
///   void do_remove_peer(std::string_view pubkey)
///   void do_send_digest(const GossipPeer& peer)
///   void do_handle_digest(const GossipPeer& peer, uint64_t their_seq, const std::array<uint8_t,32>& their_hash)
///   void do_send_deltas(const GossipPeer& peer, uint64_t from_seq)
///   void do_handle_deltas(const GossipPeer& peer, const nlohmann::json& deltas_json)
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

    void handle_digest(const GossipPeer& peer, uint64_t their_seq,
                       const std::array<uint8_t, 32>& their_hash) {
        self().do_handle_digest(peer, their_seq, their_hash);
    }

    void send_deltas(const GossipPeer& peer, uint64_t from_seq) {
        self().do_send_deltas(peer, from_seq);
    }

    void handle_deltas(const GossipPeer& peer, const nlohmann::json& deltas_json) {
        self().do_handle_deltas(peer, deltas_json);
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
                                       const GossipPeer& peer,
                                       uint64_t seq,
                                       const std::array<uint8_t, 32>& hash,
                                       const nlohmann::json& j) {
    { t.do_add_peer(sv, sv) } -> std::same_as<void>;
    { t.do_remove_peer(sv) } -> std::same_as<void>;
    { t.do_send_digest(peer) } -> std::same_as<void>;
    { t.do_handle_digest(peer, seq, hash) } -> std::same_as<void>;
    { t.do_send_deltas(peer, seq) } -> std::same_as<void>;
    { t.do_handle_deltas(peer, j) } -> std::same_as<void>;
    { ct.do_get_peers() } -> std::same_as<std::vector<GossipPeer>>;
};

} // namespace nexus::gossip
