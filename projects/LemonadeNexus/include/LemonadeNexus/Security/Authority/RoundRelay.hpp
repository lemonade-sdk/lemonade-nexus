#pragma once

// The key-generation race fix (design Part C), in one place for every
// multi-round key protocol: the FROST epoch DKG (DkgSession and the lifecycle
// driver) and the storage-key sessions (StorageKeyService).
//
// Datagrams are mortal, and a fast participant's round-2 package can reach a
// peer before that peer finished round 1, or before its session exists. Two
// parts keep every honest participant finishing without a stall:
//
// - RoundInbox holds at most one message per sender for one round. A message
//   that arrives before the receiver reached the round is held early and
//   counts when the receiver gets there. A second, different message from the
//   same sender is equivocation.
// - ResendCadence paces the re-sending of a participant's own messages. The
//   owner re-sends while its session runs and for a bounded tail after it
//   completed, because a peer may still miss a package.
//
// Neither part decides validity. The caller checks the binding of each message
// before it reaches the inbox, and decides what a full round means.

#include <cstddef>
#include <cstdint>
#include <map>

namespace nexus::security {

/// What RoundInbox::accept did with one message.
enum class RoundAccept : uint8_t {
    /// First message from this sender for this round.
    Accepted,
    /// The same bytes again: a re-send, benign.
    Duplicate,
    /// Different bytes from a sender that already spoke in this round.
    Equivocation,
};

/// One round's messages, at most one per sender. `Sender` is any ordered key
/// (a node id, a holder index); `Payload` must be equality-comparable.
template <typename Sender, typename Payload>
class RoundInbox {
public:
    /// Holds `payload` from `sender`. `early` is true while the receiver has
    /// not reached this round: the message is held, bounded to one per
    /// sender, and counts only after release_early().
    [[nodiscard]] RoundAccept accept(const Sender& sender, const Payload& payload, bool early) {
        for (const auto* held : {&counted_, &early_}) {
            const auto existing = held->find(sender);
            if (existing != held->end()) {
                return existing->second == payload ? RoundAccept::Duplicate
                                                   : RoundAccept::Equivocation;
            }
        }
        (early ? early_ : counted_).emplace(sender, payload);
        return RoundAccept::Accepted;
    }

    /// The receiver reached this round: messages held early count now.
    void release_early() {
        counted_.merge(early_);
        early_.clear();
    }

    /// The messages that count, by sender.
    [[nodiscard]] const std::map<Sender, Payload>& messages() const { return counted_; }
    [[nodiscard]] std::size_t size() const { return counted_.size(); }
    /// True when `sender` spoke in this round, counted or early.
    [[nodiscard]] bool contains(const Sender& sender) const {
        return counted_.contains(sender) || early_.contains(sender);
    }

    void clear() {
        counted_.clear();
        early_.clear();
    }

private:
    std::map<Sender, Payload> counted_;
    std::map<Sender, Payload> early_;
};

/// Paces re-sends of a participant's own messages: due() answers true at most
/// once per interval. Liveness only; a re-send never changes validity.
class ResendCadence {
public:
    explicit ResendCadence(uint64_t interval_ms) : interval_ms_(interval_ms) {}

    /// True when a re-send is due at `now_ms`; records the re-send.
    [[nodiscard]] bool due(uint64_t now_ms) {
        if (now_ms - last_ms_ < interval_ms_) {
            return false;
        }
        last_ms_ = now_ms;
        return true;
    }

    /// Records a send made outside the cadence (the first send of a round), so
    /// the next re-send waits one full interval.
    void mark(uint64_t now_ms) { last_ms_ = now_ms; }

private:
    uint64_t interval_ms_;
    uint64_t last_ms_ = 0;
};

}  // namespace nexus::security
