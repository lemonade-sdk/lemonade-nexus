#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::account {

inline constexpr std::size_t kMaxAvatarRecordBytes = 2048;
inline constexpr uint64_t kMaxAvatarRevision = 9007199254740991ULL;
inline constexpr std::string_view kAvatarSyncStream = "avatar-ref";

/// A device-signed account image reference. Image bytes stay on account devices.
/// An empty image_hash retains a removal. Revisions are logical counters.
/// Concurrent records order by revision, author, then hash.
struct AccountAvatarRecord {
    std::string group_id;
    std::string author_pubkey;
    uint64_t revision{0};
    std::string image_hash;
    std::string signature;
};

/// Canonical JSON bytes covered by the device signature.
[[nodiscard]] std::string avatar_canonical(const AccountAvatarRecord& record);
/// JSON transport form, including the device signature.
[[nodiscard]] nlohmann::json avatar_wire(const AccountAvatarRecord& record);
/// Bounded, versioned decoder. Cryptographic and PNG checks are separate.
[[nodiscard]] std::optional<AccountAvatarRecord> avatar_from_wire(const nlohmann::json& value);
/// Verify the device signature and a lowercase SHA-256 digest (or removal).
/// This verifies identity only; the store checks current authority.
[[nodiscard]] bool verify_avatar(const AccountAvatarRecord& record,
                                  crypto::SodiumCryptoService& crypto);
/// Deterministic last-writer order, shared by storage and replication.
[[nodiscard]] bool avatar_newer(const AccountAvatarRecord& a, const AccountAvatarRecord& b);

} // namespace nexus::account
