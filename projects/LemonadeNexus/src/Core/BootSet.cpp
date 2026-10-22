#include <LemonadeNexus/Core/BootSet.hpp>

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <iterator>
#include <system_error>
#include <thread>
#include <vector>

#ifndef _WIN32
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace nexus::core {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr uint32_t kStateVersion = 1;
constexpr std::string_view kPendingName = "sealed-pending";
constexpr std::string_view kSealedName = "sealed";

struct BootSetState {
    GossipIdentityProtection protection{GossipIdentityProtection::SealedPending};
    std::string sealed_boot_id;
    std::string public_key_b64;
};

fs::path state_path(const fs::path& data_root) {
    return data_root / std::string(kSealedDirectory) /
           (std::string(kGossipIdentitySealDomain) + ".state.json");
}

fs::path legacy_path(const fs::path& data_root) {
    return data_root / "identity" / "keypair.json";
}

std::optional<BootSetState> read_state(const fs::path& data_root, bool& unreadable) {
    unreadable = false;
    std::error_code ec;
    const auto path = state_path(data_root);
    if (!fs::exists(path, ec)) return std::nullopt;
    std::ifstream in(path);
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const json j = json::parse(text, nullptr, false);
    unreadable = true;
    if (j.is_discarded() || !j.is_object() || j.size() != 4 || !j.contains("version") ||
        !j["version"].is_number_unsigned() || j["version"].get<uint64_t>() != kStateVersion ||
        !j.contains("protection") || !j["protection"].is_string() ||
        !j.contains("sealed_boot_id") || !j["sealed_boot_id"].is_string() ||
        !j.contains("public_key") || !j["public_key"].is_string()) {
        return std::nullopt;
    }
    BootSetState state;
    const auto protection = j["protection"].get<std::string>();
    if (protection == kPendingName) {
        state.protection = GossipIdentityProtection::SealedPending;
    } else if (protection == kSealedName) {
        state.protection = GossipIdentityProtection::Sealed;
    } else {
        return std::nullopt;
    }
    state.sealed_boot_id = j["sealed_boot_id"].get<std::string>();
    state.public_key_b64 = j["public_key"].get<std::string>();
    unreadable = false;
    return state;
}

bool write_state(const fs::path& data_root, const BootSetState& state) {
    json j;
    j["version"] = kStateVersion;
    j["protection"] = std::string(state.protection == GossipIdentityProtection::Sealed
                                      ? kSealedName
                                      : kPendingName);
    j["sealed_boot_id"] = state.sealed_boot_id;
    j["public_key"] = state.public_key_b64;
    const auto path = state_path(data_root);
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (!security::write_durable(path, j.dump())) return false;
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec);
    return true;
}

/// The whole 64-byte secret key must be consistent: its seed regenerates the
/// same public key it carries.
bool consistent(const crypto::Ed25519Keypair& keypair) {
    std::array<uint8_t, crypto_sign_SEEDBYTES> seed{};
    crypto::Ed25519Keypair regenerated;
    crypto_sign_ed25519_sk_to_seed(seed.data(), keypair.private_key.data());
    crypto_sign_seed_keypair(regenerated.public_key.data(), regenerated.private_key.data(),
                             seed.data());
    sodium_memzero(seed.data(), seed.size());
    const bool same =
        sodium_memcmp(regenerated.private_key.data(), keypair.private_key.data(),
                      keypair.private_key.size()) == 0 &&
        regenerated.public_key == keypair.public_key;
    sodium_memzero(regenerated.private_key.data(), regenerated.private_key.size());
    return same;
}

/// The sealed plaintext is the 64-byte Ed25519 secret key; the public key is
/// its second half.
std::optional<crypto::Ed25519Keypair> keypair_from_secret(const crypto::SecureBuffer& secret) {
    if (secret.size() != crypto::kEd25519PrivateKeySize) return std::nullopt;
    crypto::Ed25519Keypair keypair;
    std::memcpy(keypair.private_key.data(), secret.data(), secret.size());
    crypto_sign_ed25519_sk_to_pk(keypair.public_key.data(), keypair.private_key.data());
    if (!consistent(keypair)) {
        sodium_memzero(keypair.private_key.data(), keypair.private_key.size());
        return std::nullopt;
    }
    return keypair;
}

enum class LegacyRead { Absent, Valid, Unreadable };

LegacyRead read_legacy(storage::FileStorageService& storage, crypto::Ed25519Keypair& out) {
    const auto envelope = storage.read_file("identity", "keypair.json");
    if (!envelope) {
        std::error_code ec;
        return fs::exists(storage.data_root() / "identity" / "keypair.json", ec)
                   ? LegacyRead::Unreadable
                   : LegacyRead::Absent;
    }
    json j = json::parse(envelope->data, nullptr, false);
    if (j.is_discarded() || !j.is_object() || !j.contains("public_key") ||
        !j.contains("private_key") || !j["public_key"].is_string() ||
        !j["private_key"].is_string()) {
        return LegacyRead::Unreadable;
    }
    std::vector<uint8_t> pub;
    std::vector<uint8_t> priv;
    try {
        pub = crypto::from_base64(j["public_key"].get<std::string>());
        priv = crypto::from_base64(j["private_key"].get<std::string>());
    } catch (const std::exception&) {
        return LegacyRead::Unreadable;
    }
    auto& encoded = j["private_key"].get_ref<std::string&>();
    sodium_memzero(encoded.data(), encoded.size());
    const bool sized = pub.size() == crypto::kEd25519PublicKeySize &&
                       priv.size() == crypto::kEd25519PrivateKeySize;
    if (sized) {
        std::memcpy(out.public_key.data(), pub.data(), pub.size());
        std::memcpy(out.private_key.data(), priv.data(), priv.size());
    }
    if (!priv.empty()) sodium_memzero(priv.data(), priv.size());
    if (!sized || !consistent(out)) {
        sodium_memzero(out.private_key.data(), out.private_key.size());
        return LegacyRead::Unreadable;
    }
    return LegacyRead::Valid;
}

/// Same envelope and format GossipService writes, so an older binary can still
/// read the file while the migration is pending.
bool write_legacy(storage::FileStorageService& storage, const crypto::Ed25519Keypair& keypair) {
    storage::SignedEnvelope envelope;
    envelope.type = "identity_keypair";
    json j;
    j["public_key"] = crypto::to_base64(keypair.public_key);
    j["private_key"] = crypto::to_base64(keypair.private_key);
    envelope.data = j.dump();
    auto& encoded = j["private_key"].get_ref<std::string&>();
    sodium_memzero(encoded.data(), encoded.size());
    envelope.signer_pubkey = "ed25519:" + crypto::to_base64(keypair.public_key);
    envelope.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    const bool ok = storage.write_file("identity", "keypair.json", envelope);
    sodium_memzero(envelope.data.data(), envelope.data.size());
    return ok;
}

/// Overwrite the plaintext file, flush it to the device, then remove it. The
/// overwrite is best effort (security::scrub_file).
bool scrub_legacy(const fs::path& data_root) {
    return security::scrub_file(legacy_path(data_root));
}

crypto::SecureBuffer secret_of(const crypto::Ed25519Keypair& keypair) {
    return crypto::SecureBuffer(
        std::span<const uint8_t>(keypair.private_key.data(), keypair.private_key.size()));
}

security::UnsealReply unseal_waiting(security::SealedBlobStore& store,
                                     const BootSetConfig& config) {
    auto reply = store.unseal(kGossipIdentitySealDomain);
    for (int attempt = 1;
         reply.status == security::SealStatus::Unreachable && attempt < config.unreachable_attempts;
         ++attempt) {
        if (attempt == 1) {
            spdlog::warn("[BootSet] nexus-attestd is unreachable ({}); waiting to unseal the "
                         "gossip identity",
                         reply.detail);
        }
        std::this_thread::sleep_for(config.retry_delay);
        reply = store.unseal(kGossipIdentitySealDomain);
    }
    return reply;
}

std::string recovery_text(security::SealStatus status, const std::string& detail,
                          const fs::path& data_root) {
    const auto blob = (data_root / std::string(kSealedDirectory) /
                       (std::string(kGossipIdentitySealDomain) + ".sealed"))
                          .string();
    const std::string why = std::string(security::seal_status_name(status)) +
                            (detail.empty() ? "" : " (" + detail + ")");
    switch (status) {
        case security::SealStatus::PolicyMismatch:
            return "the sealed gossip identity does not unseal: " + why +
                   ". PCR 8/9 differ from every sealed copy, so the boot chain (kernel, "
                   "initramfs, GRUB configuration, or kernel command line) changed without an "
                   "approved release staging a copy for it. Boot the previous boot entry; the "
                   "server re-seals to the running boot chain on its next start";
        case security::SealStatus::Corrupt:
            return "the sealed gossip identity does not unseal on this TPM: " + why +
                   ". Restore " + blob + " from a backup of this host";
        case security::SealStatus::Unavailable:
        case security::SealStatus::Unreachable:
            return "nexus-attestd cannot unseal the gossip identity: " + why +
                   ". Start nexus-attestd on this host. A new identity is not created while a "
                   "sealed one exists";
        default:
            return "the sealed gossip identity does not unseal: " + why;
    }
}

}  // namespace

std::string_view gossip_identity_protection_name(GossipIdentityProtection value) {
    switch (value) {
        case GossipIdentityProtection::LegacyFile:    return "legacy-file";
        case GossipIdentityProtection::SealedPending: return kPendingName;
        case GossipIdentityProtection::Sealed:        return kSealedName;
    }
    return "unknown";
}

std::string read_kernel_boot_id() {
#ifdef __linux__
    std::ifstream in("/proc/sys/kernel/random/boot_id");
    std::string id;
    std::getline(in, id);
    return id;
#else
    return {};
#endif
}

std::optional<std::string> gossip_public_key_b64(storage::FileStorageService& storage,
                                                 const fs::path& data_root) {
    crypto::Ed25519Keypair legacy;
    if (read_legacy(storage, legacy) == LegacyRead::Valid) {
        sodium_memzero(legacy.private_key.data(), legacy.private_key.size());
        return crypto::to_base64(legacy.public_key);
    }
    bool unreadable = false;
    if (const auto state = read_state(data_root, unreadable)) return state->public_key_b64;
    return std::nullopt;
}

namespace {

/// Seal the key, prove the sealed copy unseals to the same bytes, and record
/// SealedPending. Any failure leaves keypair.json as the identity's only copy.
GossipIdentityProtection migrate(security::SealedBlobStore& store, const BootSetConfig& config,
                                 const crypto::Ed25519Keypair& keypair) {
    if (!store.sealing_available()) return GossipIdentityProtection::LegacyFile;
    const auto secret = secret_of(keypair);
    const auto sealed = store.seal(kGossipIdentitySealDomain, secret.span());
    if (sealed.status != security::SealStatus::Ok) {
        if (sealed.status == security::SealStatus::Unavailable ||
            sealed.status == security::SealStatus::Unreachable) {
            spdlog::info("[BootSet] this host cannot seal ({}); the gossip identity stays in "
                         "identity/keypair.json",
                         sealed.detail);
        } else {
            spdlog::warn("[BootSet] sealing the gossip identity failed: {}{}{}; it stays in "
                         "identity/keypair.json",
                         security::seal_status_name(sealed.status),
                         sealed.detail.empty() ? "" : " — ", sealed.detail);
        }
        return GossipIdentityProtection::LegacyFile;
    }
    const auto check = store.unseal(kGossipIdentitySealDomain);
    if (check.status != security::SealStatus::Ok || check.plaintext.size() != secret.size() ||
        sodium_memcmp(check.plaintext.data(), secret.data(), secret.size()) != 0) {
        spdlog::warn("[BootSet] the sealed gossip identity did not unseal to the same key ({}); "
                     "removing it and keeping identity/keypair.json",
                     security::seal_status_name(check.status));
        (void)store.remove(kGossipIdentitySealDomain);
        std::error_code ec;
        fs::remove(state_path(config.data_root), ec);
        return GossipIdentityProtection::LegacyFile;
    }
    BootSetState state;
    state.protection = GossipIdentityProtection::SealedPending;
    state.sealed_boot_id = config.boot_id ? config.boot_id() : read_kernel_boot_id();
    state.public_key_b64 = crypto::to_base64(keypair.public_key);
    if (!write_state(config.data_root, state)) {
        spdlog::warn("[BootSet] could not record the sealing state; keeping identity/keypair.json");
        return GossipIdentityProtection::LegacyFile;
    }
    spdlog::info("[BootSet] sealed the gossip identity; identity/keypair.json is removed after "
                 "the sealed copy unseals in a later boot");
    return GossipIdentityProtection::SealedPending;
}

/// The sealed copy unsealed. Advance the migration and decide what happens to
/// keypair.json.
std::optional<GossipIdentityProtection> settle_sealed(const BootSetConfig& config,
                                                      const crypto::Ed25519Keypair& keypair,
                                                      bool legacy_present,
                                                      const std::optional<BootSetState>& state,
                                                      std::string& error) {
    const std::string boot = config.boot_id ? config.boot_id() : read_kernel_boot_id();
    BootSetState next;
    next.public_key_b64 = crypto::to_base64(keypair.public_key);

    if (!legacy_present) {
        if (state && state->protection == GossipIdentityProtection::Sealed &&
            state->public_key_b64 == next.public_key_b64) {
            return GossipIdentityProtection::Sealed;
        }
        next.protection = GossipIdentityProtection::Sealed;
        next.sealed_boot_id = state ? state->sealed_boot_id : boot;
        if (!write_state(config.data_root, next)) {
            error = "could not record the sealing state in " +
                    state_path(config.data_root).string();
            return std::nullopt;
        }
        return GossipIdentityProtection::Sealed;
    }

    const bool later_boot = state && state->protection == GossipIdentityProtection::SealedPending &&
                            !state->sealed_boot_id.empty() && !boot.empty() &&
                            boot != state->sealed_boot_id;
    const bool already_sealed = state && state->protection == GossipIdentityProtection::Sealed;
    if (later_boot || already_sealed) {
        // Record Sealed first: a crash between the two steps then leaves a
        // plaintext copy behind, never a missing key.
        next.protection = GossipIdentityProtection::Sealed;
        next.sealed_boot_id = state->sealed_boot_id;
        if (!write_state(config.data_root, next)) {
            error = "could not record the sealing state in " +
                    state_path(config.data_root).string();
            return std::nullopt;
        }
        if (!scrub_legacy(config.data_root)) {
            spdlog::warn("[BootSet] could not remove identity/keypair.json; remove it by hand");
        } else {
            spdlog::info("[BootSet] the sealed gossip identity unsealed after a reboot; removed "
                         "identity/keypair.json");
        }
        return GossipIdentityProtection::Sealed;
    }
    if (!state) {
        next.protection = GossipIdentityProtection::SealedPending;
        next.sealed_boot_id = boot;
        if (!write_state(config.data_root, next)) {
            spdlog::warn("[BootSet] could not record the sealing state");
        }
    }
    return GossipIdentityProtection::SealedPending;
}

}  // namespace

std::optional<GossipIdentity> load_gossip_identity(storage::FileStorageService& storage,
                                                   const BootSetConfig& config,
                                                   std::string& error) {
    security::SealedBlobStore store{config.data_root / std::string(kSealedDirectory),
                                    config.backend};
    store.set_next_boot_chain(config.next_boot_chain);

    bool state_unreadable = false;
    const auto state = read_state(config.data_root, state_unreadable);
    if (state_unreadable) {
        error = "the boot-set state file " + state_path(config.data_root).string() +
                " is unreadable";
        return std::nullopt;
    }
    const bool complete = state && state->protection == GossipIdentityProtection::Sealed;

    GossipIdentity identity;
    const LegacyRead legacy = read_legacy(storage, identity.keypair);
    if (legacy == LegacyRead::Unreadable) {
        // Today's loader replaced an unreadable key with a new one. A changed
        // identity is never the safe answer, so this stops startup instead.
        error = "identity/keypair.json exists but does not hold a valid Ed25519 key pair";
        return std::nullopt;
    }
    const bool legacy_present = legacy == LegacyRead::Valid;

    if (store.contains(kGossipIdentitySealDomain)) {
        const auto reply = unseal_waiting(store, config);
        std::optional<crypto::Ed25519Keypair> sealed;
        if (reply.status == security::SealStatus::Ok) sealed = keypair_from_secret(reply.plaintext);
        if (sealed) {
            if (legacy_present && sealed->public_key != identity.keypair.public_key) {
                error = "identity/keypair.json holds a different key than the sealed gossip "
                        "identity. Remove the file that is wrong; the server does not choose "
                        "between two identities";
                return std::nullopt;
            }
            if (state && state->public_key_b64 != crypto::to_base64(sealed->public_key)) {
                error = "the boot-set state file names a different key than the sealed gossip "
                        "identity";
                return std::nullopt;
            }
            const auto protection =
                settle_sealed(config, *sealed, legacy_present, state, error);
            if (!protection) return std::nullopt;
            identity.keypair = *sealed;
            identity.protection = *protection;
            return identity;
        }
        const auto status = reply.status == security::SealStatus::Ok
                                ? security::SealStatus::Corrupt
                                : reply.status;
        if (legacy_present && !complete) {
            spdlog::warn("[BootSet] the sealed gossip identity did not unseal ({}{}{}); using "
                         "identity/keypair.json and sealing it again",
                         security::seal_status_name(status), reply.detail.empty() ? "" : " — ",
                         reply.detail);
            identity.protection = migrate(store, config, identity.keypair);
            return identity;
        }
        error = recovery_text(status, reply.detail, config.data_root);
        return std::nullopt;
    }

    // A state file without a sealed copy or a plaintext copy means the key is
    // gone. A new identity is never the silent answer.
    if (complete || (state && !legacy_present)) {
        error = "the sealed gossip identity is missing from " +
                store.current_path(kGossipIdentitySealDomain).string() +
                (legacy_present ? ", and identity/keypair.json is not used after sealing "
                                  "completed"
                                : ", and identity/keypair.json is gone") +
                ". Restore the sealed file from a backup of this host. " +
                (legacy_present ? std::string("To use the key in identity/keypair.json "
                                              "instead, remove ")
                                : std::string("To start over with a new identity (which "
                                              "needs new enrollment), remove ")) +
                state_path(config.data_root).string();
        return std::nullopt;
    }

    if (!legacy_present) {
        if (!config.create_if_absent) {
            error = "this server has no gossip identity";
            return std::nullopt;
        }
        crypto_sign_ed25519_keypair(identity.keypair.public_key.data(),
                                    identity.keypair.private_key.data());
        // The plaintext file comes first, so a host whose vTPM loses its seed
        // at reboot still has the key; the migration removes it later.
        if (!write_legacy(storage, identity.keypair)) {
            error = "could not write identity/keypair.json";
            return std::nullopt;
        }
        identity.created = true;
        spdlog::info("[BootSet] generated a new gossip identity");
    }
    identity.protection = migrate(store, config, identity.keypair);
    return identity;
}

}  // namespace nexus::core
