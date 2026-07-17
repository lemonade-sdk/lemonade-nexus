#include <LemonadeNexus/Core/AdmissionTokenStore.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <fstream>
#include <span>
#include <sstream>
#include <system_error>

namespace nexus::core {

using json = nlohmann::json;

namespace {

uint64_t now_epoch_sec() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace

AdmissionTokenStore::AdmissionTokenStore(storage::FileStorageService& storage,
                                         crypto::SodiumCryptoService& crypto)
    : storage_(storage)
    , crypto_(crypto)
{
}

std::optional<std::pair<std::string, AdmissionTokenRecord>>
AdmissionTokenStore::mint(const std::string& candidate_pubkey, std::chrono::seconds ttl,
                          const std::string& server_id) {
    if (!candidate_pubkey.empty()) {
        bool valid = false;
        try {   // from_base64 throws on malformed input
            valid = crypto::from_base64(candidate_pubkey).size() ==
                    crypto::kEd25519PublicKeySize;
        } catch (...) {}
        if (!valid) {
            spdlog::error("[admission-token] Refusing mint: bind key is not a 32-byte "
                          "base64 Ed25519 public key");
            return std::nullopt;
        }
    }
    ttl = std::clamp(ttl, std::chrono::seconds{60}, kMaxTtl);

    std::array<uint8_t, 32> raw{};
    crypto_.random_bytes(std::span<uint8_t>(raw));
    auto token = "adm_" + crypto::to_hex(std::span<const uint8_t>(raw));

    auto now = now_epoch_sec();
    AdmissionTokenRecord record{
        .candidate_pubkey = candidate_pubkey,
        .server_id        = server_id,
        .created_at       = now,
        .expires_at       = now + static_cast<uint64_t>(ttl.count()),
    };

    json j = {
        {"candidate_pubkey", record.candidate_pubkey},
        {"server_id",        record.server_id},
        {"created_at",       record.created_at},
        {"expires_at",       record.expires_at},
    };

    auto path = token_path(token);
    try {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) {
            spdlog::error("[admission-token] Failed to open token file: {}", path.string());
            return std::nullopt;
        }
        ofs << j.dump(2);
        if (!ofs.good()) return std::nullopt;
    } catch (const std::exception& e) {
        spdlog::error("[admission-token] Exception writing token file: {}", e.what());
        return std::nullopt;
    }

    spdlog::info("[admission-token] Minted server-admission token (ttl {}s, bind {})",
                 ttl.count(), candidate_pubkey.empty() ? "any" : "candidate-key");
    return std::make_pair(std::move(token), std::move(record));
}

std::optional<AdmissionTokenRecord>
AdmissionTokenStore::verify(std::string_view token,
                            const std::string& candidate_pubkey) const {
    if (token.empty()) return std::nullopt;

    auto path = token_path(token);
    json j;
    {
        std::ifstream ifs(path);
        if (!ifs) return std::nullopt;
        std::ostringstream ss;
        ss << ifs.rdbuf();
        j = json::parse(ss.str(), nullptr, false);
        if (j.is_discarded()) return std::nullopt;
    }

    AdmissionTokenRecord record{
        .candidate_pubkey = j.value("candidate_pubkey", std::string{}),
        .server_id        = j.value("server_id", std::string{}),
        .created_at       = j.value("created_at", uint64_t{0}),
        .expires_at       = j.value("expires_at", uint64_t{0}),
    };

    if (record.expires_at <= now_epoch_sec()) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        spdlog::debug("[admission-token] Rejected expired token");
        return std::nullopt;
    }

    // Bind mismatch: reject but keep the file — only the bound key may spend it.
    if (!record.candidate_pubkey.empty() && record.candidate_pubkey != candidate_pubkey) {
        spdlog::warn("[admission-token] Token bound to a different candidate key");
        return std::nullopt;
    }
    return record;
}

std::optional<AdmissionTokenRecord>
AdmissionTokenStore::consume(std::string_view token, const std::string& candidate_pubkey) {
    auto record = verify(token, candidate_pubkey);
    if (!record) return std::nullopt;

    std::error_code ec;
    if (!std::filesystem::remove(token_path(token), ec)) {
        // Already consumed by a concurrent request — treat as spent.
        spdlog::warn("[admission-token] Token already consumed");
        return std::nullopt;
    }

    spdlog::info("[admission-token] Consumed server-admission token");
    return record;
}

std::filesystem::path AdmissionTokenStore::token_path(std::string_view token) const {
    // Store hashed so a data-root leak doesn't expose live tokens.
    auto hash = crypto_.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(token.data()), token.size()));
    auto name = crypto::to_hex(std::span<const uint8_t>(hash));
    return storage_.data_root() / "onboarding" / "admission_tokens" / (name + ".json");
}

} // namespace nexus::core
