#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <spdlog/spdlog.h>

#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>

namespace nexus::security {

namespace fs = std::filesystem;

std::string_view seal_status_name(SealStatus status) {
    switch (status) {
        case SealStatus::Ok:             return "ok";
        case SealStatus::Missing:        return "missing";
        case SealStatus::Unavailable:    return "unavailable";
        case SealStatus::Unreachable:    return "unreachable";
        case SealStatus::PolicyMismatch: return "policy_mismatch";
        case SealStatus::Corrupt:        return "corrupt";
        case SealStatus::Failed:         return "failed";
    }
    return "unknown";
}

SealedBlobStore::SealedBlobStore(fs::path directory, SealBackend backend)
    : directory_(std::move(directory)), backend_(std::move(backend)) {}

void SealedBlobStore::set_next_boot_chain(std::optional<BootPcrValues> values) {
    next_boot_chain_ = std::move(values);
}

fs::path SealedBlobStore::current_path(std::string_view name) const {
    return directory_ / (std::string(name) + ".sealed");
}

fs::path SealedBlobStore::next_path(std::string_view name) const {
    return directory_ / (std::string(name) + ".next.sealed");
}

bool SealedBlobStore::contains(std::string_view name) const {
    std::error_code ec;
    return valid_seal_domain(name) &&
           (fs::exists(current_path(name), ec) || fs::exists(next_path(name), ec));
}

bool SealedBlobStore::remove(std::string_view name) {
    if (!valid_seal_domain(name)) return false;
    std::error_code ec;
    fs::remove(current_path(name), ec);
    fs::remove(next_path(name), ec);
    return !contains(name);
}

bool SealedBlobStore::write_blob(const fs::path& path, std::string_view blob,
                                 std::string& why) const {
    std::error_code ec;
    fs::create_directories(directory_, ec);
    fs::permissions(directory_, fs::perms::owner_all, fs::perm_options::replace, ec);
    if (!write_durable(path, blob)) {
        why = "could not write " + path.string();
        return false;
    }
    // The blob is useless without this TPM, but nothing else needs to read it.
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec);
    return true;
}

std::optional<std::string> SealedBlobStore::read_blob(const fs::path& path) const {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec) return std::nullopt;
    // An oversized file is reported as present but unreadable: the backend
    // refuses it as corrupt, which keeps "missing" meaning "no file".
    if (size > kMaxSealedBlobBytes) return std::string{};
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void SealedBlobStore::stage_next(std::string_view name, std::span<const uint8_t> plaintext,
                                 const Digest& current_binding) {
    if (!next_boot_chain_) return;
    const auto next_file = next_path(name);
    std::error_code ec;
    const Digest target = boot_pcr_digest(*next_boot_chain_);
    if (target == current_binding) {
        // The approved chain is the running chain: nothing to stage, and an
        // older staged blob is obsolete.
        if (fs::remove(next_file, ec)) {
            spdlog::info("[sealed] {}: removed the staged blob; the approved boot chain is running",
                         name);
        }
        return;
    }
    if (const auto existing = read_blob(next_file)) {
        if (const auto parsed = decode_sealed_blob(*existing);
            parsed && parsed->pcr_digest == target) {
            return;  // already staged for this approval
        }
    }
    const auto reply = backend_.seal(name, plaintext, *next_boot_chain_);
    std::string why;
    if (reply.status != SealStatus::Ok) {
        spdlog::warn("[sealed] {}: could not stage a blob for the approved next boot chain: {}{}{}",
                     name, seal_status_name(reply.status), reply.detail.empty() ? "" : " — ",
                     reply.detail);
        return;
    }
    const auto parsed = decode_sealed_blob(reply.blob);
    if (!parsed || parsed->pcr_digest != target || !write_blob(next_file, reply.blob, why)) {
        spdlog::warn("[sealed] {}: could not store the blob for the approved next boot chain{}{}",
                     name, why.empty() ? "" : ": ", why);
        return;
    }
    spdlog::info("[sealed] {}: staged a blob for the approved next boot chain", name);
}

SealReply SealedBlobStore::seal(std::string_view name, std::span<const uint8_t> plaintext) {
    SealReply out;
    if (!valid_seal_domain(name)) {
        out.detail = "invalid sealing domain name";
        return out;
    }
    if (!backend_.available()) {
        out.status = SealStatus::Unavailable;
        out.detail = "this build has no sealing backend";
        return out;
    }
    out = backend_.seal(name, plaintext, std::nullopt);
    if (out.status != SealStatus::Ok) return out;

    const auto parsed = decode_sealed_blob(out.blob);
    std::string why;
    if (!parsed || parsed->domain != name) {
        out.status = SealStatus::Failed;
        out.detail = "the sealing daemon returned a blob that does not parse for this domain";
        out.blob.clear();
        return out;
    }
    if (!write_blob(current_path(name), out.blob, why)) {
        out.status = SealStatus::Failed;
        out.detail = why;
        out.blob.clear();
        return out;
    }
    // A next blob holds the previous secret; re-stage it for the new one or drop it.
    std::error_code ec;
    fs::remove(next_path(name), ec);
    stage_next(name, plaintext, parsed->pcr_digest);
    return out;
}

UnsealReply SealedBlobStore::unseal(std::string_view name) {
    UnsealReply out;
    if (!valid_seal_domain(name)) {
        out.detail = "invalid sealing domain name";
        return out;
    }
    const auto current = read_blob(current_path(name));
    const auto next = read_blob(next_path(name));
    if (!current && !next) {
        out.status = SealStatus::Missing;
        return out;
    }
    if (!backend_.available()) {
        out.status = SealStatus::Unavailable;
        out.detail = "this build has no sealing backend";
        return out;
    }

    if (current) {
        out = backend_.unseal(name, *current);
        if (out.status == SealStatus::Ok) {
            if (const auto parsed = decode_sealed_blob(*current)) {
                stage_next(name, out.plaintext.span(), parsed->pcr_digest);
            }
            return out;
        }
        // Without a reachable daemon the next blob cannot be tried either.
        if (out.status == SealStatus::Unavailable || out.status == SealStatus::Unreachable ||
            !next) {
            return out;
        }
    }

    auto from_next = backend_.unseal(name, *next);
    if (from_next.status != SealStatus::Ok) {
        return current ? std::move(out) : std::move(from_next);
    }
    // The running boot chain is the one the next blob was staged for. Bind the
    // secret to it as the current blob, then drop the staged copy. If that
    // fails, both files stay and the next start tries again.
    const auto resealed = backend_.seal(name, from_next.plaintext.span(), std::nullopt);
    std::string why;
    const auto parsed = resealed.status == SealStatus::Ok ? decode_sealed_blob(resealed.blob)
                                                          : std::nullopt;
    if (parsed && parsed->domain == name &&
        write_blob(current_path(name), resealed.blob, why)) {
        std::error_code ec;
        fs::remove(next_path(name), ec);
        spdlog::info("[sealed] {}: unsealed the staged blob and re-sealed it to the running "
                     "boot chain",
                     name);
        stage_next(name, from_next.plaintext.span(), parsed->pcr_digest);
    } else {
        spdlog::warn("[sealed] {}: unsealed the staged blob but could not re-seal it: {}{}{}",
                     name, seal_status_name(resealed.status),
                     resealed.detail.empty() && why.empty() ? "" : " — ",
                     why.empty() ? resealed.detail : why);
    }
    return from_next;
}

}  // namespace nexus::security
