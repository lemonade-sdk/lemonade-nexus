#include <LemonadeNexus/Core/BootChainStaging.hpp>

#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <iterator>

namespace nexus::core {

namespace fs = std::filesystem;

namespace {

constexpr std::string_view kCurrentSuffix = ".sealed";
constexpr std::string_view kNextSuffix = ".next.sealed";

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

std::optional<security::SealedBlob> read_blob(const fs::path& path) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > security::kMaxSealedBlobBytes) return std::nullopt;
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    return security::decode_sealed_blob(text);
}

}  // namespace

BootChainStageResult stage_boot_chain_for_approval(
    const BootChainStagingInputs& inputs, const security::ReleaseApprovalBundleV1& accepted) {
    BootChainStageResult result;
    const auto next = security::boot_pcrs_from_approval(accepted.approval);
    if (!next) {
        result.detail = "the release approval carries no qualified PCR 8/9 values";
        return result;
    }
    const auto target = security::boot_pcr_digest(*next);

    std::vector<std::string> names;
    std::error_code ec;
    // No directory: this host seals nothing, so a reboot loses nothing.
    const bool have_directory = fs::is_directory(inputs.sealed_directory, ec);
    for (const auto& entry : have_directory
                                 ? fs::directory_iterator(inputs.sealed_directory, ec)
                                 : fs::directory_iterator()) {
        const auto file = entry.path().filename().string();
        if (!ends_with(file, kCurrentSuffix) || ends_with(file, kNextSuffix)) continue;
        const auto name = file.substr(0, file.size() - kCurrentSuffix.size());
        if (security::valid_seal_domain(name)) names.push_back(name);
    }
    if (ec) {
        result.detail = "cannot list " + inputs.sealed_directory.string();
        return result;
    }
    std::sort(names.begin(), names.end());

    security::SealedBlobStore store{inputs.sealed_directory, inputs.backend};
    store.set_next_boot_chain(*next);
    for (const auto& name : names) {
        // A successful unseal stages the next slot (SealedBlobStore::stage_next).
        const auto reply = store.unseal(name);
        if (reply.status != security::SealStatus::Ok) {
            result.detail = name + ": cannot unseal the current blob: " +
                            std::string(security::seal_status_name(reply.status));
            return result;
        }
        const auto current = read_blob(store.current_path(name));
        if (current && current->pcr_digest == target) {
            continue;  // the approved chain is the running chain
        }
        const auto staged = read_blob(store.next_path(name));
        if (!staged || staged->pcr_digest != target || staged->domain != name) {
            result.detail = name + ": no blob is staged for the approved boot chain";
            return result;
        }
        result.staged.push_back(name);
    }
    result.ok = true;
    result.detail = names.empty() ? "no sealed boot-set secrets on this host"
                                  : "staged for release " + accepted.approval.release_id;
    spdlog::info("[update] boot chain staged for release {} ({} secrets)",
                 accepted.approval.release_id, result.staged.size());
    return result;
}

}  // namespace nexus::core
