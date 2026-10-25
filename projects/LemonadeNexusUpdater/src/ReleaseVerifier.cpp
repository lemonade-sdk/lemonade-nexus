#include <LemonadeNexusUpdater/ReleaseVerifier.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <set>

namespace nexus::updater {
namespace {

using json = nlohmann::json;

bool is_hex(std::string_view s, std::size_t length) {
    return s.size() == length && std::all_of(s.begin(), s.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

/// An asset name is a release file name: no separators, no traversal.
bool valid_asset_name(std::string_view s) {
    if (s.empty() || s.size() > 200 || s == "." || s == "..") return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '.' || c == '-' || c == '_' || c == '+';
    });
}

bool get_string(const json& j, const char* key, std::string& out) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return false;
    out = it->get<std::string>();
    return true;
}

bool get_object(const json& j, const char* key, const json*& out) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_object()) return false;
    out = &*it;
    return true;
}

}  // namespace

std::string sha256_hex(std::string_view bytes) {
    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(bytes.data()),
                       bytes.size());
    return crypto::to_hex(digest);
}

std::optional<std::string> sha256_file_hex(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    std::array<char, 64 * 1024> chunk{};
    while (in.read(chunk.data(), chunk.size()) || in.gcount() > 0) {
        crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char*>(chunk.data()),
                                  static_cast<unsigned long long>(in.gcount()));
    }
    if (in.bad()) return std::nullopt;
    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256_final(&state, digest.data());
    return crypto::to_hex(digest);
}

std::optional<ReleaseManifest> parse_release_manifest(std::string_view text, std::string& error) {
    if (text.size() > kMaxManifestBytes) {
        error = "the manifest is too large";
        return std::nullopt;
    }
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        error = "the manifest is not a JSON object";
        return std::nullopt;
    }
    ReleaseManifest m;
    const json* approval = nullptr;
    const json* os = nullptr;
    const auto fv = j.find("format_version");
    const auto rn = j.find("release_number");
    if (fv == j.end() || !fv->is_number_unsigned() || rn == j.end() ||
        !rn->is_number_unsigned() || !get_string(j, "repository", m.repository) ||
        !get_string(j, "tag", m.tag) || !get_string(j, "version", m.version) ||
        !get_string(j, "source_commit", m.source_commit) ||
        !get_object(j, "approval", approval) || !get_object(j, "os_packages", os)) {
        error = "the manifest is missing a required field";
        return std::nullopt;
    }
    m.format_version = fv->get<uint32_t>();
    m.release_number = rn->get<uint64_t>();
    if (m.format_version != kManifestFormatVersion) {
        error = "the manifest format version is not supported";
        return std::nullopt;
    }
    if (!is_hex(m.source_commit, 40)) {
        error = "the manifest source commit is not 40 hex";
        return std::nullopt;
    }
    if (!get_string(*approval, "asset", m.approval_asset) ||
        !get_string(*approval, "sha256", m.approval_sha256) ||
        !get_string(*approval, "digest", m.approval_digest) ||
        !valid_asset_name(m.approval_asset) || !is_hex(m.approval_sha256, 64) ||
        !is_hex(m.approval_digest, 64)) {
        error = "the manifest approval entry is invalid";
        return std::nullopt;
    }
    const auto bcc = os->find("boot_chain_changed");
    if (!get_string(*os, "asset", m.os_lock_asset) ||
        !get_string(*os, "sha256", m.os_lock_sha256) || bcc == os->end() ||
        !bcc->is_boolean() || !valid_asset_name(m.os_lock_asset) ||
        !is_hex(m.os_lock_sha256, 64)) {
        error = "the manifest OS package entry is invalid";
        return std::nullopt;
    }
    m.boot_chain_changed = bcc->get<bool>();

    const auto files = j.find("server_files");
    if (files == j.end() || !files->is_array() || files->empty() || files->size() > 16) {
        error = "the manifest has no server files";
        return std::nullopt;
    }
    std::set<std::string> paths;
    std::set<std::string> assets{m.approval_asset, m.os_lock_asset};
    if (assets.size() != 2) {
        error = "the manifest names one asset twice";
        return std::nullopt;
    }
    for (const auto& f : *files) {
        ManifestFile file;
        if (!f.is_object() || !get_string(f, "asset", file.asset) ||
            !get_string(f, "path", file.path) || !get_string(f, "sha256", file.sha256) ||
            !valid_asset_name(file.asset) || !is_hex(file.sha256, 64)) {
            error = "the manifest has an invalid server file entry";
            return std::nullopt;
        }
        if (std::find(std::begin(kSwappablePaths), std::end(kSwappablePaths), file.path) ==
            std::end(kSwappablePaths)) {
            error = "the manifest installs a path the updater does not replace: " + file.path;
            return std::nullopt;
        }
        if (!paths.insert(file.path).second || !assets.insert(file.asset).second) {
            error = "the manifest names one path or asset twice";
            return std::nullopt;
        }
        m.server_files.push_back(std::move(file));
    }
    if (paths.size() != std::size(kSwappablePaths)) {
        error = "the manifest must install every swappable path";
        return std::nullopt;
    }
    if (const auto arts = j.find("artifacts"); arts != j.end()) {
        if (!arts->is_array() || arts->size() > 512) {
            error = "the manifest artifact list is invalid";
            return std::nullopt;
        }
        for (const auto& a : *arts) {
            ManifestArtifact art;
            if (!a.is_object() || !get_string(a, "name", art.name) ||
                !get_string(a, "sha256", art.sha256) || !valid_asset_name(art.name) ||
                !is_hex(art.sha256, 64)) {
                error = "the manifest has an invalid artifact entry";
                return std::nullopt;
            }
            m.artifacts.push_back(std::move(art));
        }
    }
    return m;
}

std::optional<VerifiedRelease> verify_release_metadata(const ReleaseTrust& trust,
                                                       std::string_view manifest_bytes,
                                                       std::string_view manifest_signature_b64,
                                                       std::string_view approval_bytes,
                                                       uint64_t installed_release_number,
                                                       std::string& error) {
    error.clear();
    // 1. The approval, under the Genesis-delegated release key and this network.
    auto bundle = security::parse_release_approval_bundle(approval_bytes, error);
    if (!bundle) {
        error = "the release approval does not parse: " + error;
        return std::nullopt;
    }
    if (!security::verify_release_approval_bundle(*bundle, trust.genesis_public_key,
                                                  trust.network_id, error)) {
        error = "the release approval does not verify: " + error;
        return std::nullopt;
    }

    // 2. The release number: the signed release_number, which must be the
    //    number of the signed release_id tag.
    const auto tag = parse_release_tag(bundle->approval.release_id);
    if (!tag) {
        error = "the release approval id is not a release tag: " + bundle->approval.release_id;
        return std::nullopt;
    }
    if (bundle->approval.release_number != tag->number) {
        error = "the approval release_number does not match its tag " + tag->tag;
        return std::nullopt;
    }
    if (tag->number <= installed_release_number) {
        error = "release " + std::to_string(tag->number) +
                " is not newer than the installed release " +
                std::to_string(installed_release_number);
        return std::nullopt;
    }

    // 3. The manifest signature, under the same release key.
    const auto signer = crypto::from_base64(bundle->approval.signer_pubkey_b64);
    const auto signature = crypto::from_base64(manifest_signature_b64);
    std::string preimage(kManifestSignatureDomain);
    preimage.append(manifest_bytes);
    if (signer.size() != crypto_sign_PUBLICKEYBYTES || signature.size() != crypto_sign_BYTES ||
        crypto_sign_verify_detached(signature.data(),
                                    reinterpret_cast<const unsigned char*>(preimage.data()),
                                    preimage.size(), signer.data()) != 0) {
        error = "the manifest signature does not verify under the release key";
        return std::nullopt;
    }
    auto manifest = parse_release_manifest(manifest_bytes, error);
    if (!manifest) return std::nullopt;

    // 4. The manifest agrees with the approval and the pinned repository.
    if (manifest->repository != trust.repository) {
        error = "the manifest names repository " + manifest->repository;
        return std::nullopt;
    }
    if (manifest->tag != tag->tag || manifest->release_number != tag->number) {
        error = "the manifest tag or release number does not match the approval";
        return std::nullopt;
    }
    if (manifest->approval_digest != security::release_approval_digest_hex(bundle->approval) ||
        manifest->approval_sha256 != sha256_hex(approval_bytes)) {
        error = "the manifest does not name this approval";
        return std::nullopt;
    }
    for (const auto& file : manifest->server_files) {
        const auto it = std::find_if(bundle->approval.approved_paths.begin(),
                                     bundle->approval.approved_paths.end(),
                                     [&](const auto& p) { return p.path == file.path; });
        if (it == bundle->approval.approved_paths.end() || it->sha256.empty() ||
            it->sha256.front() != file.sha256) {
            error = "the approval does not list " + file.path + " with the manifest hash";
            return std::nullopt;
        }
    }

    VerifiedRelease out;
    out.approval = std::move(*bundle);
    out.manifest = std::move(*manifest);
    out.tag = *tag;
    out.approval_json = std::string(approval_bytes);
    return out;
}

bool verify_asset_hash(const VerifiedRelease& release, std::string_view asset,
                       std::string_view sha256, std::string& error) {
    const auto& m = release.manifest;
    std::string expected;
    if (asset == m.approval_asset) {
        expected = m.approval_sha256;
    } else if (asset == m.os_lock_asset) {
        expected = m.os_lock_sha256;
    } else {
        for (const auto& f : m.server_files) {
            if (f.asset == asset) expected = f.sha256;
        }
    }
    if (expected.empty()) {
        error = "asset " + std::string(asset) + " is not in the manifest";
        return false;
    }
    if (expected != sha256) {
        error = "asset " + std::string(asset) + " has SHA-256 " + std::string(sha256) +
                ", the signed manifest lists " + expected;
        return false;
    }
    return true;
}

}  // namespace nexus::updater
