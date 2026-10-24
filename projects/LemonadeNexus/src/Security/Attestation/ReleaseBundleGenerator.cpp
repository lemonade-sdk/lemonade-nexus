#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include "../AttestationDetail.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <set>

namespace nexus::security {
namespace {

using detail::valid_hex;

std::optional<std::string> sha256_of_file(const std::filesystem::path& file) {
    std::ifstream stream(file, std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    std::array<char, 64 * 1024> chunk{};
    while (stream.read(chunk.data(), chunk.size()) || stream.gcount() > 0) {
        crypto_hash_sha256_update(&state,
                                  reinterpret_cast<const unsigned char*>(chunk.data()),
                                  static_cast<unsigned long long>(stream.gcount()));
    }
    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256_final(&state, digest.data());
    return crypto::to_hex(digest);
}

}  // namespace

std::optional<ReleaseApprovalV1> generate_release_approval(const ReleaseBundleSpec& spec,
                                                           std::string& error) {
    error.clear();
    if (spec.release_id.empty() || spec.nexus_version.empty()) {
        error = "release_id and nexus_version are required";
        return std::nullopt;
    }
    if (!valid_hex(spec.final_patched_tree, 40)) {
        error = "final_patched_tree must be the 40-hex git tree of the built source";
        return std::nullopt;
    }
    if (!valid_hex(spec.network_id_hex, 64)) {
        error = "network_id must be the 64-hex network id";
        return std::nullopt;
    }
    if (crypto::canonical_key_b64(spec.signer_pubkey_b64) != spec.signer_pubkey_b64 ||
        spec.signer_pubkey_b64.empty()) {
        error = "signer_pubkey must be a canonical base64 Ed25519 public key";
        return std::nullopt;
    }
    if (spec.qualification_state == "PENDING_LIVE_QUALIFICATION") {
        if (!spec.expected_pcrs.empty()) {
            error = "a pending approval must not carry PCR values";
            return std::nullopt;
        }
    } else if (spec.qualification_state == "LIVE_BOOT_APPROVED") {
        if (spec.expected_pcrs.size() != 2 || spec.expected_pcrs[0].first != 8 ||
            spec.expected_pcrs[1].first != 9 ||
            !valid_hex(spec.expected_pcrs[0].second, 64) ||
            !valid_hex(spec.expected_pcrs[1].second, 64)) {
            error = "a qualified approval carries exactly SHA-256 PCR8 and PCR9";
            return std::nullopt;
        }
    } else {
        error = "unknown qualification_state";
        return std::nullopt;
    }
    // Producer side canonicalizes by sorting; verification then enforces the
    // sorted-unique form. Duplicates are an authoring error, not repairable.
    auto measurements = spec.svsm_launch_measurements;
    if (!measurements.empty()) {
        for (const auto& measurement : measurements) {
            if (!valid_hex(measurement, 96)) {
                error = "svsm_launch_measurements entries must be 96 lowercase hex: " +
                        measurement;
                return std::nullopt;
            }
        }
        std::sort(measurements.begin(), measurements.end());
        if (std::adjacent_find(measurements.begin(), measurements.end()) !=
            measurements.end()) {
            error = "duplicate svsm_launch_measurements entry";
            return std::nullopt;
        }
    }
    if (spec.artifacts.empty()) {
        error = "no artifacts given";
        return std::nullopt;
    }
    if (spec.previous) {
        // Only digests the same release key approved are carried over.
        const auto signature = crypto::from_base64(spec.previous->signature_b64);
        const auto signer = crypto::from_base64(spec.signer_pubkey_b64);
        const auto preimage = canonical_release_approval_json(*spec.previous);
        if (spec.previous->signer_pubkey_b64 != spec.signer_pubkey_b64 ||
            spec.previous->network_id_hex != spec.network_id_hex ||
            signature.size() != crypto_sign_BYTES || signer.size() != crypto_sign_PUBLICKEYBYTES ||
            crypto_sign_verify_detached(signature.data(),
                                        reinterpret_cast<const unsigned char*>(preimage.data()),
                                        preimage.size(), signer.data()) != 0) {
            error = "the previous approval is not signed by this release key for this network";
            return std::nullopt;
        }
    }
    if (spec.artifacts.size() > constants::kMaxSummarisedPaths) {
        error = "more artifacts than the summarised-path protocol bound";
        return std::nullopt;
    }

    ReleaseApprovalV1 approval = release_approval_template();
    approval.release_id = spec.release_id;
    approval.nexus_version = spec.nexus_version;
    approval.final_patched_tree = spec.final_patched_tree;
    approval.network_id_hex = spec.network_id_hex;
    approval.signer_pubkey_b64 = spec.signer_pubkey_b64;
    approval.qualification_state = spec.qualification_state;
    approval.expected_pcrs = spec.expected_pcrs;
    if (!measurements.empty()) {
        approval.svsm_launch_measurements_hex = std::move(measurements);
    }

    approval.approved_paths.clear();
    std::set<std::string> seen;
    bool have_nexus = false;
    bool have_collector = false;
    for (const auto& artifact : spec.artifacts) {
        if (artifact.installed_path.empty() || artifact.installed_path.front() != '/') {
            error = "artifact path is not absolute: " + artifact.installed_path;
            return std::nullopt;
        }
        if (!seen.insert(artifact.installed_path).second) {
            error = "duplicate artifact path: " + artifact.installed_path;
            return std::nullopt;
        }
        std::vector<std::string> digests;
        if (!artifact.file.empty()) {
            const auto digest = sha256_of_file(artifact.file);
            if (!digest.has_value()) {
                error = "cannot read artifact file: " + artifact.file.string();
                return std::nullopt;
            }
            digests.push_back(*digest);
        } else {
            if (artifact.sha256.empty()) {
                error = "artifact has neither a file nor digests: " + artifact.installed_path;
                return std::nullopt;
            }
            for (const auto& digest : artifact.sha256) {
                if (!valid_hex(digest, 64)) {
                    error = "artifact digest is not 64 lowercase hex: " + artifact.installed_path;
                    return std::nullopt;
                }
                if (std::find(digests.begin(), digests.end(), digest) == digests.end()) {
                    digests.push_back(digest);
                }
            }
        }
        if (spec.previous) {
            for (const auto& previous : spec.previous->approved_paths) {
                if (previous.path != artifact.installed_path) continue;
                for (const auto& digest : previous.sha256) {
                    if (valid_hex(digest, 64) &&
                        std::find(digests.begin(), digests.end(), digest) == digests.end()) {
                        digests.push_back(digest);
                    }
                }
            }
        }
        approval.approved_paths.push_back({artifact.installed_path, std::move(digests)});
        have_nexus |= artifact.installed_path == "/usr/bin/lemonade-nexus";
        have_collector |= artifact.installed_path == approval.evidence_collector_path;
    }
    if (!have_nexus || !have_collector) {
        error = "artifacts must include /usr/bin/lemonade-nexus and the evidence collector";
        return std::nullopt;
    }
    return approval;
}

std::string unsigned_release_bundle_json(const ReleaseApprovalV1& approval) {
    ReleaseAuthorityV1 authority;
    authority.network_id_hex = approval.network_id_hex;
    authority.release_signing_pubkey_b64 = approval.signer_pubkey_b64;

    // Reuse the canonical forms so the file fields are exactly the signed ones.
    auto authority_json = nlohmann::json::parse(canonical_release_authority_json(authority));
    authority_json["genesis_signature"] = "";
    auto approval_json = nlohmann::json::parse(canonical_release_approval_json(approval));
    approval_json["signature"] = "";

    nlohmann::json root;
    root["authority"] = std::move(authority_json);
    root["approval"] = std::move(approval_json);
    return root.dump(2);
}

}  // namespace nexus::security
