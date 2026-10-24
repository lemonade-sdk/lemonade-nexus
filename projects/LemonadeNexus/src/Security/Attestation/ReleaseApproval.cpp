#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>

#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
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

using json = nlohmann::json;

// Pinned release line; pins are re-issued at each release cut.
// final_patched_tree is generator-computed from the built tree, never
// hand-typed.
constexpr std::string_view kExpectedSourceCommit =
    "dd80e7f99d104e6be71ee9c30e32d39ea911bec8";
constexpr std::string_view kExpectedStartingTree =
    "148bcf279cd18a7c46295fcd76db022ed5451422";
constexpr std::string_view kExpectedKernelRelease =
    "7.1.0-coconut-svsm-tier1+";
constexpr std::string_view kExpectedBzImage =
    "d9854417fea45a490b632b0e7860827b34443f94da0877e34a0633bbb5078584";
constexpr std::string_view kExpectedVmlinux =
    "dfb88d060ef4fca3b51ce87b95803ad6b64addaad840d4aecb63bc85e9bcd552";
constexpr std::string_view kExpectedModuleTree =
    "8735b602a2e2b86dcc5bd06426e345a09f9c279ceaeb989acd6db0b11279a2be";
constexpr std::string_view kExpectedModuleCertificate =
    "a43447d3a1658efc13eb1349f1d14e9727630280e5449c5c5459885f9eb88de5";
constexpr std::string_view kExpectedImaPolicyId = "nexus-tier1-ima-v1";
constexpr std::string_view kExpectedImaPolicy =
    "b3cabc30317af8b7127a175d7b4f906a40203e7ebe28122d82a713e03dad4092";
// One entry per approved VM shape. Keep sorted ascending and unique: the
// entries are the canonical set the preimage encodes verbatim.
constexpr std::string_view kExpectedLaunchMeasurements[] = {
    "2f073e15d2501910b6208ca52a349d16247d443f326cee2b46292d608821"
    "c6e84c2490814e22a2b5ba860a37208d1d9a",
    "bca89f077c4d647b08ce1fb83cfa92ff12789815378baa0de00ca883e40e"
    "79313e3df3f88b9798a7eb53ab1b3ff59a54",
};

json approved_paths_json(const std::vector<ApprovedPath>& paths) {
    json out = json::array();
    for (const auto& path : paths) {
        out.push_back({{"path", path.path}, {"sha256", path.sha256}});
    }
    return out;
}

json tcb_json(const TcbVersion& tcb) {
    return {{"bootloader", tcb.bootloader}, {"tee", tcb.tee},
            {"snp", tcb.snp}, {"microcode", tcb.microcode}};
}

json authority_preimage(const ReleaseAuthorityV1& authority) {
    return {{"format_version", authority.format_version},
            {"network_id", authority.network_id_hex},
            {"release_signing_pubkey", authority.release_signing_pubkey_b64}};
}

json approval_preimage(const ReleaseApprovalV1& approval) {
    json pcrs = json::array();
    for (const auto& [index, digest] : approval.expected_pcrs) {
        pcrs.push_back({{"index", index}, {"sha256", digest}});
    }
    json preimage = {
        {"format_version", approval.format_version},
        {"release_id", approval.release_id},
        {"nexus_version", approval.nexus_version},
        {"source_commit", approval.source_commit},
        {"starting_patched_tree", approval.starting_patched_tree},
        {"final_patched_tree", approval.final_patched_tree},
        {"network_id", approval.network_id_hex},
        {"security_wire_version", approval.security_wire_version},
        {"security_ruleset", approval.security_ruleset},
        {"consensus_ruleset", approval.consensus_ruleset},
        {"attestation_profile", approval.attestation_profile},
        {"attestation_profile_ruleset", approval.attestation_profile_ruleset},
        {"attestd_wire_version", approval.attestd_wire_version},
        {"ima_policy", {{"id", approval.ima_policy_id},
                         {"sha256", approval.ima_policy_sha256}}},
        {"kernel", {{"release", approval.kernel.release},
                     {"bzimage_sha256", approval.kernel.bzimage_sha256},
                     {"vmlinux_sha256", approval.kernel.vmlinux_sha256},
                     {"module_tree_sha256", approval.kernel.module_tree_sha256},
                     {"module_certificate_der_sha256",
                      approval.kernel.module_certificate_der_sha256}}},
        {"svsm_launch_measurements", approval.svsm_launch_measurements_hex},
        {"min_tcb", tcb_json(approval.min_tcb)},
        {"approved_paths", approved_paths_json(approval.approved_paths)},
        {"evidence_collector_path", approval.evidence_collector_path},
        {"expected_pcrs", std::move(pcrs)},
        {"qualification_state", approval.qualification_state},
        {"signer_pubkey", approval.signer_pubkey_b64},
    };
    // Format 2 has no such fields; adding them would change its digest, which
    // a stored bootstrap certificate commits.
    if (approval.format_version >= kReleaseApprovalFormatVersion) {
        preimage["release_number"] = approval.release_number;
        preimage["previous_release_paths"] =
            approved_paths_json(approval.previous_release_paths);
    }
    return preimage;
}

using detail::valid_hex;

bool valid_sha256(std::string_view value) { return valid_hex(value, 64); }

// Canonical measurement set: non-empty, 96 lowercase hex each, strictly
// ascending. Strict order makes the signed preimage deterministic and rejects
// duplicates in the same comparison.
bool valid_measurement_set(const std::vector<std::string>& measurements,
                           std::string& error) {
    if (measurements.empty()) {
        error = "release approval pins no SVSM launch measurement";
        return false;
    }
    for (std::size_t i = 0; i < measurements.size(); ++i) {
        if (!valid_hex(measurements[i], 96)) {
            error = "an SVSM launch measurement is not 96 lowercase hex characters";
            return false;
        }
        if (i != 0 && measurements[i - 1] >= measurements[i]) {
            error = "SVSM launch measurements are duplicated or not sorted";
            return false;
        }
    }
    return true;
}

bool verify_ed25519(std::string_view public_key_b64, std::string_view signature_b64,
                    std::string_view message) {
    try {
        const auto public_key = crypto::from_base64(public_key_b64);
        const auto signature = crypto::from_base64(signature_b64);
        if (public_key.size() != crypto::kEd25519PublicKeySize ||
            signature.size() != crypto::kEd25519SignatureSize) return false;
        return crypto_sign_verify_detached(
            signature.data(), reinterpret_cast<const unsigned char*>(message.data()),
            message.size(), public_key.data()) == 0;
    } catch (...) {
        return false;
    }
}

bool compiled_release_fields_match(const ReleaseApprovalV1& a, std::string& error) {
    if (a.format_version != kReleaseApprovalFormatVersion || a.release_id.empty() ||
        a.nexus_version.empty() || a.final_patched_tree.size() != 40) {
        error = "release identity is incomplete or has an unsupported format";
        return false;
    }
    if (a.release_number == 0 || a.release_number > kMaxReleaseNumber) {
        error = "release number is outside the valid range";
        return false;
    }
    if (a.source_commit != kExpectedSourceCommit ||
        a.starting_patched_tree != kExpectedStartingTree ||
        !valid_hex(a.final_patched_tree, 40)) {
        error = "release source identity does not match this current-head line";
        return false;
    }
    if (a.security_wire_version != constants::kSecurityWireVersion ||
        a.security_ruleset != constants::kSecurityRulesetVersion ||
        a.consensus_ruleset != constants::kConsensusRulesetVersion ||
        a.attestation_profile != "SnpSvsmVtpm" ||
        a.attestation_profile_ruleset != kAttestationProfileRulesetVersion ||
        a.attestd_wire_version != constants::kAttestdWireVersion) {
        error = "release protocol identity does not match the compiled protocol";
        return false;
    }
    if (!valid_measurement_set(a.svsm_launch_measurements_hex, error)) return false;
    // Set equality: both sides are canonically sorted and unique, so
    // element-wise comparison is the whole check.
    if (a.kernel.release != kExpectedKernelRelease ||
        a.kernel.bzimage_sha256 != kExpectedBzImage ||
        a.kernel.vmlinux_sha256 != kExpectedVmlinux ||
        a.kernel.module_tree_sha256 != kExpectedModuleTree ||
        a.kernel.module_certificate_der_sha256 != kExpectedModuleCertificate ||
        a.ima_policy_id != kExpectedImaPolicyId ||
        a.ima_policy_sha256 != kExpectedImaPolicy ||
        a.svsm_launch_measurements_hex.size() != std::size(kExpectedLaunchMeasurements) ||
        !std::equal(a.svsm_launch_measurements_hex.begin(),
                    a.svsm_launch_measurements_hex.end(),
                    std::begin(kExpectedLaunchMeasurements))) {
        error = "release kernel, IMA, or SVSM launch identity is not approved";
        return false;
    }
    // Floors from AMD-SB-3030/3034; policy cites no TEE or microcode minimum.
    if (a.min_tcb.bootloader < 0x0c || a.min_tcb.snp < 0x1c ||
        a.min_tcb.tee != 0 || a.min_tcb.microcode != 0) {
        error = "release TCB floor is below policy or invents an uncited component floor";
        return false;
    }
    return true;
}

ReleaseApprovalBundleV1 parse_bundle(const json& root) {
    ReleaseApprovalBundleV1 bundle;
    const auto& aj = root.at("authority");
    bundle.authority.format_version = aj.at("format_version").get<uint32_t>();
    bundle.authority.network_id_hex = aj.at("network_id").get<std::string>();
    bundle.authority.release_signing_pubkey_b64 =
        aj.at("release_signing_pubkey").get<std::string>();
    bundle.authority.genesis_signature_b64 =
        aj.at("genesis_signature").get<std::string>();

    const auto& j = root.at("approval");
    auto& a = bundle.approval;
    a.format_version = j.at("format_version").get<uint32_t>();
    a.release_id = j.at("release_id").get<std::string>();
    a.nexus_version = j.at("nexus_version").get<std::string>();
    a.source_commit = j.at("source_commit").get<std::string>();
    a.starting_patched_tree = j.at("starting_patched_tree").get<std::string>();
    a.final_patched_tree = j.at("final_patched_tree").get<std::string>();
    a.network_id_hex = j.at("network_id").get<std::string>();
    // Fields outside a format's preimage are unsigned there, so they are
    // refused rather than read.
    if (a.format_version >= kReleaseApprovalFormatVersion) {
        a.release_number = j.at("release_number").get<uint64_t>();
        for (const auto& path : j.at("previous_release_paths")) {
            a.previous_release_paths.push_back(
                {path.at("path").get<std::string>(),
                 path.at("sha256").get<std::vector<std::string>>()});
        }
    } else if (j.contains("release_number") || j.contains("previous_release_paths")) {
        throw std::invalid_argument("format 2 approval carries format 3 fields");
    }
    a.security_wire_version = j.at("security_wire_version").get<uint16_t>();
    a.security_ruleset = j.at("security_ruleset").get<SecurityRulesetVersion>();
    a.consensus_ruleset = j.at("consensus_ruleset").get<ConsensusRulesetVersion>();
    a.attestation_profile = j.at("attestation_profile").get<std::string>();
    a.attestation_profile_ruleset = j.at("attestation_profile_ruleset").get<uint16_t>();
    a.attestd_wire_version = j.at("attestd_wire_version").get<uint16_t>();
    a.ima_policy_id = j.at("ima_policy").at("id").get<std::string>();
    a.ima_policy_sha256 = j.at("ima_policy").at("sha256").get<std::string>();
    const auto& kernel = j.at("kernel");
    a.kernel.release = kernel.at("release").get<std::string>();
    a.kernel.bzimage_sha256 = kernel.at("bzimage_sha256").get<std::string>();
    a.kernel.vmlinux_sha256 = kernel.at("vmlinux_sha256").get<std::string>();
    a.kernel.module_tree_sha256 = kernel.at("module_tree_sha256").get<std::string>();
    a.kernel.module_certificate_der_sha256 =
        kernel.at("module_certificate_der_sha256").get<std::string>();
    a.svsm_launch_measurements_hex =
        j.at("svsm_launch_measurements").get<std::vector<std::string>>();
    const auto& tcb = j.at("min_tcb");
    a.min_tcb.bootloader = tcb.at("bootloader").get<uint8_t>();
    a.min_tcb.tee = tcb.at("tee").get<uint8_t>();
    a.min_tcb.snp = tcb.at("snp").get<uint8_t>();
    a.min_tcb.microcode = tcb.at("microcode").get<uint8_t>();
    for (const auto& path : j.at("approved_paths")) {
        a.approved_paths.push_back({path.at("path").get<std::string>(),
                                    path.at("sha256").get<std::vector<std::string>>()});
    }
    a.evidence_collector_path = j.at("evidence_collector_path").get<std::string>();
    for (const auto& pcr : j.at("expected_pcrs")) {
        a.expected_pcrs.emplace_back(pcr.at("index").get<uint32_t>(),
                                     pcr.at("sha256").get<std::string>());
    }
    a.qualification_state = j.at("qualification_state").get<std::string>();
    a.signer_pubkey_b64 = j.at("signer_pubkey").get<std::string>();
    a.signature_b64 = j.at("signature").get<std::string>();
    return bundle;
}

}  // namespace

std::string canonical_release_authority_json(const ReleaseAuthorityV1& authority) {
    return authority_preimage(authority).dump();
}

std::string canonical_release_approval_json(const ReleaseApprovalV1& approval) {
    return approval_preimage(approval).dump();
}

Digest release_approval_digest(const ReleaseApprovalV1& approval) {
    const auto canonical = canonical_release_approval_json(approval);
    Digest digest{};
    static_assert(std::tuple_size_v<Digest> == crypto_hash_sha256_BYTES);
    crypto_hash_sha256(digest.data(),
                       reinterpret_cast<const unsigned char*>(canonical.data()),
                       canonical.size());
    return digest;
}

std::string release_approval_digest_hex(const ReleaseApprovalV1& approval) {
    return crypto::to_hex(release_approval_digest(approval));
}

ReleaseApprovalV1 release_approval_template() {
    ReleaseApprovalV1 a;
    a.source_commit = std::string(kExpectedSourceCommit);
    a.starting_patched_tree = std::string(kExpectedStartingTree);
    a.security_wire_version = constants::kSecurityWireVersion;
    a.security_ruleset = constants::kSecurityRulesetVersion;
    a.consensus_ruleset = constants::kConsensusRulesetVersion;
    a.attestation_profile = "SnpSvsmVtpm";
    a.attestation_profile_ruleset = kAttestationProfileRulesetVersion;
    a.attestd_wire_version = constants::kAttestdWireVersion;
    a.ima_policy_id = std::string(kExpectedImaPolicyId);
    a.ima_policy_sha256 = std::string(kExpectedImaPolicy);
    a.kernel = {std::string(kExpectedKernelRelease), std::string(kExpectedBzImage),
                std::string(kExpectedVmlinux), std::string(kExpectedModuleTree),
                std::string(kExpectedModuleCertificate)};
    a.svsm_launch_measurements_hex.assign(std::begin(kExpectedLaunchMeasurements),
                                          std::end(kExpectedLaunchMeasurements));
    a.min_tcb = {0x0c, 0, 0x1c, 0};
    a.evidence_collector_path = "/usr/bin/nexus-attestd";
    return a;
}

std::string release_approval_bundle_json(const ReleaseApprovalBundleV1& bundle) {
    auto authority_json =
        json::parse(canonical_release_authority_json(bundle.authority));
    authority_json["genesis_signature"] = bundle.authority.genesis_signature_b64;
    auto approval_json = json::parse(canonical_release_approval_json(bundle.approval));
    approval_json["signature"] = bundle.approval.signature_b64;
    json root;
    root["authority"] = std::move(authority_json);
    root["approval"] = std::move(approval_json);
    return root.dump();
}

bool verify_release_approval_signatures(const ReleaseApprovalBundleV1& bundle,
                                        const crypto::Ed25519PublicKey& genesis_public_key,
                                        const NetworkId& expected_network_id,
                                        std::string& error) {
    error.clear();
    if (bundle.approval.format_version != kReleaseApprovalFormatV2 &&
        bundle.approval.format_version != kReleaseApprovalFormatVersion) {
        error = "release approval has an unsupported format";
        return false;
    }
    const auto expected_network_hex = crypto::to_hex(expected_network_id);
    if (bundle.authority.format_version != kReleaseAuthorityFormatVersion ||
        bundle.authority.network_id_hex != expected_network_hex) {
        error = "release authority is not delegated for this network";
        return false;
    }
    const auto authority_key = crypto::canonical_key_b64(
        bundle.authority.release_signing_pubkey_b64);
    if (authority_key.empty() || authority_key != bundle.authority.release_signing_pubkey_b64) {
        error = "release authority public key is not canonical Ed25519";
        return false;
    }
    const auto authority_preimage_text = canonical_release_authority_json(bundle.authority);
    if (!verify_ed25519(crypto::to_base64(genesis_public_key),
                        bundle.authority.genesis_signature_b64,
                        authority_preimage_text)) {
        error = "release authority delegation has no valid Genesis signature";
        return false;
    }
    const auto& a = bundle.approval;
    if (a.network_id_hex != expected_network_hex || a.signer_pubkey_b64 != authority_key) {
        error = "release approval network or signer does not match the Genesis delegation";
        return false;
    }
    if (!verify_ed25519(authority_key, a.signature_b64,
                        canonical_release_approval_json(a))) {
        error = "release approval signature is invalid";
        return false;
    }
    return true;
}

bool verify_release_approval_bundle(const ReleaseApprovalBundleV1& bundle,
                                    const crypto::Ed25519PublicKey& genesis_public_key,
                                    const NetworkId& expected_network_id,
                                    std::string& error) {
    if (!verify_release_approval_signatures(bundle, genesis_public_key, expected_network_id,
                                            error)) {
        return false;
    }
    const auto& a = bundle.approval;
    if (!compiled_release_fields_match(a, error)) return false;

    std::set<std::string> paths;
    bool have_nexus = false;
    bool have_attestd = false;
    for (const auto& approved : a.approved_paths) {
        if (approved.path.empty() || approved.path.front() != '/' ||
            !paths.insert(approved.path).second || approved.sha256.empty() ||
            std::any_of(approved.sha256.begin(), approved.sha256.end(),
                        [](const auto& hash) { return !valid_sha256(hash); })) {
            error = "release approval contains an invalid, duplicate, or unhashed path";
            return false;
        }
        have_nexus |= approved.path == "/usr/bin/lemonade-nexus";
        have_attestd |= approved.path == "/usr/bin/nexus-attestd";
    }
    if (!have_nexus || !have_attestd ||
        a.evidence_collector_path != "/usr/bin/nexus-attestd") {
        error = "release approval omits a required executable or collector binding";
        return false;
    }
    std::set<std::string> previous;
    for (const auto& prior : a.previous_release_paths) {
        if (!paths.contains(prior.path) || !previous.insert(prior.path).second ||
            prior.sha256.empty() ||
            std::any_of(prior.sha256.begin(), prior.sha256.end(),
                        [](const auto& hash) { return !valid_sha256(hash); })) {
            error = "previous release paths name an unapproved, duplicate, or unhashed path";
            return false;
        }
    }
    if (a.qualification_state == "PENDING_LIVE_QUALIFICATION") {
        if (!a.expected_pcrs.empty()) {
            error = "pending approval must not carry guessed PCR8/PCR9 values";
            return false;
        }
    } else if (a.qualification_state == "LIVE_BOOT_APPROVED") {
        if (a.expected_pcrs.size() != 2 || a.expected_pcrs[0].first != 8 ||
            a.expected_pcrs[1].first != 9 ||
            !valid_sha256(a.expected_pcrs[0].second) ||
            !valid_sha256(a.expected_pcrs[1].second)) {
            error = "qualified approval must carry exact SHA-256 PCR8 and PCR9";
            return false;
        }
    } else {
        error = "unknown release qualification state";
        return false;
    }
    return true;
}

std::optional<ReleaseApprovalBundleV1> parse_release_approval_bundle(
    std::string_view json_text, std::string& error) {
    try {
        return parse_bundle(json::parse(json_text));
    } catch (const std::exception& exception) {
        error = std::string("release approval parse failed: ") + exception.what();
        return std::nullopt;
    }
}

std::optional<ReleaseApprovalBundleV1> load_release_approval_bundle(
    const std::filesystem::path& path,
    const crypto::Ed25519PublicKey& genesis_public_key,
    const NetworkId& expected_network_id,
    std::string& error) {
    std::ifstream stream(path);
    if (!stream) {
        error = "release approval is unavailable at the fixed packaged path";
        return std::nullopt;
    }
    const std::string text((std::istreambuf_iterator<char>(stream)),
                           std::istreambuf_iterator<char>());
    auto bundle = parse_release_approval_bundle(text, error);
    if (!bundle || !verify_release_approval_bundle(*bundle, genesis_public_key,
                                                    expected_network_id, error)) {
        return std::nullopt;
    }
    return bundle;
}

LinuxAttestationProfile profile_from_release_approval(const ReleaseApprovalV1& approval) {
    auto profile = linux_attestation_profile_v3_svsm_release();
    profile.snp.min_tcb = approval.min_tcb;
    profile.snp.expected_measurements_hex = approval.svsm_launch_measurements_hex;
    profile.approved_paths = approval.approved_paths;
    for (auto& path : profile.approved_paths) {
        const auto prior = std::find_if(
            approval.previous_release_paths.begin(), approval.previous_release_paths.end(),
            [&path](const ApprovedPath& candidate) { return candidate.path == path.path; });
        if (prior == approval.previous_release_paths.end()) continue;
        for (const auto& hash : prior->sha256) {
            if (std::find(path.sha256.begin(), path.sha256.end(), hash) == path.sha256.end()) {
                path.sha256.push_back(hash);
            }
        }
    }
    profile.evidence_collector_path = approval.evidence_collector_path;
    profile.expected_pcrs = approval.expected_pcrs;
    return profile;
}

}  // namespace nexus::security
