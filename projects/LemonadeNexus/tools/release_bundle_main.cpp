// nexus-release-bundle: build-time generation of the unsigned release-approval
// bundle plus the exact canonical preimages the signing ceremony signs.
//
//   nexus-release-bundle --spec <spec.json> --out <bundle.json>
//                        [--approval-preimage <file>] [--authority-preimage <file>]
//                        [--previous-approval <bundle.json> [--previous-halted]]
//
// --previous-approval reads the previous release's signed bundle. Its
// approval must be signed by the same release key for the same network. Its
// approved_paths become previous_release_paths (for the paths this release
// still lists), so servers on both releases attest each other during the
// rollout. It cannot be combined with "previous_release_paths" in the spec.
//
// --previous-halted: the rollout of the previous release halted, so servers
// run that release or the release before it. previous_release_paths then
// carries the hashes of both (release_overlap_paths). The release workflow
// passes it only when nexus-rollout-check proved the halt, and checks the
// result again with nexus-rollout-check --approval.
//
// Spec format:
//   {
//     "release_id": "...", "nexus_version": "...",
//     "release_number": 2026102401,          // YYYYMMDD * 100 + N
//     "previous_release_paths": [{"path": "...", "sha256": ["..."]}],  // optional
//     "final_patched_tree": "<git rev-parse 'HEAD^{tree}'>",
//     "network_id": "<64-hex>", "signer_pubkey": "<base64 Ed25519>",
//     "qualification_state": "PENDING_LIVE_QUALIFICATION" | "LIVE_BOOT_APPROVED",
//     "expected_pcrs": [{"index": 8, "sha256": "..."}, {"index": 9, "sha256": "..."}],
//     // The boot line, from release/fleet-profile.json (all required):
//     "source_commit": "<40-hex>", "starting_patched_tree": "<40-hex>",
//     "ima_policy": {"id": "...", "sha256": "<64-hex>"},
//     "kernel": {"release": "...", "bzimage_sha256": "<64-hex>", "vmlinux_sha256": "<64-hex>",
//                "module_tree_sha256": "<64-hex>", "module_certificate_der_sha256": "<64-hex>"},
//     "svsm_launch_measurements": ["<96-hex>", ...],   // one per approved VM shape
//     "artifacts": [{"path": "/usr/bin/lemonade-nexus", "file": "build/bin/lemonade-nexus"},
//                   {"path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "sha256": ["<64-hex>"]}, ...]
//                                                      // "sha256" for reviewed digests of
//                                                      // files the build does not produce
//   }
//
// No key material is read or written; signatures stay empty.

#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>

using nexus::security::ReleaseBundleSpec;

namespace {

int fail(const std::string& reason) {
    std::fprintf(stderr, "nexus-release-bundle: %s\n", reason.c_str());
    return 1;
}

bool write_file(const std::string& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    return static_cast<bool>(out);
}

}  // namespace

int main(int argc, char** argv) {
    std::string spec_path, out_path, approval_preimage_path, authority_preimage_path;
    std::string previous_approval_path;
    bool previous_halted = false;
    for (int i = 1; i < argc; i += 2) {
        if (std::strcmp(argv[i], "--previous-halted") == 0) {
            previous_halted = true;
            --i;
            continue;
        }
        if (i + 1 >= argc) return fail(std::string("missing value for ") + argv[i]);
        if (std::strcmp(argv[i], "--spec") == 0) spec_path = argv[i + 1];
        else if (std::strcmp(argv[i], "--out") == 0) out_path = argv[i + 1];
        else if (std::strcmp(argv[i], "--approval-preimage") == 0) approval_preimage_path = argv[i + 1];
        else if (std::strcmp(argv[i], "--authority-preimage") == 0) authority_preimage_path = argv[i + 1];
        else if (std::strcmp(argv[i], "--previous-approval") == 0) previous_approval_path = argv[i + 1];
        else return fail(std::string("unknown argument: ") + argv[i]);
    }
    if (spec_path.empty() || out_path.empty()) {
        return fail("--spec and --out are required");
    }

    std::ifstream spec_stream(spec_path);
    if (!spec_stream) return fail("cannot read spec: " + spec_path);
    nlohmann::json spec_json = nlohmann::json::parse(spec_stream, nullptr, false);
    if (spec_json.is_discarded()) return fail("spec is not valid JSON");

    ReleaseBundleSpec spec;
    try {
        spec.release_id = spec_json.at("release_id").get<std::string>();
        spec.nexus_version = spec_json.at("nexus_version").get<std::string>();
        spec.release_number = spec_json.at("release_number").get<uint64_t>();
        for (const auto& path :
             spec_json.value("previous_release_paths", nlohmann::json::array())) {
            spec.previous_release_paths.push_back(
                {path.at("path").get<std::string>(),
                 path.at("sha256").get<std::vector<std::string>>()});
        }
        spec.final_patched_tree = spec_json.at("final_patched_tree").get<std::string>();
        spec.network_id_hex = spec_json.at("network_id").get<std::string>();
        spec.signer_pubkey_b64 = spec_json.at("signer_pubkey").get<std::string>();
        spec.qualification_state = spec_json.at("qualification_state").get<std::string>();
        for (const auto& pcr : spec_json.value("expected_pcrs", nlohmann::json::array())) {
            spec.expected_pcrs.emplace_back(pcr.at("index").get<uint32_t>(),
                                            pcr.at("sha256").get<std::string>());
        }
        spec.source_commit = spec_json.at("source_commit").get<std::string>();
        spec.starting_patched_tree = spec_json.at("starting_patched_tree").get<std::string>();
        spec.ima_policy_id = spec_json.at("ima_policy").at("id").get<std::string>();
        spec.ima_policy_sha256 = spec_json.at("ima_policy").at("sha256").get<std::string>();
        const auto& kernel = spec_json.at("kernel");
        spec.kernel.release = kernel.at("release").get<std::string>();
        spec.kernel.bzimage_sha256 = kernel.at("bzimage_sha256").get<std::string>();
        spec.kernel.vmlinux_sha256 = kernel.at("vmlinux_sha256").get<std::string>();
        spec.kernel.module_tree_sha256 = kernel.at("module_tree_sha256").get<std::string>();
        spec.kernel.module_certificate_der_sha256 =
            kernel.at("module_certificate_der_sha256").get<std::string>();
        for (const auto& measurement : spec_json.at("svsm_launch_measurements")) {
            spec.svsm_launch_measurements.push_back(measurement.get<std::string>());
        }
        for (const auto& artifact : spec_json.at("artifacts")) {
            nexus::security::ReleaseArtifact entry;
            entry.installed_path = artifact.at("path").get<std::string>();
            if (artifact.contains("file")) {
                entry.file = artifact.at("file").get<std::string>();
            } else {
                entry.sha256 = artifact.at("sha256").get<std::vector<std::string>>();
            }
            spec.artifacts.push_back(std::move(entry));
        }
        if (spec_json.contains("previous_approval")) {
            return fail("\"previous_approval\" is not a spec field; use --previous-approval");
        }
    } catch (const std::exception& e) {
        return fail(std::string("spec field error: ") + e.what());
    }

    std::string error;
    if (!previous_approval_path.empty()) {
        std::ifstream previous_stream(previous_approval_path);
        if (!previous_stream) return fail("cannot read " + previous_approval_path);
        const std::string text((std::istreambuf_iterator<char>(previous_stream)),
                               std::istreambuf_iterator<char>());
        const auto previous = nexus::security::parse_release_approval_bundle(text, error);
        if (!previous.has_value()) return fail(error);
        spec.previous = previous->approval;
    }
    spec.previous_halted = previous_halted;
    const auto approval = nexus::security::generate_release_approval(spec, error);
    if (!approval.has_value()) return fail(error);

    if (!write_file(out_path, nexus::security::unsigned_release_bundle_json(*approval))) {
        return fail("cannot write " + out_path);
    }
    if (!approval_preimage_path.empty() &&
        !write_file(approval_preimage_path,
                    nexus::security::canonical_release_approval_json(*approval))) {
        return fail("cannot write " + approval_preimage_path);
    }
    if (!authority_preimage_path.empty()) {
        nexus::security::ReleaseAuthorityV1 authority;
        authority.network_id_hex = approval->network_id_hex;
        authority.release_signing_pubkey_b64 = approval->signer_pubkey_b64;
        if (!write_file(authority_preimage_path,
                        nexus::security::canonical_release_authority_json(authority))) {
            return fail("cannot write " + authority_preimage_path);
        }
    }

    std::printf("release %s (%s) number %llu, %zu artifacts, %zu previous, state %s\n",
                approval->release_id.c_str(), approval->nexus_version.c_str(),
                static_cast<unsigned long long>(approval->release_number),
                approval->approved_paths.size(), approval->previous_release_paths.size(),
                approval->qualification_state.c_str());
    for (const auto& path : approval->approved_paths) {
        std::printf("  %s %s\n", path.sha256.front().c_str(), path.path.c_str());
    }
    std::printf("approval digest (pre-signing identity): %s\n",
                nexus::security::release_approval_digest_hex(*approval).c_str());
    return 0;
}
