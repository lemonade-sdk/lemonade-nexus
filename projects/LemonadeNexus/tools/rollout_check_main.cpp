// nexus-rollout-check: the release guard (docs/Releasing.md).
//
//   nexus-rollout-check --network-id <64-hex> --release <release number>
//                       --proof <rollout-proof.json>
//                       [--previous-approval <bundle.json>]
//                       [--print-state | --approval <new bundle.json>]
//
// The proof must verify from the Genesis key that derives the pinned network
// id. The proof comes from any server (GET /api/upgrade/rollout-proof); the
// server is not trusted for it. No key material is read.
//
// --previous-approval is the published approval of the previous release
// (--release). It must be the approval that the finalized Start record names.
//
// Without --print-state or --approval: exits 0 only when the rollout of the
// release finalized as complete and not halted.
//
// --print-state: exits 0 when the rollout finalized as complete, or as halted
// with --previous-approval given, and prints "rollout=complete" or
// "rollout=halted" on stdout. This only selects how the new approval is
// built; it never passes a release on its own.
//
// --approval: the new (unsigned) approval bundle. Exits 0 only when its
// previous_release_paths are exactly those the proven state requires: the
// previous release after a completed rollout, or the halted release and the
// release before it after a halt (release_follows_rollout). Requires
// --previous-approval.
//
// Any other result exits 1 with the reason.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseChain.hpp>
#include <LemonadeNexus/Security/Upgrade/RolloutProof.hpp>

#include <sodium.h>

#include <charconv>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>

namespace {

int fail(const std::string& reason) {
    std::fprintf(stderr, "nexus-rollout-check: %s\n", reason.c_str());
    return 1;
}

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::nullopt;
    return std::string{std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

std::optional<nexus::security::ReleaseApprovalBundleV1> read_bundle(const std::string& path,
                                                                    std::string& error) {
    const auto text = read_file(path);
    if (!text) {
        error = "cannot read " + path;
        return std::nullopt;
    }
    if (text->size() > nexus::security::kMaxReleaseApprovalBytes) {
        error = path + " is larger than an approval bundle can be";
        return std::nullopt;
    }
    return nexus::security::parse_release_approval_bundle(*text, error);
}

}  // namespace

int main(int argc, char** argv) {
    std::string network_hex, release_text, proof_path, previous_path, approval_path;
    bool print_state = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--print-state") == 0) {
            print_state = true;
            continue;
        }
        if (i + 1 >= argc) return fail(std::string("missing value for ") + argv[i]);
        const char* value = argv[++i];
        if (std::strcmp(argv[i - 1], "--network-id") == 0) network_hex = value;
        else if (std::strcmp(argv[i - 1], "--release") == 0) release_text = value;
        else if (std::strcmp(argv[i - 1], "--proof") == 0) proof_path = value;
        else if (std::strcmp(argv[i - 1], "--previous-approval") == 0) previous_path = value;
        else if (std::strcmp(argv[i - 1], "--approval") == 0) approval_path = value;
        else return fail(std::string("unknown argument: ") + argv[i - 1]);
    }
    if (network_hex.empty() || release_text.empty() || proof_path.empty()) {
        return fail("--network-id, --release, and --proof are required");
    }
    if (print_state && !approval_path.empty()) {
        return fail("--print-state and --approval are separate steps");
    }
    if (!approval_path.empty() && previous_path.empty()) {
        return fail("--approval needs --previous-approval");
    }
    if (sodium_init() < 0) return fail("libsodium did not initialize");

    nexus::security::NetworkId network{};
    const auto network_bytes = nexus::crypto::from_hex(network_hex);
    if (network_bytes.size() != network.size()) return fail("--network-id is not 64 hex");
    std::copy(network_bytes.begin(), network_bytes.end(), network.begin());

    uint64_t release = 0;
    const auto* end = release_text.data() + release_text.size();
    if (std::from_chars(release_text.data(), end, release).ptr != end || release == 0) {
        return fail("--release is not a release number");
    }

    const auto text = read_file(proof_path);
    if (!text) return fail("cannot read " + proof_path);
    std::string error;
    const auto proof = nexus::security::parse_rollout_proof(*text, error);
    if (!proof) return fail(error);
    const auto rollout = nexus::security::verify_rollout_proof(*proof, network, error);
    if (!rollout) return fail("the rollout proof does not verify: " + error);

    std::optional<nexus::security::ReleaseApprovalBundleV1> previous;
    if (!previous_path.empty()) {
        previous = read_bundle(previous_path, error);
        if (!previous) return fail(error);
    }

    std::string reason;
    if (!approval_path.empty()) {
        const auto next = read_bundle(approval_path, error);
        if (!next) return fail(error);
        if (!nexus::security::release_follows_rollout(*rollout, release, *previous,
                                                      next->approval, reason)) {
            return fail(reason);
        }
        std::printf("%s\n", reason.c_str());
        return 0;
    }

    const auto state = nexus::security::previous_rollout_state(
        *rollout, release, previous ? &*previous : nullptr, reason);
    if (!state) return fail(reason);
    if (print_state) {
        std::fprintf(stderr, "%s (authority chain to epoch %llu)\n", reason.c_str(),
                     static_cast<unsigned long long>(rollout->epoch.underlying()));
        std::printf("rollout=%s\n",
                    *state == nexus::security::PreviousRollout::Halted ? "halted" : "complete");
        return 0;
    }
    if (*state != nexus::security::PreviousRollout::Complete) {
        return fail(reason + "; check the new approval with --approval");
    }
    std::printf("%s (authority chain to epoch %llu)\n", reason.c_str(),
                static_cast<unsigned long long>(rollout->epoch.underlying()));
    return 0;
}
