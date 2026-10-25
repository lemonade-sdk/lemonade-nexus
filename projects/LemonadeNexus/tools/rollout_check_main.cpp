// nexus-rollout-check: the release guard (docs/Releasing.md).
//
//   nexus-rollout-check --network-id <64-hex> --release <release number>
//                       --proof <rollout-proof.json>
//
// Exits 0 only when the proof verifies from the Genesis key that derives the
// pinned network id, and it shows the rollout of the release finalized as
// complete and not halted. Any other result exits 1 with the reason. The proof
// comes from any server (GET /api/upgrade/rollout-proof); the server is not
// trusted for it. No key material is read.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Upgrade/RolloutProof.hpp>

#include <sodium.h>

#include <charconv>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>

namespace {

int fail(const std::string& reason) {
    std::fprintf(stderr, "nexus-rollout-check: %s\n", reason.c_str());
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    std::string network_hex, release_text, proof_path;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (std::strcmp(argv[i], "--network-id") == 0) network_hex = argv[i + 1];
        else if (std::strcmp(argv[i], "--release") == 0) release_text = argv[i + 1];
        else if (std::strcmp(argv[i], "--proof") == 0) proof_path = argv[i + 1];
        else return fail(std::string("unknown argument: ") + argv[i]);
    }
    if (network_hex.empty() || release_text.empty() || proof_path.empty()) {
        return fail("--network-id, --release, and --proof are required");
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

    std::ifstream stream(proof_path, std::ios::binary);
    if (!stream) return fail("cannot read " + proof_path);
    const std::string text{std::istreambuf_iterator<char>(stream),
                           std::istreambuf_iterator<char>()};
    std::string error;
    const auto proof = nexus::security::parse_rollout_proof(text, error);
    if (!proof) return fail(error);
    const auto rollout = nexus::security::verify_rollout_proof(*proof, network, error);
    if (!rollout) return fail("the rollout proof does not verify: " + error);
    std::string reason;
    if (!nexus::security::rollout_complete(*rollout, release, reason)) return fail(reason);
    std::printf("%s (authority chain to epoch %llu)\n", reason.c_str(),
                static_cast<unsigned long long>(rollout->epoch.underlying()));
    return 0;
}
