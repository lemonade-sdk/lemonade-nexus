#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace nexus::attestd {

struct Tier1AuthorityProbeResult {
    bool ok{false};
    std::string failure;
    // Diagnostic only. The verifier trusts kernel IMA events, not this list.
    std::vector<std::string> opened_paths;
};

// No path discovery: production always uses the finite absolute list. The
// test root exists only for an offline fixture filesystem.
[[nodiscard]] Tier1AuthorityProbeResult run_tier1_authority_probe(
    const std::filesystem::path& test_root = {});

}  // namespace nexus::attestd
