#include <LemonadeNexusAttestd/Tier1AuthorityProbe.hpp>

#include <cstdio>

int main(int argc, char*[]) {
    if (argc != 1) return 2;
    const auto result = nexus::attestd::run_tier1_authority_probe();
    if (!result.ok) {
        std::fprintf(stderr, "Tier-1 authority probe refused: %s\n", result.failure.c_str());
        return 1;
    }
    std::puts("Tier-1 authority probe v1 complete");
    return 0;
}
