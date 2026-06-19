#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>

#include <sodium.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace nexus::routing {
namespace {

// Crockford base32 (lowercase): excludes i, l, o, u.
constexpr char kCrockford[] = "0123456789abcdefghjkmnpqrstvwxyz";

std::string base32_crockford(const uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve((len * 8 + 4) / 5);
    uint32_t buffer = 0;
    int bits = 0;
    for (std::size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kCrockford[(buffer >> bits) & 0x1F]);
        }
    }
    if (bits > 0) {
        out.push_back(kCrockford[(buffer << (5 - bits)) & 0x1F]);
    }
    return out;
}

void append(std::vector<uint8_t>& v, std::string_view s) {
    v.insert(v.end(), s.begin(), s.end());
}

} // namespace

std::string derive_endpoint_identifier(std::string_view node_id,
                                       std::string_view region,
                                       std::string_view cpu_id,
                                       std::string_view net_mac,
                                       bool is_inference) {
    static constexpr std::string_view kDomain = "ln-endpoint-id:v1";
    static constexpr uint8_t kSep = 0x1F; // unit separator, unlikely in inputs

    std::vector<uint8_t> input;
    input.reserve(kDomain.size() + node_id.size() + region.size() +
                  cpu_id.size() + net_mac.size() + 3);
    append(input, kDomain);
    append(input, node_id); input.push_back(kSep);
    append(input, region);  input.push_back(kSep);
    append(input, cpu_id);  input.push_back(kSep);
    append(input, net_mac);

    std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), input.data(), input.size());

    // 10 bytes (80 bits) of the digest form the label core.
    std::string core = base32_crockford(digest.data(), 10);

    // Light grouping for readability: groups of 4 separated by '-'.
    std::string grouped;
    grouped.reserve(core.size() + core.size() / 4);
    for (std::size_t i = 0; i < core.size(); ++i) {
        if (i > 0 && i % 4 == 0) grouped.push_back('-');
        grouped.push_back(core[i]);
    }

    return std::string(is_inference ? "infer" : "client") + "-" + grouped;
}

} // namespace nexus::routing
