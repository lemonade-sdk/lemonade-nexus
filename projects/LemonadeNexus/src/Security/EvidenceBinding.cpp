#include <LemonadeNexus/Security/EvidenceBinding.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <string_view>
#include <vector>

namespace nexus::security {

namespace {

constexpr std::string_view kDomain = "lemonade-nexus/evidence-binding:v1";

void put_lp(std::vector<uint8_t>& out, std::span<const uint8_t> field) {
    const auto n = static_cast<uint32_t>(field.size());
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((n >> (i * 8)) & 0xFF));
    out.insert(out.end(), field.begin(), field.end());
}

}  // namespace

std::array<uint8_t, kEvidenceBindingSize>
evidence_binding(std::span<const uint8_t> nonce,
                 std::span<const uint8_t> identity_pubkey,
                 std::span<const uint8_t> binary_measurement) {
    std::vector<uint8_t> input;
    input.reserve(kDomain.size() + nonce.size() + identity_pubkey.size() +
                  binary_measurement.size() + 16);
    put_lp(input, {reinterpret_cast<const uint8_t*>(kDomain.data()), kDomain.size()});
    put_lp(input, nonce);
    put_lp(input, identity_pubkey);
    put_lp(input, binary_measurement);

    std::array<uint8_t, kEvidenceBindingSize> out{};
    unsigned len = 0;
    EVP_Digest(input.data(), input.size(), out.data(), &len, EVP_sha256(), nullptr);
    return out;
}

std::array<uint8_t, kEvidenceReportDataSize>
evidence_report_data(std::span<const uint8_t> nonce,
                     std::span<const uint8_t> identity_pubkey,
                     std::span<const uint8_t> binary_measurement) {
    const auto binding = evidence_binding(nonce, identity_pubkey, binary_measurement);
    std::array<uint8_t, kEvidenceReportDataSize> out{};
    std::copy(binding.begin(), binding.end(), out.begin());
    return out;
}

}  // namespace nexus::security
