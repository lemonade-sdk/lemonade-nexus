#include <LemonadeNexus/Security/HclReport.hpp>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <cstring>

namespace nexus::security {

namespace {

using json = nlohmann::json;

uint32_t rd_u32(std::span<const uint8_t> b, std::size_t off) {
    uint32_t v = 0;
    std::memcpy(&v, b.data() + off, sizeof(v));
    return v;
}

/// JWK values are base64url without padding.
std::vector<uint8_t> b64url_decode(std::string_view in) {
    std::string s(in);
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (s.size() % 4 != 0) s.push_back('=');

    std::vector<uint8_t> out(s.size() / 4 * 3 + 3);
    const int n = EVP_DecodeBlock(out.data(),
                                  reinterpret_cast<const unsigned char*>(s.data()),
                                  static_cast<int>(s.size()));
    if (n < 0) return {};
    out.resize(static_cast<std::size_t>(n));
    // EVP_DecodeBlock counts the '=' we added as zero bytes; drop them.
    std::size_t pad = 0;
    for (auto it = s.rbegin(); it != s.rend() && *it == '='; ++it) ++pad;
    if (pad > out.size()) return {};
    out.resize(out.size() - pad);
    return out;
}

std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) {
    std::array<uint8_t, 32> out{};
    unsigned len = 0;
    EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr);
    return out;
}

}  // namespace

std::optional<HclReport> parse_hcl_blob(std::span<const uint8_t> blob) {
    if (blob.size() < kHclHeaderSize + kSnpReportSize) {
        spdlog::warn("[snp] HCL blob too small ({} bytes)", blob.size());
        return std::nullopt;
    }
    if (std::memcmp(blob.data(), kHclMagic, sizeof(kHclMagic)) != 0) {
        spdlog::warn("[snp] HCL blob missing 'HCLA' magic");
        return std::nullopt;
    }

    const uint32_t declared = rd_u32(blob, 8);  // header: magic, version, size, req type
    if (declared < kSnpReportSize || kHclHeaderSize + declared > blob.size()) {
        spdlog::warn("[snp] HCL declared report size {} does not fit in {} bytes",
                      declared, blob.size());
        return std::nullopt;
    }

    HclReport out;
    auto snp = parse_snp_report(blob.subspan(kHclHeaderSize, kSnpReportSize));
    if (!snp) {
        spdlog::warn("[snp] could not parse the embedded attestation report");
        return std::nullopt;
    }
    out.snp = std::move(*snp);

    // Runtime data follows the report: u32 total size (incl. this 20-byte header),
    // u32 version, u32 report type, u32 hash type, u32 payload length, then payload.
    const std::size_t rt = kHclHeaderSize + kSnpReportSize;
    constexpr std::size_t kRtHeader = 20;
    if (rt + kRtHeader > blob.size()) {
        spdlog::warn("[snp] HCL blob has no runtime-data region");
        return std::nullopt;
    }
    const uint32_t payload_len = rd_u32(blob, rt + 16);
    if (payload_len == 0 || rt + kRtHeader + payload_len > blob.size()) {
        spdlog::warn("[snp] HCL runtime payload length {} out of range", payload_len);
        return std::nullopt;
    }

    const auto payload = blob.subspan(rt + kRtHeader, payload_len);
    out.runtime_json.assign(reinterpret_cast<const char*>(payload.data()), payload.size());

    // THE binding: the AMD signature covers REPORT_DATA, and REPORT_DATA is the
    // SHA-256 of these exact bytes. Recomputing it is what turns the AK below from
    // an assertion into something the silicon vouched for.
    const auto digest = sha256(payload);
    out.report_data_binds_runtime =
        std::memcmp(digest.data(), out.snp.report_data.data(), digest.size()) == 0;
    if (!out.report_data_binds_runtime) {
        spdlog::warn("[snp] runtime-data digest does not match REPORT_DATA — blob is "
                      "internally inconsistent");
        return std::nullopt;
    }

    try {
        const auto j = json::parse(out.runtime_json);
        for (const auto& k : j.at("keys")) {
            if (k.value("kid", "") != "HCLAkPub") continue;
            out.ak.kid      = "HCLAkPub";
            out.ak.modulus  = b64url_decode(k.value("n", ""));
            out.ak.exponent = b64url_decode(k.value("e", ""));
            break;
        }
    } catch (const std::exception& e) {
        spdlog::warn("[snp] HCL runtime data is not the expected JWK set: {}", e.what());
        return std::nullopt;
    }

    if (out.ak.empty()) {
        spdlog::warn("[snp] HCL runtime data carries no usable HCLAkPub");
        return std::nullopt;
    }
    return out;
}

}  // namespace nexus::security
