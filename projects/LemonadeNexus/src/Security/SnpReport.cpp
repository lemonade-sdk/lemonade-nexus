#include <LemonadeNexus/Security/SnpReport.hpp>

#include <cstdio>
#include <cstring>

namespace nexus::security {

namespace {

uint32_t rd_u32(std::span<const uint8_t> b, std::size_t off) {
    uint32_t v = 0;
    std::memcpy(&v, b.data() + off, sizeof(v));
    return v;  // SNP reports are little-endian; so is every platform we build for
}

uint64_t rd_u64(std::span<const uint8_t> b, std::size_t off) {
    uint64_t v = 0;
    std::memcpy(&v, b.data() + off, sizeof(v));
    return v;
}

template <std::size_t N>
void rd_arr(std::span<const uint8_t> b, std::size_t off, std::array<uint8_t, N>& out) {
    std::memcpy(out.data(), b.data() + off, N);
}

}  // namespace

std::string hex_of(std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t c : bytes) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0F]);
    }
    return out;
}

std::string TcbVersion::to_string() const {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "bl=%u tee=%u snp=%u ucode=%u",
                  bootloader, tee, snp, microcode);
    return buf;
}

std::string SnpReport::measurement_hex() const { return hex_of(measurement); }
std::string SnpReport::chip_id_hex() const { return hex_of(chip_id); }

std::optional<SnpReport> parse_snp_report(std::span<const uint8_t> bytes) {
    if (bytes.size() < kSnpReportSize) return std::nullopt;

    SnpReport r;
    r.version        = rd_u32(bytes, snp_off::kVersion);
    r.guest_svn      = rd_u32(bytes, snp_off::kGuestSvn);
    r.vmpl           = rd_u32(bytes, snp_off::kVmpl);
    r.signature_algo = rd_u32(bytes, snp_off::kSigAlgo);

    const uint64_t pol = rd_u64(bytes, snp_off::kPolicy);
    r.policy.raw           = pol;
    r.policy.abi_minor     = static_cast<uint8_t>(pol & 0xFF);
    r.policy.abi_major     = static_cast<uint8_t>((pol >> 8) & 0xFF);
    r.policy.smt           = (pol >> 16) & 1;
    r.policy.migrate_ma    = (pol >> 18) & 1;
    r.policy.debug         = (pol >> 19) & 1;
    r.policy.single_socket = (pol >> 20) & 1;

    // TCB_VERSION: bootloader, tee, 4 reserved, snp, microcode.
    const uint8_t* tcb = bytes.data() + snp_off::kReportedTcb;
    r.reported_tcb = {tcb[0], tcb[1], tcb[6], tcb[7]};

    rd_arr(bytes, snp_off::kReportData,  r.report_data);
    rd_arr(bytes, snp_off::kMeasurement, r.measurement);
    rd_arr(bytes, snp_off::kHostData,    r.host_data);
    rd_arr(bytes, snp_off::kIdKeyDigest, r.id_key_digest);
    rd_arr(bytes, snp_off::kChipId,      r.chip_id);

    r.raw.assign(bytes.begin(), bytes.begin() + kSnpReportSize);
    return r;
}

std::string snp_report_summary(const SnpReport& r) {
    char buf[320];
    std::snprintf(buf, sizeof(buf),
                  "snp v%u vmpl=%u policy=0x%llx (debug=%d migrate_ma=%d smt=%d) tcb[%s] "
                  "measurement=%.16s...",
                  r.version, r.vmpl, static_cast<unsigned long long>(r.policy.raw),
                  r.policy.debug ? 1 : 0, r.policy.migrate_ma ? 1 : 0, r.policy.smt ? 1 : 0,
                  r.reported_tcb.to_string().c_str(), r.measurement_hex().c_str());
    return buf;
}

}  // namespace nexus::security
