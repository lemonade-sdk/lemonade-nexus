#include <LemonadeNexus/Security/MeasurementIma.hpp>

#include <LemonadeNexus/Security/TpmQuote.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>

namespace nexus::security {

namespace {

inline constexpr uint32_t kImaReplayPcr = 10;

class LeReader {
public:
    explicit LeReader(std::span<const uint8_t> bytes) : bytes_(bytes) {}

    bool u32(uint32_t& out) {
        if (left() < 4) return false;
        out = static_cast<uint32_t>(bytes_[at_]) |
              (static_cast<uint32_t>(bytes_[at_ + 1]) << 8) |
              (static_cast<uint32_t>(bytes_[at_ + 2]) << 16) |
              (static_cast<uint32_t>(bytes_[at_ + 3]) << 24);
        at_ += 4;
        return true;
    }

    bool take(std::size_t n, std::span<const uint8_t>& out) {
        if (n > left()) return false;
        out = bytes_.subspan(at_, n);
        at_ += n;
        return true;
    }

    [[nodiscard]] std::size_t position() const { return at_; }
    [[nodiscard]] std::size_t left() const { return bytes_.size() - at_; }

private:
    std::span<const uint8_t> bytes_;
    std::size_t at_{0};
};

bool digest_bytes(const EVP_MD* md, std::span<const uint8_t> in,
                  std::span<uint8_t> out) {
    unsigned len = 0;
    return md && EVP_Digest(in.data(), in.size(), out.data(), &len, md, nullptr) == 1 &&
           len == out.size();
}

bool length_field(LeReader& reader, std::span<const uint8_t>& field) {
    uint32_t len = 0;
    return reader.u32(len) && reader.take(len, field);
}

std::optional<std::string> nul_string(std::span<const uint8_t> field) {
    if (field.empty() || field.back() != 0 ||
        std::find(field.begin(), field.end() - 1, 0) != field.end() - 1) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(field.data()), field.size() - 1);
}

bool parse_binary_template(std::string_view name, std::span<const uint8_t> data,
                           ImaBinaryEntry& out) {
    if (name != "ima-ng" && name != "ima-sig") return false;
    LeReader fields(data);
    std::span<const uint8_t> digest_field;
    std::span<const uint8_t> path_field;
    if (!length_field(fields, digest_field) || !length_field(fields, path_field)) return false;

    const auto path = nul_string(path_field);
    if (!path) return false;
    // d-ng is "algorithm:\0" followed by the binary digest, all within one
    // length-prefixed field.  It is not the ASCII form printed by securityfs.
    const auto separator = std::find(digest_field.begin(), digest_field.end(), 0);
    if (separator == digest_field.end() || separator == digest_field.begin()) return false;
    std::string algorithm(reinterpret_cast<const char*>(digest_field.data()),
                          static_cast<std::size_t>(separator - digest_field.begin()));
    if (algorithm.back() != ':') return false;
    algorithm.pop_back();
    const auto raw_digest = digest_field.subspan(
        static_cast<std::size_t>(separator - digest_field.begin()) + 1);
    if (algorithm != "sha256" || raw_digest.size() != 32) return false;
    static constexpr char kHex[] = "0123456789abcdef";
    out.file_hash_algo = std::move(algorithm);
    out.file_hash_hex.reserve(raw_digest.size() * 2);
    for (uint8_t byte : raw_digest) {
        out.file_hash_hex.push_back(kHex[byte >> 4]);
        out.file_hash_hex.push_back(kHex[byte & 0x0f]);
    }
    out.path = *path;

    if (name == "ima-sig") {
        std::span<const uint8_t> signature;
        if (!length_field(fields, signature)) return false;
        // An empty signature is valid ima-sig; signature policy is outside PCR replay.
    }
    return fields.left() == 0;
}

std::vector<uint8_t> unhex(std::string_view s) {
    if (s.size() % 2 != 0) return {};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i < s.size(); i += 2) {
        const int hi = nib(s[i]);
        const int lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

const EVP_MD* md_for(uint16_t hash_alg) {
    switch (hash_alg) {
        case kTpmAlgSha1:   return EVP_sha1();
        case kTpmAlgSha256: return EVP_sha256();
        case kTpmAlgSha384: return EVP_sha384();
        case kTpmAlgSha512: return EVP_sha512();
        default:            return nullptr;
    }
}

/// IMA escapes characters outside [ -~] as \xHH in the ASCII log's path field.
std::string unescape_path(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 3 < in.size() && in[i + 1] == 'x') {
            const auto byte = unhex(in.substr(i + 2, 2));
            if (byte.size() == 1) {
                out.push_back(static_cast<char>(byte[0]));
                i += 3;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

/// One log line. Shared by the parser and the truncator so both agree on what
/// an entry is, and so on where the log ends.
bool parse_ima_line(std::string_view text, ImaEntry& e) {
    // <pcr> <template-hash> <template-name> <file-hash> <path> [signature...]
    std::istringstream fields{std::string(text)};
    std::string pcr_s, tmpl_hash_s, tmpl_name, file_hash_s;
    if (!(fields >> pcr_s >> tmpl_hash_s >> tmpl_name >> file_hash_s)) {
        return false;  // not an IMA log
    }

    try {
        e.pcr = static_cast<uint32_t>(std::stoul(pcr_s));
    } catch (...) {
        return false;
    }
    e.template_hash = unhex(tmpl_hash_s);
    if (e.template_hash.empty()) return false;
    e.template_name = tmpl_name;

    // ima-ng/ima-sig write "<algo>:<hex>"; the original "ima" template writes
    // a bare hex digest with no algorithm.
    if (const auto colon = file_hash_s.find(':'); colon != std::string::npos) {
        e.file_hash_algo = file_hash_s.substr(0, colon);
        e.file_hash_hex  = file_hash_s.substr(colon + 1);
    } else {
        e.file_hash_hex = file_hash_s;
    }

    // The path runs to the end of the line for ima-ng, but ima-sig appends a
    // signature field after it. Paths may contain spaces, so take everything
    // up to the last field only when the template is known to have one.
    std::string rest;
    std::getline(fields, rest);
    if (!rest.empty() && rest.front() == ' ') rest.erase(0, 1);
    if (tmpl_name == "ima-sig") {
        // Trailing signature is hex or empty; strip a final whitespace-delimited
        // token that looks like one.
        const auto last_sp = rest.find_last_of(' ');
        if (last_sp != std::string::npos) {
            const std::string tail = rest.substr(last_sp + 1);
            const bool hexy = !tail.empty() &&
                              std::all_of(tail.begin(), tail.end(), [](unsigned char c) {
                                  return std::isxdigit(c) != 0;
                              });
            if (hexy) rest.resize(last_sp);
        }
    }
    e.path = unescape_path(rest);
    return true;
}

/// Extend `pcr` with `digest`, in place. False on any OpenSSL failure.
bool extend_pcr(EVP_MD_CTX* ctx, const EVP_MD* md, std::vector<uint8_t>& pcr,
                std::span<const uint8_t> digest) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, pcr.data(), pcr.size()) != 1 ||
        EVP_DigestUpdate(ctx, digest.data(), digest.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, out, &len) != 1 || len != pcr.size()) {
        return false;
    }
    pcr.assign(out, out + len);
    return true;
}

}  // namespace

std::optional<ImaBinaryLog> parse_ima_binary(std::span<const uint8_t> bytes) {
    ImaBinaryLog log;
    LeReader reader(bytes);
    while (reader.left() != 0) {
        ImaBinaryEntry entry;
        std::span<const uint8_t> header_digest;
        uint32_t name_len = 0;
        uint32_t data_len = 0;
        if (!reader.u32(entry.pcr) || !reader.take(entry.header_template_sha1.size(), header_digest) ||
            !reader.u32(name_len)) {
            return std::nullopt;
        }
        std::span<const uint8_t> name_bytes;
        if (name_len == 0 || !reader.take(name_len, name_bytes) ||
            std::find(name_bytes.begin(), name_bytes.end(), 0) != name_bytes.end()) {
            return std::nullopt;
        }
        const std::string name(reinterpret_cast<const char*>(name_bytes.data()),
                               name_bytes.size());
        if (name != "ima-ng" && name != "ima-sig") return std::nullopt;
        entry.template_name = name;
        if (!reader.u32(data_len)) return std::nullopt;
        std::span<const uint8_t> template_data;
        if (!reader.take(data_len, template_data)) return std::nullopt;
        entry.template_data.assign(template_data.begin(), template_data.end());
        std::copy(header_digest.begin(), header_digest.end(), entry.header_template_sha1.begin());

        const bool all_zero = std::all_of(header_digest.begin(), header_digest.end(),
                                          [](uint8_t b) { return b == 0; });
        std::array<uint8_t, 20> computed{};
        if (!digest_bytes(EVP_sha1(), template_data, computed)) return std::nullopt;
        entry.violation = all_zero;
        if (!all_zero && !std::equal(computed.begin(), computed.end(), header_digest.begin())) {
            return std::nullopt;
        }
        if (!parse_binary_template(entry.template_name, template_data, entry)) {
            return std::nullopt;
        }
        entry.wire_end = reader.position();
        log.entries.push_back(std::move(entry));
    }
    return log;
}

std::optional<ImaBinaryPrefixReplay> replay_ima_binary_prefix(
    const ImaBinaryLog& log, uint64_t entry_count, uint64_t prior_event_count,
    std::span<const uint8_t> prior_pcr10,
    std::span<const ImaBinaryPathState> prior_paths) {
    if (prior_pcr10.size() != 32 || entry_count > log.entries.size() ||
        entry_count > UINT64_MAX - prior_event_count) {
        return std::nullopt;
    }
    ImaBinaryPrefixReplay replay;
    ImaBinaryReplayState& state = replay.state;
    state.event_count = prior_event_count;
    state.pcr10.assign(prior_pcr10.begin(), prior_pcr10.end());
    state.paths.assign(prior_paths.begin(), prior_paths.end());

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::nullopt;
    for (uint64_t i = 0; i < entry_count; ++i) {
        const ImaBinaryEntry& entry = log.entries[static_cast<std::size_t>(i)];
        ++state.event_count;
        if (entry.violation) {
            EVP_MD_CTX_free(ctx);
            return std::nullopt;
        }
        if (entry.pcr == kImaReplayPcr) {
            std::array<uint8_t, 32> event{};
            if (!digest_bytes(EVP_sha256(), entry.template_data, event) ||
                !extend_pcr(ctx, EVP_sha256(), state.pcr10, event)) {
                EVP_MD_CTX_free(ctx);
                return std::nullopt;
            }
        }
        const auto existing = std::find_if(state.paths.begin(), state.paths.end(),
                                           [&](const auto& p) { return p.path == entry.path; });
        if (existing == state.paths.end()) {
            state.paths.push_back({entry.path, entry.file_hash_hex});
        } else {
            existing->sha256 = entry.file_hash_hex;
        }
        replay.wire_end = entry.wire_end;
    }
    EVP_MD_CTX_free(ctx);
    return replay;
}

std::optional<ImaBinaryReplayState> replay_ima_binary_from(
    const ImaBinaryLog& suffix, uint64_t prior_event_count,
    std::span<const uint8_t> prior_pcr10,
    std::span<const ImaBinaryPathState> prior_paths) {
    auto replay = replay_ima_binary_prefix(suffix, suffix.entries.size(),
                                           prior_event_count, prior_pcr10, prior_paths);
    if (!replay) return std::nullopt;
    return std::move(replay->state);
}

std::optional<std::vector<uint8_t>> ima_binary_suffix_after_checkpoint(
    std::span<const uint8_t> bytes, uint64_t prior_event_count,
    std::span<const uint8_t> prior_pcr10) {
    if (prior_pcr10.size() != 32) return std::nullopt;
    const auto log = parse_ima_binary(bytes);
    if (!log || prior_event_count > log->entries.size()) return std::nullopt;
    std::array<uint8_t, 32> zero{};
    const auto replay = replay_ima_binary_prefix(*log, prior_event_count, 0, zero);
    if (!replay || !std::equal(replay->state.pcr10.begin(), replay->state.pcr10.end(),
                               prior_pcr10.begin(), prior_pcr10.end())) {
        return std::nullopt;
    }
    if (replay->wire_end > bytes.size()) return std::nullopt;
    return std::vector<uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(replay->wire_end),
                                bytes.end());
}

std::vector<uint8_t> replay_ima_binary_pcr(const ImaBinaryLog& log, uint32_t pcr_index,
                                            uint16_t bank_hash_alg) {
    if (bank_hash_alg != kTpmAlgSha256) return {};
    std::vector<uint8_t> running(32, 0);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    for (const auto& entry : log.entries) {
        if (entry.pcr != pcr_index) continue;
        if (entry.violation) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        std::array<uint8_t, 32> event{};
        if (!digest_bytes(EVP_sha256(), entry.template_data, event) ||
            !extend_pcr(ctx, EVP_sha256(), running, event)) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
    }
    EVP_MD_CTX_free(ctx);
    return running;
}

std::optional<std::vector<uint8_t>> ima_binary_truncate_to_pcr(
    std::span<const uint8_t> bytes, uint32_t pcr_index, uint16_t bank_hash_alg,
    std::span<const uint8_t> target) {
    if (bank_hash_alg != kTpmAlgSha256 || target.size() != 32) return std::nullopt;
    LeReader reader(bytes);
    std::vector<uint8_t> running(32, 0);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::nullopt;
    std::optional<std::size_t> match;
    std::size_t matches = std::equal(running.begin(), running.end(), target.begin()) ? 1 : 0;
    if (matches == 1) match = 0;

    while (reader.left() != 0) {
        uint32_t entry_pcr = 0, name_len = 0, data_len = 0;
        std::span<const uint8_t> digest, name, data;
        if (!reader.u32(entry_pcr) || !reader.take(20, digest) || !reader.u32(name_len) ||
            !reader.take(name_len, name) || !reader.u32(data_len) || !reader.take(data_len, data)) {
            EVP_MD_CTX_free(ctx);
            return std::nullopt;
        }
        if (entry_pcr != pcr_index) continue;
        const bool violation = std::all_of(digest.begin(), digest.end(),
                                           [](uint8_t b) { return b == 0; });
        if (violation) {
            EVP_MD_CTX_free(ctx);
            return std::nullopt;
        }
        std::array<uint8_t, 32> event{};
        if (!digest_bytes(EVP_sha256(), data, event) ||
            !extend_pcr(ctx, EVP_sha256(), running, event)) {
            EVP_MD_CTX_free(ctx);
            return std::nullopt;
        }
        if (std::equal(running.begin(), running.end(), target.begin())) {
            ++matches;
            match = reader.position();
        }
    }
    EVP_MD_CTX_free(ctx);
    if (matches != 1 || !match) return std::nullopt;
    return std::vector<uint8_t>(bytes.begin(), bytes.begin() + static_cast<long>(*match));
}

std::optional<ImaBinaryEntry> ima_binary_entry_for_path(const ImaBinaryLog& log,
                                                         std::string_view path) {
    std::optional<ImaBinaryEntry> found;
    for (const auto& entry : log.entries) {
        if (entry.path == path) found = entry;
    }
    return found;
}

std::vector<uint8_t> read_ima_binary_log() {
#if defined(__linux__)
    static constexpr const char* kPaths[] = {
        "/sys/kernel/security/ima/binary_runtime_measurements",
        "/sys/kernel/security/integrity/ima/binary_runtime_measurements",
    };
    for (const char* path : kPaths) {
        std::ifstream file(path, std::ios::binary);
        if (!file) continue;
        std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                                   std::istreambuf_iterator<char>()};
        if (!bytes.empty()) return bytes;
    }
#endif
    return {};
}

std::size_t ImaLog::template_hash_size() const {
    return entries.empty() ? 0 : entries.front().template_hash.size();
}

std::optional<ImaLog> parse_ima_ascii(std::string_view text) {
    ImaLog log;
    std::istringstream stream{std::string(text)};

    for (std::string line; std::getline(stream, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        ImaEntry e;
        if (!parse_ima_line(line, e)) return std::nullopt;
        log.entries.push_back(std::move(e));
    }
    return log;
}

std::vector<uint8_t> replay_ima_pcr(const ImaLog& log, uint32_t pcr_index,
                                    uint16_t bank_hash_alg) {
    const std::size_t width = tpm_digest_size(bank_hash_alg);
    const EVP_MD* md = md_for(bank_hash_alg);
    if (width == 0 || !md) return {};

    std::vector<uint8_t> pcr(width, 0);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};

    for (const auto& e : log.entries) {
        if (e.pcr != pcr_index) continue;

        // Only a log whose template digests are this bank's width can be replayed
        // into it; see ima_replay_bank. Anything else is the wrong log, not a
        // padding question.
        if (e.template_hash.size() != width) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        if (!extend_pcr(ctx, md, pcr, e.template_hash)) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
    }

    EVP_MD_CTX_free(ctx);
    return pcr;
}

std::optional<std::string> ima_truncate_to_pcr(std::string_view text, uint32_t pcr_index,
                                                uint16_t bank_hash_alg,
                                                std::span<const uint8_t> target) {
    const std::size_t width = tpm_digest_size(bank_hash_alg);
    const EVP_MD* md = md_for(bank_hash_alg);
    if (width == 0 || !md || target.size() != width) return std::nullopt;

    std::vector<uint8_t> pcr(width, 0);
    const auto reached = [&] { return std::memcmp(pcr.data(), target.data(), width) == 0; };
    // Nothing measured yet: the empty prefix is the endpoint.
    if (reached()) return std::string{};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::nullopt;

    std::optional<std::string> cut;
    for (std::size_t cursor = 0; cursor < text.size() && !cut;) {
        const auto nl = text.find('\n', cursor);
        const std::size_t end  = (nl == std::string_view::npos) ? text.size() : nl;
        const std::size_t next = (nl == std::string_view::npos) ? text.size() : nl + 1;

        std::string_view line = text.substr(cursor, end - cursor);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        cursor = next;
        if (line.empty()) continue;

        ImaEntry e;
        if (!parse_ima_line(line, e)) break;  // not an IMA log
        if (e.pcr != pcr_index) continue;
        // Wrong width means another bank; see ima_replay_bank.
        if (e.template_hash.size() != width) break;
        if (!extend_pcr(ctx, md, pcr, e.template_hash)) break;
        if (reached()) cut = std::string(text.substr(0, next));
    }

    EVP_MD_CTX_free(ctx);
    return cut;
}

uint16_t ima_replay_bank(const ImaLog& log) {
    switch (log.template_hash_size()) {
        case 20: return kTpmAlgSha1;
        case 32: return kTpmAlgSha256;
        case 48: return kTpmAlgSha384;
        case 64: return kTpmAlgSha512;
        default: return 0;
    }
}

std::optional<ImaEntry> ima_entry_for_path(const ImaLog& log, std::string_view path) {
    std::optional<ImaEntry> found;
    for (const auto& e : log.entries) {
        if (e.path == path) found = e;  // last measurement wins
    }
    return found;
}

std::string read_ima_ascii_log() {
#if defined(__linux__)
    static constexpr const char* kPaths[] = {
        "/sys/kernel/security/ima/ascii_runtime_measurements",
        "/sys/kernel/security/integrity/ima/ascii_runtime_measurements",
    };
    for (const char* p : kPaths) {
        std::ifstream f(p);
        if (!f) continue;
        // securityfs reports size 0, so read to EOF rather than seeking.
        std::string text{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
        if (!text.empty()) return text;
    }
#endif
    return {};
}

std::string running_executable_path() {
#if defined(__linux__)
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) return p.string();
#endif
    return {};
}

}  // namespace nexus::security
