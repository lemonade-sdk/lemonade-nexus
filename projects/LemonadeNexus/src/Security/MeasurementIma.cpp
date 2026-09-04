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
