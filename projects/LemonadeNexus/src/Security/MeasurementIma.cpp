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

        // <pcr> <template-hash> <template-name> <file-hash> <path> [signature...]
        std::istringstream fields{line};
        std::string pcr_s, tmpl_hash_s, tmpl_name, file_hash_s;
        if (!(fields >> pcr_s >> tmpl_hash_s >> tmpl_name >> file_hash_s)) {
            return std::nullopt;  // not an IMA log
        }

        ImaEntry e;
        try {
            e.pcr = static_cast<uint32_t>(std::stoul(pcr_s));
        } catch (...) {
            return std::nullopt;
        }
        e.template_hash = unhex(tmpl_hash_s);
        if (e.template_hash.empty()) return std::nullopt;
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
        const auto& extend = e.template_hash;

        unsigned char out[EVP_MAX_MD_SIZE];
        unsigned len = 0;
        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
            EVP_DigestUpdate(ctx, pcr.data(), pcr.size()) != 1 ||
            EVP_DigestUpdate(ctx, extend.data(), extend.size()) != 1 ||
            EVP_DigestFinal_ex(ctx, out, &len) != 1 || len != width) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        pcr.assign(out, out + len);
    }

    EVP_MD_CTX_free(ctx);
    return pcr;
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
