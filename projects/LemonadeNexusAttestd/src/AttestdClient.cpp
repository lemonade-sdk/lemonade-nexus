#include <LemonadeNexusAttestd/AttestdClient.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <unistd.h>
#endif

namespace nexus::attestd {

namespace {

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

AttestdFetchResult transport_fault(FrameError e, std::string detail = {}) {
    AttestdFetchResult r;
    r.transport = e;
    r.detail = std::move(detail);
    return r;
}

#ifndef _WIN32

/// Read exactly `count` bytes, or fail. Never reads to end-of-file, and never
/// waits past `expires`: the caller has already checked `count` against
/// kMaxLocalFrameBytes, so this cannot be steered into a large read.
bool read_exact(int fd, Clock::time_point expires, uint8_t* into, std::size_t count) {
    std::size_t got = 0;
    while (got < count) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              expires - Clock::now())
                              .count();
        if (left <= 0) return false;

        ::pollfd pfd{fd, POLLIN, 0};
        const int ready = ::poll(&pfd, 1, static_cast<int>(left));
        if (ready < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (ready == 0) return false;  // deadline

        const ssize_t n = ::read(fd, into + got, count - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;  // peer closed mid-frame
        got += static_cast<std::size_t>(n);
    }
    return true;
}

bool write_all(int fd, Clock::time_point expires, std::string_view data) {
    while (!data.empty()) {
        if (Clock::now() >= expires) return false;
        const ssize_t n = ::write(fd, data.data(), data.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
}

#endif  // !_WIN32

}  // namespace

std::string encode_challenge_request(const security::AttestationChallenge& challenge) {
    json j;
    j["version"] = kAttestdWireVersion;
    j["type"] = std::string(kRequestType);
    j["network_id"] = crypto::to_hex(challenge.network_id);
    j["nonce"] = crypto::to_hex(challenge.nonce);
    j["node_id"] = crypto::to_hex(challenge.node_id.bytes);
    j["node_key"] = crypto::to_hex(challenge.node_key);
    j["incarnation"] = challenge.incarnation;
    j["epoch"] = challenge.epoch;
    j["security_ruleset"] = challenge.security_ruleset;
    j["consensus_ruleset"] = challenge.consensus_ruleset;
    j["profile_id"] = static_cast<uint16_t>(challenge.profile_id);
    j["profile_ruleset"] = challenge.profile_ruleset;
    j["policy_digest"] = crypto::to_hex(challenge.policy_digest);
    j["purpose"] = static_cast<uint16_t>(challenge.purpose);
    j["context_digest"] = crypto::to_hex(challenge.context_digest);
    return j.dump() + "\n";
}

#ifndef _WIN32

AttestdFetchResult read_framed_response(int fd, int deadline_seconds,
                                        PlatformEvidenceBundle& out) {
    const auto expires = Clock::now() + std::chrono::seconds(deadline_seconds);

    ResponseAssembler assembler;
    std::vector<uint8_t> payload;
    std::size_t total = 0;

    for (;;) {
        uint8_t head[kFrameHeaderBytes];
        if (!read_exact(fd, expires, head, sizeof(head))) {
            return transport_fault(FrameError::Truncated,
                                   "the daemon stopped writing before the response was complete");
        }
        const std::size_t length = (static_cast<std::size_t>(head[0]) << 24) |
                                   (static_cast<std::size_t>(head[1]) << 16) |
                                   (static_cast<std::size_t>(head[2]) << 8) |
                                   static_cast<std::size_t>(head[3]);

        // Both bounds are checked against the DECLARED length, before a byte of
        // it is read or reserved. A hostile length is an error, never a buffer.
        if (length > kMaxLocalFrameBytes) {
            return transport_fault(FrameError::Oversized,
                                   "frame declares " + std::to_string(length) + " bytes");
        }
        total += kFrameHeaderBytes + length;
        if (total > kMaxLocalResponseBytes) {
            return transport_fault(FrameError::TooLarge,
                                   "response passed " +
                                       std::to_string(kMaxLocalResponseBytes) + " bytes");
        }

        payload.resize(length);
        if (length > 0 && !read_exact(fd, expires, payload.data(), length)) {
            return transport_fault(FrameError::Truncated, "frame body did not arrive");
        }

        const auto kind = static_cast<FrameKind>(head[4]);
        const std::string_view body(reinterpret_cast<const char*>(payload.data()), length);
        if (!assembler.offer(kind, body)) {
            if (!assembler.done()) {
                return transport_fault(assembler.error(),
                                       std::string(frame_error_name(assembler.error())));
            }
            break;  // End or Refusal: the stream is over, and correctly so
        }
    }

    AttestdFetchResult result;
    if (assembler.refusal() != Refusal::None) {
        result.refusal = assembler.refusal();
        result.detail = assembler.detail();
        return result;
    }
    if (!assembler.finish(out)) {
        return transport_fault(assembler.error() == FrameError::None ? FrameError::Malformed
                                                                     : assembler.error(),
                               "the reassembled evidence did not match what the daemon "
                               "committed to");
    }
    result.ok = true;
    return result;
}

AttestdFetchResult AttestdClient::fetch(const security::AttestationChallenge& challenge,
                                        PlatformEvidenceBundle& out) {
    const std::string path = config_.path.string();
    ::sockaddr_un addr{};
    if (path.size() + 1 > sizeof(addr.sun_path)) {
        return transport_fault(FrameError::Malformed, "socket path is too long: " + path);
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return transport_fault(FrameError::Truncated,
                               std::string("socket(AF_UNIX): ") + std::strerror(errno));
    }
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

    AttestdFetchResult result;
    if (::connect(fd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr)) != 0) {
        result = transport_fault(FrameError::Truncated,
                                 "connect(" + path + "): " + std::strerror(errno));
    } else {
        const auto expires = Clock::now() + std::chrono::seconds(kLocalStreamDeadlineSeconds);
        if (!write_all(fd, expires, encode_challenge_request(challenge))) {
            result = transport_fault(FrameError::Truncated, "could not send the challenge");
        } else {
            // Half-close so the daemon sees end-of-request even if its read
            // never finds the newline. One request per connection, always.
            ::shutdown(fd, SHUT_WR);
            result = read_framed_response(fd, kLocalStreamDeadlineSeconds, out);
        }
    }
    ::close(fd);
    return result;
}

#else  // _WIN32 — no unix domain socket transport

AttestdFetchResult read_framed_response(int, int, PlatformEvidenceBundle&) {
    return transport_fault(FrameError::Truncated, "nexus-attestd has no transport on Windows");
}

AttestdFetchResult AttestdClient::fetch(const security::AttestationChallenge&,
                                        PlatformEvidenceBundle&) {
    return transport_fault(FrameError::Truncated, "nexus-attestd has no transport on Windows");
}

#endif

security::PlatformEvidenceSource attestd_platform_source(AttestdClientConfig config) {
    return [client = AttestdClient(std::move(config))](
               const security::AttestationChallenge& challenge) mutable {
        PlatformEvidenceBundle bundle;
        const auto result = client.fetch(challenge, bundle);
        if (!result.ok) {
            spdlog::warn("[attestd-client] no platform evidence: {}{}",
                         result.refusal != Refusal::None ? refusal_name(result.refusal)
                                                         : frame_error_name(result.transport),
                         result.detail.empty() ? "" : " — " + result.detail);
            return security::SnpVtpmEvidence{};
        }
        // The daemon derived its own nonce. Evidence bound to a different
        // challenge answers a question we did not ask, so it is discarded here
        // rather than signed and gossiped.
        if (bundle.challenge_digest != security::challenge_digest(challenge)) {
            spdlog::error("[attestd-client] the daemon bound its evidence to another challenge");
            return security::SnpVtpmEvidence{};
        }
        return std::move(bundle.platform);
    };
}

}  // namespace nexus::attestd
