#pragma once

// The unprivileged half: how Nexus asks nexus-attestd for platform evidence.
//
// It lives beside the daemon so both halves compile from one grammar and one set
// of bounds. Outbound: a structured challenge — no nonce, no PCR selection, no
// bytes to sign. Inbound: platform evidence and the digest it was bound to — no
// signature, no vote key, no verdict.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexusAttestd/AttestdCodec.hpp>
#include <LemonadeNexusAttestd/AttestdFraming.hpp>
#include <LemonadeNexusAttestd/AttestdGate.hpp>
#include <LemonadeNexusAttestd/AttestdSocket.hpp>

#include <filesystem>
#include <string>

namespace nexus::attestd {

struct AttestdClientConfig {
    /// Fixed, not discovered: a client that hunts for a socket can be pointed
    /// at somebody else's.
    std::filesystem::path path{"/run/nexus-attestd/nexus-attestd.sock"};
};

/// `transport` when the exchange failed, `refusal` when the daemon declined,
/// neither when the bundle is good.
struct AttestdFetchResult {
    bool        ok{false};
    Refusal     refusal{Refusal::None};
    FrameError  transport{FrameError::None};
    std::string detail;
};

class AttestdClient {
public:
    explicit AttestdClient(AttestdClientConfig config) : config_(std::move(config)) {}

    /// One connection, one challenge, one framed response. A declared frame
    /// length is checked before anything is reserved; the whole exchange expires
    /// at kLocalStreamDeadlineSeconds and never reads to end-of-file.
    ///
    /// `out.challenge_digest` is the daemon's own derivation — the caller must
    /// compare it with challenge_digest(challenge).
    [[nodiscard]] AttestdFetchResult fetch(const security::AttestationChallenge& challenge,
                                           PlatformEvidenceBundle& out);

private:
    AttestdClientConfig config_;
};

/// Read one framed response from a connected socket. Exposed so the bounds are
/// exercisable over a socketpair with no daemon and no TPM.
[[nodiscard]] AttestdFetchResult read_framed_response(int fd, int deadline_seconds,
                                                       PlatformEvidenceBundle& out);

/// The request bytes for one challenge: the closed JSON grammar, newline
/// terminated. Separate from the socket so a test can drive a server with it.
[[nodiscard]] std::string encode_challenge_request(const security::AttestationChallenge& challenge);

/// The producer seam, wired to a daemon. Returns EMPTY evidence on any failure,
/// including a daemon that bound its answer to a different challenge — the
/// verifier refuses empty evidence, so a bad daemon costs an attestation rather
/// than buying one.
[[nodiscard]] security::PlatformEvidenceSource attestd_platform_source(AttestdClientConfig config);

}  // namespace nexus::attestd
