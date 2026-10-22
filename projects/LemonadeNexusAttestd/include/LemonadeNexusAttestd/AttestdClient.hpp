#pragma once

// The unprivileged half: how Nexus asks nexus-attestd for platform evidence.
//
// It lives beside the daemon so both halves compile from one grammar and one set
// of bounds. Outbound: a structured challenge — no nonce, no PCR selection, no
// bytes to sign. Inbound: platform evidence and the digest it was bound to — no
// signature, no vote key, no verdict.
//
// The same socket seals and unseals keys for the server's boot set
// (attestd_seal_backend). That backend is the only production SealBackend. It
// encrypts and decrypts the secret in this process, so the secret and the
// blob's ciphertext never cross the socket.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>
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

/// AttestdFetchResult's shape plus the activated secret on success.
struct AttestdActivationResult {
    bool        ok{false};
    Refusal     refusal{Refusal::None};
    FrameError  transport{FrameError::None};
    std::string detail;
    std::vector<uint8_t> activated_secret;
};

/// AttestdFetchResult's shape plus the new sealed key on success.
struct AttestdSealResult {
    bool                      ok{false};
    Refusal                   refusal{Refusal::None};
    FrameError                transport{FrameError::None};
    std::string               detail;
    security::SealedKeyObject object;
    crypto::SecureBuffer      key;
};

/// AttestdFetchResult's shape plus the unsealed key on success.
struct AttestdUnsealResult {
    bool                 ok{false};
    Refusal              refusal{Refusal::None};
    FrameError           transport{FrameError::None};
    std::string          detail;
    crypto::SecureBuffer key;
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

    /// One connection, one activation request, one framed answer: a Result
    /// frame or a Refusal.
    [[nodiscard]] AttestdActivationResult activate(const SvsmAkActivationRequest& request) const;

    /// One connection, one seal request, one framed answer: a seal Result
    /// frame or a Refusal.
    [[nodiscard]] AttestdSealResult seal(const SealRequest& request) const;

    /// One connection, one unseal request, one framed answer: an unseal
    /// Result frame or a Refusal.
    [[nodiscard]] AttestdUnsealResult unseal(const UnsealRequest& request) const;

private:
    AttestdClientConfig config_;
};

/// Read one framed response from a connected socket. Exposed so the bounds are
/// exercisable over a socketpair with no daemon and no TPM.
[[nodiscard]] AttestdFetchResult read_framed_response(int fd, int deadline_seconds,
                                                       PlatformEvidenceBundle& out);

/// Read one framed activation answer — a single Result or Refusal frame —
/// under the same local bounds as the evidence path.
[[nodiscard]] AttestdActivationResult read_activation_response(int fd, int deadline_seconds);

/// Read one framed seal answer — a single Result or Refusal frame.
[[nodiscard]] AttestdSealResult read_seal_response(int fd, int deadline_seconds);

/// Read one framed unseal answer — a single Result or Refusal frame.
[[nodiscard]] AttestdUnsealResult read_unseal_response(int fd, int deadline_seconds);

/// The request bytes for one challenge: the closed JSON grammar, newline
/// terminated. Separate from the socket so a test can drive a server with it.
[[nodiscard]] std::string encode_challenge_request(const security::AttestationChallenge& challenge);

/// The producer seam, wired to a daemon. Returns EMPTY evidence on any failure,
/// including a daemon that bound its answer to a different challenge — the
/// verifier refuses empty evidence, so a bad daemon costs an attestation rather
/// than buying one.
[[nodiscard]] security::PlatformEvidenceSource attestd_platform_source(AttestdClientConfig config);

/// The activation seam, wired to the same daemon. nullopt on any failure; the
/// producer treats that as "no activated secret", which is a hard refusal in
/// the verifier.
[[nodiscard]] security::PlatformActivationSource attestd_activation_source(
    AttestdClientConfig config);

/// The sealing seam, wired to the same daemon. Seal asks the daemon for a new
/// sealed key and encrypts the plaintext under it here
/// (security::make_sealed_blob); unseal sends only the blob's key object and
/// decrypts here (security::open_sealed_blob). A blob that does not parse,
/// names another domain, or fails its tag is Corrupt. Maps the daemon's answer
/// onto security::SealStatus:
///   transport fault                         -> Unreachable (the daemon may be starting)
///   SealUnavailable, or MalformedRequest    -> Unavailable (no TPM, or an older daemon
///                                              that does not know the operation)
///   SealPolicyMismatch                      -> PolicyMismatch
///   SealCorrupt                             -> Corrupt
///   any other refusal                       -> Failed
[[nodiscard]] security::SealBackend attestd_seal_backend(AttestdClientConfig config);

}  // namespace nexus::attestd
