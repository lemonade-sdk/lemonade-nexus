#pragma once

// The daemon's request and response forms.
//
// JSON, hex for every fixed-width field, mirroring the security stores
// (EligibilityStore, HotStuffState). This is a local IPC boundary, not the mesh
// wire — the mesh has its own length-prefixed SecurityCodec — so readability for
// an operator running `socat` against the socket is worth more here than bytes
// on the network.
//
// The request grammar is a CLOSED allowlist. That is a security property, not
// tidiness: it is what makes "the daemon never accepts caller-supplied
// qualifyingData" checkable. There is no field for a raw nonce, no field for a
// PCR selection, and no field for bytes to sign — and an unknown field is a
// refusal rather than something quietly ignored, so a future caller cannot smuggle
// one past an older daemon.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexusAttestd/AttestdFraming.hpp>
#include <LemonadeNexusAttestd/AttestdGate.hpp>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::attestd {

/// Wire format version. Bumped when the grammar below changes; a request
/// carrying anything else is malformed.
inline constexpr int kAttestdWireVersion = 1;

inline constexpr std::string_view kRequestType = "attestation_challenge";
inline constexpr std::string_view kBundleType = "platform_evidence_bundle";
inline constexpr std::string_view kRefusalType = "attestation_refusal";

/// Largest request the daemon will read off the socket. A challenge is a few
/// hundred bytes of hex; this is generous by two orders of magnitude and still
/// bounds a local caller that decides to stream forever.
inline constexpr std::size_t kMaxRequestBytes = 8 * 1024;

/// Parse a request into a challenge. Returns nullopt on ANY deviation from the
/// closed grammar: wrong version, wrong type, missing field, wrong JSON type,
/// wrong hex width, unknown purpose value, or an unrecognised key.
[[nodiscard]] std::optional<security::AttestationChallenge> decode_challenge(std::string_view json);

/// Takes one complete frame's bytes. False stops the emitter where it stands.
using FrameSink = std::function<bool(std::string_view frame)>;

/// Header, chunks, End. The platform bundle travels as the exact canonical
/// string encode_snp_vtpm_evidence() produced: re-nesting it as JSON would risk
/// a consumer computing a different digest than the one signed. False when the
/// sink refused, or when the bundle needs more than kMaxLocalChunks.
[[nodiscard]] bool emit_bundle(const PlatformEvidenceBundle& bundle, const FrameSink& sink);

/// One Refusal frame. `detail` is diagnostic; the typed value is what a caller
/// branches on.
[[nodiscard]] bool emit_refusal(Refusal refusal, const FrameSink& sink,
                                 std::string_view detail = {});

/// Reassembles a framed response under the local bounds, with no transport of
/// its own, so every bound is testable without a socket.
///
/// The grammar is a state machine: Header first, chunks only after it, End once,
/// Refusal only in place of a Header. Out of that order is Malformed.
class ResponseAssembler {
public:
    /// Offer one frame whose payload the transport has ALREADY bounds-checked.
    /// False means the stream is over — done(), or error() says why not.
    [[nodiscard]] bool offer(FrameKind kind, std::string_view payload);

    [[nodiscard]] bool done() const { return done_; }
    [[nodiscard]] FrameError error() const { return error_; }

    /// Set only when the response was a refusal.
    [[nodiscard]] Refusal refusal() const { return refusal_; }
    [[nodiscard]] const std::string& detail() const { return detail_; }

    /// False when the stream did not complete, when it was a refusal, or when
    /// the bytes do not match the length and digest End committed to.
    [[nodiscard]] bool finish(PlatformEvidenceBundle& out);

    /// Bytes accepted so far, frame headers included.
    [[nodiscard]] std::size_t accepted() const { return accepted_; }

private:
    [[nodiscard]] bool fail(FrameError e);

    security::Digest challenge_digest_{};
    std::string      evidence_;
    std::size_t      declared_bytes_{0};
    std::string      declared_digest_;
    std::size_t      chunks_{0};
    std::size_t      accepted_{0};
    bool             header_seen_{false};
    bool             done_{false};
    FrameError       error_{FrameError::None};
    Refusal          refusal_{Refusal::None};
    std::string      detail_;
};

}  // namespace nexus::attestd
