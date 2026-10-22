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

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>
#include <LemonadeNexusAttestd/AttestdFraming.hpp>
#include <LemonadeNexusAttestd/AttestdGate.hpp>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::attestd {

/// Wire format version. Bumped when the grammar of an existing request or
/// response changes; a request carrying anything else is malformed. A new
/// request type is additive: an older daemon refuses it as MalformedRequest,
/// and every existing form keeps its exact grammar. Owned by
/// SecurityConstants.hpp so the release-approval verifier checks the same
/// number this codec speaks.
inline constexpr int kAttestdWireVersion = security::constants::kAttestdWireVersion;

inline constexpr std::string_view kRequestType = "attestation_challenge";
inline constexpr std::string_view kActivationRequestType = "svsm_ak_activation_offer";
inline constexpr std::string_view kBundleType = "platform_evidence_bundle";
inline constexpr std::string_view kRefusalType = "attestation_refusal";
inline constexpr std::string_view kActivationResultType = "svsm_ak_activation_result";
inline constexpr std::string_view kSealRequestType = "sealed_key_seal";
inline constexpr std::string_view kUnsealRequestType = "sealed_key_unseal";
inline constexpr std::string_view kSealResultType = "sealed_key_seal_result";
inline constexpr std::string_view kUnsealResultType = "sealed_key_unseal_result";

/// Largest request the daemon will read off the socket. A challenge carries up
/// to kMaxSummarisedPaths checkpoint paths of up to 4 KiB each; this covers
/// that and still bounds a local caller that decides to stream forever.
inline constexpr std::size_t kMaxRequestBytes = 128 * 1024;

/// Parse a request into a challenge. Returns nullopt on ANY deviation from the
/// closed grammar: wrong version, wrong type, missing field, wrong JSON type,
/// wrong hex width, unknown purpose value, or an unrecognised key.
[[nodiscard]] std::optional<security::AttestationChallenge> decode_challenge(std::string_view json);

/// One SVSM AK activation request. The fields pass to the TPM as-is — the
/// daemon never parses or alters them — and no persistent handle is created.
struct SvsmAkActivationRequest {
    /// TPM2B_PUBLIC of the enrollment EK (outer TPM2B wrapper, wire form).
    std::vector<uint8_t> ek_public;
    /// TPM2B_PUBLIC of the proposed quote AK.
    std::vector<uint8_t> ak_public;
    /// TPM2B_ID_OBJECT credential blob from TPM2_MakeCredential.
    std::vector<uint8_t> credential_blob;
    /// TPM2B_ENCRYPTED_SECRET from TPM2_MakeCredential.
    std::vector<uint8_t> encrypted_secret;
};

/// Largest single activation field. A TPM2B_PUBLIC for an RSA-3072 key is under
/// 2 KiB; the credential and secret values are bounded by the RSA modulus.
inline constexpr std::size_t kMaxActivationFieldBytes = 4096;

/// Same closed-grammar discipline as decode_challenge. Any deviation is
/// nullopt, never a partial value.
[[nodiscard]] std::optional<SvsmAkActivationRequest> decode_activation_request(std::string_view json);

/// The one-connection request bytes for an activation, newline terminated.
[[nodiscard]] std::string encode_activation_request(const SvsmAkActivationRequest& request);

/// One seal request: create a random key sealed to PCR 8 and 9 of this host's
/// TPM. The request carries no secret; the server encrypts its secret under the
/// returned key (security::make_sealed_blob). The PCR selection is fixed
/// (security::kSvsmBootPcrs); a request can choose only the values.
struct SealRequest {
    /// A valid sealing domain (security::valid_seal_domain). It names the
    /// secret role in the daemon's log and changes nothing in the TPM object.
    std::string domain;
    /// nullopt: bind the PCR values the TPM holds now. A value: bind these
    /// values instead (the expected PCRs of a verified release approval).
    std::optional<security::BootPcrValues> target;
};

/// One unseal request: a sealed key object a seal returned. Never the blob's
/// ciphertext.
struct UnsealRequest {
    std::string domain;
    security::SealedKeyObject object;
};

/// Closed grammar: {version, type, domain, target}. `target` is the string
/// "current" or an object with exactly "pcr8" and "pcr9" (64 lowercase hex
/// each). Any deviation is nullopt.
[[nodiscard]] std::optional<SealRequest> decode_seal_request(std::string_view json);

/// Request bytes, newline terminated.
[[nodiscard]] std::string encode_seal_request(const SealRequest& request);

/// Closed grammar: {version, type, domain, pcr_digest, tpm_public,
/// tpm_private}. Hex digest, base64 objects within security::kMaxTpmObjectBytes.
[[nodiscard]] std::optional<UnsealRequest> decode_unseal_request(std::string_view json);

[[nodiscard]] std::string encode_unseal_request(const UnsealRequest& request);

/// Takes one complete frame's bytes. False stops the emitter where it stands.
using FrameSink = std::function<bool(std::string_view frame)>;

/// Header, chunks, End. The platform bundle travels as the exact canonical
/// string encode_platform_evidence() produced: re-nesting it as JSON would risk
/// a consumer computing a different digest than the one signed. False when the
/// sink refused, or when the bundle needs more than kMaxLocalChunks.
[[nodiscard]] bool emit_bundle(const PlatformEvidenceBundle& bundle, const FrameSink& sink);

/// One Refusal frame. `detail` is diagnostic; the typed value is what a caller
/// branches on.
[[nodiscard]] bool emit_refusal(Refusal refusal, const FrameSink& sink,
                                 std::string_view detail = {});

/// One Result frame: the activated secret in hex. A single frame — no chunks,
/// no End — so there is no reassembly state to get wrong.
[[nodiscard]] bool emit_activation_result(const std::vector<uint8_t>& activated_secret,
                                           const FrameSink& sink);

/// One Result frame: the sealed key object and the key it holds. The frame
/// buffer is wiped after the sink returns.
[[nodiscard]] bool emit_seal_result(const security::SealedKeyObject& object,
                                    std::span<const uint8_t> key, const FrameSink& sink);

/// One Result frame: the unsealed key. The frame buffer is wiped after the
/// sink returns.
[[nodiscard]] bool emit_unseal_result(std::span<const uint8_t> key, const FrameSink& sink);

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

    /// The activated secret, when the stream was a single Result frame;
    /// nullopt when the stream was anything else.
    [[nodiscard]] std::optional<std::vector<uint8_t>> result_secret() const;

    /// The sealed key object, when the stream was a single seal Result frame.
    [[nodiscard]] std::optional<security::SealedKeyObject> result_object() const;

    /// True when the stream was a single seal or unseal Result frame. The key
    /// is moved out once by take_result_key().
    [[nodiscard]] bool has_result_key() const;
    [[nodiscard]] crypto::SecureBuffer take_result_key();

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
    std::vector<uint8_t> result_secret_;
    std::string      result_type_;
    security::SealedKeyObject result_object_;
    crypto::SecureBuffer result_key_;
};

}  // namespace nexus::attestd
