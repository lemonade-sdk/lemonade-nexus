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
#include <LemonadeNexusAttestd/AttestdGate.hpp>

#include <cstddef>
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

/// The success response. The platform bundle travels as the exact canonical
/// string encode_snp_vtpm_evidence() produced, not as a re-nested object: the
/// identity signature covers a digest of those bytes, so re-serialising them
/// would risk a consumer computing a different digest than the one signed.
[[nodiscard]] std::string encode_bundle(const PlatformEvidenceBundle& bundle);

/// The failure response. `detail` is diagnostic text; the typed `refusal` is
/// what a caller branches on.
[[nodiscard]] std::string encode_refusal(Refusal refusal, std::string_view detail = {});

}  // namespace nexus::attestd
