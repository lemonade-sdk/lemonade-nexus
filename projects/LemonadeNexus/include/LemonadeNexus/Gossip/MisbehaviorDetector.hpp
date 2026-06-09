#pragma once

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::gossip {

// ===========================================================================
// Misbehavior proofs — dispositive, self-verifying evidence of equivocation
// ===========================================================================
//
// Every statement a peer makes on the mesh is Ed25519-signed and gossiped. That
// makes a peer's own signatures non-repudiable: if a peer signs two contradictory
// statements at the same logical position, ANY honest node can bundle both signed
// statements into a MisbehaviorProof that any third party re-verifies as a pure
// function — re-check both signatures against the accused key, re-check the conflict
// predicate. No honest node ever produces such a pair, and an attacker cannot forge
// the accused's signatures, so a valid proof is *non-forgeable* evidence and a ban
// can be applied automatically (dispositive). The `reporter_pubkey` is provenance
// only and is NOT trusted for the ban — that is what makes the proof trust-free and
// immune to griefing (a malicious reporter cannot frame an honest node).
//
// This module is pure (no I/O, no GossipService state) so it is unit-testable in
// isolation and reused by both the detection hooks and the proof verifier.

enum class MisbehaviorKind : uint8_t {
    // Two valid tree deltas signed by the same key for the same (target_node_id,
    // sequence) but with differing committed content. Storage re-sequences deltas
    // locally, so the conflict is keyed on what the *signer* committed to, not on
    // storage state. (See FileStorageService::do_append_delta.)
    TreeDeltaEquivocation = 1,
    // Reserved for future hooks (DNS/IPAM/NS-slot/ACL/vote conflicts).
};

struct MisbehaviorProof {
    MisbehaviorKind kind{MisbehaviorKind::TreeDeltaEquivocation};
    std::string accused_pubkey;   ///< base64 Ed25519, normalized (no "ed25519:" prefix)
    std::string statement_a;      ///< JSON of the first signed message (object incl. its signature)
    std::string statement_b;      ///< JSON of the second signed message
    std::string reporter_pubkey;  ///< provenance ONLY — never trusted for the ban decision
    uint64_t    observed_at{0};   ///< unix seconds the reporter observed the conflict
    std::string proof_id;         ///< deterministic dedupe id (hex); identical across observers
};

void to_json(nlohmann::json& j, const MisbehaviorProof& p);
void from_json(const nlohmann::json& j, MisbehaviorProof& p);

/// Strip an optional "ed25519:" prefix, returning the bare base64 key. Tree-delta
/// signer_pubkeys carry the prefix; certificates / trust state / revocation use the
/// bare form, so detection normalizes before comparing or banning.
[[nodiscard]] std::string normalize_pubkey(std::string_view pubkey);

/// Canonical signed preimage for a tree-delta JSON object. MUST match exactly what
/// GossipService::do_handle_deltas verifies, or the proof's signature check fails.
[[nodiscard]] std::string tree_delta_canonical(const nlohmann::json& delta);

/// True iff `delta` carries a valid Ed25519 signature by its own signer_pubkey.
[[nodiscard]] bool verify_tree_delta_signature(const nlohmann::json& delta,
                                               crypto::SodiumCryptoService& crypto);

/// True iff the two tree-delta objects equivocate: same (signer, target_node_id,
/// sequence) but differing committed content. Does NOT check signatures.
[[nodiscard]] bool tree_deltas_conflict(const nlohmann::json& a, const nlohmann::json& b);

/// Build a proof from two tree deltas. Returns nullopt unless BOTH are individually
/// signature-valid AND they constitute provable equivocation. Statements are stored
/// in a deterministic order so independent observers compute the same proof_id.
[[nodiscard]] std::optional<MisbehaviorProof> make_tree_delta_equivocation_proof(
    const nlohmann::json& a, const nlohmann::json& b,
    const std::string& reporter_pubkey, uint64_t observed_at,
    crypto::SodiumCryptoService& crypto);

/// Dispositive verification: re-verify both statements are signed by `accused_pubkey`
/// and that they genuinely conflict. Returns true only if the accused PROVABLY
/// equivocated. The reporter's identity/signature is irrelevant here by design.
[[nodiscard]] bool verify_misbehavior_proof(const MisbehaviorProof& proof,
                                            crypto::SodiumCryptoService& crypto);

/// Deterministic id = hex(SHA256(kind ‖ accused ‖ ordered(statement_a,statement_b))).
/// Independent of statement order so two observers of the same conflict converge.
[[nodiscard]] std::string misbehavior_proof_id(MisbehaviorKind kind,
                                               const std::string& accused_pubkey,
                                               const std::string& statement_a,
                                               const std::string& statement_b,
                                               crypto::SodiumCryptoService& crypto);

} // namespace nexus::gossip
