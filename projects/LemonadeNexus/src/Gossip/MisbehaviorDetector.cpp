#include <LemonadeNexus/Gossip/MisbehaviorDetector.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <algorithm>
#include <cstring>
#include <vector>

namespace nexus::gossip {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

void to_json(json& j, const MisbehaviorProof& p) {
    j = json{
        {"kind",           static_cast<uint8_t>(p.kind)},
        {"accused_pubkey", p.accused_pubkey},
        {"statement_a",    p.statement_a},
        {"statement_b",    p.statement_b},
        {"reporter_pubkey", p.reporter_pubkey},
        {"observed_at",    p.observed_at},
        {"proof_id",       p.proof_id},
    };
}

void from_json(const json& j, MisbehaviorProof& p) {
    if (j.contains("kind"))            p.kind = static_cast<MisbehaviorKind>(j.at("kind").get<uint8_t>());
    if (j.contains("accused_pubkey"))  j.at("accused_pubkey").get_to(p.accused_pubkey);
    if (j.contains("statement_a"))     j.at("statement_a").get_to(p.statement_a);
    if (j.contains("statement_b"))     j.at("statement_b").get_to(p.statement_b);
    if (j.contains("reporter_pubkey")) j.at("reporter_pubkey").get_to(p.reporter_pubkey);
    if (j.contains("observed_at"))     j.at("observed_at").get_to(p.observed_at);
    if (j.contains("proof_id"))        j.at("proof_id").get_to(p.proof_id);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string normalize_pubkey(std::string_view pubkey) {
    if (pubkey.starts_with("ed25519:")) pubkey.remove_prefix(8);
    return std::string(pubkey);
}

std::string tree_delta_canonical(const json& delta) {
    // MUST mirror GossipService::do_handle_deltas exactly:
    //   operation\n target_node_id\n sequence\n required_permission\n timestamp\n data
    const std::string op     = delta.value("operation", "");
    const std::string target = delta.value("target_node_id", "");
    const uint64_t    seq    = delta.value("sequence", uint64_t{0});
    const std::string perm   = delta.value("required_permission", "");
    const uint64_t    ts     = delta.value("timestamp", uint64_t{0});
    const std::string data   = delta.contains("data") ? delta["data"].dump() : std::string{};

    return op + "\n" + target + "\n" + std::to_string(seq) + "\n" +
           perm + "\n" + std::to_string(ts) + "\n" + data;
}

bool verify_tree_delta_signature(const json& delta, crypto::SodiumCryptoService& crypto) {
    const std::string signer = delta.value("signer_pubkey", "");
    const std::string sig_b64 = delta.value("signature", "");
    if (signer.empty() || sig_b64.empty()) return false;

    try {
        auto pk_bytes = crypto::from_base64(normalize_pubkey(signer));
        auto sig_bytes = crypto::from_base64(sig_b64);
        if (pk_bytes.size() != crypto::kEd25519PublicKeySize ||
            sig_bytes.size() != crypto::kEd25519SignatureSize) {
            return false;
        }
        crypto::Ed25519PublicKey pub{};
        crypto::Ed25519Signature sig{};
        std::memcpy(pub.data(), pk_bytes.data(), crypto::kEd25519PublicKeySize);
        std::memcpy(sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

        auto canonical = tree_delta_canonical(delta);
        std::vector<uint8_t> bytes(canonical.begin(), canonical.end());
        return crypto.ed25519_verify(pub, bytes, sig);
    } catch (...) {
        return false;
    }
}

bool tree_deltas_conflict(const json& a, const json& b) {
    const std::string sa = normalize_pubkey(a.value("signer_pubkey", ""));
    const std::string sb = normalize_pubkey(b.value("signer_pubkey", ""));
    if (sa.empty() || sa != sb) return false;  // must be the same signer

    // Same logical position...
    if (a.value("target_node_id", "") != b.value("target_node_id", "")) return false;
    if (a.value("sequence", uint64_t{0}) != b.value("sequence", uint64_t{0})) return false;

    // ...but differing committed content. Since the identity fields above are equal,
    // a difference anywhere in the canonical preimage means the signer committed to
    // two contradictory statements at the same (target, sequence).
    return tree_delta_canonical(a) != tree_delta_canonical(b);
}

std::string misbehavior_proof_id(MisbehaviorKind kind,
                                 const std::string& accused_pubkey,
                                 const std::string& statement_a,
                                 const std::string& statement_b,
                                 crypto::SodiumCryptoService& crypto) {
    // Order the statements so the id is independent of which was observed first.
    const std::string& lo = statement_a <= statement_b ? statement_a : statement_b;
    const std::string& hi = statement_a <= statement_b ? statement_b : statement_a;

    std::string preimage;
    preimage.push_back(static_cast<char>(kind));
    preimage += accused_pubkey;
    preimage.push_back('\x1f');
    preimage += lo;
    preimage.push_back('\x1f');
    preimage += hi;

    std::vector<uint8_t> bytes(preimage.begin(), preimage.end());
    auto digest = crypto.sha256(bytes);
    return crypto::to_hex(std::span<const uint8_t>(digest.data(), digest.size()));
}

std::optional<MisbehaviorProof> make_tree_delta_equivocation_proof(
    const json& a, const json& b,
    const std::string& reporter_pubkey, uint64_t observed_at,
    crypto::SodiumCryptoService& crypto) {

    // Both statements must be individually signature-valid by the accused, and they
    // must genuinely conflict. Otherwise there is no provable equivocation.
    if (!tree_deltas_conflict(a, b)) return std::nullopt;
    if (!verify_tree_delta_signature(a, crypto)) return std::nullopt;
    if (!verify_tree_delta_signature(b, crypto)) return std::nullopt;

    MisbehaviorProof proof;
    proof.kind = MisbehaviorKind::TreeDeltaEquivocation;
    proof.accused_pubkey = normalize_pubkey(a.value("signer_pubkey", ""));
    proof.reporter_pubkey = reporter_pubkey;
    proof.observed_at = observed_at;

    // Store in deterministic order so two observers produce byte-identical proofs.
    std::string da = a.dump();
    std::string db = b.dump();
    if (da <= db) {
        proof.statement_a = std::move(da);
        proof.statement_b = std::move(db);
    } else {
        proof.statement_a = std::move(db);
        proof.statement_b = std::move(da);
    }
    proof.proof_id = misbehavior_proof_id(proof.kind, proof.accused_pubkey,
                                          proof.statement_a, proof.statement_b, crypto);
    return proof;
}

bool verify_misbehavior_proof(const MisbehaviorProof& proof, crypto::SodiumCryptoService& crypto) {
    if (proof.kind != MisbehaviorKind::TreeDeltaEquivocation) {
        return false;  // only equivocation proofs are supported (and dispositive) today
    }
    if (proof.accused_pubkey.empty()) return false;

    json a, b;
    try {
        a = json::parse(proof.statement_a);
        b = json::parse(proof.statement_b);
    } catch (...) {
        return false;
    }

    // Both statements must be signed by the ACCUSED — the reporter is irrelevant.
    if (normalize_pubkey(a.value("signer_pubkey", "")) != proof.accused_pubkey) return false;
    if (normalize_pubkey(b.value("signer_pubkey", "")) != proof.accused_pubkey) return false;

    if (!verify_tree_delta_signature(a, crypto)) return false;
    if (!verify_tree_delta_signature(b, crypto)) return false;

    // And they must genuinely contradict each other.
    return tree_deltas_conflict(a, b);
}

} // namespace nexus::gossip
