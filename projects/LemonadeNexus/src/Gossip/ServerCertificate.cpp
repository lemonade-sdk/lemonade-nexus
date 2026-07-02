#include <LemonadeNexus/Gossip/ServerCertificate.hpp>

#include <chrono>
#include <vector>

namespace nexus::gossip {

using json = nlohmann::json;

void to_json(json& j, const ServerCertificate& c) {
    j = json{
        {"server_pubkey",  c.server_pubkey},
        {"wg_pubkey",      c.wg_pubkey},
        {"server_id",      c.server_id},
        {"endpoint_hint",  c.endpoint_hint},
        {"issued_at",      c.issued_at},
        {"expires_at",     c.expires_at},
        {"issuer_pubkey",  c.issuer_pubkey},
        {"tpm_ak_pubkey",  c.tpm_ak_pubkey},
        {"tpm_ek_cert",    c.tpm_ek_cert},
        {"signature",      c.signature},
    };
}

void from_json(const json& j, ServerCertificate& c) {
    if (j.contains("server_pubkey"))  j.at("server_pubkey").get_to(c.server_pubkey);
    if (j.contains("wg_pubkey"))      j.at("wg_pubkey").get_to(c.wg_pubkey);
    if (j.contains("server_id"))      j.at("server_id").get_to(c.server_id);
    if (j.contains("endpoint_hint"))  j.at("endpoint_hint").get_to(c.endpoint_hint);
    if (j.contains("issued_at"))      j.at("issued_at").get_to(c.issued_at);
    if (j.contains("expires_at"))     j.at("expires_at").get_to(c.expires_at);
    if (j.contains("issuer_pubkey"))  j.at("issuer_pubkey").get_to(c.issuer_pubkey);
    if (j.contains("tpm_ak_pubkey"))  j.at("tpm_ak_pubkey").get_to(c.tpm_ak_pubkey);
    if (j.contains("tpm_ek_cert"))    j.at("tpm_ek_cert").get_to(c.tpm_ek_cert);
    if (j.contains("signature"))      j.at("signature").get_to(c.signature);
}

std::string canonical_cert_json(const ServerCertificate& cert) {
    // Sorted keys (nlohmann default), excludes "signature". The pinned AK and EK
    // cert are inside the canonical form so the root signature binds them to the
    // server identity (closing the self-asserted-key gap structurally).
    json j;
    j["endpoint_hint"]  = cert.endpoint_hint;
    j["expires_at"]     = cert.expires_at;
    j["issued_at"]      = cert.issued_at;
    j["issuer_pubkey"]  = cert.issuer_pubkey;
    j["server_id"]      = cert.server_id;
    j["server_pubkey"]  = cert.server_pubkey;
    j["tpm_ak_pubkey"]  = cert.tpm_ak_pubkey;
    j["tpm_ek_cert"]    = cert.tpm_ek_cert;
    return j.dump();
}

bool valid_server_id_label(const std::string& s) {
    if (s.empty() || s.size() > 63) return false;
    if (s.front() == '-' || s.back() == '-') return false;
    for (char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) return false;
    }
    return true;
}

ServerCertificate issue_server_certificate(
    const CertIssueParams& params,
    crypto::SodiumCryptoService& crypto,
    const crypto::Ed25519PrivateKey& root_privkey,
    const crypto::Ed25519PublicKey& root_pubkey)
{
    ServerCertificate cert;
    cert.server_pubkey = params.server_pubkey_b64;
    cert.server_id     = params.server_id;
    cert.issued_at     = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    cert.expires_at    = params.expires_at;
    cert.issuer_pubkey = crypto::to_base64(root_pubkey);
    cert.tpm_ak_pubkey = params.tpm_ak_pubkey;
    cert.tpm_ek_cert   = params.tpm_ek_cert;

    auto canonical = canonical_cert_json(cert);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig = crypto.ed25519_sign(root_privkey, canonical_bytes);
    cert.signature = crypto::to_base64(sig);
    return cert;
}

} // namespace nexus::gossip
