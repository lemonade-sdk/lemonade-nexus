#include <LemonadeNexus/Gossip/ServerCertificate.hpp>

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
    if (j.contains("signature"))      j.at("signature").get_to(c.signature);
}

std::string canonical_cert_json(const ServerCertificate& cert) {
    // Sorted keys (nlohmann default), excludes "signature"
    json j;
    j["endpoint_hint"]  = cert.endpoint_hint;
    j["expires_at"]     = cert.expires_at;
    j["issued_at"]      = cert.issued_at;
    j["issuer_pubkey"]  = cert.issuer_pubkey;
    j["server_id"]      = cert.server_id;
    j["server_pubkey"]  = cert.server_pubkey;
    return j.dump();
}

} // namespace nexus::gossip
