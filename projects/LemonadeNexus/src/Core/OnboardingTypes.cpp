#include <LemonadeNexus/Core/OnboardingTypes.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

namespace nexus::core {

namespace {

struct LegacyAdmission : OnboardingDto<LegacyAdmission> {
    std::string request_id;
    std::string candidate_pubkey;
    std::string server_id;
    std::string region;
    std::string tpm_ak_pubkey;
    std::string tpm_ek_cert;
    std::optional<std::string> platform_class;
    std::optional<std::string> measurement;
    std::optional<std::string> binary_hash;
    std::optional<std::string> evidence_sha256;
    std::optional<std::string> evidence;
    std::optional<std::string> challenge_nonce;
    std::string source_ip;
    uint8_t state{0};
    uint64_t created_at{0};
    uint64_t expires_at{0};
    std::string issued_cert_json;
    std::string decision_reason;
    std::string decided_by;
    std::optional<std::string> decision_mode;
    std::optional<std::string> ballot_claim_json;
    std::optional<std::string> claim_hash;

    static constexpr auto jsonFields() {
        using onboarding_json::field;
        return std::tuple{
            field("request_id", &LegacyAdmission::request_id),
            field("candidate_pubkey", &LegacyAdmission::candidate_pubkey),
            field("server_id", &LegacyAdmission::server_id),
            field("region", &LegacyAdmission::region),
            field("tpm_ak_pubkey", &LegacyAdmission::tpm_ak_pubkey),
            field("tpm_ek_cert", &LegacyAdmission::tpm_ek_cert),
            field("platform_class", &LegacyAdmission::platform_class),
            field("measurement", &LegacyAdmission::measurement),
            field("binary_hash", &LegacyAdmission::binary_hash),
            field("evidence_sha256", &LegacyAdmission::evidence_sha256),
            field("evidence", &LegacyAdmission::evidence),
            field("challenge_nonce", &LegacyAdmission::challenge_nonce),
            field("source_ip", &LegacyAdmission::source_ip),
            field("state", &LegacyAdmission::state),
            field("created_at", &LegacyAdmission::created_at),
            field("expires_at", &LegacyAdmission::expires_at),
            field("issued_cert_json", &LegacyAdmission::issued_cert_json),
            field("decision_reason", &LegacyAdmission::decision_reason),
            field("decided_by", &LegacyAdmission::decided_by),
            field("decision_mode", &LegacyAdmission::decision_mode),
            field("ballot_claim_json", &LegacyAdmission::ballot_claim_json),
            field("claim_hash", &LegacyAdmission::claim_hash)};
    }
};

struct LegacyAdmissionStore : OnboardingDto<LegacyAdmissionStore> {
    bool ever_approved{false};
    std::vector<LegacyAdmission> admissions;
    std::optional<std::map<std::string, uint64_t>> denied_until;

    static constexpr auto jsonFields() {
        using onboarding_json::field;
        return std::tuple{field("ever_approved", &LegacyAdmissionStore::ever_approved),
                          field("admissions", &LegacyAdmissionStore::admissions),
                          field("denied_until", &LegacyAdmissionStore::denied_until)};
    }
};

std::optional<std::string> require_base64_size(std::string_view path,
                                               const std::string& value,
                                               std::size_t expected_size) {
    try {
        if (crypto::from_base64(value).size() == expected_size) return std::nullopt;
    } catch (...) {
    }
    return std::string(path) + ": invalid base64 encoding or decoded size";
}

std::optional<std::string> require_base64(std::string_view path,
                                         const std::string& value) {
    try {
        if (!crypto::from_base64(value).empty()) return std::nullopt;
    } catch (...) {
    }
    return std::string(path) + ": invalid base64 encoding";
}

std::optional<std::string> require_hex_size(std::string_view path,
                                            const std::string& value,
                                            std::size_t expected_size) {
    try {
        if (crypto::from_hex(value).size() == expected_size &&
            value.size() == expected_size * 2) {
            return std::nullopt;
        }
    } catch (...) {
    }
    return std::string(path) + ": invalid hex encoding or decoded size";
}

std::optional<std::string> validate_signed_status(const std::string& request_id,
                                                  const std::string& candidate_pubkey,
                                                  const std::string& signature) {
    if (auto error = require_hex_size("/request_id", request_id, 16)) return error;
    if (auto error = require_base64_size("/candidate_pubkey", candidate_pubkey,
                                         crypto::kEd25519PublicKeySize)) {
        return error;
    }
    return require_base64_size("/signature", signature, crypto::kEd25519SignatureSize);
}

std::optional<std::string> validate_certificate(const gossip::ServerCertificate& certificate) {
    if (auto error = require_hex_size("/certificate/network_id", certificate.network_id,
                                      crypto::kHash256Size)) {
        return error;
    }
    if (auto error = require_base64_size("/certificate/server_pubkey",
                                         certificate.server_pubkey,
                                         crypto::kEd25519PublicKeySize)) {
        return error;
    }
    if (!certificate.mesh_pubkey.empty()) {
        if (auto error = require_base64_size("/certificate/mesh_pubkey",
                                             certificate.mesh_pubkey,
                                             crypto::kX25519PublicKeySize)) {
            return error;
        }
    }
    if (auto error = require_base64_size("/certificate/issuer_pubkey",
                                         certificate.issuer_pubkey,
                                         crypto::kEd25519PublicKeySize)) {
        return error;
    }
    if (auto error = require_base64_size("/certificate/signature", certificate.signature,
                                         crypto::kEd25519SignatureSize)) {
        return error;
    }
    if (!certificate.expected_measurement.empty()) {
        if (auto error = require_hex_size("/certificate/expected_measurement",
                                          certificate.expected_measurement, 48)) {
            return error;
        }
    }
    if (!certificate.approved_binary_hash.empty()) {
        if (auto error = require_hex_size("/certificate/approved_binary_hash",
                                          certificate.approved_binary_hash,
                                          crypto::kHash256Size)) {
            return error;
        }
    }
    return std::nullopt;
}

AdmissionRecord migrate_legacy_admission(LegacyAdmission legacy,
                                         AdmissionPlatform platform) {
    AdmissionRecord record;
    record.request_id = std::move(legacy.request_id);
    record.candidate_pubkey = std::move(legacy.candidate_pubkey);
    record.server_id = std::move(legacy.server_id);
    record.region = std::move(legacy.region);
    record.tpm_ak_pubkey = std::move(legacy.tpm_ak_pubkey);
    record.tpm_ek_cert = std::move(legacy.tpm_ek_cert);
    record.platform_class = platform;
    record.measurement = legacy.measurement.value_or("");
    record.binary_hash = legacy.binary_hash.value_or("");
    record.evidence_sha256 = legacy.evidence_sha256.value_or("");
    record.evidence = legacy.evidence.value_or("");
    record.challenge_nonce = legacy.challenge_nonce.value_or("");
    record.source_ip = std::move(legacy.source_ip);
    record.state = static_cast<AdmissionState>(legacy.state);
    record.created_at = legacy.created_at;
    record.expires_at = legacy.expires_at;
    record.issued_cert_json = std::move(legacy.issued_cert_json);
    record.decision_reason = std::move(legacy.decision_reason);
    record.decided_by = std::move(legacy.decided_by);
    record.decision_mode = legacy.decision_mode.value_or("");
    if (record.decision_mode.empty() && legacy.ballot_claim_json &&
        !legacy.ballot_claim_json->empty()) {
        record.decision_mode = "ballot";
    }
    return record;
}

void put_lp(std::vector<uint8_t>& buffer, std::string_view value) {
    const auto size = static_cast<uint32_t>(value.size());
    for (int shift = 0; shift < 32; shift += 8) {
        buffer.push_back(static_cast<uint8_t>((size >> shift) & 0xff));
    }
    buffer.insert(buffer.end(), value.begin(), value.end());
}

}  // namespace

std::string_view admission_state_name(AdmissionState state) {
    return onboarding_json::EnumCodec<AdmissionState>::toString(state);
}

std::string_view admission_platform_name(AdmissionPlatform platform) {
    return onboarding_json::EnumCodec<AdmissionPlatform>::toString(platform);
}

std::optional<std::string> ChallengeRequest::validate() const {
    return require_base64_size("/candidate_pubkey", candidate_pubkey,
                               crypto::kEd25519PublicKeySize);
}

std::optional<std::string> ChallengeResponse::validate() const {
    return require_base64_size("/nonce", nonce, 32);
}

std::optional<std::string> AdmissionRequest::validate() const {
    if (auto error = require_base64_size("/candidate_pubkey", candidate_pubkey,
                                         crypto::kEd25519PublicKeySize)) {
        return error;
    }
    if (auto error = require_base64_size("/nonce", nonce, 32)) return error;
    if (auto error = require_base64_size("/signature", signature,
                                         crypto::kEd25519SignatureSize)) {
        return error;
    }
    if (!tpm_ak_pubkey.empty()) {
        if (auto error = require_base64("/tpm_ak_pubkey", tpm_ak_pubkey)) return error;
    }
    if (!measurement.empty()) {
        if (auto error = require_hex_size("/measurement", measurement, 48)) return error;
    }
    if (!binary_hash.empty()) {
        if (auto error = require_hex_size("/binary_hash", binary_hash,
                                          crypto::kHash256Size)) {
            return error;
        }
    }
    if (!evidence_sha256.empty()) {
        if (auto error = require_hex_size("/evidence_sha256", evidence_sha256,
                                          crypto::kHash256Size)) {
            return error;
        }
    }
    if (evidence.empty() != evidence_sha256.empty()) {
        return "/evidence: evidence and evidence_sha256 must be present together";
    }
    if (enrollment_token && enrollment_token->empty()) {
        return "/enrollment_token: must be omitted instead of empty";
    }
    return std::nullopt;
}

std::optional<std::string> AdmissionResponse::validate() const {
    if (state != AdmissionState::Pending) return "/state: expected pending";
    return require_hex_size("/request_id", request_id, 16);
}

std::optional<std::string> PollRequest::validate() const {
    return validate_signed_status(request_id, candidate_pubkey, signature);
}

std::optional<std::string> AdmissionStatusResponse::validate() const {
    if (state == AdmissionState::Approved) {
        return "/state: approved responses require an approved onboarding bundle";
    }
    return std::nullopt;
}

std::optional<std::string> ApprovedOnboardingBundle::validate() const {
    if (state != AdmissionState::Approved) return "/state: expected approved";
    if (auto error = require_hex_size("/root_pubkey", root_pubkey,
                                      crypto::kEd25519PublicKeySize)) {
        return error;
    }
    if (mesh_server_pubkey) {
        if (auto error = require_base64_size("/mesh_server_pubkey", *mesh_server_pubkey,
                                             crypto::kX25519PublicKeySize)) {
            return error;
        }
    }
    if (gossip_port == 0) return "/gossip_port: must be nonzero";
    return validate_certificate(certificate);
}

onboarding_json::DecodeResult<PollResponse> poll_response_from_json(
        const nlohmann::json& json) {
    if (!json.is_object()) return {std::nullopt, "/: expected object"};
    const auto state_it = json.find("state");
    if (state_it == json.end()) return {std::nullopt, "/state: missing required field"};
    AdmissionState state{};
    std::string error;
    if (!onboarding_json::decode_value(*state_it, state, "/state", error)) {
        return {std::nullopt, std::move(error)};
    }
    if (state == AdmissionState::Approved) {
        auto decoded = ApprovedOnboardingBundle::fromJson(json);
        if (!decoded) return {std::nullopt, std::move(decoded.error)};
        return {PollResponse{std::move(*decoded.value)}, {}};
    }
    auto decoded = AdmissionStatusResponse::fromJson(json);
    if (!decoded) return {std::nullopt, std::move(decoded.error)};
    return {PollResponse{std::move(*decoded.value)}, {}};
}

nlohmann::json poll_response_to_json(const PollResponse& response) {
    return std::visit([](const auto& value) { return value.toJson(); }, response);
}

std::optional<std::string> AckRequest::validate() const {
    return validate_signed_status(request_id, candidate_pubkey, signature);
}

std::optional<std::string> AckResponse::validate() const {
    if (state != AdmissionState::Completed) return "/state: expected completed";
    return std::nullopt;
}

std::optional<std::string> AdmissionTokenRequest::validate() const {
    if (auto error = require_base64_size("/candidate_pubkey", candidate_pubkey,
                                         crypto::kEd25519PublicKeySize)) {
        return error;
    }
    if (ttl_sec && *ttl_sec > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return "/ttl_sec: integer is out of range";
    }
    return std::nullopt;
}

std::optional<std::string> AdmissionInvitation::validate() const {
    if (enrollment_token.empty()) return "/enrollment_token: must not be empty";
    if (auto error = require_base64_size("/candidate_pubkey", candidate_pubkey,
                                         crypto::kEd25519PublicKeySize)) {
        return error;
    }
    return require_hex_size("/root_pubkey", root_pubkey, crypto::kEd25519PublicKeySize);
}

std::optional<std::string> AdmissionRecord::validate() const {
    if (auto error = require_hex_size("/request_id", request_id, 16)) return error;
    if (auto error = require_base64_size("/candidate_pubkey", candidate_pubkey,
                                         crypto::kEd25519PublicKeySize)) {
        return error;
    }
    switch (platform_class) {
        case AdmissionPlatform::None:
        case AdmissionPlatform::Tpm2:
        case AdmissionPlatform::SnpVtpm:
            break;
        default:
            return "/platform_class: invalid enum value";
    }
    if (!measurement.empty()) {
        if (auto error = require_hex_size("/measurement", measurement, 48)) return error;
    }
    if (!binary_hash.empty()) {
        if (auto error = require_hex_size("/binary_hash", binary_hash,
                                          crypto::kHash256Size)) {
            return error;
        }
    }
    if (!evidence_sha256.empty()) {
        if (auto error = require_hex_size("/evidence_sha256", evidence_sha256,
                                          crypto::kHash256Size)) {
            return error;
        }
    }
    if (!challenge_nonce.empty()) {
        if (auto error = require_base64_size("/challenge_nonce", challenge_nonce, 32)) {
            return error;
        }
    }
    if (decision_mode != "" && decision_mode != "sole" && decision_mode != "ballot") {
        return "/decision_mode: invalid enum value";
    }
    if (decided_by != "" && decided_by != "admin" && decided_by != "token" &&
        decided_by != "ballot" && decided_by != "auto") {
        return "/decided_by: invalid enum value";
    }
    return std::nullopt;
}

std::optional<std::string> AdmissionStoreDocument::validate() const {
    if (version != kVersion) return "/version: unsupported admission store version";
    return std::nullopt;
}

onboarding_json::DecodeResult<AdmissionStoreDocument> admission_store_from_json(
        const nlohmann::json& json) {
    if (!json.is_object()) return {std::nullopt, "/: expected object"};
    if (json.contains("version")) return AdmissionStoreDocument::fromJson(json);

    auto legacy = LegacyAdmissionStore::fromJson(json);
    if (!legacy) return {std::nullopt, std::move(legacy.error)};

    AdmissionStoreDocument document;
    document.ever_approved = legacy.value->ever_approved;
    document.denied_until = legacy.value->denied_until.value_or(
        std::map<std::string, uint64_t>{});
    document.admissions.reserve(legacy.value->admissions.size());
    for (auto& admission : legacy.value->admissions) {
        if (admission.state > static_cast<uint8_t>(AdmissionState::Completed)) {
            return {std::nullopt, "/admissions/state: invalid persisted state"};
        }
        auto platform = onboarding_json::EnumCodec<AdmissionPlatform>::fromString(
            admission.platform_class.value_or(""));
        if (!platform) {
            return {std::nullopt, "/admissions/platform_class: invalid persisted enum"};
        }
        auto migrated = migrate_legacy_admission(std::move(admission), *platform);
        if (auto error = migrated.validate()) return {std::nullopt, std::move(*error)};
        document.admissions.push_back(std::move(migrated));
    }
    return {std::move(document), {}};
}

std::vector<uint8_t> canonical_admission_request(const AdmissionRequest& request) {
    std::vector<uint8_t> buffer;
    put_lp(buffer, "ln-onboard:v2");
    put_lp(buffer, request.nonce);
    put_lp(buffer, request.candidate_pubkey);
    put_lp(buffer, request.server_id);
    put_lp(buffer, request.region);
    put_lp(buffer, request.tpm_ak_pubkey);
    put_lp(buffer, admission_platform_name(request.platform_class));
    put_lp(buffer, request.measurement);
    put_lp(buffer, request.binary_hash);
    put_lp(buffer, request.evidence_sha256);
    put_lp(buffer, std::to_string(request.timestamp));
    return buffer;
}

std::vector<uint8_t> canonical_onboarding_status(std::string_view tag,
                                                 std::string_view request_id,
                                                 uint64_t timestamp) {
    std::vector<uint8_t> buffer;
    put_lp(buffer, tag);
    put_lp(buffer, request_id);
    put_lp(buffer, std::to_string(timestamp));
    return buffer;
}

}  // namespace nexus::core

namespace nexus::core::onboarding_json {

template <>
bool decode_value(const nlohmann::json& json, gossip::ServerCertificate& out,
                  const std::string& path, std::string& error) {
    if (!json.is_object()) {
        error = path + ": expected object";
        return false;
    }
    const nlohmann::json shape = gossip::ServerCertificate{};
    for (const auto& [key, unused] : json.items()) {
        if (!shape.contains(key)) {
            error = child_path(path, key) + ": unknown field";
            return false;
        }
    }
    for (const auto& [key, expected] : shape.items()) {
        const auto it = json.find(key);
        if (it == json.end()) {
            error = child_path(path, key) + ": missing required field";
            return false;
        }
        if (expected.is_string() && !it->is_string()) {
            error = child_path(path, key) + ": expected string";
            return false;
        }
        if (expected.is_number_unsigned() && !it->is_number_unsigned()) {
            error = child_path(path, key) + ": expected unsigned integer";
            return false;
        }
    }
    try {
        out = json.get<gossip::ServerCertificate>();
        return true;
    } catch (const std::exception& ex) {
        error = path + ": " + ex.what();
        return false;
    }
}

std::string_view EnumCodec<AdmissionState>::toString(AdmissionState state) {
    switch (state) {
        case AdmissionState::Pending: return "pending";
        case AdmissionState::Approved: return "approved";
        case AdmissionState::Denied: return "denied";
        case AdmissionState::Expired: return "expired";
        case AdmissionState::Completed: return "completed";
    }
    return {};
}

std::optional<AdmissionState> EnumCodec<AdmissionState>::fromString(std::string_view value) {
    if (value == "pending") return AdmissionState::Pending;
    if (value == "approved") return AdmissionState::Approved;
    if (value == "denied") return AdmissionState::Denied;
    if (value == "expired") return AdmissionState::Expired;
    if (value == "completed") return AdmissionState::Completed;
    return std::nullopt;
}

std::string_view EnumCodec<AdmissionPlatform>::toString(AdmissionPlatform platform) {
    switch (platform) {
        case AdmissionPlatform::None: return "";
        case AdmissionPlatform::Tpm2: return "tpm2";
        case AdmissionPlatform::SnpVtpm: return "snp-vtpm";
    }
    return {};
}

std::optional<AdmissionPlatform> EnumCodec<AdmissionPlatform>::fromString(
        std::string_view value) {
    if (value.empty()) return AdmissionPlatform::None;
    if (value == "tpm2") return AdmissionPlatform::Tpm2;
    if (value == "snp-vtpm") return AdmissionPlatform::SnpVtpm;
    return std::nullopt;
}

}  // namespace nexus::core::onboarding_json
