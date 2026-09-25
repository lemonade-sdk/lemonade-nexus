#pragma once

#include <LemonadeNexus/Gossip/ServerCertificate.hpp>

#include <nlohmann/json.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace nexus::core::onboarding_json {

template <typename T>
struct DecodeResult {
    std::optional<T> value;
    std::string error;

    [[nodiscard]] explicit operator bool() const { return value.has_value(); }
};

template <typename Object, typename Member>
struct Field {
    std::string_view name;
    Member Object::*member;
};

template <typename Object, typename Member>
constexpr auto field(std::string_view name, Member Object::*member) {
    return Field<Object, Member>{name, member};
}

template <typename T>
struct is_optional : std::false_type {};

template <typename T>
struct is_optional<std::optional<T>> : std::true_type {};

template <typename T>
inline constexpr bool is_optional_v = is_optional<T>::value;

template <typename T>
struct is_vector : std::false_type {};

template <typename T, typename Allocator>
struct is_vector<std::vector<T, Allocator>> : std::true_type {};

template <typename T>
inline constexpr bool is_vector_v = is_vector<T>::value;

template <typename T>
struct is_string_map : std::false_type {};

template <typename Value, typename Compare, typename Allocator>
struct is_string_map<std::map<std::string, Value, Compare, Allocator>> : std::true_type {};

template <typename T>
inline constexpr bool is_string_map_v = is_string_map<T>::value;

template <typename T>
struct EnumCodec;

template <typename T>
concept JsonDto = requires(const T& value, const nlohmann::json& json) {
    { T::jsonFields() };
    { value.toJson() } -> std::same_as<nlohmann::json>;
    { T::fromJson(json) } -> std::same_as<DecodeResult<T>>;
};

inline std::string child_path(const std::string& parent, std::string_view child) {
    return parent == "/" ? "/" + std::string(child)
                         : parent + "/" + std::string(child);
}

template <typename T>
bool decode_value(const nlohmann::json& json, T& out, const std::string& path,
                  std::string& error);

template <typename T>
nlohmann::json encode_value(const T& value) {
    if constexpr (JsonDto<T>) {
        return value.toJson();
    } else if constexpr (std::is_enum_v<T>) {
        return std::string(EnumCodec<T>::toString(value));
    } else if constexpr (is_vector_v<T>) {
        nlohmann::json result = nlohmann::json::array();
        for (const auto& item : value) result.push_back(encode_value(item));
        return result;
    } else if constexpr (is_string_map_v<T>) {
        nlohmann::json result = nlohmann::json::object();
        for (const auto& [key, item] : value) result[key] = encode_value(item);
        return result;
    } else {
        return nlohmann::json(value);
    }
}

template <typename T>
bool decode_value(const nlohmann::json& json, T& out, const std::string& path,
                  std::string& error) {
    if constexpr (std::same_as<T, std::string>) {
        if (!json.is_string()) {
            error = path + ": expected string";
            return false;
        }
        out = json.get<std::string>();
        return true;
    } else if constexpr (std::same_as<T, bool>) {
        if (!json.is_boolean()) {
            error = path + ": expected boolean";
            return false;
        }
        out = json.get<bool>();
        return true;
    } else if constexpr (std::unsigned_integral<T>) {
        if (!json.is_number_integer()) {
            error = path + ": expected unsigned integer";
            return false;
        }
        uint64_t value = 0;
        if (json.is_number_unsigned()) {
            value = json.get<uint64_t>();
        } else {
            const auto signed_value = json.get<int64_t>();
            if (signed_value < 0) {
                error = path + ": expected unsigned integer";
                return false;
            }
            value = static_cast<uint64_t>(signed_value);
        }
        if (value > std::numeric_limits<T>::max()) {
            error = path + ": integer is out of range";
            return false;
        }
        out = static_cast<T>(value);
        return true;
    } else if constexpr (std::signed_integral<T>) {
        if (!json.is_number_integer()) {
            error = path + ": expected integer";
            return false;
        }
        const auto value = json.get<int64_t>();
        if (value < std::numeric_limits<T>::min() || value > std::numeric_limits<T>::max()) {
            error = path + ": integer is out of range";
            return false;
        }
        out = static_cast<T>(value);
        return true;
    } else if constexpr (std::is_enum_v<T>) {
        if (!json.is_string()) {
            error = path + ": expected string enum";
            return false;
        }
        auto value = EnumCodec<T>::fromString(json.get_ref<const std::string&>());
        if (!value) {
            error = path + ": invalid enum value";
            return false;
        }
        out = *value;
        return true;
    } else if constexpr (is_vector_v<T>) {
        if (!json.is_array()) {
            error = path + ": expected array";
            return false;
        }
        out.clear();
        out.reserve(json.size());
        for (std::size_t i = 0; i < json.size(); ++i) {
            typename T::value_type item{};
            if (!decode_value(json[i], item, child_path(path, std::to_string(i)), error)) {
                return false;
            }
            out.push_back(std::move(item));
        }
        return true;
    } else if constexpr (is_string_map_v<T>) {
        if (!json.is_object()) {
            error = path + ": expected object";
            return false;
        }
        out.clear();
        for (const auto& [key, encoded] : json.items()) {
            typename T::mapped_type value{};
            if (!decode_value(encoded, value, child_path(path, key), error)) return false;
            out.emplace(key, std::move(value));
        }
        return true;
    } else if constexpr (JsonDto<T>) {
        auto decoded = T::fromJson(json);
        if (!decoded) {
            error = path == "/" ? decoded.error : path + decoded.error;
            return false;
        }
        out = std::move(*decoded.value);
        return true;
    } else {
        try {
            out = json.get<T>();
            return true;
        } catch (const std::exception& ex) {
            error = path + ": " + ex.what();
            return false;
        }
    }
}

template <typename T>
nlohmann::json encode(const T& value) {
    nlohmann::json result = nlohmann::json::object();
    std::apply(
        [&](const auto&... descriptor) {
            ([&] {
                const auto& member = value.*(descriptor.member);
                using Member = std::remove_cvref_t<decltype(member)>;
                if constexpr (is_optional_v<Member>) {
                    if (member) result[descriptor.name] = encode_value(*member);
                } else {
                    result[descriptor.name] = encode_value(member);
                }
            }(), ...);
        },
        T::jsonFields());
    return result;
}

template <typename T>
DecodeResult<T> decode(const nlohmann::json& json) {
    if (!json.is_object()) return {std::nullopt, "/: expected object"};

    std::string error;
    for (const auto& item : json.items()) {
        // Plain local, not a structured binding: AppleClang rejects lambdas
        // capturing structured bindings from the enclosing function.
        const std::string key = item.key();
        bool known = false;
        std::apply([&](const auto&... descriptor) {
            ((known = known || key == descriptor.name), ...);
        }, T::jsonFields());
        if (!known) return {std::nullopt, child_path("/", key) + ": unknown field"};
    }

    T result;
    bool valid = true;
    std::apply(
        [&](const auto&... descriptor) {
            ([&] {
                if (!valid) return;
                auto& member = result.*(descriptor.member);
                using Member = std::remove_cvref_t<decltype(member)>;
                const auto it = json.find(descriptor.name);
                if (it == json.end()) {
                    if constexpr (is_optional_v<Member>) {
                        member.reset();
                    } else {
                        error = child_path("/", descriptor.name) + ": missing required field";
                        valid = false;
                    }
                    return;
                }
                if constexpr (is_optional_v<Member>) {
                    if (it->is_null()) {
                        error = child_path("/", descriptor.name) + ": null is not allowed";
                        valid = false;
                        return;
                    }
                    typename Member::value_type decoded{};
                    valid = decode_value(*it, decoded, child_path("/", descriptor.name), error);
                    if (valid) member = std::move(decoded);
                } else {
                    valid = decode_value(*it, member, child_path("/", descriptor.name), error);
                }
            }(), ...);
        },
        T::jsonFields());

    if (!valid) return {std::nullopt, std::move(error)};
    if constexpr (requires(const T& value) {
                      { value.validate() } -> std::same_as<std::optional<std::string>>;
                  }) {
        if (auto validation_error = result.validate()) {
            return {std::nullopt, std::move(*validation_error)};
        }
    }
    return {std::move(result), {}};
}

template <typename Derived>
struct Serializable {
    [[nodiscard]] nlohmann::json toJson() const {
        return encode(static_cast<const Derived&>(*this));
    }

    [[nodiscard]] static DecodeResult<Derived> fromJson(const nlohmann::json& json) {
        return decode<Derived>(json);
    }
};

template <>
bool decode_value(const nlohmann::json& json, gossip::ServerCertificate& out,
                  const std::string& path, std::string& error);

}  // namespace nexus::core::onboarding_json

namespace nexus::core {

inline constexpr std::string_view kOnboardPollTag = "ln-onboard-poll:v1";
inline constexpr std::string_view kOnboardAckTag = "ln-onboard-ack:v1";

enum class AdmissionState : uint8_t { Pending, Approved, Denied, Expired, Completed };
enum class AdmissionPlatform : uint8_t { None, Tpm2, SnpVtpm };

[[nodiscard]] std::string_view admission_state_name(AdmissionState state);
[[nodiscard]] std::string_view admission_platform_name(AdmissionPlatform platform);

template <typename Derived>
using OnboardingDto = onboarding_json::Serializable<Derived>;

#define NEXUS_ONBOARDING_FIELD(Type, Name) \
    ::nexus::core::onboarding_json::field(#Name, &Type::Name)

struct OnboardingInfoResponse : OnboardingDto<OnboardingInfoResponse> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 3;
    bool accepts_onboarding{false};
    std::string dns_base_domain;
    std::string server_fqdn;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(OnboardingInfoResponse, accepts_onboarding),
                          NEXUS_ONBOARDING_FIELD(OnboardingInfoResponse, dns_base_domain),
                          NEXUS_ONBOARDING_FIELD(OnboardingInfoResponse, server_fqdn)};
    }
};

struct ChallengeRequest : OnboardingDto<ChallengeRequest> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 1;
    std::string candidate_pubkey;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(ChallengeRequest, candidate_pubkey)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct ChallengeResponse : OnboardingDto<ChallengeResponse> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 2;
    std::string nonce;
    bool server_id_required{true};

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(ChallengeResponse, nonce),
                          NEXUS_ONBOARDING_FIELD(ChallengeResponse, server_id_required)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct AdmissionRequest : OnboardingDto<AdmissionRequest> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 14;
    std::string candidate_pubkey;
    std::string server_id;
    std::string region;
    std::string tpm_ak_pubkey;
    std::string tpm_ek_cert;
    AdmissionPlatform platform_class{AdmissionPlatform::None};
    std::string measurement;
    std::string binary_hash;
    std::string evidence_sha256;
    std::string evidence;
    std::string nonce;
    uint64_t timestamp{0};
    std::string signature;
    std::optional<std::string> enrollment_token;

    static constexpr auto jsonFields() {
        return std::tuple{
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, candidate_pubkey),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, server_id),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, region),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, tpm_ak_pubkey),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, tpm_ek_cert),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, platform_class),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, measurement),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, binary_hash),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, evidence_sha256),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, evidence),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, nonce),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, timestamp),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, signature),
            NEXUS_ONBOARDING_FIELD(AdmissionRequest, enrollment_token)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct AdmissionResponse : OnboardingDto<AdmissionResponse> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 2;
    std::string request_id;
    AdmissionState state{AdmissionState::Pending};

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(AdmissionResponse, request_id),
                          NEXUS_ONBOARDING_FIELD(AdmissionResponse, state)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct PollRequest : OnboardingDto<PollRequest> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 4;
    std::string request_id;
    std::string candidate_pubkey;
    uint64_t timestamp{0};
    std::string signature;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(PollRequest, request_id),
                          NEXUS_ONBOARDING_FIELD(PollRequest, candidate_pubkey),
                          NEXUS_ONBOARDING_FIELD(PollRequest, timestamp),
                          NEXUS_ONBOARDING_FIELD(PollRequest, signature)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct AdmissionStatusResponse : OnboardingDto<AdmissionStatusResponse> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 2;
    AdmissionState state{AdmissionState::Pending};
    std::string reason;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(AdmissionStatusResponse, state),
                          NEXUS_ONBOARDING_FIELD(AdmissionStatusResponse, reason)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct ApprovedOnboardingBundle : OnboardingDto<ApprovedOnboardingBundle> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 8;
    AdmissionState state{AdmissionState::Approved};
    gossip::ServerCertificate certificate;
    std::string root_pubkey;
    // Genesis identity must derive the network_id in the root-signed certificate.
    std::string genesis_pubkey;
    std::optional<std::string> mesh_server_pubkey;
    std::vector<std::string> seed_peers;
    std::optional<std::string> mesh_endpoint;
    uint16_t gossip_port{0};

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, state),
                          NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, certificate),
                          NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, root_pubkey),
                          NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, genesis_pubkey),
                          NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, mesh_server_pubkey),
                          NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, seed_peers),
                          NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, mesh_endpoint),
                          NEXUS_ONBOARDING_FIELD(ApprovedOnboardingBundle, gossip_port)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

using PollResponse = std::variant<AdmissionStatusResponse, ApprovedOnboardingBundle>;

[[nodiscard]] onboarding_json::DecodeResult<PollResponse> poll_response_from_json(
    const nlohmann::json& json);
[[nodiscard]] nlohmann::json poll_response_to_json(const PollResponse& response);

struct AckRequest : OnboardingDto<AckRequest> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 4;
    std::string request_id;
    std::string candidate_pubkey;
    uint64_t timestamp{0};
    std::string signature;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(AckRequest, request_id),
                          NEXUS_ONBOARDING_FIELD(AckRequest, candidate_pubkey),
                          NEXUS_ONBOARDING_FIELD(AckRequest, timestamp),
                          NEXUS_ONBOARDING_FIELD(AckRequest, signature)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct AckResponse : OnboardingDto<AckResponse> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 1;
    AdmissionState state{AdmissionState::Completed};

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(AckResponse, state)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct PendingAdmissionSummary : OnboardingDto<PendingAdmissionSummary> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 8;
    std::string request_id;
    std::string server_id;
    std::string region;
    std::string candidate_pubkey;
    std::string fingerprint;
    bool tier1_capable{false};
    std::string source_ip;
    uint64_t created_at{0};

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, request_id),
                          NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, server_id),
                          NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, region),
                          NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, candidate_pubkey),
                          NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, fingerprint),
                          NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, tier1_capable),
                          NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, source_ip),
                          NEXUS_ONBOARDING_FIELD(PendingAdmissionSummary, created_at)};
    }
};

struct PendingAdmissionsResponse : OnboardingDto<PendingAdmissionsResponse> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 1;
    std::vector<PendingAdmissionSummary> pending;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(PendingAdmissionsResponse, pending)};
    }
};

struct ApprovalRequest : OnboardingDto<ApprovalRequest> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 3;
    std::optional<std::string> pubkey;
    std::optional<std::string> fingerprint;
    std::optional<bool> supersede;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(ApprovalRequest, pubkey),
                          NEXUS_ONBOARDING_FIELD(ApprovalRequest, fingerprint),
                          NEXUS_ONBOARDING_FIELD(ApprovalRequest, supersede)};
    }
};

struct DenialRequest : OnboardingDto<DenialRequest> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 1;
    std::optional<std::string> reason;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(DenialRequest, reason)};
    }
};

struct AdmissionDecisionResponse : OnboardingDto<AdmissionDecisionResponse> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 2;
    AdmissionState state{AdmissionState::Pending};
    std::string request_id;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(AdmissionDecisionResponse, state),
                          NEXUS_ONBOARDING_FIELD(AdmissionDecisionResponse, request_id)};
    }
};

struct AdmissionTokenRequest : OnboardingDto<AdmissionTokenRequest> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 3;
    std::string candidate_pubkey;
    std::optional<uint64_t> ttl_sec;
    std::optional<std::string> server_id;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(AdmissionTokenRequest, candidate_pubkey),
                          NEXUS_ONBOARDING_FIELD(AdmissionTokenRequest, ttl_sec),
                          NEXUS_ONBOARDING_FIELD(AdmissionTokenRequest, server_id)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct AdmissionInvitation : OnboardingDto<AdmissionInvitation> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 5;
    std::string enrollment_token;
    uint64_t expires_at{0};
    std::string candidate_pubkey;
    std::string server_id;
    std::string root_pubkey;

    static constexpr auto jsonFields() {
        return std::tuple{NEXUS_ONBOARDING_FIELD(AdmissionInvitation, enrollment_token),
                          NEXUS_ONBOARDING_FIELD(AdmissionInvitation, expires_at),
                          NEXUS_ONBOARDING_FIELD(AdmissionInvitation, candidate_pubkey),
                          NEXUS_ONBOARDING_FIELD(AdmissionInvitation, server_id),
                          NEXUS_ONBOARDING_FIELD(AdmissionInvitation, root_pubkey)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct AdmissionRecord : OnboardingDto<AdmissionRecord> {
    // Drift guard: number of data members.
    static constexpr std::size_t kFieldCount = 20;
    std::string request_id;
    std::string candidate_pubkey;
    std::string server_id;
    std::string region;
    std::string tpm_ak_pubkey;
    std::string tpm_ek_cert;
    AdmissionPlatform platform_class{AdmissionPlatform::None};
    std::string measurement;
    std::string binary_hash;
    std::string evidence_sha256;
    std::string evidence;
    std::string challenge_nonce;
    std::string source_ip;
    AdmissionState state{AdmissionState::Pending};
    uint64_t created_at{0};
    uint64_t expires_at{0};
    std::string issued_cert_json;
    std::string decision_reason;
    std::string decided_by;
    std::string decision_mode;

    static constexpr auto jsonFields() {
        using onboarding_json::field;
        return std::tuple{
            field("request_id", &AdmissionRecord::request_id),
            field("candidate_pubkey", &AdmissionRecord::candidate_pubkey),
            field("server_id", &AdmissionRecord::server_id),
            field("region", &AdmissionRecord::region),
            field("tpm_ak_pubkey", &AdmissionRecord::tpm_ak_pubkey),
            field("tpm_ek_cert", &AdmissionRecord::tpm_ek_cert),
            field("platform_class", &AdmissionRecord::platform_class),
            field("measurement", &AdmissionRecord::measurement),
            field("binary_hash", &AdmissionRecord::binary_hash),
            field("evidence_sha256", &AdmissionRecord::evidence_sha256),
            field("evidence", &AdmissionRecord::evidence),
            field("challenge_nonce", &AdmissionRecord::challenge_nonce),
            field("source_ip", &AdmissionRecord::source_ip),
            field("state", &AdmissionRecord::state),
            field("created_at", &AdmissionRecord::created_at),
            field("expires_at", &AdmissionRecord::expires_at),
            field("issued_cert_json", &AdmissionRecord::issued_cert_json),
            field("decision_reason", &AdmissionRecord::decision_reason),
            field("decided_by", &AdmissionRecord::decided_by),
            field("decision_mode", &AdmissionRecord::decision_mode)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

struct AdmissionStoreDocument : OnboardingDto<AdmissionStoreDocument> {
    // Drift guard: number of data members. (kVersion is not a data member.)
    static constexpr std::size_t kFieldCount = 4;
    static constexpr uint32_t kVersion = 1;

    uint32_t version{kVersion};
    bool ever_approved{false};
    std::vector<AdmissionRecord> admissions;
    std::map<std::string, uint64_t> denied_until;

    static constexpr auto jsonFields() {
        return std::tuple{
            onboarding_json::field("version", &AdmissionStoreDocument::version),
            onboarding_json::field("ever_approved", &AdmissionStoreDocument::ever_approved),
            onboarding_json::field("admissions", &AdmissionStoreDocument::admissions),
            onboarding_json::field("denied_until", &AdmissionStoreDocument::denied_until)};
    }
    [[nodiscard]] std::optional<std::string> validate() const;
};

[[nodiscard]] onboarding_json::DecodeResult<AdmissionStoreDocument>
admission_store_from_json(const nlohmann::json& json);

[[nodiscard]] std::vector<uint8_t> canonical_admission_request(const AdmissionRequest& request);
[[nodiscard]] std::vector<uint8_t> canonical_onboarding_status(
    std::string_view tag, std::string_view request_id, uint64_t timestamp);

static_assert(std::tuple_size_v<decltype(OnboardingInfoResponse::jsonFields())> == OnboardingInfoResponse::kFieldCount,
              "OnboardingInfoResponse::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(ChallengeRequest::jsonFields())> == ChallengeRequest::kFieldCount,
              "ChallengeRequest::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(ChallengeResponse::jsonFields())> == ChallengeResponse::kFieldCount,
              "ChallengeResponse::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionRequest::jsonFields())> == AdmissionRequest::kFieldCount,
              "AdmissionRequest::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionResponse::jsonFields())> == AdmissionResponse::kFieldCount,
              "AdmissionResponse::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(PollRequest::jsonFields())> == PollRequest::kFieldCount,
              "PollRequest::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionStatusResponse::jsonFields())> == AdmissionStatusResponse::kFieldCount,
              "AdmissionStatusResponse::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(ApprovedOnboardingBundle::jsonFields())> == ApprovedOnboardingBundle::kFieldCount,
              "ApprovedOnboardingBundle::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AckRequest::jsonFields())> == AckRequest::kFieldCount,
              "AckRequest::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AckResponse::jsonFields())> == AckResponse::kFieldCount,
              "AckResponse::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(PendingAdmissionSummary::jsonFields())> == PendingAdmissionSummary::kFieldCount,
              "PendingAdmissionSummary::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(PendingAdmissionsResponse::jsonFields())> == PendingAdmissionsResponse::kFieldCount,
              "PendingAdmissionsResponse::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(ApprovalRequest::jsonFields())> == ApprovalRequest::kFieldCount,
              "ApprovalRequest::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(DenialRequest::jsonFields())> == DenialRequest::kFieldCount,
              "DenialRequest::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionDecisionResponse::jsonFields())> == AdmissionDecisionResponse::kFieldCount,
              "AdmissionDecisionResponse::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionTokenRequest::jsonFields())> == AdmissionTokenRequest::kFieldCount,
              "AdmissionTokenRequest::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionInvitation::jsonFields())> == AdmissionInvitation::kFieldCount,
              "AdmissionInvitation::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionRecord::jsonFields())> == AdmissionRecord::kFieldCount,
              "AdmissionRecord::jsonFields() field count drifted from kFieldCount");
static_assert(std::tuple_size_v<decltype(AdmissionStoreDocument::jsonFields())> == AdmissionStoreDocument::kFieldCount,
              "AdmissionStoreDocument::jsonFields() field count drifted from kFieldCount");

#undef NEXUS_ONBOARDING_FIELD

}  // namespace nexus::core

namespace nexus::core::onboarding_json {

template <>
struct EnumCodec<AdmissionState> {
    [[nodiscard]] static std::string_view toString(AdmissionState state);
    [[nodiscard]] static std::optional<AdmissionState> fromString(std::string_view value);
};

template <>
struct EnumCodec<AdmissionPlatform> {
    [[nodiscard]] static std::string_view toString(AdmissionPlatform platform);
    [[nodiscard]] static std::optional<AdmissionPlatform> fromString(std::string_view value);
};

}  // namespace nexus::core::onboarding_json
