#pragma once

// Internal helpers shared by the attestation/evidence sources. Not part of
// the public include tree.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nexus::security::detail {

inline bool set_failure(std::string* failure, std::string message) {
    if (failure) *failure = std::move(message);
    return false;
}

inline bool valid_hex(std::string_view value, std::size_t length) {
    if (value.size() != length) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

/// The object carries exactly these keys, no more and no fewer.
inline bool exact_keys(const nlohmann::json& json,
                       std::initializer_list<std::string_view> keys) {
    if (!json.is_object() || json.size() != keys.size()) return false;
    return std::all_of(keys.begin(), keys.end(), [&json](std::string_view key) {
        return json.contains(std::string(key));
    });
}

inline std::string b64(std::span<const uint8_t> bytes) {
    return bytes.empty() ? std::string{} : crypto::to_base64(bytes);
}

inline std::vector<uint8_t> unb64(const std::string& text) {
    if (text.empty()) return {};
    try { return crypto::from_base64(text); } catch (...) { return {}; }
}

inline std::vector<uint8_t> unb64(const nlohmann::json& value) {
    if (!value.is_string()) return {};
    return unb64(value.get<std::string>());
}

}  // namespace nexus::security::detail
