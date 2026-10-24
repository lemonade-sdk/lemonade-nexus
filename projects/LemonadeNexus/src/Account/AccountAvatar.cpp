#include <LemonadeNexus/Account/AccountAvatar.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <algorithm>
#include <span>
#include <tuple>

namespace nexus::account {
namespace {
nlohmann::json fields(const AccountAvatarRecord& r) {
    return {{"type", "nexus.account_avatar.ref.v2"}, {"group_id", r.group_id},
            {"author_pubkey", r.author_pubkey}, {"revision", r.revision}, {"image_hash", r.image_hash}};
}

bool valid_hash(const std::string& hash) {
    return hash.empty() || (hash.size() == 64 &&
        hash.find_first_not_of("0123456789abcdef") == std::string::npos);
}
} // namespace

std::string avatar_canonical(const AccountAvatarRecord& record) { return fields(record).dump(); }

nlohmann::json avatar_wire(const AccountAvatarRecord& record) {
    auto out = fields(record);
    out["signature"] = record.signature;
    return out;
}

std::optional<AccountAvatarRecord> avatar_from_wire(const nlohmann::json& value) {
    if (!value.is_object() || value.size() != 6 ||
        value.value("type", nlohmann::json()) != "nexus.account_avatar.ref.v2") return std::nullopt;
    const auto text = [&](const char* name, std::string& out, std::size_t max, bool required) {
        auto it = value.find(name);
        if (it == value.end() || !it->is_string()) return false;
        out = it->get<std::string>();
        return out.size() <= max && (!required || !out.empty());
    };
    AccountAvatarRecord r;
    if (!text("group_id", r.group_id, 128, true) ||
        !text("author_pubkey", r.author_pubkey, 64, true) ||
        !text("image_hash", r.image_hash, 64, false) ||
        !text("signature", r.signature, 128, true)) return std::nullopt;
    auto revision = value.find("revision");
    if (revision == value.end() || !revision->is_number_integer() ||
        (!revision->is_number_unsigned() && revision->get<int64_t>() <= 0)) return std::nullopt;
    r.revision = revision->get<uint64_t>();
    if (r.revision == 0 || r.revision > kMaxAvatarRevision) return std::nullopt;
    return r;
}

bool verify_avatar(const AccountAvatarRecord& record, crypto::SodiumCryptoService& crypto) {
    if (record.group_id.empty() || record.group_id.size() > 128 || record.revision == 0 ||
        record.revision > kMaxAvatarRevision || record.author_pubkey.size() > 64 ||
        record.signature.size() > 128 || !valid_hash(record.image_hash)) return false;
    try {
        const auto pk = crypto::from_base64(record.author_pubkey);
        const auto sig = crypto::from_base64(record.signature);
        if (pk.size() != crypto::kEd25519PublicKeySize || sig.size() != crypto::kEd25519SignatureSize ||
            crypto::to_base64(pk) != record.author_pubkey || crypto::to_base64(sig) != record.signature) return false;
        crypto::Ed25519PublicKey key;
        crypto::Ed25519Signature signature;
        std::copy(pk.begin(), pk.end(), key.begin());
        std::copy(sig.begin(), sig.end(), signature.begin());
        const auto canonical = avatar_canonical(record);
        return crypto.ed25519_verify(key, std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size()), signature);
    } catch (...) { return false; }
}

bool avatar_newer(const AccountAvatarRecord& a, const AccountAvatarRecord& b) {
    return std::tie(a.revision, a.author_pubkey, a.image_hash) > std::tie(b.revision, b.author_pubkey, b.image_hash);
}

} // namespace nexus::account
