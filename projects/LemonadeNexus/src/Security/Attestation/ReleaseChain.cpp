#include <LemonadeNexus/Security/Attestation/ReleaseChain.hpp>

#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <fstream>
#include <system_error>

namespace nexus::security {

namespace {

using json = nlohmann::json;

std::optional<std::string> read_text(const std::filesystem::path& path, std::size_t limit) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > limit) return std::nullopt;
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::nullopt;
    std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    return text;
}

bool signer_matches(const ReleaseApprovalBundleV1& bundle, std::string_view signer) {
    return bundle.authority.release_signing_pubkey_b64 == signer &&
           bundle.approval.signer_pubkey_b64 == signer;
}

std::optional<ReleaseChainRecord> parse_record(const std::string& text) {
    try {
        const auto j = json::parse(text);
        ReleaseChainRecord record;
        record.format_version = j.at("format_version").get<uint32_t>();
        record.network_id_hex = j.at("network_id").get<std::string>();
        record.release_signing_pubkey_b64 = j.at("release_signing_pubkey").get<std::string>();
        const auto read_digest = [&j](const char* key, Digest& out) {
            const auto bytes = crypto::from_hex(j.at(key).get<std::string>());
            if (bytes.size() != out.size()) return false;
            std::copy(bytes.begin(), bytes.end(), out.begin());
            return true;
        };
        if (!read_digest("pin_approval_digest", record.pin_approval_digest) ||
            !read_digest("founding_approval_digest", record.founding_approval_digest)) {
            return std::nullopt;
        }
        record.highest_release_number = j.at("highest_release_number").get<uint64_t>();
        record.approval_bundle_json = j.at("approval_bundle").get<std::string>();
        if (record.format_version != kReleaseChainFormatVersion) return std::nullopt;
        return record;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace

std::string_view release_offer_result_name(ReleaseOfferResult result) {
    switch (result) {
        case ReleaseOfferResult::Adopted: return "adopted";
        case ReleaseOfferResult::Current: return "current";
        case ReleaseOfferResult::Stale: return "stale";
        case ReleaseOfferResult::WrongSigner: return "wrong_signer";
        case ReleaseOfferResult::Invalid: return "invalid";
        case ReleaseOfferResult::Oversize: return "oversize";
        case ReleaseOfferResult::Unavailable: return "unavailable";
    }
    return "unknown";
}

ReleaseChain::ReleaseChain(std::filesystem::path directory,
                           crypto::Ed25519PublicKey genesis_public_key, NetworkId network_id)
    : directory_(std::move(directory)),
      genesis_public_key_(genesis_public_key),
      network_id_(network_id) {}

const std::optional<ReleaseApprovalBundleV1>& ReleaseChain::current() const {
    static const std::optional<ReleaseApprovalBundleV1> kNone;
    return below_floor() ? kNone : current_;
}

Digest ReleaseChain::current_digest() const {
    const auto& held = current();
    return held ? release_approval_digest(held->approval) : Digest{};
}

bool ReleaseChain::below_floor() const {
    return floor_ != 0 && (!record_ || record_->highest_release_number < floor_);
}

bool ReleaseChain::raise_floor(uint64_t finalized_release_number) {
    if (finalized_release_number <= floor_) return false;
    floor_ = finalized_release_number;
    if (below_floor()) {
        spdlog::warn("[release] finalized state shows release {}, above the accepted release "
                     "{}; the accepted approval is not used until a newer one is adopted",
                     floor_, highest_release_number());
    }
    return true;
}

bool ReleaseChain::persist(const ReleaseChainRecord& record) {
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
    if (ec) return false;
    const json j = {
        {"format_version", record.format_version},
        {"network_id", record.network_id_hex},
        {"release_signing_pubkey", record.release_signing_pubkey_b64},
        {"pin_approval_digest", crypto::to_hex(record.pin_approval_digest)},
        {"founding_approval_digest", crypto::to_hex(record.founding_approval_digest)},
        {"highest_release_number", record.highest_release_number},
        {"approval_bundle", record.approval_bundle_json},
    };
    return write_durable(directory_ / kReleaseChainFile, j.dump());
}

bool ReleaseChain::load(const std::optional<ReleaseApprovalBundleV1>& installed) {
    healthy_ = true;
    record_.reset();
    current_.reset();
    const auto path = directory_ / kReleaseChainFile;
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        const auto text = read_text(path, 4 * kMaxReleaseApprovalBytes);
        auto record = text ? parse_record(*text) : std::nullopt;
        if (!record || record->network_id_hex != crypto::to_hex(network_id_) ||
            crypto::canonical_key_b64(record->release_signing_pubkey_b64) !=
                record->release_signing_pubkey_b64 ||
            record->release_signing_pubkey_b64.empty()) {
            spdlog::warn("[release] the release chain record is corrupt or names another "
                         "network; release adoption is disabled");
            healthy_ = false;
            return false;
        }
        record_ = std::move(*record);
        std::string error;
        auto stored = parse_release_approval_bundle(record_->approval_bundle_json, error);
        if (stored && verify_release_approval_bundle(*stored, genesis_public_key_, network_id_,
                                                     error) &&
            signer_matches(*stored, record_->release_signing_pubkey_b64) &&
            stored->approval.release_number == record_->highest_release_number) {
            current_ = std::move(*stored);
        } else {
            // The pin and the number stay: a stored approval that this build
            // cannot verify never lowers the accepted release number.
            spdlog::warn("[release] the stored approval does not verify under this build: {}",
                         error);
        }
    } else if (installed.has_value()) {
        ReleaseChainRecord record;
        record.network_id_hex = crypto::to_hex(network_id_);
        record.release_signing_pubkey_b64 = installed->authority.release_signing_pubkey_b64;
        record.highest_release_number = installed->approval.release_number;
        record.pin_approval_digest = release_approval_digest(installed->approval);
        record.approval_bundle_json = release_approval_bundle_json(*installed);
        if (!signer_matches(*installed, record.release_signing_pubkey_b64) || !persist(record)) {
            spdlog::warn("[release] cannot pin the release signer from the installed approval");
            return true;
        }
        record_ = std::move(record);
        current_ = installed;
        spdlog::info("[release] pinned release signer from installed release {}",
                     installed->approval.release_number);
        return true;
    }
    if (installed.has_value()) {
        const auto result = offer(*installed);
        if (result == ReleaseOfferResult::Stale) {
            spdlog::info("[release] installed release {} is older than accepted release {}; "
                         "the accepted approval stays current",
                         installed->approval.release_number, highest_release_number());
        } else if (result != ReleaseOfferResult::Adopted &&
                   result != ReleaseOfferResult::Current) {
            spdlog::warn("[release] installed approval refused: {}",
                         release_offer_result_name(result));
        }
    }
    return true;
}

ReleaseOfferResult ReleaseChain::offer_json(std::string_view json_text) {
    if (json_text.size() > kMaxReleaseApprovalBytes) return ReleaseOfferResult::Oversize;
    std::string error;
    const auto bundle = parse_release_approval_bundle(json_text, error);
    if (!bundle) return ReleaseOfferResult::Invalid;
    return offer(*bundle);
}

ReleaseOfferResult ReleaseChain::offer(const ReleaseApprovalBundleV1& bundle) {
    if (!healthy_ || !record_.has_value()) return ReleaseOfferResult::Unavailable;
    std::string error;
    if (!verify_release_approval_bundle(bundle, genesis_public_key_, network_id_, error)) {
        spdlog::debug("[release] offer refused: {}", error);
        return ReleaseOfferResult::Invalid;
    }
    if (!signer_matches(bundle, record_->release_signing_pubkey_b64)) {
        return ReleaseOfferResult::WrongSigner;
    }
    if (current_ && release_approval_digest(bundle.approval) ==
                        release_approval_digest(current_->approval)) {
        return ReleaseOfferResult::Current;
    }
    if (bundle.approval.release_number <= record_->highest_release_number) {
        return ReleaseOfferResult::Stale;
    }
    ReleaseChainRecord next = *record_;
    next.highest_release_number = bundle.approval.release_number;
    next.approval_bundle_json = release_approval_bundle_json(bundle);
    if (!persist(next)) {
        spdlog::warn("[release] cannot persist release {}; not adopted",
                     bundle.approval.release_number);
        return ReleaseOfferResult::Unavailable;
    }
    record_ = std::move(next);
    current_ = bundle;
    spdlog::info("[release] adopted release {} ({})", bundle.approval.release_number,
                 bundle.approval.release_id);
    return ReleaseOfferResult::Adopted;
}

std::optional<ReleaseApprovalBundleV1> ReleaseChain::founding_from_file(
    const Digest& committed) const {
    const auto text = read_text(directory_ / kFoundingApprovalFile, kMaxReleaseApprovalBytes);
    if (!text) return std::nullopt;
    std::string error;
    auto bundle = parse_release_approval_bundle(*text, error);
    if (!bundle ||
        !verify_release_approval_signatures(*bundle, genesis_public_key_, network_id_, error) ||
        release_approval_digest(bundle->approval) != committed) {
        spdlog::warn("[release] the founding approval file does not match the commitment: {}",
                     error);
        return std::nullopt;
    }
    return bundle;
}

bool ReleaseChain::bind_commitment(const Digest& committed_approval_digest) {
    if (!healthy_ || !record_.has_value() || committed_approval_digest == Digest{}) {
        return false;
    }
    if (record_->founding_approval_digest != Digest{}) {
        return record_->founding_approval_digest == committed_approval_digest;
    }
    // The pin approval was verified and supplied the pinned signer, so its
    // digest needs no second look. Any other founding approval must come
    // from the migration file and carry the same signer.
    if (committed_approval_digest != record_->pin_approval_digest) {
        const auto founding = founding_from_file(committed_approval_digest);
        if (!founding || !signer_matches(*founding, record_->release_signing_pubkey_b64) ||
            founding->approval.release_number > record_->highest_release_number) {
            spdlog::warn("[release] no founding approval with the committed digest carries the "
                         "pinned release signer");
            return false;
        }
    }
    ReleaseChainRecord next = *record_;
    next.founding_approval_digest = committed_approval_digest;
    if (!persist(next)) return false;
    record_ = std::move(next);
    return true;
}

}  // namespace nexus::security
