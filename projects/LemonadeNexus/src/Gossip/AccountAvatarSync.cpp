#include <LemonadeNexus/Gossip/GossipService.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>

namespace nexus::gossip {
namespace {
sync::ReplicaEntry avatar_entry(const account::AccountAvatarRecord& record,
                                crypto::SodiumCryptoService& crypto) {
    const auto key = record.group_id + ":" + record.author_pubkey;
    const auto digest = crypto.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(key.data()), key.size()));
    const auto origin = crypto::to_base64(digest);
    const auto wire = account::avatar_wire(record).dump();
    return {origin, origin, record.revision, record.revision, record.image_hash.empty(),
             std::vector<uint8_t>(wire.begin(), wire.end())};
}
}

void GossipService::set_account_avatar_sink(
    std::function<bool(const account::AccountAvatarRecord&)> sink) {
    account_avatar_sink_ = std::move(sink);
    load_avatar_replica();
}

void GossipService::broadcast_account_avatar(account::AccountAvatarRecord record) {
    asio::post(socket_.get_executor(), [this, alive = backbone_alive_, record = std::move(record)] {
        if (!alive->load() || !avatar_replica_) return;
        if (!apply_account_avatar(record)) return;
        const auto entry = avatar_entry(record, crypto_);
        save_avatar_replica();
        for (const auto& peer : backbone_targets(!self_is_tier1())) send_avatar_entry(peer, entry);
    });
}

void GossipService::send_avatar_entry(const GossipPeer& peer, const sync::ReplicaEntry& entry) {
    for (const auto& chunk : sync::encode_entry_chunks(account::kAvatarSyncStream,
                                                       entry.seq, entry.payload, 900)) {
        const auto bytes = nlohmann::json::to_msgpack(chunk);
        (void)send_backbone_packet(peer, GossipMsgType::AccountAvatarSync, bytes);
    }
}

bool GossipService::apply_account_avatar(const account::AccountAvatarRecord& record) {
    if (!avatar_replica_ || !account_avatar_sink_ || !account::verify_avatar(record, crypto_)) return false;
    auto entry = avatar_entry(record, crypto_);
    if (avatar_replica_->holds_newer(entry.key, entry.timestamp, entry.seq)) return false;
    if (!account_avatar_sink_(record)) return false;
    return avatar_replica_->offer(std::move(entry)) == sync::OfferResult::Stored;
}

void GossipService::handle_account_avatar_sync(const asio::ip::udp::endpoint& sender,
                                               const std::string& sender_pubkey,
                                               const uint8_t* payload, std::size_t payload_len, Via via) {
    if (!backbone_sender_verified(sender, sender_pubkey, via, "AccountAvatarSync") || !avatar_assembler_) return;
    const auto doc = nlohmann::json::from_msgpack(payload, payload + payload_len, true, false);
    const auto chunk = sync::decode_entry_chunk(doc, account::kMaxAvatarRecordBytes);
    if (!chunk || chunk->stream != account::kAvatarSyncStream) return;
    const auto bytes = avatar_assembler_->add(sender_pubkey, *chunk, static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()));
    if (!bytes) return;
    const auto record = account::avatar_from_wire(nlohmann::json::parse(bytes->begin(), bytes->end(), nullptr, false));
    if (!record || record->revision != chunk->seq || !apply_account_avatar(*record)) return;
    save_avatar_replica();
    if (self_is_tier1()) {
        const auto entry = avatar_entry(*record, crypto_);
        for (const auto& peer : backbone_targets(false)) {
            if (peer.pubkey != sender_pubkey) send_avatar_entry(peer, entry);
        }
    }
}

void GossipService::save_avatar_replica() {
    if (!avatar_replica_ || avatar_replica_->version() == avatar_replica_saved_version_) return;
    const auto version = avatar_replica_->version();
    if (save_replica_file(*avatar_replica_, "avatar_refs", "account_avatar_reference_replica")) {
        avatar_replica_saved_version_ = version;
    } else {
        spdlog::warn("[{}] account avatar replica write failed", name());
    }
}

void GossipService::load_avatar_replica() {
    if (!avatar_replica_ || !account_avatar_sink_ || avatar_replica_loaded_) return;
    avatar_replica_loaded_ = true;
    const auto env = storage_.read_file("avatar_refs", "replica.json");
    if (!env) return;
    const auto doc = nlohmann::json::parse(env->data, nullptr, false);
    if (!doc.is_object() || !doc.contains("entries") || !doc["entries"].is_array()) return;
    for (const auto& value : doc["entries"]) {
        if (!value.is_string() || value.get_ref<const std::string&>().size() > 2 * account::kMaxAvatarRecordBytes) continue;
        try {
            const auto bytes = crypto::from_base64(value.get<std::string>());
            const auto record = account::avatar_from_wire(nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false));
            if (record) (void)apply_account_avatar(*record);
        } catch (const std::exception&) {
            spdlog::warn("[{}] refused malformed account avatar replica entry", name());
        }
    }
    avatar_replica_saved_version_ = avatar_replica_->version();
}

} // namespace nexus::gossip
