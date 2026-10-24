#include <LemonadeNexusSDK/AccountAvatarClient.hpp>
#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <gtest/gtest.h>
#include <httplib.h>
#include <sodium.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>

namespace {
using json = nlohmann::json;
const std::string pixel = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a6XcAAAAASUVORK5CYII=";
const std::string other_pixel = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

std::string b64(std::span<const uint8_t> bytes) {
    std::string out(sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    out.pop_back();
    return out;
}

struct Device {
    lnsdk::Identity identity;
    std::string id, ip, pubkey, mesh_key, group{"account"};
    std::atomic<bool> read{true}, connect{true};
    lnsdk::BoringtunMesh mesh;
    std::unique_ptr<lnsdk::AccountAvatarClient> avatar;
};

class AccountAvatarClientTest : public testing::Test {
protected:
    std::filesystem::path root;
    std::array<Device, 3> devices;
    std::mutex mutex;
    json record;
    std::vector<std::string> api_posts;
    bool legacy{false}, lose_post_response{false}, publish_before_loss{false};
    int reject_post_status{0};

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root = std::filesystem::temp_directory_path() / ("nexus-peer-avatar-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root);
        for (unsigned i = 0; i < devices.size(); ++i) {
            auto& d = devices[i];
            d.identity.generate();
            d.id = "device" + std::to_string(i);
            d.ip = "10.64.0." + std::to_string(i + 2);
            d.pubkey = b64(d.identity.public_key());
            const auto keys = lnsdk::BoringtunMesh::identity_bound_keypair(d.identity.private_key());
            d.mesh_key = keys.second;
            lnsdk::BoringtunConfig cfg;
            cfg.private_key = keys.first;
            cfg.public_key = keys.second;
            cfg.tunnel_ip = d.ip + "/32";
            cfg.allowed_ips = {"10.64.0.0/10"};
            ASSERT_TRUE(d.mesh.start(cfg));
        }
        for (auto& d : devices) {
            ASSERT_TRUE(d.mesh.sync_peers(peers_for(d)).ok);
            start(d);
        }
    }

    void TearDown() override {
        for (auto& d : devices) d.avatar.reset();
        for (auto& d : devices) d.mesh.stop();
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    std::vector<lnsdk::MeshPeer> peers_for(Device& self) {
        std::vector<lnsdk::MeshPeer> result;
        for (auto& d : devices) {
            if (&d == &self || !d.mesh.is_active()) continue;
            lnsdk::MeshPeer peer;
            peer.node_id = d.id;
            peer.tunnel_ip = d.ip + "/32";
            peer.mesh_pubkey = d.mesh_key;
            peer.endpoint = "127.0.0.1:" + std::to_string(d.mesh.bound_port());
            peer.is_online = true;
            result.push_back(std::move(peer));
        }
        return result;
    }

    void start(Device& d) {
        d.avatar = std::make_unique<lnsdk::AccountAvatarClient>(d.identity, root / d.id,
            [this, &d](const std::string& method, const std::string& path, const std::string& body) {
                std::lock_guard lock(mutex);
                EXPECT_EQ(path, "/api/account/avatar");
                if (!d.read.load()) return lnsdk::Result<std::string>{false, {}, 403, "Access revoked"};
                if (method == "POST") {
                    api_posts.push_back(body);
                    if (reject_post_status) return lnsdk::Result<std::string>{false, {}, reject_post_status, "Write refused"};
                    auto update = json::parse(body);
                    if (update["revision"] <= (record.is_null() ? json(0) : record["revision"]))
                        return lnsdk::Result<std::string>{false, {}, 409, "Profile image changed"};
                    if (!lose_post_response || publish_before_loss) record = update;
                    if (lose_post_response) return lnsdk::Result<std::string>{false, {}, 0, "Response lost"};
                }
                json directory = json::array();
                for (const auto& candidate : devices) {
                    if (!candidate.read.load() || candidate.group != d.group) continue;
                    directory.push_back({{"node_id", candidate.id}, {"pubkey", "ed25519:" + candidate.pubkey},
                        {"can_fetch_from_me", candidate.connect.load()}, {"can_serve_me", d.connect.load()}});
                }
                const auto visible = d.group == "account" ? record : json();
                json response{{"protocol", legacy ? "old" : "nexus.account_avatar.ref.v2"},
                    {"group_id", d.group}, {"record", visible}, {"revision", visible.is_null() ? json(0) : visible["revision"]},
                    {"can_write", true}, {"devices", std::move(directory)}};
                return lnsdk::Result<std::string>{true, response.dump(), 200, ""};
            },
            [&d](uint16_t vport, const std::string& target) { return d.mesh.tcp_ingress(vport, target); },
            [&d](const std::string& ip, uint16_t vport) { return d.mesh.tcp_egress(ip, vport); },
            [this, &d] { return peers_for(d); });
    }

    lnsdk::Result<json> put(Device& d, const std::string& image, uint64_t revision) {
        return d.avatar->write(lnsdk::sign_avatar_reference(d.identity, d.group, image, revision), image);
    }

    json proof(httplib::Client& http, Device& requester, Device& target, const std::string& hash) {
        auto response = http.Post("/avatar/challenge", "{}", "application/json");
        EXPECT_TRUE(response);
        if (!response) return {};
        const auto challenge = json::parse(response->body);
        json value{{"type", "nexus.account_avatar.fetch.v1"}, {"group_id", "account"}, {"image_hash", hash},
            {"requester_pubkey", requester.pubkey}, {"recipient_pubkey", target.pubkey}, {"nonce", challenge["nonce"]}};
        const auto canonical = value.dump();
        value["signature"] = b64(requester.identity.sign(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size())));
        return value;
    }
};

TEST_F(AccountAvatarClientTest, TransfersThroughEncryptedMeshCachesRestartsAndReshares) {
    auto& a = devices[0]; auto& b = devices[1]; auto& c = devices[2];
    ASSERT_TRUE(put(a, pixel, 1).ok);
    const auto received = b.avatar->read();
    ASSERT_TRUE(received.ok) << received.error;
    EXPECT_EQ(received.value["image"], pixel);
    EXPECT_FALSE(received.value["pending"].get<bool>());
    ASSERT_EQ(api_posts.size(), 1u);
    EXPECT_EQ(api_posts[0].find("data:image"), std::string::npos);
    EXPECT_FALSE(json::parse(api_posts[0]).contains("image"));
    a.avatar.reset(); a.mesh.stop();
    b.avatar.reset(); start(b);
    ASSERT_EQ(b.avatar->read().value["image"], pixel);
    const auto reshared = c.avatar->read();
    ASSERT_TRUE(reshared.ok) << reshared.error;
    EXPECT_EQ(reshared.value["image"], pixel);
}

TEST_F(AccountAvatarClientTest, ReplacementsRemovalsAndStaleWrites) {
    auto& a = devices[0]; auto& b = devices[1];
    ASSERT_TRUE(put(a, pixel, 1).ok);
    ASSERT_EQ(b.avatar->read().value["image"], pixel);
    ASSERT_TRUE(put(a, other_pixel, 2).ok);
    ASSERT_EQ(b.avatar->read().value["image"], other_pixel);
    EXPECT_EQ(put(a, pixel, 1).http_status, 409);
    ASSERT_TRUE(put(a, "", 3).ok);
    const auto removed = b.avatar->read();
    ASSERT_TRUE(removed.ok);
    EXPECT_TRUE(removed.value["image"].is_null());
    EXPECT_FALSE(removed.value["pending"].get<bool>());
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root / b.id))
        EXPECT_FALSE(entry.is_regular_file());
}

TEST_F(AccountAvatarClientTest, OfflineSourceIsPendingAndAnotherAccountDoesNotInheritImage) {
    auto& a = devices[0]; auto& b = devices[1]; auto& c = devices[2];
    ASSERT_TRUE(put(a, pixel, 1).ok);
    a.avatar.reset(); a.mesh.stop();
    const auto pending = b.avatar->read();
    ASSERT_TRUE(pending.ok);
    EXPECT_TRUE(pending.value["pending"].get<bool>());
    EXPECT_TRUE(pending.value["image"].is_null());
    c.group = "other-account";
    const auto other = c.avatar->read();
    ASSERT_TRUE(other.ok);
    EXPECT_TRUE(other.value["image"].is_null());
    EXPECT_FALSE(other.value["pending"].get<bool>());
}

TEST_F(AccountAvatarClientTest, LostWriteResponseRetainsBytesAcrossRestartAndLaggingMetadata) {
    auto& a = devices[0]; auto& b = devices[1];
    lose_post_response = true;
    EXPECT_FALSE(put(a, pixel, 1).ok);
    a.avatar.reset(); start(a);
    ASSERT_TRUE(a.avatar->read().ok);
    EXPECT_EQ(put(a, other_pixel, 1).http_status, 409);
    reject_post_status = 409;
    EXPECT_EQ(put(a, pixel, 1).http_status, 409);
    reject_post_status = 0;
    {
        std::lock_guard lock(mutex);
        record = lnsdk::sign_avatar_reference(a.identity, a.group, pixel, 1);
    }
    ASSERT_EQ(a.avatar->read().value["image"], pixel);
    const auto downloaded = b.avatar->read();
    ASSERT_TRUE(downloaded.ok);
    EXPECT_EQ(downloaded.value["image"], pixel);
}

TEST_F(AccountAvatarClientTest, PeerFetchRejectsReplayTamperRevokedReadAndConnectRightsAndOtherAccounts) {
    auto& a = devices[0]; auto& b = devices[1]; auto& c = devices[2];
    ASSERT_TRUE(put(a, pixel, 1).ok);
    ASSERT_TRUE(b.avatar->read().ok);
    const auto port = b.mesh.tcp_egress(a.ip, lnsdk::kAccountAvatarPort);
    ASSERT_NE(port, 0);
    httplib::Client http("127.0.0.1", port);
    http.set_read_timeout(5);
    http.set_connection_timeout(3);
    const auto hash = lnsdk::avatar_image_hash(pixel);
    auto request = proof(http, b, a, hash);
    auto send = [&](const json& value) {
        const auto response = http.Post("/avatar/image", value.dump(), "application/json");
        EXPECT_TRUE(response);
        return response ? response->status : 0;
    };
    EXPECT_EQ(send(request), 200);
    EXPECT_EQ(send(request), 404);
    request = proof(http, b, a, hash); request["image_hash"] = std::string(64, 'b');
    EXPECT_EQ(send(request), 404);
    request = proof(http, b, a, hash); b.read = false;
    EXPECT_EQ(send(request), 404);
    b.read = true;
    request = proof(http, b, a, hash); b.connect = false;
    EXPECT_EQ(send(request), 404);
    b.connect = true;
    c.group = "other-account";
    request = proof(http, c, a, hash);
    EXPECT_EQ(send(request), 404);
    request = proof(http, b, a, hash); request["recipient_pubkey"] = c.pubkey;
    EXPECT_EQ(send(request), 404);
    request = proof(http, b, a, hash); request["requester_pubkey"] = c.pubkey;
    EXPECT_EQ(send(request), 404);
}

TEST_F(AccountAvatarClientTest, DefiniteRefusalAndExplicitRetryOfUnconfirmedImageRecover) {
    auto& a = devices[0];
    ASSERT_TRUE(put(a, pixel, 1).ok);
    reject_post_status = 403;
    EXPECT_EQ(put(a, other_pixel, 2).http_status, 403);
    EXPECT_EQ(a.avatar->read().value["image"], pixel);
    reject_post_status = 0;
    ASSERT_TRUE(put(a, other_pixel, 2).ok);
    lose_post_response = true;
    EXPECT_FALSE(put(a, pixel, 3).ok);
    EXPECT_EQ(put(a, other_pixel, 3).http_status, 409);
    lose_post_response = false;
    const auto retried = put(a, pixel, 3);
    ASSERT_TRUE(retried.ok) << retried.error;
    EXPECT_EQ(retried.value["image"], pixel);
}

TEST_F(AccountAvatarClientTest, ValidatesCacheBytesReferenceSignatureAndOldProtocol) {
    auto& a = devices[0]; auto& b = devices[1];
    auto signed_record = lnsdk::sign_avatar_reference(a.identity, "account", pixel, 1);
    EXPECT_FALSE(a.avatar->write(signed_record, other_pixel).ok);
    EXPECT_TRUE(api_posts.empty());
    signed_record["image"] = pixel;
    EXPECT_FALSE(a.avatar->write(signed_record, pixel).ok);
    ASSERT_TRUE(put(a, pixel, 1).ok);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root / a.id)) {
        if (entry.is_regular_file() && entry.path().filename() != "pending.ref") {
            std::ofstream out(entry.path()); out << other_pixel;
        }
    }
    const auto invalid = b.avatar->read();
    ASSERT_TRUE(invalid.ok);
    EXPECT_TRUE(invalid.value["pending"].get<bool>());
    EXPECT_TRUE(invalid.value["image"].is_null());
    legacy = true;
    EXPECT_EQ(a.avatar->read().http_status, 501);
    legacy = false;
    {
        std::lock_guard lock(mutex);
        record["revision"] = 9;
    }
    EXPECT_FALSE(b.avatar->read().ok);
}

TEST(AccountAvatarClient, RejectsInvalidImageBoundsAndCAbiNullArguments) {
    ASSERT_GE(sodium_init(), 0);
    lnsdk::Identity identity; identity.generate();
    EXPECT_FALSE(lnsdk::valid_avatar_image("data:image/png;base64,AAAA"));
    EXPECT_FALSE(lnsdk::valid_avatar_image(std::string(128 * 1024 + 1, 'a')));
    EXPECT_THROW((void)lnsdk::sign_avatar_reference(identity, "", pixel, 1), std::invalid_argument);
    EXPECT_THROW((void)lnsdk::sign_avatar_reference(identity, "account", pixel, 0), std::invalid_argument);
    EXPECT_EQ(ln_account_avatar_configure(nullptr, nullptr, nullptr), LN_ERR_NULL_ARG);
    char* out = reinterpret_cast<char*>(1);
    EXPECT_EQ(ln_account_avatar_put(nullptr, "{}", "", &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(out, nullptr);
    auto handle = ln_identity_generate();
    ASSERT_NE(handle, nullptr);
    EXPECT_EQ(ln_account_avatar_sign(handle, "account", "data:image/png;base64,AAAA", 1, &out), LN_ERR_REJECTED);
    EXPECT_EQ(out, nullptr);
    ln_identity_destroy(handle);
}
} // namespace
