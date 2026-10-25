// The SDK sends tree traffic only to Tier 1 servers it verified itself: it
// walks the authority chain from the pinned Genesis key and keeps a member
// only after the member signs an endpoint proof for the exact host and port.
// These tests drive Tier1Directory over a stand-in network: Tier 1 members,
// a Tier 2 server, and hostile servers.

#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/Tier1Directory.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include "support/tier1_chain.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

using json = nlohmann::json;
using tier1_chain_test::Chain;
using tier1_chain_test::new_identity;
namespace sec = nexus::security;

namespace {

constexpr uint16_t kPort = 9100;

/// One stand-in server.
struct FakeServer {
    /// The identity it signs endpoint proofs with; nullopt for a server that
    /// is no Tier 1 member and refuses /api/tier1/proof.
    std::optional<nexus::crypto::Ed25519Keypair> identity;
    /// The epoch its proofs name.
    uint64_t proof_epoch = 0;
    /// The chain it serves, and how many epochs of it.
    const Chain* chain = nullptr;
    std::size_t known_epochs = 0;
    /// When set, it answers proofs with another host's proof (a relay).
    std::string relay_proof_for;
    bool down = false;
};

class FakeNetwork {
public:
    std::map<std::string, FakeServer> servers;
    const Chain* network_chain = nullptr;  // network id for proofs
    std::vector<std::string> server_list;  // hosts listed by /api/servers

    std::optional<lnsdk::HttpReply> get(const lnsdk::ServerEndpoint& ep, const std::string& path) {
        auto it = servers.find(ep.host);
        if (it == servers.end() || it->second.down) return std::nullopt;
        const FakeServer& s = it->second;
        const std::string authority = "/api/tier1/authority?have_epoch=";
        const std::string proof = "/api/tier1/proof?nonce=";
        if (path.starts_with(authority)) {
            if (!s.chain) return lnsdk::HttpReply{404, R"({"error":"none"})"};
            const auto have = std::stoull(path.substr(authority.size()));
            const auto page = s.chain->page_after(have, s.known_epochs);
            if (!page) return lnsdk::HttpReply{404, R"({"error":"none"})"};
            const auto bytes = sec::encode_authority_chain_page(*page);
            return lnsdk::HttpReply{
                200, json{{"have_epoch", have}, {"page", nexus::crypto::to_base64(bytes)}}.dump()};
        }
        if (path == "/api/servers") {
            json list = json::array();
            for (const auto& host : server_list) {
                const auto& entry = servers.at(host);
                json e{{"fqdn", host}, {"http_port", kPort}, {"endpoint", host + ":9100"}};
                if (entry.identity) {
                    e["pubkey"] = nexus::crypto::to_base64(entry.identity->public_key);
                }
                list.push_back(e);
            }
            return lnsdk::HttpReply{200, list.dump()};
        }
        if (path.starts_with(proof)) {
            const auto nonce = nexus::crypto::from_hex(path.substr(proof.size()));
            const FakeServer* signer = &s;
            std::string host = ep.host;
            if (!s.relay_proof_for.empty()) {
                // Ask the real member, as a relaying server would.
                signer = &servers.at(s.relay_proof_for);
                host = s.relay_proof_for;
            }
            if (!signer->identity) {
                return lnsdk::HttpReply{421, R"({"error":"this server is not a Tier 1 member"})"};
            }
            const auto p = sec::sign_tier1_endpoint_proof(network_chain->network,
                                                          sec::EpochId{signer->proof_epoch}, host,
                                                          kPort, nonce, *signer->identity);
            return lnsdk::HttpReply{200, json{
                                             {"node_id", nexus::crypto::to_base64(p.node.bytes)},
                                             {"epoch", p.epoch.underlying()},
                                             {"host", p.host},
                                             {"port", p.port},
                                             {"signature", nexus::crypto::to_base64(p.signature)},
                                         }
                                             .dump()};
        }
        return lnsdk::HttpReply{404, "{}"};
    }
};

std::string b64(const nexus::crypto::Ed25519PublicKey& key) {
    return nexus::crypto::to_base64(key);
}

class SdkTier1Test : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        for (int i = 0; i < 5; ++i) epoch1.push_back(new_identity());
        // Epoch 2 keeps two members and adds three.
        epoch2 = {epoch1[0], epoch1[1], new_identity(), new_identity(), new_identity()};
        chain = Chain::make({epoch1, epoch2});

        net.network_chain = &chain;
        // Two reachable Tier 1 members of epoch 2.
        net.servers["t1a.example"] = FakeServer{epoch2[0], 2, &chain, 2, "", false};
        net.servers["t1b.example"] = FakeServer{epoch2[2], 2, &chain, 2, "", false};
        // A Tier 2 server: it serves the chain and the server list, never a proof.
        net.servers["t2.example"] = FakeServer{std::nullopt, 0, &chain, 2, "", false};
        // A former member (epoch 1 only), now Tier 2, that still signs.
        net.servers["old.example"] = FakeServer{epoch1[4], 2, &chain, 2, "", false};
        net.server_list = {"t2.example", "t1a.example", "t1b.example", "old.example"};
    }

    lnsdk::Tier1Directory directory() {
        return lnsdk::Tier1Directory(
            [this](const lnsdk::ServerEndpoint& ep, const std::string& path) {
                std::lock_guard lock(mutex);
                return net.get(ep, path);
            });
    }

    static std::vector<lnsdk::ServerEndpoint> seed(const std::string& host) {
        return {{host, kPort, true}};
    }

    std::vector<nexus::crypto::Ed25519Keypair> epoch1, epoch2;
    Chain chain;
    FakeNetwork net;
    std::mutex mutex;
};

/// Records which host each tree request went to.
struct AttemptLog {
    std::vector<std::string> hosts;
    std::map<std::string, std::optional<lnsdk::HttpReply>> replies;  // by host; default 200

    lnsdk::Tier1Attempt attempt() {
        return [this](const lnsdk::ServerEndpoint& ep) -> std::optional<lnsdk::HttpReply> {
            hosts.push_back(ep.host);
            auto it = replies.find(ep.host);
            if (it != replies.end()) return it->second;
            return lnsdk::HttpReply{200, R"({"ok":true})"};
        };
    }
};

}  // namespace

TEST_F(SdkTier1Test, NoTreeRequestLeavesWithoutAPinnedKey) {
    auto dir = directory();
    const auto refreshed = dir.refresh(seed("t2.example"));
    EXPECT_FALSE(refreshed.ok);
    EXPECT_EQ(refreshed.http_status, 403);
    AttemptLog log;
    std::string error;
    EXPECT_FALSE(dir.send(log.attempt(), "", nullptr, error).has_value());
    EXPECT_TRUE(log.hosts.empty()) << "a tree request was sent with nothing verified";
    EXPECT_FALSE(error.empty());
}

TEST_F(SdkTier1Test, TheVerifiedListHoldsOnlyCurrentMembersThatProvedTheirEndpoint) {
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    // The seed is a Tier 2 server; it serves the chain and the server list.
    const auto refreshed = dir.refresh(seed("t2.example"));
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    EXPECT_EQ(refreshed.value.epoch, 2u);
    EXPECT_EQ(refreshed.value.members.size(), 5u);
    std::vector<std::string> hosts;
    for (const auto& s : refreshed.value.servers) hosts.push_back(s.host);
    std::sort(hosts.begin(), hosts.end());
    EXPECT_EQ(hosts, (std::vector<std::string>{"t1a.example", "t1b.example"}));
    EXPECT_TRUE(dir.is_verified_member(b64(epoch2[0].public_key)));
    EXPECT_FALSE(dir.is_verified_member(b64(epoch1[4].public_key)));
}

TEST_F(SdkTier1Test, TreeRequestsGoOnlyToVerifiedTier1ServersAndFailOver) {
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    ASSERT_TRUE(dir.refresh(seed("t2.example")).ok);

    AttemptLog log;
    std::string error;
    lnsdk::Tier1Server answered;
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(dir.send(log.attempt(), "", &answered, error).has_value()) << error;
    }
    for (const auto& host : log.hosts) {
        EXPECT_TRUE(host == "t1a.example" || host == "t1b.example") << host;
    }
    // Sticky: the server that answered keeps answering.
    const std::string first = log.hosts.front();
    for (const auto& host : log.hosts) EXPECT_EQ(host, first);

    // That server goes down: the request fails over to the other member.
    log.hosts.clear();
    log.replies[first] = std::nullopt;
    ASSERT_TRUE(dir.send(log.attempt(), "", &answered, error).has_value()) << error;
    ASSERT_EQ(log.hosts.size(), 2u);
    EXPECT_EQ(log.hosts[0], first);
    EXPECT_NE(log.hosts[1], first);
    EXPECT_EQ(answered.host, log.hosts[1]);

    // A server that answers 421 (it holds no tree) is skipped, and the
    // membership is verified again before the next request.
    log.hosts.clear();
    log.replies.clear();
    log.replies[answered.host] = lnsdk::HttpReply{421, R"({"error":"x"})"};
    ASSERT_TRUE(dir.send(log.attempt(), "", &answered, error).has_value()) << error;
    EXPECT_EQ(log.hosts.size(), 2u);
    EXPECT_TRUE(dir.needs_refresh(60'000));

    // Every verified server down: no request reaches anyone else.
    log.hosts.clear();
    log.replies["t1a.example"] = std::nullopt;
    log.replies["t1b.example"] = std::nullopt;
    EXPECT_FALSE(dir.send(log.attempt(), "", &answered, error).has_value());
    for (const auto& host : log.hosts) {
        EXPECT_TRUE(host == "t1a.example" || host == "t1b.example") << host;
    }
}

TEST_F(SdkTier1Test, ASessionIsPinnedToTheServerThatIssuedIt) {
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    ASSERT_TRUE(dir.refresh(seed("t2.example")).ok);
    AttemptLog log;
    std::string error;
    const auto pin = b64(epoch2[2].public_key);  // t1b
    ASSERT_TRUE(dir.send(log.attempt(), pin, nullptr, error).has_value()) << error;
    EXPECT_EQ(log.hosts, std::vector<std::string>{"t1b.example"});
    // A pinned server that is down is not replaced by another one.
    log.hosts.clear();
    log.replies["t1b.example"] = std::nullopt;
    EXPECT_FALSE(dir.send(log.attempt(), pin, nullptr, error).has_value());
    EXPECT_EQ(log.hosts, std::vector<std::string>{"t1b.example"});
    // A pin that names no verified server sends nothing.
    log.hosts.clear();
    EXPECT_FALSE(dir.send(log.attempt(), b64(epoch1[4].public_key), nullptr, error).has_value());
    EXPECT_TRUE(log.hosts.empty());
}

TEST_F(SdkTier1Test, AForgedMembershipIsRefused) {
    // Another Genesis key signs a chain that names the hostile servers.
    auto forged = Chain::make({{new_identity(), new_identity(), new_identity(), new_identity()}});
    net.servers["evil.example"] = FakeServer{forged.epochs[0].identities.begin()->second, 1,
                                             &forged, 1, "", false};
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    const auto refreshed = dir.refresh(seed("evil.example"));
    EXPECT_FALSE(refreshed.ok);
    EXPECT_EQ(refreshed.http_status, 403);
    EXPECT_TRUE(dir.membership().servers.empty());
    AttemptLog log;
    std::string error;
    EXPECT_FALSE(dir.send(log.attempt(), "", nullptr, error).has_value());
    EXPECT_TRUE(log.hosts.empty());

    // A genuine source after the forged one still verifies.
    auto second = dir.refresh({{"evil.example", kPort, true}, {"t2.example", kPort, true}});
    EXPECT_TRUE(second.ok) << second.error;
}

TEST_F(SdkTier1Test, ARelayedProofDoesNotMakeAHostATier1Server) {
    // evil.example lists itself under t1a's node id and relays t1a's proof.
    net.servers["evil.example"] = FakeServer{epoch2[0], 2, &chain, 2, "t1a.example", false};
    net.server_list = {"evil.example", "t1b.example"};
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    const auto refreshed = dir.refresh(seed("evil.example"));
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    for (const auto& s : refreshed.value.servers) EXPECT_NE(s.host, "evil.example");
}

TEST_F(SdkTier1Test, AStaleMembershipIsRefused) {
    // Every source withholds the epoch 2 handoff, and the members prove
    // epoch 2: no server verifies against the stale epoch 1 list.
    for (auto& [host, server] : net.servers) server.known_epochs = 1;
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    auto refreshed = dir.refresh(seed("t2.example"));
    EXPECT_FALSE(refreshed.ok);
    EXPECT_TRUE(dir.membership().servers.empty());

    // A floor from an earlier run refuses an older list outright.
    auto floor = directory();
    ASSERT_TRUE(floor.set_genesis_key(b64(chain.genesis.public_key), 3));
    for (auto& [host, server] : net.servers) server.known_epochs = 2;
    refreshed = floor.refresh(seed("t2.example"));
    EXPECT_FALSE(refreshed.ok);
    EXPECT_EQ(refreshed.http_status, 403);
    EXPECT_NE(refreshed.error.find("stale"), std::string::npos) << refreshed.error;
}

TEST_F(SdkTier1Test, AWithheldHandoffIsFetchedFromAMemberThatProvesTheNewerEpoch) {
    // The seed withholds epoch 2; the members hold it.
    net.servers["t2.example"].known_epochs = 1;
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    const auto refreshed = dir.refresh(seed("t2.example"));
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    EXPECT_EQ(refreshed.value.epoch, 2u);
    EXPECT_FALSE(refreshed.value.servers.empty());
}

TEST_F(SdkTier1Test, TheClientSendsNoTreeCallWithoutAVerifiedTier1Server) {
    // The configured server is unreachable and no key is pinned: the
    // session request is refused locally and names the missing key.
    lnsdk::ServerConfig cfg;
    cfg.servers = {{"127.0.0.1", 1, true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    lnsdk::Identity identity;
    identity.generate();
    client.set_identity(identity);
    auto auth = client.authenticate_ed25519();
    EXPECT_FALSE(auth.ok);
    EXPECT_EQ(auth.http_status, 0);
    EXPECT_NE(auth.error.find("Genesis"), std::string::npos) << auth.error;

    EXPECT_FALSE(client.set_genesis_key("not base64 of 32 bytes").ok);
    auto* c = ln_create_tls("127.0.0.1", 1);
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(ln_set_genesis_key(c, "AAAA", 0), LN_ERR_REJECTED);
    EXPECT_EQ(ln_set_genesis_key(c, b64(chain.genesis.public_key).c_str(), 0), LN_OK);
    char* out = nullptr;
    EXPECT_EQ(ln_tier1_membership(c, &out), LN_OK);
    ASSERT_NE(out, nullptr);
    EXPECT_TRUE(json::parse(out)["servers"].empty());
    ln_free(out);
    out = nullptr;
    EXPECT_EQ(ln_tier1_refresh(c, &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    EXPECT_TRUE(json::parse(out).contains("error"));
    ln_free(out);
    ln_destroy(c);
}
