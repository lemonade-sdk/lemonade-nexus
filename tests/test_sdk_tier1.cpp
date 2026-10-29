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
    std::map<std::string, lnsdk::HttpReply> onboard_info;  // GET /api/onboard/info by host

    std::optional<lnsdk::HttpReply> get(const lnsdk::ServerEndpoint& ep, const std::string& path) {
        auto it = servers.find(ep.host);
        if (it == servers.end() || it->second.down) return std::nullopt;
        if (path == "/api/onboard/info") {
            const auto info = onboard_info.find(ep.host);
            if (info == onboard_info.end()) return lnsdk::HttpReply{404, "{}"};
            return info->second;
        }
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

std::string network_hex(const nexus::crypto::Ed25519PublicKey& key) {
    return nexus::crypto::to_hex(sec::derive_network_id(
        key, sec::constants::kSecurityRulesetVersion, sec::constants::kConsensusRulesetVersion));
}

/// A GET /api/onboard/info answer that names `key`, as a server sends it.
lnsdk::HttpReply onboard_info(const nexus::crypto::Ed25519PublicKey& key,
                              const std::string& domain = "example") {
    return {200, json{{"accepts_onboarding", false},
                      {"dns_base_domain", domain},
                      {"server_fqdn", ""},
                      {"genesis_pubkey", b64(key)},
                      {"network_id", network_hex(key)}}
                     .dump()};
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

    static std::vector<lnsdk::ServerEndpoint> hosts(const std::vector<std::string>& names) {
        std::vector<lnsdk::ServerEndpoint> out;
        for (const auto& name : names) out.push_back({name, kPort, true});
        return out;
    }

    /// Every fixture server reports the network's Genesis key.
    void serve_genesis_everywhere() {
        for (const auto& host : {"t1a.example", "t1b.example", "t2.example", "old.example"}) {
            net.onboard_info[host] = onboard_info(chain.genesis.public_key);
        }
    }

    const std::vector<lnsdk::ServerEndpoint> all_hosts =
        hosts({"t1a.example", "t1b.example", "t2.example", "old.example"});

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

// Without a pin, no avoided member's server is tried; with every member
// avoided, nothing is sent. A pin is not affected by the avoid set.
TEST_F(SdkTier1Test, AvoidedMembersAreNotTried) {
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    ASSERT_TRUE(dir.refresh(seed("t2.example")).ok);
    AttemptLog log;
    std::string error;
    lnsdk::Tier1Server answered;
    const auto t1b = b64(epoch2[2].public_key);
    std::string t1a;
    for (const auto& server : dir.membership().servers) {
        if (server.node_id != t1b) t1a = server.node_id;
    }
    ASSERT_FALSE(t1a.empty());

    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(dir.send(log.attempt(), "", &answered, error, {t1a}).has_value()) << error;
    }
    EXPECT_EQ(log.hosts, (std::vector<std::string>{"t1b.example", "t1b.example", "t1b.example"}));

    log.hosts.clear();
    EXPECT_FALSE(dir.send(log.attempt(), "", &answered, error, {t1a, t1b}).has_value());
    EXPECT_TRUE(log.hosts.empty());
    EXPECT_FALSE(error.empty());

    ASSERT_TRUE(dir.send(log.attempt(), t1b, &answered, error, {t1a, t1b}).has_value()) << error;
    EXPECT_EQ(log.hosts, std::vector<std::string>{"t1b.example"});
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

// ---------------------------------------------------------------------------
// First-connect Genesis key discovery
// ---------------------------------------------------------------------------

TEST_F(SdkTier1Test, DiscoveryPinsTheKeyThatSeveralServersAgreeOn) {
    serve_genesis_everywhere();
    net.servers["old.example"].down = true;
    auto dir = directory();
    // A host repeated with another case, port, or a trailing dot is one host.
    auto candidates = all_hosts;
    candidates.push_back({"T1A.example.", 9443, true});
    const auto found = dir.discover_genesis_key(candidates);
    ASSERT_TRUE(found.ok) << found.error;
    EXPECT_EQ(found.value.genesis_pubkey, b64(chain.genesis.public_key));
    EXPECT_EQ(found.value.network_id, network_hex(chain.genesis.public_key));
    EXPECT_EQ(found.value.dns_base_domain, "example");
    EXPECT_EQ(found.value.hosts,
              (std::vector<std::string>{"t1a.example", "t1b.example", "t2.example"}));
    ASSERT_TRUE(dir.has_genesis_key());

    // The pinned key is the one the Tier 1 walk verifies from.
    const auto refreshed = dir.refresh(seed("t2.example"));
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    EXPECT_EQ(refreshed.value.epoch, 2u);
}

TEST_F(SdkTier1Test, DiscoveryFailsClosedWhenServersDisagree) {
    serve_genesis_everywhere();
    const auto other = new_identity();
    net.onboard_info["old.example"] = onboard_info(other.public_key);
    auto dir = directory();
    const auto found = dir.discover_genesis_key(all_hosts);
    EXPECT_FALSE(found.ok);
    EXPECT_EQ(found.http_status, 403);
    EXPECT_NE(found.error.find("disagree"), std::string::npos) << found.error;
    EXPECT_FALSE(dir.has_genesis_key());

    // A server that reports the same key under another domain also disagrees.
    net.onboard_info["old.example"] = onboard_info(chain.genesis.public_key, "elsewhere.test");
    EXPECT_EQ(dir.discover_genesis_key(all_hosts).http_status, 403);
    EXPECT_FALSE(dir.has_genesis_key());
}

TEST_F(SdkTier1Test, DiscoveryFailsClosedWithTooFewAgreeingServers) {
    serve_genesis_everywhere();
    net.servers["t2.example"].down = true;
    net.onboard_info.erase("old.example");  // answers without a key: not counted
    auto dir = directory();
    auto candidates = all_hosts;
    candidates.push_back({"T1B.EXAMPLE", kPort, true});  // the same host again
    const auto found = dir.discover_genesis_key(candidates);
    EXPECT_FALSE(found.ok);
    EXPECT_EQ(found.http_status, 0);
    EXPECT_NE(found.error.find("found 2"), std::string::npos) << found.error;
    EXPECT_FALSE(dir.has_genesis_key());

    // An agreeing host outside the reported network domain is not counted.
    net.servers["outside.test"] = FakeServer{std::nullopt, 0, &chain, 2, "", false};
    net.onboard_info["outside.test"] = onboard_info(chain.genesis.public_key);
    candidates.push_back({"outside.test", kPort, true});
    EXPECT_EQ(dir.discover_genesis_key(candidates).http_status, 0);
    EXPECT_FALSE(dir.has_genesis_key());

    // Agreement without a network domain binds nothing.
    net.servers["t2.example"].down = false;
    serve_genesis_everywhere();
    for (auto& [host, reply] : net.onboard_info) reply = onboard_info(chain.genesis.public_key, "");
    const auto no_domain = dir.discover_genesis_key(all_hosts);
    EXPECT_FALSE(no_domain.ok);
    EXPECT_EQ(no_domain.http_status, 403);
    EXPECT_FALSE(dir.has_genesis_key());
}

TEST_F(SdkTier1Test, DiscoveryFailsClosedOnAMalformedKey) {
    serve_genesis_everywhere();
    const std::vector<json> malformed = {
        json("not base64!"), json(nexus::crypto::to_base64(std::vector<uint8_t>(16, 7))),
        json(42)};
    for (const auto& bad : malformed) {
        net.onboard_info["t2.example"] = {
            200, json{{"dns_base_domain", "example"},
                      {"genesis_pubkey", bad},
                      {"network_id", network_hex(chain.genesis.public_key)}}
                     .dump()};
        auto dir = directory();
        const auto found = dir.discover_genesis_key(all_hosts);
        EXPECT_FALSE(found.ok) << bad.dump();
        EXPECT_EQ(found.http_status, 403) << bad.dump();
        EXPECT_FALSE(dir.has_genesis_key()) << bad.dump();
    }
}

TEST_F(SdkTier1Test, DiscoveryFailsClosedWhenTheNetworkIdDoesNotDeriveFromTheKey) {
    serve_genesis_everywhere();
    const auto other = new_identity();
    // Every server agrees, but the network id names another network.
    for (auto& [host, reply] : net.onboard_info) {
        auto doc = json::parse(reply.body);
        doc["network_id"] = network_hex(other.public_key);
        reply.body = doc.dump();
    }
    auto dir = directory();
    const auto found = dir.discover_genesis_key(all_hosts);
    EXPECT_FALSE(found.ok);
    EXPECT_EQ(found.http_status, 403);
    EXPECT_NE(found.error.find("does not derive"), std::string::npos) << found.error;
    EXPECT_FALSE(dir.has_genesis_key());
}

TEST_F(SdkTier1Test, DiscoveryNeverReplacesAPinnedKey) {
    // Every server reports another key; the pinned key stays.
    const auto other = new_identity();
    for (const auto& host : {"t1a.example", "t1b.example", "t2.example", "old.example"}) {
        net.onboard_info[host] = onboard_info(other.public_key);
    }
    auto dir = directory();
    ASSERT_TRUE(dir.set_genesis_key(b64(chain.genesis.public_key)));
    const auto found = dir.discover_genesis_key(all_hosts);
    EXPECT_FALSE(found.ok);
    EXPECT_EQ(found.http_status, 409);
    const auto refreshed = dir.refresh(seed("t2.example"));
    ASSERT_TRUE(refreshed.ok) << "the pinned key changed: " << refreshed.error;

    // The client and the C ABI refuse before any network I/O.
    lnsdk::ServerConfig cfg;
    cfg.servers = {{"127.0.0.1", 1, true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    ASSERT_TRUE(client.set_genesis_key(b64(chain.genesis.public_key)).ok);
    EXPECT_EQ(client.discover_genesis_key().http_status, 409);

    auto* c = ln_create_tls("127.0.0.1", 1);
    ASSERT_NE(c, nullptr);
    char* out = nullptr;
    EXPECT_EQ(ln_discover_genesis_key(c, nullptr, nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_discover_genesis_key(c, R"([{"port":9100}])", &out), LN_ERR_REJECTED);
    ASSERT_NE(out, nullptr);
    EXPECT_TRUE(json::parse(out).contains("error"));
    ln_free(out);
    out = nullptr;
    // No key and nothing reachable: too few servers, nothing pinned.
    EXPECT_EQ(ln_discover_genesis_key(c, R"([{"host":"127.0.0.1","port":1}])", &out),
              LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    EXPECT_TRUE(json::parse(out).contains("error"));
    ln_free(out);
    out = nullptr;
    ASSERT_EQ(ln_set_genesis_key(c, b64(chain.genesis.public_key).c_str(), 0), LN_OK);
    EXPECT_EQ(ln_discover_genesis_key(c, nullptr, &out), LN_ERR_REJECTED);
    ASSERT_NE(out, nullptr);
    EXPECT_NE(json::parse(out)["error"].get<std::string>().find("already pinned"),
              std::string::npos);
    ln_free(out);
    ln_destroy(c);
}
