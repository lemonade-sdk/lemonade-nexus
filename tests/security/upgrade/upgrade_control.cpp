// The local control interface for nexus-updater: request handling and the
// root-only socket (Core/UpgradeControl.hpp).

#include <LemonadeNexus/Core/UpgradeControl.hpp>

#include "support/lifecycle_mesh.hpp"
#include "support/release_fixture.hpp"

#if defined(NEXUS_HAVE_UPDATER_CLIENT)
#include <LemonadeNexusUpdater/ControlClient.hpp>
#endif

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <thread>

namespace lifecycle_test {
namespace {

using json = nlohmann::json;
using nexus::core::handle_upgrade_control_request;
using nexus_test::ReleaseSigner;

constexpr uint64_t kN = 2026102401;
constexpr uint64_t kN1 = 2026102501;

class UpgradeControl : public DriverMeshBase {
protected:
    void SetUp() override {
        DriverMeshBase::SetUp();
        signer.emplace(genesis_node->identity.public_key, genesis_node->identity.private_key);
        node = founders.front();
        chain = std::make_unique<ReleaseChain>(node->dir / "release",
                                               genesis_node->identity.public_key, network);
        ASSERT_TRUE(chain->load(signer->approval(kN)));
        UpgradeServiceConfig config;
        config.self = node->id;
        config.identity = node->identity;
        config.network_id = network;
        config.directory = node->dir / "upgrade";
        config.wall_clock_ms = [] { return 1'800'000'000'000ULL; };
        config.running_release = kN;
        service = std::make_unique<UpgradeService>(std::move(config), *node->driver,
                                                   *node->router, *node->runtime, chain.get());
        service->attach();
        ASSERT_TRUE(service->start(mesh.now_ms));
    }
    void TearDown() override {
        service.reset();
        DriverMeshBase::TearDown();
    }

    json call(const json& request) {
        return json::parse(handle_upgrade_control_request(*service, request.dump(), hooks));
    }

    /// A qualified approval (PCR 8/9 present) for boot-chain staging.
    [[nodiscard]] ReleaseApprovalBundleV1 qualified(uint64_t number, uint64_t previous) const {
        auto bundle = signer->approval(number, previous);
        bundle.approval.qualification_state = "LIVE_BOOT_APPROVED";
        bundle.approval.expected_pcrs = {{8, std::string(64, 'b')}, {9, std::string(64, 'c')}};
        signer->sign(bundle);
        return bundle;
    }

    nexus::core::UpgradeControlHooks hooks;

    std::optional<ReleaseSigner> signer;
    Node* node = nullptr;
    std::unique_ptr<ReleaseChain> chain;
    std::unique_ptr<UpgradeService> service;
};

TEST_F(UpgradeControl, HealthAndStatusReportWhatThisProcessHolds) {
    const auto health = call({{"op", "health"}});
    EXPECT_TRUE(health["ok"].get<bool>());
    EXPECT_EQ(health["running_release"].get<uint64_t>(), kN);
    EXPECT_EQ(health["accepted_release"].get<uint64_t>(), kN);
    EXPECT_FALSE(health["healthy"].get<bool>()) << "no epoch authority yet";
    const auto status = call({{"op", "status"}});
    EXPECT_TRUE(status["ok"].get<bool>());
    EXPECT_TRUE(status["rollout"].is_null());
}

TEST_F(UpgradeControl, AnApprovalIsAdoptedOnlyUnderTheChainRules) {
    auto reply = call({{"op", "offer_approval"},
                       {"bundle", release_approval_bundle_json(signer->approval(kN1, kN))}});
    EXPECT_TRUE(reply["ok"].get<bool>());
    EXPECT_EQ(reply["result"], "adopted");
    EXPECT_EQ(reply["accepted_release"].get<uint64_t>(), kN1);
    reply = call({{"op", "offer_approval"},
                  {"bundle", release_approval_bundle_json(signer->approval(kN))}});
    EXPECT_FALSE(reply["ok"].get<bool>());
    EXPECT_EQ(reply["result"], "stale");
    ReleaseSigner rogue(signer->genesis_pk, signer->genesis_sk);
    reply = call({{"op", "offer_approval"},
                  {"bundle", release_approval_bundle_json(rogue.approval(kN1 + 1, kN1))}});
    EXPECT_EQ(reply["result"], "wrong_signer");
}

TEST_F(UpgradeControl, TheGateNeverOpensWithoutFinalizedRecords) {
    EXPECT_EQ(call({{"op", "stage"}, {"release_number", kN1}})["ok"].get<bool>(), true);
    EXPECT_EQ(service->staged_release(), kN1);
    EXPECT_EQ(call({{"op", "turn"}, {"release_number", kN1}})["gate"], "not_started");
    // An "upgraded" report from the updater is not counted.
    const auto report = call({{"op", "report"}, {"release_number", kN1}, {"result", "upgraded"}});
    EXPECT_TRUE(report["ok"].get<bool>());
    EXPECT_FALSE(report["counted"].get<bool>());
    EXPECT_EQ(call({{"op", "turn"}, {"release_number", kN1}})["gate"], "not_started");
}

TEST_F(UpgradeControl, BootChainStagingActsOnlyOnTheAcceptedApproval) {
    std::vector<uint64_t> staged_for;
    hooks.stage_boot_chain = [&staged_for](const ReleaseApprovalBundleV1& accepted) {
        staged_for.push_back(accepted.approval.release_number);
        nexus::core::BootChainStageResult result;
        result.ok = true;
        result.staged = {"gossip-identity"};
        result.detail = "staged";
        return result;
    };
    const auto next = release_approval_bundle_json(qualified(kN1, kN));
    // Not yet accepted: the updater cannot choose the PCRs.
    auto reply = call({{"op", "stage_boot_chain"}, {"bundle", next}});
    EXPECT_FALSE(reply["ok"].get<bool>());
    EXPECT_TRUE(staged_for.empty());
    // A rogue signer's approval is refused by the chain, so it never stages.
    ReleaseSigner rogue(signer->genesis_pk, signer->genesis_sk);
    EXPECT_EQ(call({{"op", "offer_approval"},
                    {"bundle", release_approval_bundle_json(rogue.approval(kN1, kN))}})["result"],
              "wrong_signer");
    reply = call({{"op", "stage_boot_chain"},
                  {"bundle", release_approval_bundle_json(rogue.approval(kN1, kN))}});
    EXPECT_FALSE(reply["ok"].get<bool>());
    EXPECT_TRUE(staged_for.empty());
    // Accepted: staging runs for exactly that approval.
    ASSERT_EQ(call({{"op", "offer_approval"}, {"bundle", next}})["result"], "adopted");
    reply = call({{"op", "stage_boot_chain"}, {"bundle", next}});
    EXPECT_TRUE(reply["ok"].get<bool>()) << reply.dump();
    EXPECT_EQ(reply["staged"], json::array({"gossip-identity"}));
    EXPECT_EQ(staged_for, std::vector<uint64_t>{kN1});
    // Garbage and oversize bundles are refused before parsing matters.
    EXPECT_FALSE(call({{"op", "stage_boot_chain"}, {"bundle", "{}"}})["ok"].get<bool>());
    EXPECT_FALSE(call({{"op", "stage_boot_chain"},
                       {"bundle", std::string(kMaxReleaseApprovalBytes + 1, ' ')}})["ok"]
                     .get<bool>());
    EXPECT_EQ(staged_for.size(), 1u);
}

TEST_F(UpgradeControl, StagingIsRefusedWithoutAHook) {
    const auto current = release_approval_bundle_json(signer->approval(kN));
    const auto reply = call({{"op", "stage_boot_chain"}, {"bundle", current}});
    EXPECT_FALSE(reply["ok"].get<bool>());
    EXPECT_TRUE(reply.contains("error"));
}

TEST_F(UpgradeControl, TreeMergeRequestsGoToTheirHookOnly) {
    EXPECT_FALSE(call({{"op", "tree_merge_context"}})["ok"].get<bool>());
    json seen;
    hooks.tree_merge = [&seen](const json& request) {
        seen = request;
        return json{{"ok", true}, {"answered", request.value("op", "")}};
    };
    const auto reply = call({{"op", "tree_merge_build"}, {"exports", json::array()}});
    EXPECT_TRUE(reply["ok"].get<bool>());
    EXPECT_EQ(reply["answered"], "tree_merge_build");
    EXPECT_EQ(seen["op"], "tree_merge_build");
    // Other requests never reach it.
    seen = nullptr;
    (void)call({{"op", "status"}});
    EXPECT_TRUE(seen.is_null());
}

TEST_F(UpgradeControl, HealthCarriesTheTreeLogWhenItRuns) {
    EXPECT_TRUE(call({{"op", "health"}})["tree"].is_null());
    hooks.tree_status = [] {
        return std::optional<nexus::core::UpgradeTreeStatus>(
            nexus::core::UpgradeTreeStatus{true, 12, 11, false, 1});
    };
    const auto tree = call({{"op", "health"}})["tree"];
    EXPECT_TRUE(tree["healthy"].get<bool>());
    EXPECT_EQ(tree["height"].get<uint64_t>(), 12u);
    EXPECT_EQ(tree["applied_height"].get<uint64_t>(), 11u);
    EXPECT_EQ(tree["held"].get<uint64_t>(), 1u);
}

#if defined(NEXUS_HAVE_UPDATER_CLIENT)
TEST_F(UpgradeControl, TheUpdaterDecodesEveryServerReply) {
    namespace u = nexus::updater;
    const auto serve = [this](const std::string& line) {
        // The updater sends a newline-terminated line; the socket strips it.
        return handle_upgrade_control_request(*service, line.substr(0, line.size() - 1), hooks) +
               "\n";
    };
    hooks.tree_status = [] {
        return std::optional<nexus::core::UpgradeTreeStatus>(
            nexus::core::UpgradeTreeStatus{true, 5, 5, false, 0});
    };
    const auto health = u::decode_health_reply(serve(u::encode_health_request()));
    ASSERT_TRUE(health);
    EXPECT_EQ(health->running_release, kN);
    EXPECT_FALSE(health->healthy);
    ASSERT_TRUE(health->tree);
    EXPECT_EQ(health->tree->height, 5u);

    const auto next = release_approval_bundle_json(qualified(kN1, kN));
    const auto offer = u::decode_offer_reply(serve(u::encode_offer_request(next)));
    ASSERT_TRUE(offer);
    EXPECT_TRUE(offer->ok);
    EXPECT_EQ(offer->result, "adopted");
    EXPECT_TRUE(u::decode_ok_reply(serve(u::encode_stage_request(kN1))));
    EXPECT_EQ(u::decode_turn_reply(serve(u::encode_turn_request(kN1))), u::TurnGate::NotStarted);
    EXPECT_TRUE(u::decode_ok_reply(serve(u::encode_report_request(kN1, true))));

    const auto refused = u::decode_stage_boot_chain_reply(
        serve(u::encode_stage_boot_chain_request(next)));
    ASSERT_TRUE(refused);
    EXPECT_FALSE(refused->ok) << "no staging hook";
    EXPECT_FALSE(refused->detail.empty());
    hooks.stage_boot_chain = [](const ReleaseApprovalBundleV1&) {
        nexus::core::BootChainStageResult result;
        result.ok = true;
        result.staged = {"gossip-identity", "storage-share"};
        result.detail = "staged";
        return result;
    };
    const auto staged = u::decode_stage_boot_chain_reply(
        serve(u::encode_stage_boot_chain_request(next)));
    ASSERT_TRUE(staged);
    EXPECT_TRUE(staged->ok);
    EXPECT_EQ(staged->staged, (std::vector<std::string>{"gossip-identity", "storage-share"}));
}
#endif

TEST_F(UpgradeControl, MalformedRequestsAreRefused) {
    for (const auto& line : {std::string("not json"), std::string("[]"), std::string("{}"),
                             json{{"op", "turn"}}.dump(),
                             json{{"op", "turn"}, {"release_number", 0}}.dump(),
                             json{{"op", "turn"}, {"release_number", -4}}.dump(),
                             json{{"op", "report"}, {"release_number", kN1}, {"result", "maybe"}}
                                 .dump(),
                             json{{"op", "reboot"}}.dump()}) {
        const auto reply = json::parse(handle_upgrade_control_request(*service, line));
        EXPECT_FALSE(reply["ok"].get<bool>()) << line;
        EXPECT_TRUE(reply.contains("error")) << line;
    }
    const std::string oversize(nexus::core::kMaxUpgradeControlLine + 1, ' ');
    EXPECT_FALSE(
        json::parse(handle_upgrade_control_request(*service, oversize))["ok"].get<bool>());
}

#if defined(LEMONADE_HAVE_UPGRADE_CONTROL)

std::string round_trip(const std::filesystem::path& path, const std::string& line) {
    asio::io_context client_io;
    asio::local::stream_protocol::socket socket(client_io);
    asio::error_code ec;
    socket.connect(asio::local::stream_protocol::endpoint(path.string()), ec);
    if (ec) return "connect: " + ec.message();
    asio::write(socket, asio::buffer(line + "\n"), ec);
    if (ec) return "write: " + ec.message();
    asio::streambuf reply;
    asio::read_until(socket, reply, '\n', ec);
    if (ec) return "read: " + ec.message();
    std::string out((std::istreambuf_iterator<char>(&reply)), std::istreambuf_iterator<char>());
    if (!out.empty() && out.back() == '\n') out.pop_back();
    return out;
}

TEST_F(UpgradeControl, TheSocketServesOnlyTheAllowedUser) {
    // Short path: sun_path is about 100 bytes.
    const auto path = std::filesystem::path("/tmp") /
                      ("nxu-" + std::to_string(::getpid()) + ".sock");
    asio::io_context io;
    const auto run_on_io = [&io](std::function<void()> work) { asio::post(io, std::move(work)); };

    nexus::core::UpgradeControlServer server(io, {path, static_cast<uint32_t>(::getuid())},
                                             run_on_io, *service);
    std::string error;
    ASSERT_TRUE(server.start(error)) << error;
    struct stat info {};
    ASSERT_EQ(::stat(path.c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, 0600);
    std::thread loop([&io] {
        auto guard = asio::make_work_guard(io);
        io.run_for(std::chrono::seconds(5));
    });
    const auto reply = json::parse(round_trip(path, json{{"op", "health"}}.dump()), nullptr, false);
    ASSERT_FALSE(reply.is_discarded());
    EXPECT_TRUE(reply["ok"].get<bool>());
    EXPECT_EQ(reply["running_release"].get<uint64_t>(), kN);
    io.stop();
    loop.join();
    server.stop();
    EXPECT_FALSE(std::filesystem::exists(path));

    // Any other user id is refused before a request is read.
    asio::io_context io2;
    nexus::core::UpgradeControlServer strict(
        io2, {path, static_cast<uint32_t>(::getuid()) + 1},
        [&io2](std::function<void()> work) { asio::post(io2, std::move(work)); }, *service);
    ASSERT_TRUE(strict.start(error)) << error;
    std::thread loop2([&io2] {
        auto guard = asio::make_work_guard(io2);
        io2.run_for(std::chrono::seconds(5));
    });
    const auto refused = round_trip(path, json{{"op", "health"}}.dump());
    EXPECT_EQ(refused.rfind("read:", 0), 0u) << refused;
    io2.stop();
    loop2.join();
    strict.stop();
}

#endif

}  // namespace
}  // namespace lifecycle_test
