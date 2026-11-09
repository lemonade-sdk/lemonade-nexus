// The AMD CRL refresh: a cached list is replaced before it expires, and only
// by a list AMD signed that is not older than the one on disk.
//
// Every list on disk expires on its signed nextUpdate, and the verifier then
// fails new attestation closed. The refresher exists so that moment never
// arrives on a node that can reach KDS. The tests here drive it with a fake
// fetch: the accepting path, and every way a fetch must NOT change the cache.
//
// amd_milan_crl.der is AMD's Milan list valid 2026-08-19 to 2026-10-04;
// amd_milan_crl_2026_10.der is the one that followed it, valid 2026-10-27 to
// 2026-12-09; amd_genoa_crl.der is the Genoa list from the same day. All three
// are real KDS downloads, so the signature checks run against AMD's keys.

#include <LemonadeNexus/Security/Attestation/AmdRevocationRefresher.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace fs = std::filesystem;

using nexus::security::AmdCrlFetchResult;
using nexus::security::AmdCrlRefreshOutcome;
using nexus::security::AmdRevocationRefresher;
using nexus::security::AmdRevocationRefresherConfig;
using nexus::security::inspect_amd_crl;

namespace {

fs::path fixture_dir() {
    if (const char* d = std::getenv("NEXUS_TEST_FIXTURES")) return fs::path(d);
    return fs::path(NEXUS_TEST_FIXTURE_DIR);
}

std::string fixture(const char* name) {
    std::ifstream f(fixture_dir() / name, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

std::vector<uint8_t> fixture_bytes(const char* name) {
    const std::string text = fixture(name);
    return {text.begin(), text.end()};
}

std::string old_milan() { return fixture("amd_milan_crl.der"); }
std::string new_milan() { return fixture("amd_milan_crl_2026_10.der"); }
std::string genoa() { return fixture("amd_genoa_crl.der"); }

// The signed windows of the fixtures, Unix seconds.
constexpr int64_t kOldMilanThisUpdate = 1'787'149'163;  // 2026-08-19T14:19:23Z
constexpr int64_t kOldMilanNextUpdate = 1'791'072'000;  // 2026-10-04T00:00:00Z
constexpr int64_t kNewMilanThisUpdate = 1'793'082'435;  // 2026-10-27T06:27:15Z
constexpr int64_t kNewMilanNextUpdate = 1'796'778'000;  // 2026-12-09T01:00:00Z

// Clock positions the tests stand at.
constexpr int64_t kFourDaysBeforeOldExpiry = 1'790'726'400;  // 2026-09-30
constexpr int64_t kAfterOldExpiry          = 1'793'491'200;  // 2026-11-01
constexpr int64_t kFarFromNewExpiry        = 1'794'096'000;  // 2026-11-08
constexpr int64_t kFourDaysBeforeNewExpiry = 1'796'428'800;  // 2026-12-05

constexpr int64_t kWindow = 7 * 24 * 3600;
constexpr int64_t kCheckInterval = 3600;
constexpr int64_t kBackoffBase = 300;
constexpr int64_t kBackoffMax = 6 * 3600;

/// Answers every fetch with one scripted result and remembers the URLs asked.
struct FakeKds {
    AmdCrlFetchResult answer;
    std::vector<std::string> urls;

    nexus::security::AmdCrlFetch fetch() {
        return [this](const std::string& url) {
            urls.push_back(url);
            return answer;
        };
    }
    static AmdCrlFetchResult ok(std::string body) { return {200, std::move(body), {}}; }
    static AmdCrlFetchResult status(int code) { return {code, "throttled", {}}; }
    static AmdCrlFetchResult down() { return {0, {}, "connection refused"}; }
};

struct RefresherFixture : ::testing::Test {
    fs::path root;
    FakeKds kds;

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("nexus_crl_refresh_" + std::to_string(::getpid()) + "_" +
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(root);
    }
    void TearDown() override { fs::remove_all(root); }

    AmdRevocationRefresher make(std::vector<std::string> products = {"Milan"}) {
        return AmdRevocationRefresher(AmdRevocationRefresherConfig{
            .directory = root,
            .fetch = kds.fetch(),
            .products = std::move(products),
            .refresh_window_seconds = kWindow,
            .check_interval_seconds = kCheckInterval,
            .backoff_base_seconds = kBackoffBase,
            .backoff_max_seconds = kBackoffMax});
    }

    std::string cached_milan(const AmdRevocationRefresher& r) {
        const auto cached = r.cache().load("Milan");
        return cached ? cached->bytes : std::string{};
    }
};

}  // namespace

// --- inspect_amd_crl: the acceptance test a fetched list must pass ---------------

TEST(AmdCrlInspection, ReadsAmdsOwnListAndItsWindow) {
    const auto milan = inspect_amd_crl("Milan", old_milan());
    ASSERT_TRUE(milan.ok) << milan.failure;
    EXPECT_TRUE(milan.parsed);
    EXPECT_EQ(milan.this_update_unix, kOldMilanThisUpdate);
    EXPECT_EQ(milan.next_update_unix, kOldMilanNextUpdate);
    EXPECT_EQ(milan.revoked_count, 0u);

    const auto newer = inspect_amd_crl("Milan", new_milan());
    ASSERT_TRUE(newer.ok) << newer.failure;
    EXPECT_EQ(newer.this_update_unix, kNewMilanThisUpdate);
    EXPECT_EQ(newer.next_update_unix, kNewMilanNextUpdate);

    const auto genoa_list = inspect_amd_crl("Genoa", genoa());
    ASSERT_TRUE(genoa_list.ok) << genoa_list.failure;
    EXPECT_EQ(genoa_list.next_update_unix, kNewMilanNextUpdate);
    EXPECT_EQ(genoa_list.revoked_count, 1u);
}

TEST(AmdCrlInspection, RefusesWhatIsNotAmdsListForTheProduct) {
    // Not a CRL at all.
    for (const char* junk : {"", "not a crl", "<html>captive portal</html>",
                             "-----BEGIN X509 CRL-----\nAAAA\n", "\x30\x82\xff"}) {
        const auto result = inspect_amd_crl("Milan", junk);
        EXPECT_FALSE(result.ok);
        EXPECT_FALSE(result.parsed) << junk;
    }
    // A well-formed list from another issuer.
    const auto foreign = inspect_amd_crl("Milan", fixture("foreign_crl.pem"));
    EXPECT_FALSE(foreign.ok);
    EXPECT_TRUE(foreign.parsed);
    EXPECT_NE(foreign.failure.find("not signed by the compiled-in AMD chain"), std::string::npos)
        << foreign.failure;
    // AMD's list, but for the other product: the Genoa chain did not sign it.
    const auto crossed = inspect_amd_crl("Genoa", new_milan());
    EXPECT_FALSE(crossed.ok);
    EXPECT_TRUE(crossed.parsed);
    // No compiled-in chain: nothing to check against.
    const auto unknown = inspect_amd_crl("Turin", new_milan());
    EXPECT_FALSE(unknown.ok);
    EXPECT_NE(unknown.failure.find("no compiled-in AMD chain"), std::string::npos)
        << unknown.failure;
}

// --- the refresh: accepting path -------------------------------------------------

TEST_F(RefresherFixture, AListInsideTheWindowIsReplacedByANewerSignedOne) {
    auto refresher = make();
    ASSERT_FALSE(refresher.cache().load("Milan").has_value());
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", old_milan(), kOldMilanThisUpdate));

    kds.answer = FakeKds::ok(new_milan());
    EXPECT_TRUE(refresher.due(kFourDaysBeforeOldExpiry));
    EXPECT_EQ(refresher.refresh("Milan", kFourDaysBeforeOldExpiry),
              AmdCrlRefreshOutcome::Refreshed);
    ASSERT_EQ(kds.urls.size(), 1u);
    EXPECT_EQ(kds.urls[0], "https://kdsintf.amd.com/vcek/v1/Milan/crl");
    EXPECT_EQ(cached_milan(refresher), new_milan());

    // Success resets the pacing to the check interval, not a backoff.
    const auto state = refresher.state("Milan");
    EXPECT_EQ(state.failures, 0u);
    EXPECT_EQ(state.next_attempt_unix, kFourDaysBeforeOldExpiry + kCheckInterval);
    EXPECT_FALSE(refresher.due(kFourDaysBeforeOldExpiry + kCheckInterval - 1));
    EXPECT_TRUE(refresher.due(kFourDaysBeforeOldExpiry + kCheckInterval));
}

TEST_F(RefresherFixture, AnExpiredListIsReplaced) {
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", old_milan(), kOldMilanThisUpdate));
    auto refresher = make();
    kds.answer = FakeKds::ok(new_milan());

    EXPECT_EQ(refresher.refresh("Milan", kAfterOldExpiry), AmdCrlRefreshOutcome::Refreshed);
    EXPECT_EQ(cached_milan(refresher), new_milan());

    // What the refresher stored is what the verifier accepts, with no network.
    const auto verdict = nexus::security::verify_snp_revocation(
        fixture_bytes("vcek_milan.der"), {}, refresher.cache().state(kFarFromNewExpiry));
    EXPECT_TRUE(verdict.ok) << verdict.failure;
}

TEST_F(RefresherFixture, AnEmptyCacheIsFilled) {
    auto refresher = make({"Milan", "Genoa"});
    kds.answer = FakeKds::ok(new_milan());
    EXPECT_EQ(refresher.refresh("Milan", kFarFromNewExpiry), AmdCrlRefreshOutcome::Refreshed);
    kds.answer = FakeKds::ok(genoa());
    EXPECT_EQ(refresher.refresh("Genoa", kFarFromNewExpiry), AmdCrlRefreshOutcome::Refreshed);
    EXPECT_EQ(refresher.cache().state(kFarFromNewExpiry).crls.size(), 2u);
}

TEST_F(RefresherFixture, AValidListFarFromExpiryIsLeftAlone) {
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", new_milan(), kNewMilanThisUpdate));
    auto refresher = make();
    kds.answer = FakeKds::ok(new_milan());

    EXPECT_EQ(refresher.refresh("Milan", kFarFromNewExpiry), AmdCrlRefreshOutcome::NotDue);
    EXPECT_TRUE(kds.urls.empty());
    EXPECT_EQ(refresher.state("Milan").next_attempt_unix, kFarFromNewExpiry + kCheckInterval);

    // Inside the window the same list is asked for again.
    EXPECT_NE(refresher.refresh("Milan", kFourDaysBeforeNewExpiry), AmdCrlRefreshOutcome::NotDue);
    EXPECT_EQ(kds.urls.size(), 1u);
}

TEST_F(RefresherFixture, TheSameListAgainIsNotARefreshAndNotAFailure) {
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", new_milan(), kNewMilanThisUpdate));
    auto refresher = make();
    kds.answer = FakeKds::ok(new_milan());

    EXPECT_EQ(refresher.refresh("Milan", kFourDaysBeforeNewExpiry),
              AmdCrlRefreshOutcome::Unchanged);
    EXPECT_EQ(cached_milan(refresher), new_milan());
    EXPECT_EQ(refresher.state("Milan").failures, 0u);
    EXPECT_EQ(refresher.state("Milan").next_attempt_unix,
              kFourDaysBeforeNewExpiry + kCheckInterval);
}

// --- the refresh: every way a fetch must not change the cache ------------------

TEST_F(RefresherFixture, AnUnparsableAnswerIsRefusedAndTheOldFileStays) {
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", old_milan(), kOldMilanThisUpdate));
    auto refresher = make();

    kds.answer = FakeKds::ok("<html>sign in to the hotel network</html>");
    EXPECT_EQ(refresher.refresh("Milan", kFourDaysBeforeOldExpiry),
              AmdCrlRefreshOutcome::Unparsable);
    EXPECT_EQ(cached_milan(refresher), old_milan());
    EXPECT_EQ(refresher.state("Milan").failures, 1u);
    EXPECT_EQ(refresher.state("Milan").next_attempt_unix,
              kFourDaysBeforeOldExpiry + kBackoffBase);
}

TEST_F(RefresherFixture, AListNotSignedByAmdIsRefused) {
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", old_milan(), kOldMilanThisUpdate));
    auto refresher = make();

    // Another issuer's list, well formed and unexpired.
    kds.answer = FakeKds::ok(fixture("foreign_crl.pem"));
    EXPECT_EQ(refresher.refresh("Milan", kFourDaysBeforeOldExpiry),
              AmdCrlRefreshOutcome::SignatureInvalid);
    EXPECT_EQ(cached_milan(refresher), old_milan());

    // AMD's list for the other product: a substitution, refused the same way.
    kds.answer = FakeKds::ok(genoa());
    EXPECT_EQ(refresher.refresh("Milan", kFourDaysBeforeOldExpiry),
              AmdCrlRefreshOutcome::SignatureInvalid);
    EXPECT_EQ(cached_milan(refresher), old_milan());
    EXPECT_EQ(refresher.state("Milan").failures, 2u);
}

TEST_F(RefresherFixture, AnOlderListIsRefused) {
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", new_milan(), kNewMilanThisUpdate));
    auto refresher = make();

    // The cached list is due, and KDS (or whoever answers for it) serves the
    // list that preceded it. thisUpdate would go backwards; the cache keeps
    // the newer one.
    kds.answer = FakeKds::ok(old_milan());
    EXPECT_EQ(refresher.refresh("Milan", kFourDaysBeforeNewExpiry),
              AmdCrlRefreshOutcome::OlderThanCached);
    EXPECT_EQ(cached_milan(refresher), new_milan());
    EXPECT_EQ(refresher.state("Milan").failures, 1u);
}

TEST_F(RefresherFixture, AFetchFailureKeepsTheFileAndBacksOff) {
    nexus::security::AmdRevocationCache seed{root};
    ASSERT_TRUE(seed.store("Milan", old_milan(), kOldMilanThisUpdate));
    auto refresher = make();

    int64_t now = kFourDaysBeforeOldExpiry;
    int64_t expected_delay = kBackoffBase;
    kds.answer = FakeKds::status(429);
    for (uint32_t attempt = 1; attempt <= 8; ++attempt) {
        EXPECT_EQ(refresher.refresh("Milan", now), AmdCrlRefreshOutcome::FetchFailed);
        EXPECT_EQ(cached_milan(refresher), old_milan());
        const auto state = refresher.state("Milan");
        EXPECT_EQ(state.failures, attempt);
        EXPECT_EQ(state.next_attempt_unix, now + expected_delay) << "attempt " << attempt;
        // Not due until the backoff passes, so tick() leaves KDS alone.
        EXPECT_FALSE(refresher.due(now + expected_delay - 1));
        const auto asked = kds.urls.size();
        refresher.tick(now + expected_delay - 1);
        EXPECT_EQ(kds.urls.size(), asked);
        EXPECT_TRUE(refresher.due(now + expected_delay));
        now += expected_delay;
        expected_delay = std::min<int64_t>(expected_delay * 2, kBackoffMax);
    }
    // 300 s doubling reaches the 6 h cap at the eighth failure and stays there.
    EXPECT_EQ(refresher.refresh("Milan", now), AmdCrlRefreshOutcome::FetchFailed);
    EXPECT_EQ(refresher.state("Milan").failures, 9u);
    EXPECT_EQ(refresher.state("Milan").next_attempt_unix, now + kBackoffMax);

    // No response at all is the same failure, and an outage with nothing
    // cached leaves nothing cached: no empty file for the verifier to find.
    kds.answer = FakeKds::down();
    auto empty = AmdRevocationRefresher(AmdRevocationRefresherConfig{
        .directory = root / "empty", .fetch = kds.fetch(), .products = {"Milan"}});
    EXPECT_EQ(empty.refresh("Milan", now), AmdCrlRefreshOutcome::FetchFailed);
    EXPECT_FALSE(empty.cache().load("Milan").has_value());

    // A success after the outage clears the backoff.
    kds.answer = FakeKds::ok(new_milan());
    EXPECT_EQ(refresher.refresh("Milan", now), AmdCrlRefreshOutcome::Refreshed);
    EXPECT_EQ(refresher.state("Milan").failures, 0u);
}

TEST_F(RefresherFixture, AProductWithoutAPinnedRootIsSkipped) {
    auto refresher = make({"Turin", "Milan"});
    kds.answer = FakeKds::ok(new_milan());

    EXPECT_EQ(refresher.refresh("Turin", kFarFromNewExpiry), AmdCrlRefreshOutcome::Skipped);
    EXPECT_TRUE(kds.urls.empty());
    EXPECT_FALSE(refresher.cache().load("Turin").has_value());

    // A tick serves the products that can be checked and never asks for Turin.
    refresher.tick(kFarFromNewExpiry);
    ASSERT_EQ(kds.urls.size(), 1u);
    EXPECT_EQ(kds.urls[0], "https://kdsintf.amd.com/vcek/v1/Milan/crl");
    EXPECT_FALSE(refresher.due(kFarFromNewExpiry));
}

TEST_F(RefresherFixture, ATickServesEveryDueProductAndPinnedProductsAreTheDefault) {
    auto refresher = AmdRevocationRefresher(AmdRevocationRefresherConfig{
        .directory = root, .fetch = kds.fetch()});
    std::vector<std::string> expected;
    for (const auto product : nexus::security::pinned_amd_products()) {
        expected.emplace_back(product);
    }
    EXPECT_EQ(refresher.products(), expected);

    // The fake answers Milan's list to every product: Milan takes it, Genoa
    // refuses it as not signed by its chain.
    kds.answer = FakeKds::ok(new_milan());
    EXPECT_TRUE(refresher.due(kFarFromNewExpiry));
    refresher.tick(kFarFromNewExpiry);
    EXPECT_EQ(kds.urls.size(), expected.size());
    EXPECT_EQ(cached_milan(refresher), new_milan());
    EXPECT_FALSE(refresher.cache().load("Genoa").has_value());
    EXPECT_EQ(refresher.state("Genoa").failures, 1u);
    EXPECT_FALSE(refresher.due(kFarFromNewExpiry));
}

TEST(AmdRevocationRefresherBackoff, DoublesFromTheBaseAndIsBounded) {
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(0, 300, 21600), 0);
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(1, 300, 21600), 300);
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(2, 300, 21600), 600);
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(3, 300, 21600), 1200);
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(7, 300, 21600), 19200);
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(8, 300, 21600), 21600);
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(32, 300, 21600), 21600);
    EXPECT_EQ(AmdRevocationRefresher::backoff_seconds(1000, 300, 21600), 21600);
}
