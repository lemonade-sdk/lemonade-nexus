#include <LemonadeNexus/Core/NetUtil.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Network/SeipNaming.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

using nexus::core::build_dns_query;
using nexus::net::splitHostPort;
using namespace nexus::seip;

// ---------------------------------------------------------------------------
// SeipNaming: the exact bytes ARE the test — pure concatenation, no
// normalization.
// ---------------------------------------------------------------------------

namespace {

using Case = std::pair<std::string, std::string>;  // input, expected

constexpr const char* kRegion = "us-west";
constexpr const char* kBase = "lemonade-nexus.io";

}  // namespace

TEST(SeipNamingTest, SeipFqdn) {
    EXPECT_EQ(seipFqdn("alpha", kRegion, kBase),
              "alpha.us-west.seip.lemonade-nexus.io");
    EXPECT_EQ(seipFqdn("server-01", "eu", "example.com"),
              "server-01.eu.seip.example.com");
}

TEST(SeipNamingTest, TierFqdn) {
    EXPECT_EQ(tierFqdn(1, kRegion, kBase), "tier1.us-west.seip.lemonade-nexus.io");
    EXPECT_EQ(tierFqdn(2, "eu", "example.com"), "tier2.eu.seip.example.com");
}

TEST(SeipNamingTest, MemberTierFqdn) {
    EXPECT_EQ(memberTierFqdn("alpha", 1, kRegion, kBase),
              "alpha.tier1.us-west.seip.lemonade-nexus.io");
    EXPECT_EQ(memberTierFqdn("alpha", 2, "eu", "example.com"),
              "alpha.tier2.eu.seip.example.com");
}

TEST(SeipNamingTest, PrivateFqdn) {
    EXPECT_EQ(privateFqdn("alpha", kRegion, kBase),
              "private.alpha.us-west.seip.lemonade-nexus.io");
}

TEST(SeipNamingTest, BackendFqdn) {
    EXPECT_EQ(backendFqdn("alpha", kRegion, kBase),
              "backend.alpha.us-west.seip.lemonade-nexus.io");
}

TEST(SeipNamingTest, ConfigFqdn) {
    EXPECT_EQ(configFqdn("alpha", kRegion, kBase),
              "_config.alpha.us-west.seip.lemonade-nexus.io");
}

TEST(SeipNamingTest, NoNormalizationIsApplied) {
    // Mixed case must pass through untouched — callers keep their own
    // normalization so zone keys and TXT contents stay byte-identical.
    EXPECT_EQ(seipFqdn("Alpha", "US-West", "Example.COM"),
              "Alpha.US-West.seip.Example.COM");
    EXPECT_EQ(tierFqdn(1, "US", "Example.COM"),
              "tier1.US.seip.Example.COM");
}

// ---------------------------------------------------------------------------
// NetUtil: splitHostPort — last-colon split, fail-closed port validation.
// ---------------------------------------------------------------------------

TEST(NetUtilTest, SplitHostPort) {
    auto r = splitHostPort("host:8080", 9100);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->first, "host");
    EXPECT_EQ(r->second, 8080);

    r = splitHostPort("host", 9100);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->first, "host");
    EXPECT_EQ(r->second, 9100);

    // No colon anywhere in the host part, only the port colon: the LAST
    // colon is still the split point.
    r = splitHostPort("a:b:9000", 9100);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->first, "a:b");
    EXPECT_EQ(r->second, 9000);

    // Empty input has no colon: rfind -> npos -> {empty, default_port}.
    r = splitHostPort("", 9100);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->first, "");
    EXPECT_EQ(r->second, 9100);

    EXPECT_FALSE(splitHostPort("host:", 9100).has_value());
    EXPECT_FALSE(splitHostPort("host:abc", 9100).has_value());
    EXPECT_FALSE(splitHostPort("host:0", 9100).has_value());
    EXPECT_FALSE(splitHostPort("host:70000", 9100).has_value());
    EXPECT_FALSE(splitHostPort("host:99999999999999", 9100).has_value());  // overflow
    EXPECT_FALSE(splitHostPort("host:-1", 9100).has_value());

    // Boundaries that stay valid.
    r = splitHostPort("host:1", 9100);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->second, 1);
    r = splitHostPort("host:65535", 9100);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->second, 65535);
}

// ---------------------------------------------------------------------------
// build_dns_query: exact wire bytes for a hand-built query, plus fail-closed
// label validation.
// ---------------------------------------------------------------------------

namespace {

// Hand-built expected bytes for
// build_dns_query("node.test.local", /*qtype=*/16, /*id=*/0x1234):
// 12 34   id (0x1234)
// 01 00   RD set
// 00 01   QDCOUNT = 1
// 00 00   ANCOUNT
// 00 00   NSCOUNT
// 00 00   ARCOUNT
// 04 "node" 04 "test" 05 "local" 00   question name + root label
// 00 10   qtype TXT (16)
// 00 01   qclass IN
const std::vector<uint8_t> kExpectedQuery = {
    0x12, 0x34, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 'n', 'o', 'd', 'e',
    0x04, 't', 'e', 's', 't',
    0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,
    0x00, 0x10,
    0x00, 0x01,
};

}  // namespace

TEST(DnsQueryTest, BuildDnsQueryMatchesHandBuiltBytes) {
    EXPECT_EQ(build_dns_query("node.test.local", 16 /* TXT */, 0x1234),
              kExpectedQuery);

    // qtype is caller-supplied (A record query differs only in bytes 29..30).
    auto a = build_dns_query("node.test.local", 1 /* A */, 0x1234);
    auto expected_a = kExpectedQuery;
    expected_a[29] = 0x00;
    expected_a[30] = 0x01;
    EXPECT_EQ(a, expected_a);

    // The ID lands in the first two bytes.
    auto id_7a11 = build_dns_query("node.test.local", 16, 0x7A11);
    EXPECT_EQ(id_7a11[0], 0x7A);
    EXPECT_EQ(id_7a11[1], 0x11);
    EXPECT_EQ(id_7a11,
              (std::vector<uint8_t>{0x7A, 0x11, 0x01, 0x00,
                                    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x04, 'n', 'o', 'd', 'e',
                                    0x04, 't', 'e', 's', 't',
                                    0x05, 'l', 'o', 'c', 'a', 'l',
                                    0x00, 0x00, 0x10, 0x00, 0x01}));
}

TEST(DnsQueryTest, BuildDnsQueryFailsClosedOnBadLabels) {
    EXPECT_TRUE(build_dns_query("a..b", 16, 0x1234).empty());     // empty label
    EXPECT_TRUE(build_dns_query("trailing.", 16, 0x1234).empty());  // trailing dot
    EXPECT_TRUE(build_dns_query(
        std::string(64, 'x') + ".b", 16, 0x1234).empty());        // 64-octet label
    // Exactly 63 octets is legal.
    EXPECT_FALSE(build_dns_query(std::string(63, 'x') + ".b", 16, 0x1234).empty());
}
