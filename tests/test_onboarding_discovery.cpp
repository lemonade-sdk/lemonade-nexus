// Unit tests for the onboarding DNS-discovery helpers: raw DNS TXT response
// parsing (fail closed on malformed input), tier TXT host= field extraction,
// and candidate construction (member FQDNs first, tier FQDN fallback second).

#include <LemonadeNexus/Core/OnboardingClient.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace nexus::core;

namespace {

constexpr uint16_t kFlagsResponseNoError = 0x8180;  // QR + RD, rcode 0
constexpr uint16_t kFlagsQuery = 0x0100;            // no QR: not a response
constexpr uint16_t kFlagsResponseNxdomain = 0x8183; // rcode 3

void put16(std::vector<uint8_t>& m, uint16_t v) {
    m.push_back(static_cast<uint8_t>(v >> 8));
    m.push_back(static_cast<uint8_t>(v & 0xFF));
}

/// Minimal DNS response: one question ("a.b", TXT/IN), then answers where
/// each answer name is a compression pointer to the question name.
std::vector<uint8_t> make_response(
        uint16_t id, uint16_t flags,
        std::initializer_list<std::pair<uint16_t, std::vector<uint8_t>>> answers) {
    std::vector<uint8_t> m;
    put16(m, id);
    put16(m, flags);
    put16(m, 1);                        // QDCOUNT
    put16(m, static_cast<uint16_t>(answers.size()));
    put16(m, 0); put16(m, 0);
    // Question name "a.b" at offset 12, type TXT, class IN.
    m.push_back(1); m.push_back('a');
    m.push_back(1); m.push_back('b');
    m.push_back(0);
    put16(m, 16);
    put16(m, 1);
    for (const auto& [type, rdata] : answers) {
        m.push_back(0xC0); m.push_back(0x0C);      // pointer to the question
        put16(m, type);
        put16(m, 1);                               // class IN
        put16(m, 0); put16(m, 0);                  // ttl
        put16(m, static_cast<uint16_t>(rdata.size()));
        m.insert(m.end(), rdata.begin(), rdata.end());
    }
    return m;
}

/// TXT RDATA from a list of wire chunks (length-prefixed).
std::vector<uint8_t> txt_chunks(std::initializer_list<const char*> chunks) {
    std::vector<uint8_t> rdata;
    for (const char* chunk : chunks) {
        const auto len = std::strlen(chunk);
        if (len > 255) return {};  // not exercised; keeps the helper honest
        rdata.push_back(static_cast<uint8_t>(len));
        rdata.insert(rdata.end(), chunk, chunk + len);
    }
    return rdata;
}

}  // namespace

// ===========================================================================
// parse_dns_txt_records — valid responses
// ===========================================================================

TEST(DnsTxtParse, SingleChunkYieldsOneString) {
    const auto m = make_response(0x1234, kFlagsResponseNoError,
                                 {{16, txt_chunks({"v=sp1 host=a.t"})}});
    const auto txt = parse_dns_txt_records(m);
    ASSERT_EQ(txt.size(), 1u);
    EXPECT_EQ(txt[0], "v=sp1 host=a.t");
}

TEST(DnsTxtParse, MultipleChunksWithinOneRrAreConcatenated) {
    const auto m = make_response(
        0x1234, kFlagsResponseNoError,
        {{16, txt_chunks({"v=sp1 host=al", "pha.us.seip.t host=be", "ta.us.seip.t"})}});
    const auto txt = parse_dns_txt_records(m);
    ASSERT_EQ(txt.size(), 1u);
    EXPECT_EQ(txt[0], "v=sp1 host=alpha.us.seip.t host=beta.us.seip.t");
}

TEST(DnsTxtParse, EachTxtRrYieldsOneString) {
    const auto m = make_response(0x1234, kFlagsResponseNoError,
                                 {{16, txt_chunks({"first"})},
                                  {16, txt_chunks({"second"})}});
    const auto txt = parse_dns_txt_records(m);
    ASSERT_EQ(txt.size(), 2u);
    EXPECT_EQ(txt[0], "first");
    EXPECT_EQ(txt[1], "second");
}

TEST(DnsTxtParse, NonTxtAnswersAreSkipped) {
    // An A record (4-byte rdata) followed by a TXT record.
    const std::vector<uint8_t> a_rdata{10, 0, 0, 1};
    const auto m = make_response(0x1234, kFlagsResponseNoError,
                                 {{1, a_rdata}, {16, txt_chunks({"data"})}});
    const auto txt = parse_dns_txt_records(m);
    ASSERT_EQ(txt.size(), 1u);
    EXPECT_EQ(txt[0], "data");
}

// ===========================================================================
// parse_dns_txt_records — rejected messages (fail closed)
// ===========================================================================

TEST(DnsTxtParse, NonResponseIsRejected) {
    const auto m = make_response(0x1234, kFlagsQuery,
                                 {{16, txt_chunks({"data"})}});
    EXPECT_TRUE(parse_dns_txt_records(m).empty());
}

TEST(DnsTxtParse, NxdomainRcodeIsRejected) {
    const auto m = make_response(0x1234, kFlagsResponseNxdomain,
                                 {{16, txt_chunks({"data"})}});
    EXPECT_TRUE(parse_dns_txt_records(m).empty());
}

TEST(DnsTxtParse, TruncatedMessageIsRejected) {
    const auto full = make_response(0x1234, kFlagsResponseNoError,
                                    {{16, txt_chunks({"data"})}});
    const std::vector<std::size_t> cuts =
        {0, 5, 11, 12, 15, full.size() - 1};
    for (const std::size_t cut : cuts) {
        std::vector<uint8_t> truncated(full.begin(), full.begin() + cut);
        EXPECT_TRUE(parse_dns_txt_records(truncated).empty())
            << "truncated at " << cut;
    }
}

TEST(DnsTxtParse, RdlengthOverrunIsRejected) {
    // rdlength claims 200 bytes but the message ends earlier.
    std::vector<uint8_t> m;
    put16(m, 0x1234);
    put16(m, kFlagsResponseNoError);
    put16(m, 1); put16(m, 1);
    put16(m, 0); put16(m, 0);
    m.push_back(1); m.push_back('a'); m.push_back(0);
    put16(m, 16); put16(m, 1);
    m.push_back(0xC0); m.push_back(0x0C);
    put16(m, 16); put16(m, 1);
    put16(m, 0); put16(m, 0);
    put16(m, 200);   // rdlength beyond the end of the message
    m.push_back(4); m.push_back('d'); m.push_back('a'); m.push_back('t');
    EXPECT_TRUE(parse_dns_txt_records(m).empty());
}

TEST(DnsTxtParse, TxtChunkBeyondRdataIsRejected) {
    // TXT rdata: a chunk of length 10 inside a 3-byte rdata.
    const std::vector<uint8_t> bad_rdata{10, 'x', 'y', 'z'};
    const auto m = make_response(0x1234, kFlagsResponseNoError, {{16, bad_rdata}});
    EXPECT_TRUE(parse_dns_txt_records(m).empty());
}

TEST(DnsTxtParse, ForwardPointingNamePointerIsRejected) {
    // Answer name pointer claims offset 60 — past the current position.
    std::vector<uint8_t> m;
    put16(m, 0x1234);
    put16(m, kFlagsResponseNoError);
    put16(m, 1); put16(m, 1);
    put16(m, 0); put16(m, 0);
    m.push_back(1); m.push_back('a'); m.push_back(0);   // question at 12
    put16(m, 16); put16(m, 1);
    m.push_back(0xC0); m.push_back(60);                  // points forward
    put16(m, 16); put16(m, 1);
    put16(m, 0); put16(m, 0);
    put16(m, 4);
    m.push_back(4); m.push_back('d'); m.push_back('a'); m.push_back('t');
    EXPECT_TRUE(parse_dns_txt_records(m).empty());
}

TEST(DnsTxtParse, OversizedLabelIsRejected) {
    // Question name label of length 64 (> 63).
    std::vector<uint8_t> m;
    put16(m, 0x1234);
    put16(m, kFlagsResponseNoError);
    put16(m, 1); put16(m, 1);
    put16(m, 0); put16(m, 0);
    m.push_back(64);
    m.insert(m.end(), 64, 'a');
    m.push_back(0);
    put16(m, 16); put16(m, 1);
    m.push_back(0xC0); m.push_back(0x0C);
    put16(m, 16); put16(m, 1);
    put16(m, 0); put16(m, 0);
    put16(m, 4);
    m.push_back(4); m.push_back('d'); m.push_back('a'); m.push_back('t');
    EXPECT_TRUE(parse_dns_txt_records(m).empty());
}

TEST(DnsTxtParse, AnswerWithTrailingFieldCutOffIsRejected) {
    // A single answer with only the name pointer present (no type/class/ttl/rdlength).
    std::vector<uint8_t> m;
    put16(m, 0x1234);
    put16(m, kFlagsResponseNoError);
    put16(m, 1); put16(m, 1);
    put16(m, 0); put16(m, 0);
    m.push_back(1); m.push_back('a'); m.push_back(0);
    put16(m, 16); put16(m, 1);
    m.push_back(0xC0); m.push_back(0x0C);
    EXPECT_TRUE(parse_dns_txt_records(m).empty());
}

// ===========================================================================
// resolve_txt_records — fails closed without a network
// ===========================================================================

TEST(DnsTxtParse, EmptyHostnameFailsClosed) {
    EXPECT_TRUE(resolve_txt_records("").empty());
}

// ===========================================================================
// parse_discovery_txt_hosts
// ===========================================================================

TEST(OnboardingDiscovery, ParsesHostFieldsFromTierTxt) {
    const auto hosts = parse_discovery_txt_hosts(
        {"v=sp1 host=alpha.us.seip.t host=beta.us.seip.t"});
    ASSERT_EQ(hosts.size(), 2u);
    EXPECT_EQ(hosts[0], "alpha.us.seip.t");
    EXPECT_EQ(hosts[1], "beta.us.seip.t");
}

TEST(OnboardingDiscovery, IgnoresOtherFieldsAndEmptyHosts) {
    const auto hosts = parse_discovery_txt_hosts(
        {"v=sp1 http=9100 load=3", "host=", "host=alpha.us.seip.t"});
    ASSERT_EQ(hosts.size(), 1u);
    EXPECT_EQ(hosts[0], "alpha.us.seip.t");
}

TEST(OnboardingDiscovery, EmptyRecordYieldsNoHosts) {
    EXPECT_TRUE(parse_discovery_txt_hosts({}).empty());
    EXPECT_TRUE(parse_discovery_txt_hosts({"", "v=sp1"}).empty());
}

// ===========================================================================
// build_discovery_targets — ordering and fallback
// ===========================================================================

TEST(OnboardingDiscovery, MembersFirstThenTierFallbackPerTier) {
    const auto targets = build_discovery_targets(
        {"a.us.seip.t", "b.us.seip.t"}, {"c.us.seip.t"}, "us", "t", 9100);
    ASSERT_EQ(targets.size(), 5u);
    EXPECT_EQ(targets[0], "a.us.seip.t:9100");
    EXPECT_EQ(targets[1], "b.us.seip.t:9100");
    EXPECT_EQ(targets[2], "tier1.us.seip.t:9100");   // tier1 fallback
    EXPECT_EQ(targets[3], "c.us.seip.t:9100");
    EXPECT_EQ(targets[4], "tier2.us.seip.t:9100");   // tier2 fallback
}

TEST(OnboardingDiscovery, NoMembersStillLeavesTheTierFallback) {
    const auto targets = build_discovery_targets({}, {}, "us", "t", 9101);
    ASSERT_EQ(targets.size(), 2u);
    EXPECT_EQ(targets[0], "tier1.us.seip.t:9101");
    EXPECT_EQ(targets[1], "tier2.us.seip.t:9101");
}

TEST(OnboardingDiscovery, SkipsEmptyMemberEntries) {
    const auto targets = build_discovery_targets({"", "a.us.seip.t"}, {}, "us", "t", 9100);
    ASSERT_EQ(targets.size(), 3u);
    EXPECT_EQ(targets[0], "a.us.seip.t:9100");
    EXPECT_EQ(targets[1], "tier1.us.seip.t:9100");
    EXPECT_EQ(targets[2], "tier2.us.seip.t:9100");
}
