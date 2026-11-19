// The PCP client asks the default gateway for a public UDP port with the
// RFC 6887 MAP opcode. The codec is checked byte for byte against the RFC;
// the client is checked against the fake gateway in tests/support.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/Pcp.hpp>

#include "support/FakeGateway.hpp"

#include <chrono>
#include <cstdint>
#include <vector>

namespace pcp = lnsdk::pcp;
using pcp::ResultCode;
using test_support::FakeGateway;

namespace {

std::vector<uint8_t> bytes_of(std::initializer_list<int> values) {
    std::vector<uint8_t> out;
    for (int v : values) out.push_back(static_cast<uint8_t>(v));
    return out;
}

pcp::Nonce fixed_nonce() {
    pcp::Nonce n{};
    for (size_t i = 0; i < n.size(); ++i) n[i] = static_cast<uint8_t>(0xA0 + i);
    return n;
}

std::vector<uint8_t> success_response() {
    FakeGateway::PcpMapResponse f;
    f.lifetime_sec = 7200;
    f.epoch_sec = 3600;
    f.mapping_nonce = fixed_nonce();
    f.protocol = 17;
    f.internal_port = 51820;
    f.assigned_external_port = 40000;
    f.assigned_external_address = FakeGateway::ipv4_mapped("203.0.113.5");
    return FakeGateway::encode_pcp_map_response(f);
}

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

TEST(PcpCodec, EncodesMapRequestByteExact) {
    pcp::MapRequest req;
    req.lifetime_sec = 7200;
    req.client_address = 0xC0A80114;
    req.nonce = fixed_nonce();
    req.internal_port = 51820;
    req.suggested_external_port = 51820;
    const auto pkt = pcp::encode_map_request(req);
    ASSERT_EQ(pkt.size(), 60u);
    std::vector<uint8_t> expected = bytes_of({0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x20});
    for (int i = 0; i < 10; ++i) expected.push_back(0);
    for (int b : {0xFF, 0xFF, 192, 168, 1, 20}) expected.push_back(static_cast<uint8_t>(b));
    for (int i = 0; i < 12; ++i) expected.push_back(static_cast<uint8_t>(0xA0 + i));
    for (int b : {0x11, 0x00, 0x00, 0x00, 0xCA, 0x6C, 0xCA, 0x6C}) {
        expected.push_back(static_cast<uint8_t>(b));
    }
    for (int i = 0; i < 16; ++i) expected.push_back(0);
    EXPECT_EQ(pkt, expected);

    req.suggested_external_address = 0xCB007105;
    const auto with_address = pcp::encode_map_request(req);
    const std::vector<uint8_t> tail(with_address.begin() + 44, with_address.end());
    EXPECT_EQ(tail, bytes_of({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 203, 0, 113, 5}));
}

TEST(PcpCodec, DecodesSuccessResponse) {
    const auto r = pcp::decode_map_response(success_response());
    ASSERT_TRUE(r);
    EXPECT_EQ(r->result, ResultCode::Success);
    EXPECT_EQ(r->lifetime_sec, 7200u);
    EXPECT_EQ(r->epoch_sec, 3600u);
    EXPECT_EQ(r->nonce, fixed_nonce());
    EXPECT_EQ(r->protocol, 17);
    EXPECT_EQ(r->internal_port, 51820);
    EXPECT_EQ(r->external_port, 40000);
    EXPECT_EQ(r->external_address, 0xCB007105u);
    EXPECT_FALSE(pcp::decode_unsupported_version(success_response()));
}

TEST(PcpCodec, DecodesErrorResponses) {
    auto header_only = success_response();
    header_only.resize(pcp::kHeaderLen);
    header_only[3] = 3;
    const auto malformed = pcp::decode_map_response(header_only);
    ASSERT_TRUE(malformed);
    EXPECT_EQ(malformed->result, ResultCode::MalformedRequest);
    EXPECT_EQ(malformed->epoch_sec, 3600u);
    EXPECT_EQ(malformed->internal_port, 0);
    EXPECT_EQ(malformed->external_address, 0u);
    EXPECT_EQ(malformed->nonce, pcp::Nonce{});

    FakeGateway::PcpMapResponse f;
    f.result_code = FakeGateway::kPcpNotAuthorized;
    f.epoch_sec = 10;
    f.mapping_nonce = fixed_nonce();
    f.protocol = 17;
    f.internal_port = 51820;
    const auto denied = pcp::decode_map_response(FakeGateway::encode_pcp_map_response(f));
    ASSERT_TRUE(denied);
    EXPECT_EQ(denied->result, ResultCode::NotAuthorized);
    EXPECT_EQ(denied->nonce, fixed_nonce());
    EXPECT_EQ(denied->internal_port, 51820);
    EXPECT_EQ(denied->external_address, 0u);
    EXPECT_STREQ(pcp::result_code_name(denied->result), "NotAuthorized");
    EXPECT_STREQ(pcp::result_code_name(ResultCode::ExcessiveRemotePeers), "ExcessiveRemotePeers");
    EXPECT_STREQ(pcp::result_code_name(static_cast<ResultCode>(200)), "Unknown");
}

TEST(PcpCodec, DecodesVersionFallback) {
    const auto natpmp_reply = bytes_of({0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10});
    EXPECT_EQ(pcp::decode_unsupported_version(natpmp_reply), 0);
    EXPECT_FALSE(pcp::decode_map_response(natpmp_reply));

    auto future = success_response();
    future[0] = 3;
    future[3] = 1;
    EXPECT_EQ(pcp::decode_unsupported_version(future), 3);

    auto version2 = success_response();
    version2[3] = 1;
    EXPECT_FALSE(pcp::decode_unsupported_version(version2));
    EXPECT_FALSE(pcp::decode_unsupported_version(bytes_of({0x00, 0x00, 0x00})));
    EXPECT_FALSE(pcp::decode_unsupported_version(bytes_of({0x00, 0x80, 0x00, 0x00})));
}

TEST(PcpCodec, RejectsMalformedResponses) {
    auto wrong_version = success_response();
    wrong_version[0] = 1;
    EXPECT_FALSE(pcp::decode_map_response(wrong_version));

    auto no_r_bit = success_response();
    no_r_bit[1] = 0x01;
    EXPECT_FALSE(pcp::decode_map_response(no_r_bit));

    auto wrong_opcode = success_response();
    wrong_opcode[1] = 0x82;
    EXPECT_FALSE(pcp::decode_map_response(wrong_opcode));

    auto short_body = success_response();
    short_body.pop_back();
    EXPECT_FALSE(pcp::decode_map_response(short_body));
    auto short_header = success_response();
    short_header.resize(pcp::kHeaderLen - 1);
    EXPECT_FALSE(pcp::decode_map_response(short_header));
    auto header_only_success = success_response();
    header_only_success.resize(pcp::kHeaderLen);
    EXPECT_FALSE(pcp::decode_map_response(header_only_success));
    auto too_long = success_response();
    too_long.push_back(0);
    EXPECT_FALSE(pcp::decode_map_response(too_long));

    auto ipv6_address = success_response();
    ipv6_address[44] = 0x20;
    ipv6_address[45] = 0x01;
    EXPECT_FALSE(pcp::decode_map_response(ipv6_address));
    auto no_address = success_response();
    no_address[54] = 0;
    no_address[55] = 0;
    EXPECT_FALSE(pcp::decode_map_response(no_address));
}

TEST(PcpCodec, EpochRestartDetection) {
    EXPECT_FALSE(pcp::epoch_indicates_restart(1000, 50000, 1600, 50600));
    EXPECT_FALSE(pcp::epoch_indicates_restart(1000, 50000, 1000, 50000));
    EXPECT_FALSE(pcp::epoch_indicates_restart(1000, 50000, 1570, 50600));
    EXPECT_FALSE(pcp::epoch_indicates_restart(1000, 50000, 1630, 50600));
    EXPECT_TRUE(pcp::epoch_indicates_restart(1000, 50000, 5, 50600));
    EXPECT_TRUE(pcp::epoch_indicates_restart(1000, 50000, 900, 50010));
    EXPECT_TRUE(pcp::epoch_indicates_restart(1000, 50000, 1500, 50600));
    EXPECT_TRUE(pcp::epoch_indicates_restart(1000, 50000, 1700, 50600));
    EXPECT_FALSE(pcp::epoch_indicates_restart(1000, 50000, 1000, 49000));
}

class PcpClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_NE(fake_.port(), 0);
        fake_.pcp_enabled = true;
    }

    pcp::PcpClient client() { return pcp::PcpClient("127.0.0.1", "127.0.0.1", fake_.port()); }

    FakeGateway fake_;
};

TEST_F(PcpClientTest, MapUdpTakesSuggestedPortAndEchoesNonce) {
    auto c = client();
    const auto r = c.map_udp(51940, 51940, 7200);
    ASSERT_TRUE(r) << r.error;
    EXPECT_EQ(r.value.result, ResultCode::Success);
    EXPECT_EQ(r.value.internal_port, 51940);
    EXPECT_EQ(r.value.external_port, 51940);
    EXPECT_EQ(r.value.external_address, 0xCB007105u);
    EXPECT_EQ(r.value.lifetime_sec, 7200u);
    EXPECT_EQ(r.value.protocol, 17);
    ASSERT_TRUE(c.nonce());
    EXPECT_EQ(r.value.nonce, *c.nonce());
    EXPECT_NE(r.value.nonce, pcp::Nonce{});
    EXPECT_EQ(c.last_result_code(), ResultCode::Success);
    EXPECT_FALSE(c.unsupported_version());
    EXPECT_EQ(fake_.mapped_external_port(51940), 51940);

    const auto log = fake_.requests();
    ASSERT_EQ(log.size(), 1u);
    EXPECT_EQ(log[0].protocol, 2);
    EXPECT_EQ(log[0].opcode, 1);
    EXPECT_EQ(log[0].internal_port, 51940);
    EXPECT_EQ(log[0].suggested_port, 51940);
    EXPECT_EQ(log[0].lifetime_sec, 7200u);
    EXPECT_EQ(log[0].nonce, *c.nonce());
}

TEST_F(PcpClientTest, FreshNoncePerMapping) {
    auto c = client();
    ASSERT_TRUE(c.map_udp(5000, 0, 7200));
    const auto first = *c.nonce();
    ASSERT_TRUE(c.map_udp(5001, 0, 7200));
    EXPECT_NE(*c.nonce(), first);
    pcp::PcpClient other("127.0.0.1", "127.0.0.1", fake_.port());
    ASSERT_TRUE(other.map_udp(5002, 0, 7200));
    EXPECT_NE(*other.nonce(), *c.nonce());
}

TEST_F(PcpClientTest, RenewKeepsPortAndNonce) {
    auto c = client();
    const auto first = c.map_udp(5000, 0, 7200);
    ASSERT_TRUE(first) << first.error;
    const auto nonce = *c.nonce();
    const auto renewed = c.renew_udp(3600);
    ASSERT_TRUE(renewed) << renewed.error;
    EXPECT_EQ(renewed.value.external_port, first.value.external_port);
    EXPECT_EQ(renewed.value.nonce, nonce);
    EXPECT_EQ(renewed.value.lifetime_sec, 3600u);
    const auto again = c.map_udp(5000, 0, 7200);
    ASSERT_TRUE(again) << again.error;
    EXPECT_EQ(again.value.external_port, first.value.external_port);
    EXPECT_EQ(*c.nonce(), nonce);

    const auto log = fake_.requests();
    ASSERT_EQ(log.size(), 3u);
    EXPECT_EQ(log[1].nonce, nonce);
    EXPECT_EQ(log[1].suggested_port, first.value.external_port);
    EXPECT_EQ(log[2].nonce, nonce);
}

TEST_F(PcpClientTest, RenewWithoutMappingFailsWithoutSending) {
    auto c = client();
    EXPECT_FALSE(c.renew_udp(3600));
    EXPECT_FALSE(c.release_udp(5000));
    EXPECT_TRUE(fake_.requests().empty());
}

TEST_F(PcpClientTest, ReleaseSendsLifetimeZeroWithSameNonce) {
    auto c = client();
    ASSERT_TRUE(c.map_udp(5000, 0, 7200));
    const auto nonce = *c.nonce();
    ASSERT_TRUE(fake_.mapped_external_port(5000));
    const auto r = c.release_udp(5000);
    ASSERT_TRUE(r) << r.error;
    EXPECT_FALSE(fake_.mapped_external_port(5000));
    EXPECT_FALSE(c.nonce());
    EXPECT_EQ(c.last_result_code(), ResultCode::Success);

    const auto log = fake_.requests();
    ASSERT_EQ(log.size(), 2u);
    EXPECT_EQ(log[1].protocol, 2);
    EXPECT_EQ(log[1].opcode, 1);
    EXPECT_EQ(log[1].internal_port, 5000);
    EXPECT_EQ(log[1].suggested_port, 0);
    EXPECT_EQ(log[1].lifetime_sec, 0u);
    EXPECT_EQ(log[1].nonce, nonce);
}

TEST_F(PcpClientTest, ReplyWithDifferentNonceIsIgnored) {
    auto c = client();
    ASSERT_TRUE(c.map_udp(5000, 0, 7200));
    fake_.pcp_wrong_nonce = true;
    const auto start = std::chrono::steady_clock::now();
    const auto r = c.renew_udp(3600);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_FALSE(r);
    EXPECT_NE(r.error.find("did not answer"), std::string::npos) << r.error;
    EXPECT_GE(elapsed, std::chrono::milliseconds(2000));
    EXPECT_LT(elapsed, std::chrono::milliseconds(3500));
    EXPECT_EQ(fake_.requests().size(), 3u);
    EXPECT_EQ(c.last_result_code(), ResultCode::Success);
}

TEST_F(PcpClientTest, NotAuthorizedResultIsReported) {
    fake_.pcp_result = FakeGateway::kPcpNotAuthorized;
    auto c = client();
    const auto r = c.map_udp(5000, 0, 7200);
    EXPECT_FALSE(r);
    EXPECT_EQ(c.last_result_code(), ResultCode::NotAuthorized);
    EXPECT_NE(r.error.find("NotAuthorized"), std::string::npos) << r.error;
    EXPECT_FALSE(c.unsupported_version());
    EXPECT_EQ(fake_.requests().size(), 1u);
}

TEST_F(PcpClientTest, NatPmpOnlyGatewaySetsUnsupportedVersion) {
    fake_.pcp_enabled = false;
    auto c = client();
    const auto start = std::chrono::steady_clock::now();
    const auto r = c.map_udp(5000, 0, 7200);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_FALSE(r);
    EXPECT_LT(elapsed, std::chrono::milliseconds(900));
    ASSERT_TRUE(c.unsupported_version());
    EXPECT_EQ(*c.unsupported_version(), 0);
    EXPECT_EQ(c.last_result_code(), ResultCode::UnsuppVersion);
    EXPECT_NE(r.error.find("NAT-PMP"), std::string::npos) << r.error;
    EXPECT_EQ(fake_.requests().size(), 1u);
}

TEST_F(PcpClientTest, DroppedRequestsFailWithinFirstAttemptBudget) {
    fake_.drop_requests = true;
    auto c = client();
    const auto start = std::chrono::steady_clock::now();
    const auto r = c.map_udp(5000, 0, 7200);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_FALSE(r);
    EXPECT_FALSE(c.last_result_code());
    EXPECT_GE(elapsed, std::chrono::milliseconds(6500));
    EXPECT_LT(elapsed, std::chrono::milliseconds(8000));
    EXPECT_EQ(fake_.requests().size(), 3u);
}

TEST_F(PcpClientTest, RejectsBadArgumentsWithoutSending) {
    auto c = client();
    EXPECT_FALSE(c.map_udp(0, 0, 7200));
    EXPECT_FALSE(c.map_udp(5000, 0, 0));
    EXPECT_FALSE(c.release_udp(0));
    pcp::PcpClient bad_gateway("not-an-address", "127.0.0.1", fake_.port());
    EXPECT_FALSE(bad_gateway.map_udp(5000, 0, 7200));
    pcp::PcpClient bad_local("127.0.0.1", "nope", fake_.port());
    EXPECT_FALSE(bad_local.map_udp(5000, 0, 7200));
    EXPECT_TRUE(fake_.requests().empty());
}

TEST_F(PcpClientTest, EpochTracksGatewayRestart) {
    fake_.advance_epoch(1000);
    auto c = client();
    ASSERT_TRUE(c.map_udp(5000, 0, 7200));
    const uint32_t before = c.last_epoch_sec();
    const int64_t t0 = now_unix();
    EXPECT_GE(before, 1000u);

    ASSERT_TRUE(c.renew_udp(7200));
    EXPECT_FALSE(pcp::epoch_indicates_restart(before, t0, c.last_epoch_sec(), now_unix()));

    fake_.restart();
    EXPECT_FALSE(fake_.mapped_external_port(5000));
    ASSERT_TRUE(c.renew_udp(7200));
    EXPECT_LT(c.last_epoch_sec(), 5u);
    EXPECT_TRUE(pcp::epoch_indicates_restart(before, t0, c.last_epoch_sec(), now_unix()));
    EXPECT_TRUE(fake_.mapped_external_port(5000));
}
