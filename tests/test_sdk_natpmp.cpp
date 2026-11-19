// The NAT-PMP client asks the default gateway for a public UDP port, so a
// device behind a home NAT becomes dialable by a peer behind a symmetric
// NAT. The codec is checked byte for byte against RFC 6886; the client is
// checked against the fake gateway in tests/support.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/NatPmp.hpp>

#include "support/FakeGateway.hpp"

#include <chrono>
#include <cstdint>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace natpmp = lnsdk::natpmp;
using natpmp::ResultCode;
using test_support::FakeGateway;

namespace {

std::vector<uint8_t> bytes_of(std::initializer_list<int> values) {
    std::vector<uint8_t> out;
    for (int v : values) out.push_back(static_cast<uint8_t>(v));
    return out;
}

const std::vector<uint8_t> kExternalAddressOk =
    bytes_of({0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x10, 0xCB, 0x00, 0x71, 0x05});
const std::vector<uint8_t> kMappingOk =
    bytes_of({0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x10, 0xCA, 0x6C, 0x9C, 0x40, 0x00,
              0x00, 0x1C, 0x20});

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

TEST(NatPmpCodec, EncodesRequestsByteExact) {
    EXPECT_EQ(natpmp::encode_external_address_request(), bytes_of({0x00, 0x00}));
    EXPECT_EQ(natpmp::encode_udp_map_request(51820, 51820, 7200),
              bytes_of({0x00, 0x01, 0x00, 0x00, 0xCA, 0x6C, 0xCA, 0x6C, 0x00, 0x00, 0x1C, 0x20}));
    EXPECT_EQ(natpmp::encode_udp_map_request(51820, 0, 0),
              bytes_of({0x00, 0x01, 0x00, 0x00, 0xCA, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
}

TEST(NatPmpCodec, DecodesSuccessResponses) {
    const auto addr = natpmp::decode_external_address(kExternalAddressOk);
    ASSERT_TRUE(addr);
    EXPECT_EQ(addr->epoch_sec, 3600u);
    EXPECT_EQ(addr->address, 0xCB007105u);

    const auto map = natpmp::decode_udp_mapping(kMappingOk);
    ASSERT_TRUE(map);
    EXPECT_EQ(map->epoch_sec, 3600u);
    EXPECT_EQ(map->internal_port, 51820);
    EXPECT_EQ(map->external_port, 40000);
    EXPECT_EQ(map->lifetime_sec, 7200u);
}

TEST(NatPmpCodec, RejectsMalformedResponses) {
    auto short_addr = kExternalAddressOk;
    short_addr.pop_back();
    EXPECT_FALSE(natpmp::decode_external_address(short_addr));
    auto long_map = kMappingOk;
    long_map.push_back(0);
    EXPECT_FALSE(natpmp::decode_udp_mapping(long_map));
    EXPECT_FALSE(natpmp::decode_result_code(bytes_of({0x00, 0x80, 0x00})));

    auto wrong_version = kMappingOk;
    wrong_version[0] = 1;
    EXPECT_FALSE(natpmp::decode_udp_mapping(wrong_version));
    EXPECT_FALSE(natpmp::decode_result_code(wrong_version));

    auto wrong_opcode = kMappingOk;
    wrong_opcode[1] = 0x82;
    EXPECT_FALSE(natpmp::decode_udp_mapping(wrong_opcode));
    auto request_opcode = kExternalAddressOk;
    request_opcode[1] = 0x00;
    EXPECT_FALSE(natpmp::decode_external_address(request_opcode));

    auto not_authorized = kMappingOk;
    not_authorized[3] = 0x02;
    EXPECT_FALSE(natpmp::decode_udp_mapping(not_authorized));
    EXPECT_EQ(natpmp::decode_result_code(not_authorized), ResultCode::NotAuthorized);
    EXPECT_EQ(natpmp::decode_result_code(bytes_of({0x00, 0x00, 0x00, 0x01, 0, 0, 0, 9})),
              ResultCode::UnsupportedVersion);
    EXPECT_EQ(natpmp::decode_result_code(kMappingOk), ResultCode::Success);
    EXPECT_STREQ(natpmp::result_code_name(ResultCode::OutOfResources), "OutOfResources");
}

TEST(NatPmpCodec, EpochRestartDetection) {
    EXPECT_FALSE(natpmp::epoch_indicates_restart(1000, 50000, 1600, 50600));
    EXPECT_FALSE(natpmp::epoch_indicates_restart(1000, 50000, 1000, 50000));
    EXPECT_FALSE(natpmp::epoch_indicates_restart(1000, 50000, 1523, 50600));
    EXPECT_TRUE(natpmp::epoch_indicates_restart(1000, 50000, 5, 50600));
    EXPECT_TRUE(natpmp::epoch_indicates_restart(1000, 50000, 900, 50010));
    EXPECT_FALSE(natpmp::epoch_indicates_restart(1000, 50000, 1000, 49000));
}

class NatPmpClientTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_NE(fake_.port(), 0); }

    natpmp::NatPmpClient client() { return natpmp::NatPmpClient("127.0.0.1", fake_.port()); }

    FakeGateway fake_;
};

TEST_F(NatPmpClientTest, ExternalAddress) {
    auto c = client();
    const auto r = c.external_address();
    ASSERT_TRUE(r) << r.error;
    EXPECT_EQ(r.value.address, 0xCB007105u);
    EXPECT_EQ(c.last_result_code(), ResultCode::Success);
    const auto log = fake_.requests();
    ASSERT_EQ(log.size(), 1u);
    EXPECT_EQ(log[0].protocol, 0);
    EXPECT_EQ(log[0].opcode, 0);
}

TEST_F(NatPmpClientTest, MapUdpTakesSuggestedPortWhenFree) {
    auto c = client();
    const auto r = c.map_udp(51940, 51940, 7200);
    ASSERT_TRUE(r) << r.error;
    EXPECT_EQ(r.value.internal_port, 51940);
    EXPECT_EQ(r.value.external_port, 51940);
    EXPECT_EQ(r.value.lifetime_sec, 7200u);
    EXPECT_EQ(fake_.mapped_external_port(51940), 51940);

    const auto log = fake_.requests();
    ASSERT_EQ(log.size(), 1u);
    EXPECT_EQ(log[0].opcode, 1);
    EXPECT_EQ(log[0].internal_port, 51940);
    EXPECT_EQ(log[0].suggested_port, 51940);
    EXPECT_EQ(log[0].lifetime_sec, 7200u);
}

TEST_F(NatPmpClientTest, MapUdpGetsAnotherPortWhenSuggestedTaken) {
    auto c = client();
    const auto first = c.map_udp(5000, 51940, 7200);
    ASSERT_TRUE(first) << first.error;
    const auto second = c.map_udp(5001, 51940, 7200);
    ASSERT_TRUE(second) << second.error;
    EXPECT_EQ(first.value.external_port, 51940);
    EXPECT_EQ(second.value.external_port, 40000);
    EXPECT_NE(first.value.external_port, second.value.external_port);
}

TEST_F(NatPmpClientTest, LifetimeIsCutToGatewayMaximum) {
    fake_.max_lifetime_sec = 600;
    auto c = client();
    const auto r = c.map_udp(5000, 0, 7200);
    ASSERT_TRUE(r) << r.error;
    EXPECT_EQ(r.value.lifetime_sec, 600u);
    EXPECT_EQ(r.value.external_port, 40000);
}

TEST_F(NatPmpClientTest, RenewalKeepsExternalPort) {
    auto c = client();
    const auto first = c.map_udp(5000, 0, 7200);
    ASSERT_TRUE(first) << first.error;
    const auto renewed = c.map_udp(5000, 12345, 3600);
    ASSERT_TRUE(renewed) << renewed.error;
    EXPECT_EQ(renewed.value.external_port, first.value.external_port);
    EXPECT_EQ(renewed.value.lifetime_sec, 3600u);
}

TEST_F(NatPmpClientTest, ReleaseSendsZeroLifetimeAndRemovesMapping) {
    auto c = client();
    ASSERT_TRUE(c.map_udp(5000, 0, 7200));
    ASSERT_TRUE(fake_.mapped_external_port(5000));
    const auto r = c.release_udp(5000);
    ASSERT_TRUE(r) << r.error;
    EXPECT_FALSE(fake_.mapped_external_port(5000));
    const auto log = fake_.requests();
    ASSERT_EQ(log.size(), 2u);
    EXPECT_EQ(log[1].internal_port, 5000);
    EXPECT_EQ(log[1].suggested_port, 0);
    EXPECT_EQ(log[1].lifetime_sec, 0u);
}

TEST_F(NatPmpClientTest, RejectsInvalidArgumentsBeforeSending) {
    auto c = client();
    EXPECT_FALSE(c.map_udp(0, 0, 7200));
    EXPECT_FALSE(c.map_udp(5000, 0, 0));
    EXPECT_FALSE(c.release_udp(0));
    EXPECT_TRUE(fake_.requests().empty());
    natpmp::NatPmpClient bad("not-an-address", fake_.port());
    EXPECT_FALSE(bad.external_address());
}

TEST_F(NatPmpClientTest, ErrorResultIsReported) {
    fake_.natpmp_result = FakeGateway::kNatPmpUnsupportedVersion;
    auto c = client();
    const auto r = c.map_udp(5000, 0, 7200);
    EXPECT_FALSE(r);
    EXPECT_NE(r.error.find("UnsupportedVersion"), std::string::npos) << r.error;
    EXPECT_EQ(c.last_result_code(), ResultCode::UnsupportedVersion);
    EXPECT_FALSE(fake_.mapped_external_port(5000));

    fake_.natpmp_result = FakeGateway::kNatPmpNotAuthorized;
    EXPECT_FALSE(c.external_address());
    EXPECT_EQ(c.last_result_code(), ResultCode::NotAuthorized);
}

TEST_F(NatPmpClientTest, DroppedRequestsFailWithinBudget) {
    fake_.drop_requests = true;
    auto c = client();
    const auto start = std::chrono::steady_clock::now();
    const auto r = c.map_udp(5000, 0, 7200);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_FALSE(r);
    EXPECT_FALSE(c.last_result_code());
    EXPECT_LT(elapsed, std::chrono::milliseconds(4500));
    EXPECT_GE(elapsed, std::chrono::milliseconds(3500));
    EXPECT_EQ(fake_.requests().size(), 4u);
}

TEST_F(NatPmpClientTest, DisabledNatPmpDoesNotAnswer) {
    fake_.natpmp_enabled = false;
    auto c = client();
    EXPECT_FALSE(c.external_address());
    EXPECT_FALSE(c.last_result_code());
}

TEST_F(NatPmpClientTest, EpochTracksGatewayRestart) {
    fake_.advance_epoch(1000);
    auto c = client();
    ASSERT_TRUE(c.external_address());
    const uint32_t before = c.last_epoch_sec();
    const int64_t t0 = now_unix();
    EXPECT_GE(before, 1000u);

    ASSERT_TRUE(c.external_address());
    EXPECT_FALSE(natpmp::epoch_indicates_restart(before, t0, c.last_epoch_sec(), now_unix()));

    fake_.restart();
    ASSERT_TRUE(c.external_address());
    EXPECT_LT(c.last_epoch_sec(), 5u);
    EXPECT_TRUE(natpmp::epoch_indicates_restart(before, t0, c.last_epoch_sec(), now_unix()));
}

TEST_F(NatPmpClientTest, RestartForgetsMappings) {
    auto c = client();
    ASSERT_TRUE(c.map_udp(5000, 0, 7200));
    fake_.restart();
    EXPECT_FALSE(fake_.mapped_external_port(5000));
}

TEST(FakeGatewayHarness, PcpRequestGetsNatPmpUnsupportedVersionWhenPcpDisabled) {
    FakeGateway fake;
    ASSERT_NE(fake.port(), 0);
    ASSERT_FALSE(fake.pcp_enabled);

    // A PCP MAP request: version 2, opcode 1, lifetime 7200, client address,
    // nonce, protocol UDP, internal port 51940, suggested 51940, address.
    std::vector<uint8_t> request(FakeGateway::kPcpMapRequestLen, 0);
    request[0] = 2;
    request[1] = 1;
    request[7] = 0x20;
    request[6] = 0x1C;
    for (size_t i = 0; i < 12; ++i) request[24 + i] = static_cast<uint8_t>(0xA0 + i);
    request[36] = 17;
    request[40] = 0xCA;
    request[41] = 0xE4;
    request[42] = 0xCA;
    request[43] = 0xE4;

    // The NAT-PMP client is not a PCP speaker, so exchange raw datagrams
    // through a plain socket.
    std::vector<uint8_t> reply;
    {
#ifdef _WIN32
        auto sock = ::socket(AF_INET, SOCK_DGRAM, 0);
#else
        int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
#endif
        ASSERT_GE(static_cast<long long>(sock), 0);
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = htons(fake.port());
        inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
        timeval tv{};
        tv.tv_sec = 2;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        ASSERT_GT(sendto(sock, reinterpret_cast<const char*>(request.data()),
                         static_cast<int>(request.size()), 0,
                         reinterpret_cast<const sockaddr*>(&to), sizeof(to)),
                  0);
        reply.resize(128);
        const auto n = recv(sock, reinterpret_cast<char*>(reply.data()),
                            static_cast<int>(reply.size()), 0);
        ASSERT_GT(n, 0);
        reply.resize(static_cast<size_t>(n));
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }
    ASSERT_EQ(reply.size(), 8u);
    EXPECT_EQ(reply[0], 0);
    EXPECT_EQ(reply[1], 0);
    EXPECT_EQ(natpmp::decode_result_code(reply), ResultCode::UnsupportedVersion);

    const auto log = fake.requests();
    ASSERT_EQ(log.size(), 1u);
    EXPECT_EQ(log[0].protocol, 2);
    EXPECT_EQ(log[0].opcode, 1);
    EXPECT_EQ(log[0].internal_port, 51940);
    EXPECT_EQ(log[0].suggested_port, 51940);
    EXPECT_EQ(log[0].lifetime_sec, 7200u);
    EXPECT_EQ(log[0].nonce[0], 0xA0);
    EXPECT_EQ(log[0].nonce[11], 0xAB);
}

TEST(FakeGatewayHarness, PcpMapResponseLayout) {
    FakeGateway::PcpMapResponse f;
    f.result_code = FakeGateway::kPcpSuccess;
    f.lifetime_sec = 7200;
    f.epoch_sec = 3600;
    for (size_t i = 0; i < 12; ++i) f.mapping_nonce[i] = static_cast<uint8_t>(0xA0 + i);
    f.protocol = 17;
    f.internal_port = 51940;
    f.assigned_external_port = 40000;
    f.assigned_external_address = FakeGateway::ipv4_mapped("203.0.113.5");
    const auto pkt = FakeGateway::encode_pcp_map_response(f);
    ASSERT_EQ(pkt.size(), 60u);
    EXPECT_EQ(pkt[0], 2);
    EXPECT_EQ(pkt[1], 0x81);
    EXPECT_EQ(pkt[2], 0);
    EXPECT_EQ(pkt[3], 0);
    EXPECT_EQ((bytes_of({pkt[4], pkt[5], pkt[6], pkt[7]})), bytes_of({0, 0, 0x1C, 0x20}));
    EXPECT_EQ((bytes_of({pkt[8], pkt[9], pkt[10], pkt[11]})), bytes_of({0, 0, 0x0E, 0x10}));
    for (size_t i = 12; i < 24; ++i) EXPECT_EQ(pkt[i], 0) << i;
    for (size_t i = 0; i < 12; ++i) EXPECT_EQ(pkt[24 + i], 0xA0 + i) << i;
    EXPECT_EQ(pkt[36], 17);
    EXPECT_EQ((bytes_of({pkt[40], pkt[41]})), bytes_of({0xCA, 0xE4}));
    EXPECT_EQ((bytes_of({pkt[42], pkt[43]})), bytes_of({0x9C, 0x40}));
    const std::vector<uint8_t> mapped(pkt.begin() + 44, pkt.end());
    EXPECT_EQ(mapped, bytes_of({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 203, 0, 113, 5}));
}
