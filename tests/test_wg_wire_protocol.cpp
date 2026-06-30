#include <gtest/gtest.h>

#include <LemonadeNexus/Boringtun/WireProtocol.hpp>

#include <vector>

using namespace nexus::boringtun::wire;

namespace {

std::vector<uint8_t> make_packet(uint32_t type_le, size_t total_size) {
    std::vector<uint8_t> pkt(total_size, 0);
    for (size_t i = 0; i < 4 && i < total_size; ++i)
        pkt[i] = static_cast<uint8_t>((type_le >> (8 * i)) & 0xFF);
    return pkt;
}

void write_le32(std::vector<uint8_t>& pkt, size_t offset, uint32_t v) {
    pkt[offset]     = static_cast<uint8_t>(v & 0xFF);
    pkt[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    pkt[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    pkt[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

} // namespace

TEST(WgWireProtocol, ParsesAllMessageTypes) {
    EXPECT_EQ(parse_type(make_packet(1, kHandshakeInitSize)), MsgType::HandshakeInit);
    EXPECT_EQ(parse_type(make_packet(2, kHandshakeResponseSize)), MsgType::HandshakeResponse);
    EXPECT_EQ(parse_type(make_packet(3, kCookieReplySize)), MsgType::CookieReply);
    EXPECT_EQ(parse_type(make_packet(4, kTransportDataMinSize)), MsgType::TransportData);
    EXPECT_EQ(parse_type(make_packet(4, 1500)), MsgType::TransportData);
}

TEST(WgWireProtocol, RejectsMalformedPackets) {
    // Too short for any type.
    EXPECT_FALSE(parse_type(make_packet(4, 3)).has_value());
    // Wrong size for fixed-size types.
    EXPECT_FALSE(parse_type(make_packet(1, kHandshakeInitSize - 1)).has_value());
    EXPECT_FALSE(parse_type(make_packet(2, kHandshakeResponseSize + 1)).has_value());
    EXPECT_FALSE(parse_type(make_packet(3, 10)).has_value());
    // Transport data below minimum.
    EXPECT_FALSE(parse_type(make_packet(4, kTransportDataMinSize - 1)).has_value());
    // Unknown type / non-zero reserved bytes.
    EXPECT_FALSE(parse_type(make_packet(5, 148)).has_value());
    EXPECT_FALSE(parse_type(make_packet(0, 148)).has_value());
    auto reserved = make_packet(4, 64);
    reserved[2] = 0xAB;  // reserved bytes must be zero
    EXPECT_FALSE(parse_type(reserved).has_value());
}

TEST(WgWireProtocol, ExtractsReceiverIndexPerType) {
    const uint32_t idx = (1234u << 8) | 7u;

    auto resp = make_packet(2, kHandshakeResponseSize);
    write_le32(resp, 8, idx);
    ASSERT_EQ(receiver_index(resp), idx);

    auto cookie = make_packet(3, kCookieReplySize);
    write_le32(cookie, 4, idx);
    ASSERT_EQ(receiver_index(cookie), idx);

    auto data = make_packet(4, 96);
    write_le32(data, 4, idx);
    ASSERT_EQ(receiver_index(data), idx);

    // Handshake initiations carry only the sender's index — no receiver index.
    auto init = make_packet(1, kHandshakeInitSize);
    EXPECT_FALSE(receiver_index(init).has_value());

    EXPECT_EQ(peer_index(idx), 1234u);
}

TEST(WgWireProtocol, Ipv4HeaderParsing) {
    std::vector<uint8_t> pkt(20, 0);
    pkt[0] = 0x45;  // IPv4, IHL 5
    // src 10.64.0.2, dst 172.16.0.7
    pkt[12] = 10; pkt[13] = 64; pkt[14] = 0; pkt[15] = 2;
    pkt[16] = 172; pkt[17] = 16; pkt[18] = 0; pkt[19] = 7;

    EXPECT_TRUE(ipv4::is_ipv4(pkt));
    EXPECT_EQ(ipv4::src_addr(pkt), 0x0A400002u);
    EXPECT_EQ(ipv4::dst_addr(pkt), 0xAC100007u);

    pkt[0] = 0x65;  // IPv6 version nibble
    EXPECT_FALSE(ipv4::is_ipv4(pkt));
    EXPECT_FALSE(ipv4::dst_addr(pkt).has_value());

    std::vector<uint8_t> runt(10, 0x45);
    EXPECT_FALSE(ipv4::is_ipv4(runt));
}
