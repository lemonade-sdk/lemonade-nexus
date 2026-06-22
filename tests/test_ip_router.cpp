#include <gtest/gtest.h>

#include <LemonadeNexus/WireGuard/IpRouter.hpp>

#include <memory>

using nexus::wireguard::Cidr;
using nexus::wireguard::IpRouter;

using Peer   = std::shared_ptr<std::string>;
using Router = IpRouter<Peer>;

namespace {
uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | d;
}
} // namespace

TEST(Cidr, ParsesPrefixesAndBareAddresses) {
    auto c = Cidr::parse("10.64.0.0/10");
    ASSERT_TRUE(c);
    EXPECT_EQ(c->network, ip(10, 64, 0, 0));
    EXPECT_EQ(c->prefix_len, 10);
    EXPECT_TRUE(c->contains(ip(10, 100, 3, 4)));
    EXPECT_FALSE(c->contains(ip(10, 0, 0, 1)));

    auto bare = Cidr::parse("172.16.0.7");
    ASSERT_TRUE(bare);
    EXPECT_EQ(bare->prefix_len, 32);
    EXPECT_TRUE(bare->contains(ip(172, 16, 0, 7)));
    EXPECT_FALSE(bare->contains(ip(172, 16, 0, 8)));

    auto zero = Cidr::parse("0.0.0.0/0");
    ASSERT_TRUE(zero);
    EXPECT_TRUE(zero->contains(ip(8, 8, 8, 8)));
}

TEST(Cidr, RejectsGarbage) {
    EXPECT_FALSE(Cidr::parse(""));
    EXPECT_FALSE(Cidr::parse("10.64.0/24"));
    EXPECT_FALSE(Cidr::parse("10.64.0.0.1/24"));
    EXPECT_FALSE(Cidr::parse("10.64.0.256/24"));
    EXPECT_FALSE(Cidr::parse("10.64.0.0/33"));
    EXPECT_FALSE(Cidr::parse("10.64.0.0/-1"));
    EXPECT_FALSE(Cidr::parse("banana"));
    EXPECT_FALSE(Cidr::parse("10.64.0.0/banana"));
}

TEST(Cidr, ParsesCommaSeparatedListSkippingInvalid) {
    auto list = Cidr::parse_list("10.64.4.210/32, 10.128.17.4/30, banana, 172.16.0.9/32");
    ASSERT_EQ(list.size(), 3u);
    EXPECT_EQ(list[0].prefix_len, 32);
    EXPECT_EQ(list[1].prefix_len, 30);
    EXPECT_EQ(list[2].network, ip(172, 16, 0, 9));
}

TEST(IpRouterTest, HostRouteHit) {
    Router router;
    auto peer = std::make_shared<std::string>("client-a");
    router.add_routes(Cidr::parse_list("10.64.0.2/32"), peer);

    auto r = router.lookup(ip(10, 64, 0, 2));
    EXPECT_EQ(r.verdict, Router::Verdict::Peer);
    EXPECT_EQ(r.peer, peer);

    EXPECT_EQ(router.lookup(ip(10, 64, 0, 3)).verdict, Router::Verdict::Drop);
}

TEST(IpRouterTest, LongestPrefixMatchAcrossCidrRoutes) {
    Router router;
    auto wide   = std::make_shared<std::string>("wide");
    auto narrow = std::make_shared<std::string>("narrow");
    router.add_routes(Cidr::parse_list("10.128.0.0/9"), wide);
    router.add_routes(Cidr::parse_list("10.128.17.4/30"), narrow);

    EXPECT_EQ(router.lookup(ip(10, 128, 17, 5)).peer, narrow);
    EXPECT_EQ(router.lookup(ip(10, 128, 99, 1)).peer, wide);
}

TEST(IpRouterTest, HostRouteBeatsCidrRoute) {
    Router router;
    auto subnet_peer = std::make_shared<std::string>("subnet");
    auto host_peer   = std::make_shared<std::string>("host");
    router.add_routes(Cidr::parse_list("10.128.17.4/30"), subnet_peer);
    router.add_routes(Cidr::parse_list("10.128.17.5/32"), host_peer);

    EXPECT_EQ(router.lookup(ip(10, 128, 17, 5)).peer, host_peer);
    EXPECT_EQ(router.lookup(ip(10, 128, 17, 6)).peer, subnet_peer);
}

TEST(IpRouterTest, LocalIpTakesPrecedenceOverRoutes) {
    Router router;
    auto peer = std::make_shared<std::string>("peer");
    router.add_routes(Cidr::parse_list("10.64.0.0/10"), peer);
    router.add_local_ip(ip(10, 64, 0, 1));

    EXPECT_EQ(router.lookup(ip(10, 64, 0, 1)).verdict, Router::Verdict::Local);
    EXPECT_EQ(router.lookup(ip(10, 64, 0, 2)).verdict, Router::Verdict::Peer);

    router.remove_local_ip(ip(10, 64, 0, 1));
    EXPECT_EQ(router.lookup(ip(10, 64, 0, 1)).verdict, Router::Verdict::Peer);
}

TEST(IpRouterTest, RemoveRoutesForPeer) {
    Router router;
    auto a = std::make_shared<std::string>("a");
    auto b = std::make_shared<std::string>("b");
    router.add_routes(Cidr::parse_list("10.64.0.2/32, 10.128.17.4/30"), a);
    router.add_routes(Cidr::parse_list("10.64.0.3/32"), b);
    EXPECT_EQ(router.route_count(), 3u);

    router.remove_routes_for(a);
    EXPECT_EQ(router.route_count(), 1u);
    EXPECT_EQ(router.lookup(ip(10, 64, 0, 2)).verdict, Router::Verdict::Drop);
    EXPECT_EQ(router.lookup(ip(10, 128, 17, 5)).verdict, Router::Verdict::Drop);
    EXPECT_EQ(router.lookup(ip(10, 64, 0, 3)).peer, b);
}

TEST(IpRouterTest, ReAddingSamePrefixReplacesRoute) {
    Router router;
    auto old_peer = std::make_shared<std::string>("old");
    auto new_peer = std::make_shared<std::string>("new");
    router.add_routes(Cidr::parse_list("10.128.17.4/30"), old_peer);
    router.add_routes(Cidr::parse_list("10.128.17.4/30"), new_peer);

    EXPECT_EQ(router.route_count(), 1u);
    EXPECT_EQ(router.lookup(ip(10, 128, 17, 5)).peer, new_peer);
}
