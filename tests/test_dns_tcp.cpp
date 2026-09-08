#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;

namespace {

constexpr const char* kZone = "test.local";
constexpr const char* kName = "node.test.local";
constexpr const char* kAddr = "10.64.0.7";
constexpr const char* kBigName = "big.test.local";
constexpr uint16_t kTypeTxt = 16;

std::vector<uint8_t> make_query(const std::string& name, uint16_t id = 0x1234,
                                uint16_t qtype = 1 /* A */) {
    std::vector<uint8_t> q{static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id & 0xFF),
                           0x01, 0x00,    // standard query, RD
                           0x00, 0x01,    // QDCOUNT
                           0x00, 0x00,    // ANCOUNT
                           0x00, 0x00,    // NSCOUNT
                           0x00, 0x00};   // ARCOUNT
    std::size_t start = 0;
    while (true) {
        const auto dot = name.find('.', start);
        const auto end = (dot == std::string::npos) ? name.size() : dot;
        q.push_back(static_cast<uint8_t>(end - start));
        for (std::size_t i = start; i < end; ++i) q.push_back(static_cast<uint8_t>(name[i]));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    q.push_back(0x00);                    // root label
    q.push_back(static_cast<uint8_t>(qtype >> 8));
    q.push_back(static_cast<uint8_t>(qtype & 0xFF));
    q.push_back(0x00); q.push_back(0x01); // QCLASS IN
    return q;
}

std::vector<uint8_t> frame(const std::vector<uint8_t>& payload, std::size_t declared) {
    std::vector<uint8_t> out{static_cast<uint8_t>((declared >> 8) & 0xFF),
                             static_cast<uint8_t>(declared & 0xFF)};
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

class DnsTcpTest : public ::testing::Test {
protected:
    void SetUp() override {
        spdlog::set_level(spdlog::level::warn);
        crypto_.start();
        dir_ = fs::temp_directory_path() /
               ("nexus_dns_tcp_" + std::to_string(getpid()) + "_" +
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(dir_);
        fs::create_directories(dir_);
        storage_.emplace(dir_);
        storage_->start();
        tree_.emplace(*storage_, crypto_);
        tree_->start();

        for (int attempt = 0; attempt < 8 && !dns_; ++attempt) {
            dns_ = std::make_unique<network::DnsService>(io_, 0, *tree_, kZone);
            dns_->start();
            if (!dns_->tcp_listening()) {
                dns_->stop();
                dns_.reset();
            }
        }
        ASSERT_TRUE(dns_) << "could not bind UDP and TCP on the same ephemeral port";
        port_ = dns_->local_port();
        ASSERT_NE(port_, 0);
        ASSERT_TRUE(dns_->set_record(kName, "A", kAddr, 300));
        ASSERT_TRUE(dns_->set_record(kBigName, "TXT", std::string(60000, 'x'), 300));

        runner_ = std::thread([this] {
            auto guard = asio::make_work_guard(io_);
            io_.run();
        });
    }

    void TearDown() override {
        io_.stop();
        if (runner_.joinable()) runner_.join();
        if (dns_) dns_->stop();
        if (tree_) tree_->stop();
        if (storage_) storage_->stop();
        crypto_.stop();
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

    void connect(asio::ip::tcp::socket& sock, int recv_buffer = 0) {
        sock.open(asio::ip::tcp::v4());
        if (recv_buffer > 0) {
            asio::error_code ec;
            sock.set_option(asio::socket_base::receive_buffer_size(recv_buffer), ec);
        }
        sock.connect({asio::ip::make_address("127.0.0.1"), port_});
    }

    static std::vector<uint8_t> read_framed(asio::ip::tcp::socket& sock) {
        asio::error_code ec;
        std::array<uint8_t, 2> len{};
        asio::read(sock, asio::buffer(len), ec);
        if (ec) return {};
        std::vector<uint8_t> body((static_cast<std::size_t>(len[0]) << 8) | len[1]);
        asio::read(sock, asio::buffer(body), ec);
        if (ec) return {};
        return body;
    }

    std::vector<uint8_t> tcp_query(const std::vector<uint8_t>& payload) {
        asio::io_context client;
        asio::ip::tcp::socket sock(client);
        connect(sock);
        asio::error_code ec;
        asio::write(sock, asio::buffer(frame(payload, payload.size())), ec);
        if (ec) return {};
        return read_framed(sock);
    }

    std::vector<uint8_t> udp_query(const std::vector<uint8_t>& payload) {
        asio::io_context client;
        asio::ip::udp::socket sock(client, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        sock.send_to(asio::buffer(payload),
                     {asio::ip::make_address("127.0.0.1"), port_});
        std::vector<uint8_t> reply(512);
        asio::ip::udp::endpoint from;
        asio::error_code ec;
        const std::size_t n = sock.receive_from(asio::buffer(reply), from, 0, ec);
        if (ec) return {};
        reply.resize(n);
        return reply;
    }

    asio::io_context io_;
    std::thread runner_;
    fs::path dir_;
    crypto::SodiumCryptoService crypto_;
    std::optional<storage::FileStorageService> storage_;
    std::optional<tree::PermissionTreeService> tree_;
    std::unique_ptr<network::DnsService> dns_;
    uint16_t port_{0};
};

}  // namespace

TEST_F(DnsTcpTest, TheListenerComesUpOnBothTransports) {
    EXPECT_TRUE(dns_->tcp_listening());
}

TEST_F(DnsTcpTest, TheSameQueryAnswersIdenticallyOverUdpAndTcp) {
    const auto query = make_query(kName);
    const auto over_udp = udp_query(query);
    const auto over_tcp = tcp_query(query);

    ASSERT_FALSE(over_udp.empty()) << "UDP must answer";
    ASSERT_FALSE(over_tcp.empty()) << "TCP must answer";
    EXPECT_EQ(over_udp, over_tcp);
}

TEST_F(DnsTcpTest, TheReplyPrefixDescribesExactlyWhatFollows) {
    const auto query = make_query(kName);
    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);
    asio::write(sock, asio::buffer(frame(query, query.size())));

    std::array<uint8_t, 2> len{};
    asio::read(sock, asio::buffer(len));
    const std::size_t declared =
        (static_cast<std::size_t>(len[0]) << 8) | static_cast<std::size_t>(len[1]);
    ASSERT_GE(declared, network::kDnsMinMessageBytes);
    ASSERT_LE(declared, network::kDnsTcpMaxMessageBytes);

    std::vector<uint8_t> body(declared);
    asio::error_code ec;
    EXPECT_EQ(asio::read(sock, asio::buffer(body), ec), declared);
    EXPECT_FALSE(ec);
    EXPECT_EQ(body[0], 0x12);  // the query id, echoed
    EXPECT_EQ(body[1], 0x34);
}

TEST_F(DnsTcpTest, AQueryDribbledOneByteAtATimeIsStillAnswered) {
    const auto query = make_query(kName);
    const auto framed = frame(query, query.size());

    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);
    for (std::size_t i = 0; i < framed.size(); ++i) {
        asio::error_code ec;
        asio::write(sock, asio::buffer(&framed[i], 1), ec);
        ASSERT_FALSE(ec) << "byte " << i;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(read_framed(sock).empty());
}

TEST_F(DnsTcpTest, SeveralQueriesOnOneConnectionAreEachAnswered) {
    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);

    for (int i = 0; i < 3; ++i) {
        const auto query = make_query(kName, static_cast<uint16_t>(0x2000 + i));
        asio::error_code ec;
        asio::write(sock, asio::buffer(frame(query, query.size())), ec);
        ASSERT_FALSE(ec) << "write " << i;

        const auto reply = read_framed(sock);
        ASSERT_GE(reply.size(), 2u) << "reply " << i;
        EXPECT_EQ(reply[0], 0x20);
        EXPECT_EQ(reply[1], static_cast<uint8_t>(i));
    }
}

TEST_F(DnsTcpTest, PipelinedResponsesAreWrittenOneWholeFrameAtATime) {
    constexpr int kCount = 24;

    const auto reference = tcp_query(make_query(kBigName, 0xF000, kTypeTxt));
    ASSERT_GT(reference.size(), 32768u) << "the response must exceed one socket write";

    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock, /*recv_buffer=*/4096);

    std::vector<uint8_t> burst;
    for (int i = 0; i < kCount; ++i) {
        const auto q = make_query(kBigName, static_cast<uint16_t>(0x3000 + i), kTypeTxt);
        const auto f = frame(q, q.size());
        burst.insert(burst.end(), f.begin(), f.end());
    }
    asio::error_code ec;
    asio::write(sock, asio::buffer(burst), ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    std::vector<uint8_t> expected;
    for (int i = 0; i < kCount; ++i) {
        expected.push_back(static_cast<uint8_t>((reference.size() >> 8) & 0xFF));
        expected.push_back(static_cast<uint8_t>(reference.size() & 0xFF));
        const std::size_t body = expected.size();
        expected.insert(expected.end(), reference.begin(), reference.end());
        expected[body] = 0x30;
        expected[body + 1] = static_cast<uint8_t>(i);
    }

    std::vector<uint8_t> actual(expected.size());
    const std::size_t got = asio::read(sock, asio::buffer(actual), ec);
    ASSERT_FALSE(ec) << "short reply stream: " << ec.message();
    ASSERT_EQ(got, expected.size());
    EXPECT_EQ(actual, expected) << "frames interleaved or arrived out of order";

    if (actual != expected) {
        for (std::size_t i = 0; i < expected.size(); ++i) {
            if (actual[i] != expected[i]) {
                ADD_FAILURE() << "first divergence at byte " << i << " (frame "
                              << i / (2 + reference.size()) << ")";
                break;
            }
        }
    }
}

TEST_F(DnsTcpTest, APipeliningClientThatNeverReadsIsThrottledNotUnbounded) {
    constexpr int kCount = static_cast<int>(network::kDnsTcpMaxQueuedResponses) * 2;

    const auto reference = tcp_query(make_query(kBigName, 0xF001, kTypeTxt));
    ASSERT_FALSE(reference.empty());

    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock, /*recv_buffer=*/4096);

    std::vector<uint8_t> burst;
    for (int i = 0; i < kCount; ++i) {
        const auto q = make_query(kBigName, static_cast<uint16_t>(0x4000 + i), kTypeTxt);
        const auto f = frame(q, q.size());
        burst.insert(burst.end(), f.begin(), f.end());
    }
    asio::error_code ec;
    asio::write(sock, asio::buffer(burst), ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    for (int i = 0; i < kCount; ++i) {
        const auto reply = read_framed(sock);
        ASSERT_EQ(reply.size(), reference.size()) << "frame " << i;
        EXPECT_EQ(reply[0], 0x40) << "frame " << i;
        EXPECT_EQ(reply[1], static_cast<uint8_t>(i)) << "frame " << i << " out of order";
    }
}

TEST_F(DnsTcpTest, ALengthTooSmallToBeADnsMessageIsRefused) {
    const auto query = make_query(kName);
    for (std::size_t bogus : {std::size_t{0}, std::size_t{4},
                              network::kDnsMinMessageBytes - 1}) {
        asio::io_context client;
        asio::ip::tcp::socket sock(client);
        connect(sock);
        asio::error_code ec;
        asio::write(sock, asio::buffer(frame(query, bogus)), ec);
        EXPECT_TRUE(read_framed(sock).empty()) << "declared " << bogus << " was answered";
    }
}

TEST_F(DnsTcpTest, ADeclaredLengthTheClientNeverDeliversIsNeverAnswered) {
    const auto query = make_query(kName);
    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);
    asio::error_code ec;
    asio::write(sock, asio::buffer(frame(query, network::kDnsTcpMaxMessageBytes)), ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(sock.available(), 0u) << "answered a message that was never fully sent";

    EXPECT_FALSE(tcp_query(query).empty());
}

TEST_F(DnsTcpTest, ConnectionsBeyondTheSessionCapAreDroppedNotQueued) {
    asio::io_context client;
    std::vector<std::unique_ptr<asio::ip::tcp::socket>> held;
    for (int i = 0; i < network::kDnsTcpMaxSessions; ++i) {
        auto s = std::make_unique<asio::ip::tcp::socket>(client);
        asio::error_code ec;
        s->connect({asio::ip::make_address("127.0.0.1"), port_}, ec);
        ASSERT_FALSE(ec) << "connection " << i << " should still be accepted";
        held.push_back(std::move(s));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_TRUE(tcp_query(make_query(kName)).empty())
        << "over the cap a connection must be dropped, not served";

    for (auto& s : held) {
        asio::error_code ec;
        s->close(ec);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(tcp_query(make_query(kName)).empty()) << "the cap must be recoverable";
}

TEST_F(DnsTcpTest, DestroyingServiceClosesOpenSessionsWhileEventLoopContinues) {
    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);
    const auto query = make_query(kName);
    asio::write(sock, asio::buffer(frame(query, query.size())));
    ASSERT_FALSE(read_framed(sock).empty());

    std::promise<void> destroyed;
    asio::post(io_, [this, &destroyed] {
        dns_->stop();
        dns_.reset();
        destroyed.set_value();
    });
    destroyed.get_future().wait();

    sock.non_blocking(true);
    asio::error_code ec;
    std::array<uint8_t, 2> bytes{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    do {
        sock.read_some(asio::buffer(bytes), ec);
        if (ec != asio::error::would_block && ec != asio::error::try_again) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } while (std::chrono::steady_clock::now() < deadline);
    EXPECT_TRUE(ec == asio::error::eof || ec == asio::error::connection_reset) << ec.message();
}

TEST_F(DnsTcpTest, ActivityExtendsConnectionBeyondIdleTimeoutThenSilenceClosesIt) {
    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);
    const auto query = make_query(kName);
    for (int i = 0; i < 3; ++i) {
        if (i) std::this_thread::sleep_for(std::chrono::seconds(6));
        asio::error_code ec;
        asio::write(sock, asio::buffer(frame(query, query.size())), ec);
        ASSERT_FALSE(ec);
        ASSERT_FALSE(read_framed(sock).empty()) << "exchange " << i;
    }
    std::this_thread::sleep_for(std::chrono::seconds(11));
    sock.non_blocking(true);
    std::array<uint8_t, 2> bytes{};
    asio::error_code ec;
    sock.read_some(asio::buffer(bytes), ec);
    EXPECT_TRUE(ec == asio::error::eof || ec == asio::error::connection_reset) << ec.message();
}

TEST_F(DnsTcpTest, QueuedNetworkCompletionsAreSafeAfterDestructionWithoutStop) {
    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);
    const auto query = make_query(kName);
    asio::write(sock, asio::buffer(frame(query, query.size())));
    ASSERT_FALSE(read_framed(sock).empty());

    std::promise<void> entered;
    std::promise<void> resume;
    auto resumed = resume.get_future();
    asio::post(io_, [&] {
        entered.set_value();
        resumed.wait();
    });
    entered.get_future().wait();
    asio::write(sock, asio::buffer(frame(query, query.size())));
    asio::ip::udp::socket udp(client, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
    udp.send_to(asio::buffer(query), {asio::ip::make_address("127.0.0.1"), port_});
    asio::ip::tcp::socket pending(client);
    connect(pending);
    dns_.reset();
    resume.set_value();

    EXPECT_TRUE(read_framed(sock).empty());
    std::promise<void> drained;
    asio::post(io_, [&] { drained.set_value(); });
    EXPECT_EQ(drained.get_future().wait_for(std::chrono::seconds(2)), std::future_status::ready);
}

TEST_F(DnsTcpTest, PartialMessageProgressRefreshesIdleTimeout) {
    asio::io_context client;
    asio::ip::tcp::socket sock(client);
    connect(sock);
    const auto query = make_query(kName);
    const auto framed = frame(query, query.size());
    asio::write(sock, asio::buffer(framed.data(), 3));
    std::this_thread::sleep_for(std::chrono::seconds(6));
    asio::error_code ec;
    asio::write(sock, asio::buffer(framed.data() + 3, 1), ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::seconds(6));
    asio::write(sock, asio::buffer(framed.data() + 4, framed.size() - 4), ec);
    ASSERT_FALSE(ec);
    EXPECT_FALSE(read_framed(sock).empty());
}
