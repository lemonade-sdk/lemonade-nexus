#pragma once

// Bounded readiness probe for in-process HttpServer test fixtures.
//
// A fixed sleep after HttpServer::start() races on loaded CI runners: the
// server thread may not have reached listen() yet, so the fixture's first
// request is refused and the httplib client returns nullptr. Observed
// failure: PasskeyChallengeHttpTest on ubuntu-latest, 2026-10-14. A loopback
// TCP connect succeeds only after bind+listen, so probing the port until a
// connect succeeds is a protocol-neutral readiness signal (plain and TLS
// servers alike). The hard timeout keeps a truly broken server from hanging
// the fixture.

#include <chrono>
#include <cstdint>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

inline bool wait_http_ready(uint16_t port,
                            std::chrono::milliseconds timeout =
                                std::chrono::milliseconds(5000)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            sockaddr_in addr{};
            addr.sin_family      = AF_INET;
            addr.sin_port        = htons(port);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            const int rc =
                ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            ::close(fd);
            if (rc == 0) return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}
