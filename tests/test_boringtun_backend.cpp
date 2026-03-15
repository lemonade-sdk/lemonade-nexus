#include <LemonadeNexusSDK/BoringTunBackend.hpp>
#include <LemonadeNexusSDK/ITunnelBackend.hpp>
#include <LemonadeNexusSDK/Types.hpp>
#include <LemonadeNexusSDK/Error.hpp>

#include <gtest/gtest.h>

#include <string>
#include <type_traits>

using namespace lnsdk;

// ===========================================================================
// CRTP / concept tests — compile-time verification, all platforms
// ===========================================================================

TEST(BoringTunBackendTest, SatisfiesTunnelBackendConcept) {
    static_assert(TunnelBackendType<BoringTunBackend>,
                  "BoringTunBackend must satisfy TunnelBackendType concept");
}

TEST(BoringTunBackendTest, IsNotCopyable) {
    static_assert(!std::is_copy_constructible_v<BoringTunBackend>);
    static_assert(!std::is_copy_assignable_v<BoringTunBackend>);
}

TEST(BoringTunBackendTest, DefaultConstructible) {
    static_assert(std::is_default_constructible_v<BoringTunBackend>);
}

// ===========================================================================
// State machine tests — initial state, no network required
// ===========================================================================

TEST(BoringTunBackendTest, InitiallyInactive) {
    BoringTunBackend backend;
    EXPECT_FALSE(backend.is_active());
}

TEST(BoringTunBackendTest, InitialStatusIsDown) {
    BoringTunBackend backend;
    auto st = backend.status();
    EXPECT_FALSE(st.is_up);
    EXPECT_TRUE(st.tunnel_ip.empty());
    EXPECT_TRUE(st.server_endpoint.empty());
}

TEST(BoringTunBackendTest, BringDownWhenNotActiveIsOk) {
    BoringTunBackend backend;
    // Bringing down a tunnel that was never up should not crash
    auto result = backend.bring_down();
    // The result may be ok (noop) or error; either way no crash
    (void)result;
}

// ===========================================================================
// Error handling — bad keys should fail gracefully
// ===========================================================================

TEST(BoringTunBackendTest, BringUpWithEmptyKeysReturnsError) {
    BoringTunBackend backend;

    WireGuardConfig config;
    config.private_key = "";
    config.server_public_key = "";
    config.tunnel_ip = "10.64.0.1/32";
    config.server_endpoint = "1.2.3.4:51820";

    auto result = backend.bring_up(config);
    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(result.error.empty());
    EXPECT_FALSE(backend.is_active());
}

TEST(BoringTunBackendTest, BringUpWithInvalidKeysReturnsError) {
    BoringTunBackend backend;

    WireGuardConfig config;
    config.private_key = "not-a-valid-base64-key";
    config.server_public_key = "also-not-valid";
    config.tunnel_ip = "10.64.0.1/32";
    config.server_endpoint = "1.2.3.4:51820";

    auto result = backend.bring_up(config);
    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(result.error.empty());
    EXPECT_FALSE(backend.is_active());
}

TEST(BoringTunBackendTest, StatusAfterFailedBringUpStillDown) {
    BoringTunBackend backend;

    WireGuardConfig config;
    config.private_key = "bad";
    config.server_public_key = "bad";

    backend.bring_up(config);

    auto st = backend.status();
    EXPECT_FALSE(st.is_up);
    EXPECT_FALSE(backend.is_active());
}

// ===========================================================================
// Update endpoint without active tunnel
// ===========================================================================

TEST(BoringTunBackendTest, UpdateEndpointWhenInactiveDoesNotCrash) {
    BoringTunBackend backend;

    // Should handle gracefully even when no tunnel is active
    auto result = backend.update_endpoint("some-pubkey", "1.2.3.4:51820");
    // Not asserting ok/error — just verifying no crash/segfault
    (void)result;
}

// ===========================================================================
// Platform-specific TUN creation tests (will fail without root,
// but verify error handling is correct)
// ===========================================================================

#if defined(__APPLE__) || defined(__linux__) || defined(_WIN32)

TEST(BoringTunBackendTest, BringUpWithValidKeysFailsWithoutRoot) {
    BoringTunBackend backend;

    // Generate a valid WireGuard keypair (32 bytes base64-encoded)
    // These are syntactically valid Curve25519 keys but won't match any real peer
    WireGuardConfig config;
    config.private_key = "YEluVpROEfR7bnhpPgUX0IydqBZp2eBJiKO7m1lLOFk=";
    config.server_public_key = "GJQk+4xOuJNnX/XsNxfJh7rqTT3PAURgr7jnZjrKlzk=";
    config.tunnel_ip = "10.64.0.99/32";
    config.server_endpoint = "192.0.2.1:51820";
    config.allowed_ips = {"10.64.0.0/16"};

    auto result = backend.bring_up(config);

    // On macOS/Linux: TUN device creation requires root → should fail
    // On Windows: WinTun dll must be present → should fail
    // On CI: typically not root → should fail
    // If somehow running as root, the test still passes (tunnel comes up)
    if (!result.ok) {
        EXPECT_FALSE(result.error.empty());
        EXPECT_FALSE(backend.is_active());
    } else {
        // If it succeeded (running as root), verify state and clean up
        EXPECT_TRUE(backend.is_active());
        auto st = backend.status();
        EXPECT_TRUE(st.is_up);
        EXPECT_EQ(st.tunnel_ip, "10.64.0.99/32");
        backend.bring_down();
        EXPECT_FALSE(backend.is_active());
    }
}

#endif

// ===========================================================================
// Destructor safety — should clean up even if tunnel is in error state
// ===========================================================================

TEST(BoringTunBackendTest, DestructorAfterFailedBringUpIsSafe) {
    {
        BoringTunBackend backend;
        WireGuardConfig config;
        config.private_key = "bad";
        config.server_public_key = "bad";
        backend.bring_up(config);
        // Destructor runs here — should not crash
    }
    SUCCEED();
}

TEST(BoringTunBackendTest, DestructorWithoutBringUpIsSafe) {
    {
        BoringTunBackend backend;
        // Never called bring_up — destructor should be fine
    }
    SUCCEED();
}
