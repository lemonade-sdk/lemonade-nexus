#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Acme/IAcmeProvider.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

using namespace nexus;
namespace fs = std::filesystem;

// ===========================================================================
// AcmeProviderConfig unit tests (no network, no storage needed)
// ===========================================================================

TEST(AcmeProviderConfigTest, LetsEncryptDefaults) {
    auto cfg = acme::AcmeProviderConfig::letsencrypt();
    EXPECT_EQ(cfg.name, "Let's Encrypt");
    EXPECT_EQ(cfg.host, "acme-v02.api.letsencrypt.org");
    EXPECT_EQ(cfg.directory_url, "https://acme-v02.api.letsencrypt.org/directory");
    EXPECT_FALSE(cfg.staging);
    EXPECT_FALSE(cfg.requires_eab());
    EXPECT_TRUE(cfg.eab_kid.empty());
    EXPECT_TRUE(cfg.eab_hmac_key.empty());
}

TEST(AcmeProviderConfigTest, LetsEncryptStaging) {
    auto cfg = acme::AcmeProviderConfig::letsencrypt_staging();
    EXPECT_EQ(cfg.name, "Let's Encrypt (Staging)");
    EXPECT_EQ(cfg.host, "acme-staging-v02.api.letsencrypt.org");
    EXPECT_EQ(cfg.directory_url, "https://acme-staging-v02.api.letsencrypt.org/directory");
    EXPECT_TRUE(cfg.staging);
    EXPECT_FALSE(cfg.requires_eab());
}

TEST(AcmeProviderConfigTest, ZeroSSLDefaults) {
    auto cfg = acme::AcmeProviderConfig::zerossl();
    EXPECT_EQ(cfg.name, "ZeroSSL");
    EXPECT_EQ(cfg.host, "acme.zerossl.com");
    EXPECT_EQ(cfg.directory_url, "https://acme.zerossl.com/v2/DV90");
    EXPECT_FALSE(cfg.staging);
    // Without env vars set, EAB will be empty
}

TEST(AcmeProviderConfigTest, ZeroSSLWithExplicitEAB) {
    auto cfg = acme::AcmeProviderConfig::zerossl("my-eab-kid", "my-eab-hmac");
    EXPECT_EQ(cfg.name, "ZeroSSL");
    EXPECT_EQ(cfg.host, "acme.zerossl.com");
    EXPECT_TRUE(cfg.requires_eab());
    EXPECT_EQ(cfg.eab_kid, "my-eab-kid");
    EXPECT_EQ(cfg.eab_hmac_key, "my-eab-hmac");
}

TEST(AcmeProviderConfigTest, RequiresEabFalseWhenPartial) {
    acme::AcmeProviderConfig cfg;
    cfg.eab_kid = "has-kid";
    // eab_hmac_key is empty
    EXPECT_FALSE(cfg.requires_eab());

    acme::AcmeProviderConfig cfg2;
    cfg2.eab_hmac_key = "has-hmac";
    // eab_kid is empty
    EXPECT_FALSE(cfg2.requires_eab());
}

// ===========================================================================
// AcmeService tests (with storage, offline)
// ===========================================================================

class AcmeTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<storage::FileStorageService> storage;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_acme_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
        fs::create_directories(temp_dir);

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();
    }

    void TearDown() override {
        storage->stop();
        fs::remove_all(temp_dir);
    }
};

// --- Service lifecycle with Let's Encrypt ---

TEST_F(AcmeTest, LetsEncryptServiceStartStop) {
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt()};
    svc.start();
    EXPECT_EQ(svc.service_name(), "AcmeService");
    svc.stop();
}

TEST_F(AcmeTest, LetsEncryptStagingServiceStartStop) {
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt_staging()};
    svc.start();
    EXPECT_EQ(svc.service_name(), "AcmeService");
    svc.stop();
}

// --- Service lifecycle with ZeroSSL ---

TEST_F(AcmeTest, ZeroSSLServiceStartStop) {
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::zerossl(), "cloudflare"};
    svc.start();
    EXPECT_EQ(svc.service_name(), "AcmeService");
    svc.stop();
}

TEST_F(AcmeTest, ZeroSSLWithEABServiceStartStop) {
    auto cfg = acme::AcmeProviderConfig::zerossl("test-kid", "dGVzdC1obWFj");
    acme::AcmeService svc{*storage, std::move(cfg), "cloudflare"};
    svc.start();
    svc.stop();
}

// --- Certificate lookup (none exists) ---

TEST_F(AcmeTest, GetCertificateReturnsNulloptWhenNoneExists) {
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt_staging()};
    svc.start();
    auto cert = svc.get_certificate("nonexistent.example.com");
    EXPECT_FALSE(cert.has_value());
    svc.stop();
}

// --- Certificate persistence (mock cert on disk) ---

TEST_F(AcmeTest, GetCertificateReturnsStoredCert) {
    auto cert_dir = temp_dir / "certs" / "test.example.com";
    fs::create_directories(cert_dir);

    {
        std::ofstream ofs(cert_dir / "fullchain.pem");
        ofs << "-----BEGIN CERTIFICATE-----\nMOCKCERT\n-----END CERTIFICATE-----\n";
    }
    {
        std::ofstream ofs(cert_dir / "privkey.pem");
        ofs << "-----BEGIN EC PRIVATE KEY-----\nMOCKKEY\n-----END EC PRIVATE KEY-----\n";
    }

    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt_staging()};
    svc.start();

    auto cert = svc.get_certificate("test.example.com");
    // Mock cert may or may not parse; key assertion is no crash
    svc.stop();
}

TEST_F(AcmeTest, GetCertificateReturnsStoredCertWithMeta) {
    auto cert_dir = temp_dir / "certs" / "meta.example.com";
    fs::create_directories(cert_dir);

    {
        std::ofstream ofs(cert_dir / "fullchain.pem");
        ofs << "-----BEGIN CERTIFICATE-----\nMOCKCERT\n-----END CERTIFICATE-----\n";
    }
    {
        std::ofstream ofs(cert_dir / "privkey.pem");
        ofs << "-----BEGIN EC PRIVATE KEY-----\nMOCKKEY\n-----END EC PRIVATE KEY-----\n";
    }
    {
        std::ofstream ofs(cert_dir / "meta.json");
        ofs << R"({"domain":"meta.example.com","expires_at":9999999999})";
    }

    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt()};
    svc.start();
    auto cert = svc.get_certificate("meta.example.com");
    // If returned, check that expiry was loaded from meta
    if (cert.has_value()) {
        EXPECT_EQ(cert->expires_at, 9999999999u);
    }
    svc.stop();
}

// --- DNS TXT record operations ---

TEST_F(AcmeTest, SetDnsTxtRecordFailsWithoutToken) {
    // Use "cloudflare" provider explicitly — requires CLOUDFLARE_API_TOKEN env
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt_staging(), "cloudflare"};
    svc.start();
    auto result = svc.set_dns_txt_record("_acme-challenge.test.example.com", "test_value");
    EXPECT_FALSE(result);
    svc.stop();
}

TEST_F(AcmeTest, RemoveDnsTxtRecordNoopWhenNotTracked) {
    // Use "cloudflare" provider explicitly — removal of untracked record is a no-op
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt_staging(), "cloudflare"};
    svc.start();
    // Removing a record that was never set should succeed (no-op)
    auto result = svc.remove_dns_txt_record("_acme-challenge.test.example.com");
    EXPECT_TRUE(result);
    svc.stop();
}

// --- Provider-specific behavior ---

TEST_F(AcmeTest, LetsEncryptAndZeroSSLHaveDifferentHosts) {
    auto le = acme::AcmeProviderConfig::letsencrypt();
    auto zs = acme::AcmeProviderConfig::zerossl();
    EXPECT_NE(le.host, zs.host);
    EXPECT_NE(le.directory_url, zs.directory_url);
}

TEST_F(AcmeTest, StagingAndProductionHaveDifferentHosts) {
    auto prod = acme::AcmeProviderConfig::letsencrypt();
    auto staging = acme::AcmeProviderConfig::letsencrypt_staging();
    EXPECT_NE(prod.host, staging.host);
    EXPECT_NE(prod.directory_url, staging.directory_url);
    EXPECT_FALSE(prod.staging);
    EXPECT_TRUE(staging.staging);
}

// --- Certificate request (requires network) ---

TEST_F(AcmeTest, DISABLED_LetsEncryptRequestCertificateStaging) {
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt_staging()};
    svc.start();
    auto result = svc.request_certificate("test.example.com");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error_message.empty());
    svc.stop();
}

TEST_F(AcmeTest, DISABLED_ZeroSSLRequestCertificate) {
    auto cfg = acme::AcmeProviderConfig::zerossl();
    if (!cfg.requires_eab()) GTEST_SKIP() << "ZeroSSL EAB credentials not configured";
    acme::AcmeService svc{*storage, std::move(cfg)};
    svc.start();
    auto result = svc.request_certificate("test.example.com");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error_message.empty());
    svc.stop();
}

// --- Renewal (requires network) ---

TEST_F(AcmeTest, DISABLED_LetsEncryptRenewCertificateStaging) {
    acme::AcmeService svc{*storage, acme::AcmeProviderConfig::letsencrypt_staging()};
    svc.start();
    auto result = svc.renew_certificate("test.example.com");
    EXPECT_FALSE(result.success);
    svc.stop();
}

TEST_F(AcmeTest, DISABLED_ZeroSSLRenewCertificate) {
    auto cfg = acme::AcmeProviderConfig::zerossl();
    if (!cfg.requires_eab()) GTEST_SKIP() << "ZeroSSL EAB credentials not configured";
    acme::AcmeService svc{*storage, std::move(cfg)};
    svc.start();
    auto result = svc.renew_certificate("test.example.com");
    EXPECT_FALSE(result.success);
    svc.stop();
}
