// SDK certificate renewal (CertRenewer and its C ABI): renew near expiry,
// never early, fire the callback once per renewal, keep the old files when a
// renewal fails, and replace the key file with mode 0600.

#include <LemonadeNexusSDK/CertRenewal.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#ifndef _WIN32
#  include <sys/stat.h>
#  include <unistd.h>
#else
#  include <process.h>
#  define getpid _getpid
#endif

namespace fs = std::filesystem;
using lnsdk::CertRenewalStatus;
using lnsdk::CertRenewer;

namespace {

constexpr int64_t kDay = 24 * 3600;

struct Pem {
    std::string cert;
    std::string key;
};

uint64_t now_s() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

/// A self-signed P-256 certificate valid from now + from_s to now + to_s.
Pem make_cert(const std::string& name, int64_t from_s, int64_t to_s) {
    Pem out;
    EVP_PKEY* pkey = EVP_EC_gen("P-256");
    if (!pkey) return out;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 3);
    X509_gmtime_adj(X509_getm_notBefore(x), static_cast<long>(from_s));
    X509_gmtime_adj(X509_getm_notAfter(x), static_cast<long>(to_s));
    X509_set_pubkey(x, pkey);
    X509_NAME* subject = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(name.c_str()), -1, -1, 0);
    X509_set_issuer_name(x, subject);
    if (X509_sign(x, pkey, EVP_sha256()) != 0) {
        char* data = nullptr;
        BIO* cb = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(cb, x);
        long len = BIO_get_mem_data(cb, &data);
        out.cert.assign(data, static_cast<std::size_t>(len));
        BIO_free(cb);
        BIO* kb = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(kb, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        len = BIO_get_mem_data(kb, &data);
        out.key.assign(data, static_cast<std::size_t>(len));
        BIO_free(kb);
    }
    X509_free(x);
    EVP_PKEY_free(pkey);
    return out;
}

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

class CertRenewalTest : public ::testing::Test {
protected:
    fs::path dir;
    CertRenewer renewer;
    int fetches = 0;
    std::vector<lnsdk::CertRenewedEvent> events;
    lnsdk::Result<lnsdk::DecryptedCert> next;  // what the fake server answers

    void SetUp() override {
        dir = fs::temp_directory_path() /
              ("nexus_sdk_cert_" + std::to_string(getpid()) + "_" +
               ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(dir);
        renewer.set_callback([this](const lnsdk::CertRenewedEvent& e) { events.push_back(e); });
    }
    void TearDown() override { fs::remove_all(dir); }

    CertRenewer::Fetch fetch() {
        return [this](const std::string&) {
            ++fetches;
            return next;
        };
    }

    void store(const Pem& pem) {
        std::string error;
        ASSERT_TRUE(lnsdk::write_cert_files(dir, pem.cert, pem.key, error)) << error;
    }

    void answer(const Pem& pem, const std::string& domain = "laptop.capi.example.test") {
        next = {};
        next.ok = true;
        next.value.domain = domain;
        next.value.fullchain_pem = pem.cert;
        next.value.privkey_pem = pem.key;
    }

    void answer_failure(int status) {
        next = {};
        next.http_status = status;
        next.error = "certificate request failed";
    }
};

} // namespace

TEST(CertRenewalRule, DueWhenLessThanOneThirdOfTheLifetimeRemains) {
    const lnsdk::CertValidity v{.not_before = 1000, .not_after = 1000 + 90 * kDay};
    EXPECT_FALSE(lnsdk::cert_renewal_due(v, 1000));
    EXPECT_FALSE(lnsdk::cert_renewal_due(v, 1000 + 60 * kDay));      // exactly one third left
    EXPECT_TRUE(lnsdk::cert_renewal_due(v, 1000 + 60 * kDay + 1));
    EXPECT_TRUE(lnsdk::cert_renewal_due(v, 1000 + 90 * kDay));       // expired
    EXPECT_TRUE(lnsdk::cert_renewal_due({.not_before = 0, .not_after = 5}, 1));
    EXPECT_TRUE(lnsdk::cert_renewal_due({.not_before = 9, .not_after = 9}, 1));
}

TEST(CertRenewalRule, BackoffDoublesToTheCap) {
    EXPECT_EQ(CertRenewer::backoff_seconds(0), 0u);
    EXPECT_EQ(CertRenewer::backoff_seconds(1), 60u);
    EXPECT_EQ(CertRenewer::backoff_seconds(2), 120u);
    EXPECT_EQ(CertRenewer::backoff_seconds(3), 240u);
    EXPECT_EQ(CertRenewer::backoff_seconds(30), CertRenewer::kBackoffMaxSeconds);
}

TEST_F(CertRenewalTest, DoesNotRenewEarly) {
    store(make_cert("laptop", -kDay, 89 * kDay));
    answer(make_cert("laptop", 0, 90 * kDay));
    const auto r = renewer.renew_if_needed("laptop", dir, now_s(), fetch());
    EXPECT_EQ(r.status, CertRenewalStatus::NotDue);
    EXPECT_EQ(fetches, 0);
    EXPECT_TRUE(events.empty());
    EXPECT_FALSE(renewer.renewal_pending(now_s()));
}

TEST_F(CertRenewalTest, RenewsNearExpiryAndFiresTheCallbackOnce) {
    const auto old_pem = make_cert("laptop", -80 * kDay, 10 * kDay);
    store(old_pem);
    EXPECT_TRUE(renewer.renew_if_needed("laptop", dir, now_s(), {}).status ==
                CertRenewalStatus::Failed);  // no source: still registered, old files stay
    EXPECT_EQ(read_file(dir / "fullchain.pem"), old_pem.cert);

    const auto new_pem = make_cert("laptop", 0, 90 * kDay);
    answer(new_pem);
    const auto r = renewer.renew_if_needed("laptop", dir, now_s(), fetch());
    ASSERT_EQ(r.status, CertRenewalStatus::Renewed) << r.error;
    EXPECT_EQ(fetches, 1);
    EXPECT_EQ(read_file(dir / "fullchain.pem"), new_pem.cert);
    EXPECT_EQ(read_file(dir / "privkey.pem"), new_pem.key);
#ifndef _WIN32
    struct stat st{};
    ASSERT_EQ(::stat((dir / "privkey.pem").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600);
#endif
    // No temporary file is left behind.
    for (const auto& entry : fs::directory_iterator(dir)) {
        EXPECT_EQ(entry.path().filename().string().find(".tmp-"), std::string::npos);
    }

    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].target, "laptop");
    EXPECT_EQ(events[0].domain, "laptop.capi.example.test");
    EXPECT_EQ(events[0].privkey_path, (dir / "privkey.pem").string());
    EXPECT_EQ(events[0].expires_at, r.expires_at);

    // The next checks find a fresh certificate: no request, no callback.
    EXPECT_EQ(renewer.renew_if_needed("laptop", dir, now_s(), fetch()).status,
              CertRenewalStatus::NotDue);
    renewer.renew_managed(now_s(), fetch());
    EXPECT_EQ(fetches, 1);
    EXPECT_EQ(events.size(), 1u);
}

TEST_F(CertRenewalTest, RequestsWhenNoCertificateIsStored) {
    const auto pem = make_cert("*.gabc.lo.example.test", 0, 90 * kDay);
    answer(pem, "*.gabc.lo.example.test");
    const auto r = renewer.renew_if_needed(std::string(lnsdk::kGroupLoopbackCertTarget), dir,
                                           now_s(), fetch());
    ASSERT_EQ(r.status, CertRenewalStatus::Renewed) << r.error;
    EXPECT_EQ(read_file(dir / "privkey.pem"), pem.key);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].target, "*");
}

TEST_F(CertRenewalTest, FailedRenewalKeepsTheOldCertificateAndBacksOff) {
    const auto old_pem = make_cert("laptop", -80 * kDay, 10 * kDay);
    store(old_pem);
    answer_failure(502);
    const auto t0 = now_s();
    const auto r = renewer.renew_if_needed("laptop", dir, t0, fetch());
    EXPECT_EQ(r.status, CertRenewalStatus::Failed);
    EXPECT_EQ(r.http_status, 502);
    EXPECT_EQ(read_file(dir / "fullchain.pem"), old_pem.cert);
    EXPECT_EQ(read_file(dir / "privkey.pem"), old_pem.key);
    EXPECT_TRUE(events.empty());

    // Inside the backoff delay the background pass does not ask again.
    EXPECT_FALSE(renewer.renewal_pending(t0 + 30));
    renewer.renew_managed(t0 + 30, fetch());
    EXPECT_EQ(fetches, 1);
    // After it, the pass asks again and the second failure doubles the delay.
    EXPECT_TRUE(renewer.renewal_pending(t0 + 61));
    renewer.renew_managed(t0 + 61, fetch());
    EXPECT_EQ(fetches, 2);
    EXPECT_FALSE(renewer.renewal_pending(t0 + 61 + 119));
    EXPECT_TRUE(renewer.renewal_pending(t0 + 61 + 120));
    EXPECT_EQ(read_file(dir / "privkey.pem"), old_pem.key);
}

TEST_F(CertRenewalTest, RejectsAMismatchedKeyOrAnOlderCertificate) {
    const auto old_pem = make_cert("laptop", -80 * kDay, 10 * kDay);
    store(old_pem);

    auto mixed = make_cert("laptop", 0, 90 * kDay);
    mixed.key = make_cert("laptop", 0, 90 * kDay).key;
    answer(mixed);
    EXPECT_EQ(renewer.renew_if_needed("laptop", dir, now_s(), fetch()).status,
              CertRenewalStatus::Failed);

    answer(old_pem);  // the server serves the same, still-due certificate
    EXPECT_EQ(renewer.renew_if_needed("laptop", dir, now_s(), fetch()).status,
              CertRenewalStatus::Failed);

    EXPECT_EQ(read_file(dir / "privkey.pem"), old_pem.key);
    EXPECT_TRUE(events.empty());
}

TEST_F(CertRenewalTest, ClearedCallbackIsNotCalled) {
    store(make_cert("laptop", -80 * kDay, 10 * kDay));
    renewer.set_callback({});
    answer(make_cert("laptop", 0, 90 * kDay));
    EXPECT_EQ(renewer.renew_if_needed("laptop", dir, now_s(), fetch()).status,
              CertRenewalStatus::Renewed);
    EXPECT_TRUE(events.empty());
}

// --- C ABI -------------------------------------------------------------------

namespace {
int g_calls = 0;
void count_call(const char*, void* user) { ++*static_cast<int*>(user); }
} // namespace

TEST_F(CertRenewalTest, CApiValidatesArgumentsAndReportsNotDue) {
    char* out = nullptr;
    EXPECT_EQ(ln_set_cert_renewed_callback(nullptr, count_call, &g_calls), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_cert_renew_if_needed(nullptr, "laptop", "/tmp", &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_cert_request_group(nullptr, &out), LN_ERR_NULL_ARG);

    ln_client_t* client = ln_create("127.0.0.1", 1);
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(ln_set_cert_renewed_callback(client, count_call, &g_calls), LN_OK);
    EXPECT_EQ(ln_cert_renew_if_needed(client, nullptr, "/tmp", &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_cert_renew_if_needed(client, "laptop", nullptr, &out), LN_ERR_NULL_ARG);

    // A fresh certificate needs no network: not due, no callback.
    store(make_cert("laptop", -kDay, 89 * kDay));
    ASSERT_EQ(ln_cert_renew_if_needed(client, "laptop", dir.string().c_str(), &out), LN_OK);
    ASSERT_NE(out, nullptr);
    const auto j = nlohmann::json::parse(out);
    EXPECT_EQ(j.value("status", ""), "not_due");
    EXPECT_GT(j.value("expires_at", uint64_t{0}), now_s());
    ln_free(out);
    EXPECT_EQ(g_calls, 0);

    EXPECT_EQ(ln_set_cert_renewed_callback(client, nullptr, nullptr), LN_OK);
    ln_destroy(client);
}
