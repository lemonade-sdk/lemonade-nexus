#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <thread>

namespace nexus::acme {

namespace fs = std::filesystem;
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static constexpr const char* kCloudflareApiHost = "api.cloudflare.com";
static constexpr int kCloudflareApiPort = 443;

// How many seconds before expiry to consider a cert "due for renewal"
static constexpr uint64_t kRenewalThresholdSecs = 30 * 24 * 3600; // 30 days

namespace {

/// Return the current Unix timestamp.
uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

/// Get the last OpenSSL error as a string.
std::string openssl_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "unknown error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

AcmeService::AcmeService(storage::FileStorageService& storage,
                           AcmeProviderConfig provider_config,
                           std::string dns_provider)
    : storage_(storage)
    , dns_provider_(std::move(dns_provider))
    , provider_config_(std::move(provider_config))
    , account_key_path_(storage.data_root() / "certs" / "account.key")
{
}

void AcmeService::set_dns_service(network::DnsService* dns) {
    dns_service_ = dns;
    if (dns) {
        dns_provider_ = "local";
        spdlog::info("[{}] using local authoritative DNS for ACME challenges", name());
    }
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void AcmeService::on_start() {
    scan_existing_certs();

    // Ensure the certs directory exists
    auto certs_dir = storage_.data_root() / "certs";
    if (!fs::exists(certs_dir)) {
        fs::create_directories(certs_dir);
    }

    spdlog::info("[{}] started (provider: '{}', dns: '{}', staging: {})",
                  name(), provider_config_.name, dns_provider_,
                  provider_config_.staging);
}

void AcmeService::on_stop() {
    if (account_key_) {
        EVP_PKEY_free(account_key_);
        account_key_ = nullptr;
    }
    spdlog::info("[{}] stopped", name());
}

AcmeService::~AcmeService() {
    if (account_key_) {
        EVP_PKEY_free(account_key_);
        account_key_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Base64url encoding
// ---------------------------------------------------------------------------

std::string AcmeService::base64url_encode(const std::vector<uint8_t>& data) {
    return base64url_encode(data.data(), data.size());
}

std::string AcmeService::base64url_encode(const uint8_t* data, std::size_t len) {
    auto b64 = crypto::to_base64(std::span<const uint8_t>(data, len));
    // Convert standard base64 to base64url: + -> -, / -> _, strip =
    for (auto& ch : b64) {
        if (ch == '+') ch = '-';
        else if (ch == '/') ch = '_';
    }
    // Remove padding
    while (!b64.empty() && b64.back() == '=') {
        b64.pop_back();
    }
    return b64;
}

std::string AcmeService::base64url_encode(const std::string& data) {
    return base64url_encode(
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

std::string AcmeService::url_path(const std::string& url) {
    // Extract path from https://host/path
    auto pos = url.find("://");
    if (pos == std::string::npos) return url;
    pos = url.find('/', pos + 3);
    if (pos == std::string::npos) return "/";
    return url.substr(pos);
}

std::string AcmeService::url_host(const std::string& url) {
    auto pos = url.find("://");
    if (pos == std::string::npos) return url;
    auto start = pos + 3;
    auto end = url.find('/', start);
    if (end == std::string::npos) return url.substr(start);
    return url.substr(start, end - start);
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

std::string AcmeService::read_raw_file(const std::filesystem::path& path) const {
    try {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) {
            spdlog::error("[{}] failed to open file: {}", name(), path.string());
            return {};
        }
        std::ostringstream ss;
        ss << ifs.rdbuf();
        return ss.str();
    } catch (const std::exception& e) {
        spdlog::error("[{}] failed to read file '{}': {}", name(), path.string(), e.what());
        return {};
    }
}

bool AcmeService::write_raw_file(const std::filesystem::path& path,
                                   const std::string& content) const {
    try {
        auto parent = path.parent_path();
        if (!parent.empty() && !fs::exists(parent)) {
            fs::create_directories(parent);
        }
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            spdlog::error("[{}] failed to open file for writing: {}",
                           name(), path.string());
            return false;
        }
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        return ofs.good();
    } catch (const std::exception& e) {
        spdlog::error("[{}] failed to write file '{}': {}",
                       name(), path.string(), e.what());
        return false;
    }
}

uint64_t AcmeService::parse_cert_expiry(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return 0;

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return 0;

    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (!not_after) {
        X509_free(cert);
        return 0;
    }

    // Convert ASN1_TIME to tm structure
    struct tm t{};
    if (ASN1_TIME_to_tm(not_after, &t) != 1) {
        X509_free(cert);
        return 0;
    }

    X509_free(cert);

    // Convert to Unix timestamp (UTC)
    // Use timegm on POSIX or _mkgmtime on Windows
#if defined(_WIN32)
    time_t epoch = _mkgmtime(&t);
#else
    time_t epoch = timegm(&t);
#endif
    return static_cast<uint64_t>(epoch);
}

// ---------------------------------------------------------------------------
// ACME directory
// ---------------------------------------------------------------------------

bool AcmeService::get_directory() {
    if (!new_nonce_url_.empty()) {
        return true; // Already fetched
    }

    spdlog::info("[{}] fetching ACME directory from {}", name(), provider_config_.directory_url);

    httplib::SSLClient client(provider_config_.host);
    client.set_connection_timeout(10, 0);
    client.set_read_timeout(10, 0);

    auto res = client.Get(url_path(provider_config_.directory_url));
    if (!res || res->status != 200) {
        spdlog::error("[{}] failed to fetch ACME directory (status: {})",
                       name(), res ? res->status : 0);
        return false;
    }

    auto dir = json::parse(res->body, nullptr, false);
    if (dir.is_discarded()) {
        spdlog::error("[{}] invalid JSON in ACME directory response", name());
        return false;
    }

    new_nonce_url_   = dir.value("newNonce", "");
    new_account_url_ = dir.value("newAccount", "");
    new_order_url_   = dir.value("newOrder", "");

    if (new_nonce_url_.empty() || new_account_url_.empty() || new_order_url_.empty()) {
        spdlog::error("[{}] ACME directory missing required endpoints", name());
        return false;
    }

    spdlog::info("[{}] ACME directory loaded: newNonce={}, newAccount={}, newOrder={}",
                  name(), new_nonce_url_, new_account_url_, new_order_url_);
    return true;
}

// ---------------------------------------------------------------------------
// Nonce management
// ---------------------------------------------------------------------------

std::string AcmeService::get_nonce() {
    // If we have a cached nonce, use it
    if (!current_nonce_.empty()) {
        std::string nonce = std::move(current_nonce_);
        current_nonce_.clear();
        return nonce;
    }

    // Fetch a fresh nonce via HEAD request
    httplib::SSLClient client(provider_config_.host);
    client.set_connection_timeout(10, 0);
    client.set_read_timeout(10, 0);

    auto res = client.Head(url_path(new_nonce_url_));
    if (!res) {
        spdlog::error("[{}] failed to fetch new nonce", name());
        return {};
    }

    auto it = res->headers.find("Replay-Nonce");
    if (it == res->headers.end()) {
        // Try lowercase
        it = res->headers.find("replay-nonce");
    }
    if (it != res->headers.end()) {
        return it->second;
    }

    spdlog::error("[{}] no Replay-Nonce header in nonce response", name());
    return {};
}

// ---------------------------------------------------------------------------
// Account key management
// ---------------------------------------------------------------------------

bool AcmeService::ensure_account_key() {
    if (account_key_) {
        return true; // Already loaded
    }

    // Try to load existing key
    if (fs::exists(account_key_path_)) {
        spdlog::info("[{}] loading existing account key from {}",
                      name(), account_key_path_.string());

        auto pem = read_raw_file(account_key_path_);
        if (pem.empty()) {
            spdlog::error("[{}] account key file is empty", name());
            return false;
        }

        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) return false;

        account_key_ = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!account_key_) {
            spdlog::error("[{}] failed to parse account key: {}",
                           name(), openssl_error_string());
            return false;
        }

        return true;
    }

    // Generate a new ECDSA P-256 key
    spdlog::info("[{}] generating new ECDSA P-256 account key", name());

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) {
        spdlog::error("[{}] EVP_PKEY_CTX_new_id failed: {}",
                       name(), openssl_error_string());
        return false;
    }

    bool ok = true;
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        spdlog::error("[{}] EVP_PKEY_keygen_init failed: {}",
                       name(), openssl_error_string());
        ok = false;
    }

    if (ok && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        spdlog::error("[{}] failed to set P-256 curve: {}",
                       name(), openssl_error_string());
        ok = false;
    }

    EVP_PKEY* key = nullptr;
    if (ok && EVP_PKEY_keygen(pctx, &key) <= 0) {
        spdlog::error("[{}] EVP_PKEY_keygen failed: {}",
                       name(), openssl_error_string());
        ok = false;
    }

    EVP_PKEY_CTX_free(pctx);

    if (!ok || !key) {
        return false;
    }

    // Write to PEM file
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        EVP_PKEY_free(key);
        return false;
    }

    if (!PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr)) {
        spdlog::error("[{}] PEM_write_bio_PrivateKey failed: {}",
                       name(), openssl_error_string());
        BIO_free(bio);
        EVP_PKEY_free(key);
        return false;
    }

    char* pem_data = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    std::string pem(pem_data, static_cast<std::size_t>(pem_len));
    BIO_free(bio);

    if (!write_raw_file(account_key_path_, pem)) {
        spdlog::error("[{}] failed to write account key to {}",
                       name(), account_key_path_.string());
        EVP_PKEY_free(key);
        return false;
    }

    // Set restrictive permissions on the key file
    fs::permissions(account_key_path_,
                     fs::perms::owner_read | fs::perms::owner_write,
                     fs::perm_options::replace);

    account_key_ = key;
    spdlog::info("[{}] account key saved to {}", name(), account_key_path_.string());
    return true;
}

// ---------------------------------------------------------------------------
// JWK thumbprint (RFC 7638)
// ---------------------------------------------------------------------------

std::string AcmeService::compute_thumbprint() const {
    if (!account_key_) return {};

    // Extract the EC public key coordinates (x, y) for the JWK
    BIGNUM* x_bn = nullptr;
    BIGNUM* y_bn = nullptr;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x: use EVP_PKEY_get_bn_param
    if (!EVP_PKEY_get_bn_param(account_key_, OSSL_PKEY_PARAM_EC_PUB_X, &x_bn) ||
        !EVP_PKEY_get_bn_param(account_key_, OSSL_PKEY_PARAM_EC_PUB_Y, &y_bn)) {
        spdlog::error("[{}] failed to extract EC public key coordinates", name());
        BN_free(x_bn);
        BN_free(y_bn);
        return {};
    }
#else
    // OpenSSL 1.x fallback
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(account_key_);
    if (!ec) return {};
    const EC_POINT* pub = EC_KEY_get0_public_key(ec);
    const EC_GROUP* grp = EC_KEY_get0_group(ec);
    x_bn = BN_new();
    y_bn = BN_new();
    if (!EC_POINT_get_affine_coordinates(grp, pub, x_bn, y_bn, nullptr)) {
        BN_free(x_bn);
        BN_free(y_bn);
        return {};
    }
#endif

    // Convert to fixed 32-byte big-endian arrays
    std::vector<uint8_t> x_bytes(32, 0);
    std::vector<uint8_t> y_bytes(32, 0);
    BN_bn2binpad(x_bn, x_bytes.data(), 32);
    BN_bn2binpad(y_bn, y_bytes.data(), 32);
    BN_free(x_bn);
    BN_free(y_bn);

    // JWK thumbprint input (RFC 7638): lexicographically sorted members
    // For EC P-256: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
    std::string thumbprint_input = R"({"crv":"P-256","kty":"EC","x":")"
        + base64url_encode(x_bytes)
        + R"(","y":")"
        + base64url_encode(y_bytes)
        + R"("})";

    // SHA-256 hash
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, thumbprint_input.data(), thumbprint_input.size());
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(ctx);

    return base64url_encode(hash.data(), hash_len);
}

std::string AcmeService::compute_key_authorization_digest(
    const std::string& token) const {
    auto thumbprint = compute_thumbprint();
    if (thumbprint.empty()) return {};

    // Key authorization = token || "." || thumbprint
    std::string key_auth = token + "." + thumbprint;

    // DNS-01 digest = base64url(SHA-256(key_authorization))
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, key_auth.data(), key_auth.size());
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(ctx);

    return base64url_encode(hash.data(), hash_len);
}

// ---------------------------------------------------------------------------
// JWS signing (RFC 7515, ES256)
// ---------------------------------------------------------------------------

std::string AcmeService::sign_jws(const std::string& url,
                                    const std::string& payload) {
    if (!account_key_) {
        spdlog::error("[{}] cannot sign JWS: no account key", name());
        return {};
    }

    auto nonce = get_nonce();
    if (nonce.empty()) {
        spdlog::error("[{}] cannot sign JWS: no nonce available", name());
        return {};
    }

    // Build protected header
    json header;
    header["alg"] = "ES256";
    header["nonce"] = nonce;
    header["url"] = url;

    if (!account_url_.empty()) {
        // Use kid (account URL) for all requests after registration
        header["kid"] = account_url_;
    } else {
        // For new-account, include the full JWK
        BIGNUM* x_bn = nullptr;
        BIGNUM* y_bn = nullptr;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        EVP_PKEY_get_bn_param(account_key_, OSSL_PKEY_PARAM_EC_PUB_X, &x_bn);
        EVP_PKEY_get_bn_param(account_key_, OSSL_PKEY_PARAM_EC_PUB_Y, &y_bn);
#else
        const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(account_key_);
        const EC_POINT* pub = EC_KEY_get0_public_key(ec);
        const EC_GROUP* grp = EC_KEY_get0_group(ec);
        x_bn = BN_new();
        y_bn = BN_new();
        EC_POINT_get_affine_coordinates(grp, pub, x_bn, y_bn, nullptr);
#endif

        std::vector<uint8_t> x_bytes(32, 0);
        std::vector<uint8_t> y_bytes(32, 0);
        BN_bn2binpad(x_bn, x_bytes.data(), 32);
        BN_bn2binpad(y_bn, y_bytes.data(), 32);
        BN_free(x_bn);
        BN_free(y_bn);

        json jwk;
        jwk["kty"] = "EC";
        jwk["crv"] = "P-256";
        jwk["x"] = base64url_encode(x_bytes);
        jwk["y"] = base64url_encode(y_bytes);
        header["jwk"] = jwk;
    }

    // Encode protected header and payload
    std::string protected_b64 = base64url_encode(header.dump());
    std::string payload_b64 = payload.empty()
        ? ""
        : base64url_encode(payload);

    // Signing input: protected || "." || payload
    std::string signing_input = protected_b64 + "." + payload_b64;

    // Sign with ECDSA using SHA-256
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return {};

    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, account_key_) != 1) {
        spdlog::error("[{}] EVP_DigestSignInit failed: {}", name(), openssl_error_string());
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    if (EVP_DigestSignUpdate(md_ctx, signing_input.data(), signing_input.size()) != 1) {
        spdlog::error("[{}] EVP_DigestSignUpdate failed", name());
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    // Get the DER-encoded signature length
    std::size_t der_sig_len = 0;
    if (EVP_DigestSignFinal(md_ctx, nullptr, &der_sig_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    std::vector<uint8_t> der_sig(der_sig_len);
    if (EVP_DigestSignFinal(md_ctx, der_sig.data(), &der_sig_len) != 1) {
        spdlog::error("[{}] EVP_DigestSignFinal failed: {}", name(), openssl_error_string());
        EVP_MD_CTX_free(md_ctx);
        return {};
    }
    der_sig.resize(der_sig_len);
    EVP_MD_CTX_free(md_ctx);

    // Convert DER ECDSA signature to fixed-size R||S format (64 bytes for P-256)
    // DER format: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    const uint8_t* der_ptr = der_sig.data();
    ECDSA_SIG* ecdsa_sig = d2i_ECDSA_SIG(nullptr, &der_ptr, static_cast<long>(der_sig.size()));
    if (!ecdsa_sig) {
        spdlog::error("[{}] failed to decode DER signature", name());
        return {};
    }

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(ecdsa_sig, &r, &s);

    std::vector<uint8_t> rs(64, 0);
    BN_bn2binpad(r, rs.data(), 32);
    BN_bn2binpad(s, rs.data() + 32, 32);
    ECDSA_SIG_free(ecdsa_sig);

    std::string sig_b64 = base64url_encode(rs);

    // Build flattened JWS JSON
    json jws;
    jws["protected"] = protected_b64;
    jws["payload"] = payload_b64;
    jws["signature"] = sig_b64;

    return jws.dump();
}

// ---------------------------------------------------------------------------
// ACME HTTP helpers
// ---------------------------------------------------------------------------

std::optional<AcmeService::AcmeResponse>
AcmeService::acme_post(const std::string& url, const std::string& payload) {
    auto jws = sign_jws(url, payload);
    if (jws.empty()) {
        spdlog::error("[{}] failed to sign JWS for {}", name(), url);
        return std::nullopt;
    }

    // Determine which host to use
    auto host = url_host(url);
    httplib::SSLClient client(host);
    client.set_connection_timeout(15, 0);
    client.set_read_timeout(30, 0);

    auto path = url_path(url);
    auto res = client.Post(path, jws, "application/jose+json");

    if (!res) {
        spdlog::error("[{}] POST {} failed: network error", name(), url);
        return std::nullopt;
    }

    AcmeResponse response;
    response.status = res->status;
    response.body = res->body;

    // Capture Location header
    auto loc_it = res->headers.find("Location");
    if (loc_it == res->headers.end()) {
        loc_it = res->headers.find("location");
    }
    if (loc_it != res->headers.end()) {
        response.location = loc_it->second;
    }

    // Capture and cache the new nonce
    auto nonce_it = res->headers.find("Replay-Nonce");
    if (nonce_it == res->headers.end()) {
        nonce_it = res->headers.find("replay-nonce");
    }
    if (nonce_it != res->headers.end()) {
        response.replay_nonce = nonce_it->second;
        current_nonce_ = nonce_it->second;
    }

    return response;
}

std::optional<AcmeService::AcmeResponse>
AcmeService::acme_post_as_get(const std::string& url) {
    // POST-as-GET: empty payload string (encoded as empty base64url "")
    return acme_post(url, "");
}

// ---------------------------------------------------------------------------
// External Account Binding (EAB) — RFC 8555 §7.3.4
// ---------------------------------------------------------------------------

std::optional<nlohmann::json> AcmeService::build_eab_jws() {
    if (!provider_config_.requires_eab()) {
        return std::nullopt;
    }

    if (!account_key_) {
        spdlog::error("[{}] cannot build EAB: no account key", name());
        return std::nullopt;
    }

    // Decode the EAB HMAC key from base64url
    // First, convert base64url back to standard base64
    std::string hmac_b64 = provider_config_.eab_hmac_key;
    for (auto& ch : hmac_b64) {
        if (ch == '-') ch = '+';
        else if (ch == '_') ch = '/';
    }
    // Add padding
    while (hmac_b64.size() % 4 != 0) {
        hmac_b64.push_back('=');
    }

    // Decode from base64
    auto hmac_key_bytes = crypto::from_base64(hmac_b64);
    if (hmac_key_bytes.empty()) {
        spdlog::error("[{}] failed to decode EAB HMAC key from base64url", name());
        return std::nullopt;
    }

    // Build the JWK of the account key (the EAB payload)
    BIGNUM* x_bn = nullptr;
    BIGNUM* y_bn = nullptr;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!EVP_PKEY_get_bn_param(account_key_, OSSL_PKEY_PARAM_EC_PUB_X, &x_bn) ||
        !EVP_PKEY_get_bn_param(account_key_, OSSL_PKEY_PARAM_EC_PUB_Y, &y_bn)) {
        spdlog::error("[{}] failed to extract EC key coords for EAB", name());
        BN_free(x_bn);
        BN_free(y_bn);
        return std::nullopt;
    }
#else
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(account_key_);
    if (!ec) return std::nullopt;
    const EC_POINT* pub = EC_KEY_get0_public_key(ec);
    const EC_GROUP* grp = EC_KEY_get0_group(ec);
    x_bn = BN_new();
    y_bn = BN_new();
    if (!EC_POINT_get_affine_coordinates(grp, pub, x_bn, y_bn, nullptr)) {
        BN_free(x_bn);
        BN_free(y_bn);
        return std::nullopt;
    }
#endif

    std::vector<uint8_t> x_bytes(32, 0);
    std::vector<uint8_t> y_bytes(32, 0);
    BN_bn2binpad(x_bn, x_bytes.data(), 32);
    BN_bn2binpad(y_bn, y_bytes.data(), 32);
    BN_free(x_bn);
    BN_free(y_bn);

    json jwk;
    jwk["kty"] = "EC";
    jwk["crv"] = "P-256";
    jwk["x"] = base64url_encode(x_bytes);
    jwk["y"] = base64url_encode(y_bytes);

    // EAB protected header
    json eab_header;
    eab_header["alg"] = "HS256";
    eab_header["kid"] = provider_config_.eab_kid;
    eab_header["url"] = new_account_url_;

    std::string protected_b64 = base64url_encode(eab_header.dump());
    std::string payload_b64 = base64url_encode(jwk.dump());

    // Signing input
    std::string signing_input = protected_b64 + "." + payload_b64;

    // HMAC-SHA256 using OpenSSL
    unsigned int hmac_len = 0;
    unsigned char hmac_out[EVP_MAX_MD_SIZE];

    HMAC(EVP_sha256(),
         hmac_key_bytes.data(), static_cast<int>(hmac_key_bytes.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(),
         hmac_out, &hmac_len);

    if (hmac_len == 0) {
        spdlog::error("[{}] HMAC-SHA256 for EAB failed", name());
        return std::nullopt;
    }

    std::string sig_b64 = base64url_encode(hmac_out, hmac_len);

    // Build the flattened JWS
    json eab;
    eab["protected"] = protected_b64;
    eab["payload"] = payload_b64;
    eab["signature"] = sig_b64;

    return eab;
}

// ---------------------------------------------------------------------------
// Account registration
// ---------------------------------------------------------------------------

bool AcmeService::create_account() {
    if (!account_url_.empty()) {
        return true; // Already registered
    }

    // Try loading a saved account URL
    auto account_url_path = storage_.data_root() / "certs" / "account_url.txt";
    if (fs::exists(account_url_path)) {
        auto saved_url = read_raw_file(account_url_path);
        if (!saved_url.empty()) {
            // Trim whitespace
            while (!saved_url.empty() && (saved_url.back() == '\n' || saved_url.back() == '\r')) {
                saved_url.pop_back();
            }
            account_url_ = saved_url;
            spdlog::info("[{}] loaded account URL: {}", name(), account_url_);
            return true;
        }
    }

    spdlog::info("[{}] registering ACME account", name());

    json payload;
    payload["termsOfServiceAgreed"] = true;

    // Contact email is optional; include if env var is set
    const char* email = std::getenv("ACME_EMAIL");
    if (email && std::strlen(email) > 0) {
        payload["contact"] = json::array({"mailto:" + std::string(email)});
    }

    // External Account Binding (required by ZeroSSL and some other CAs)
    if (provider_config_.requires_eab()) {
        auto eab = build_eab_jws();
        if (!eab) {
            spdlog::error("[{}] failed to build EAB JWS for provider '{}'",
                           name(), provider_config_.name);
            return false;
        }
        payload["externalAccountBinding"] = *eab;
        spdlog::info("[{}] included EAB in account registration (kid: {})",
                      name(), provider_config_.eab_kid);
    }

    auto response = acme_post(new_account_url_, payload.dump());
    if (!response) {
        spdlog::error("[{}] account registration request failed", name());
        return false;
    }

    if (response->status != 200 && response->status != 201) {
        spdlog::error("[{}] account registration returned status {}: {}",
                       name(), response->status, response->body);
        return false;
    }

    account_url_ = response->location;
    if (account_url_.empty()) {
        spdlog::error("[{}] no Location header in account response", name());
        return false;
    }

    // Persist the account URL
    write_raw_file(account_url_path, account_url_);

    spdlog::info("[{}] ACME account registered: {}", name(), account_url_);
    return true;
}

// ---------------------------------------------------------------------------
// CSR generation
// ---------------------------------------------------------------------------

std::vector<uint8_t> AcmeService::create_csr(const std::string& domain,
                                               std::string& out_privkey) {
    // Generate a new ECDSA P-256 key for this certificate
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) {
        spdlog::error("[{}] EVP_PKEY_CTX_new_id failed for CSR key", name());
        return {};
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    EVP_PKEY* cert_key = nullptr;
    if (EVP_PKEY_keygen(pctx, &cert_key) <= 0) {
        spdlog::error("[{}] failed to generate certificate key: {}",
                       name(), openssl_error_string());
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    EVP_PKEY_CTX_free(pctx);

    // Export private key to PEM
    BIO* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, cert_key, nullptr, nullptr, 0, nullptr, nullptr);
    char* key_pem_data = nullptr;
    long key_pem_len = BIO_get_mem_data(key_bio, &key_pem_data);
    out_privkey.assign(key_pem_data, static_cast<std::size_t>(key_pem_len));
    BIO_free(key_bio);

    // Create X509_REQ (CSR)
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(cert_key);
        return {};
    }

    X509_REQ_set_version(req, 0); // v1

    // Set subject CN
    X509_NAME* subj = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>(domain.c_str()),
                                -1, -1, 0);

    // Add Subject Alternative Name extension
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    std::string san_value = "DNS:" + domain;
    X509_EXTENSION* san_ext = X509V3_EXT_nconf_nid(
        nullptr, nullptr, NID_subject_alt_name,
        san_value.c_str());
    if (san_ext) {
        sk_X509_EXTENSION_push(exts, san_ext);
        X509_REQ_add_extensions(req, exts);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    // Set public key and sign the CSR
    X509_REQ_set_pubkey(req, cert_key);
    if (!X509_REQ_sign(req, cert_key, EVP_sha256())) {
        spdlog::error("[{}] failed to sign CSR: {}", name(), openssl_error_string());
        X509_REQ_free(req);
        EVP_PKEY_free(cert_key);
        return {};
    }

    EVP_PKEY_free(cert_key);

    // Encode CSR to DER
    unsigned char* der_data = nullptr;
    int der_len = i2d_X509_REQ(req, &der_data);
    X509_REQ_free(req);

    if (der_len <= 0 || !der_data) {
        spdlog::error("[{}] failed to encode CSR to DER", name());
        return {};
    }

    std::vector<uint8_t> csr_der(der_data, der_data + der_len);
    OPENSSL_free(der_data);

    return csr_der;
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

std::optional<nlohmann::json> AcmeService::poll_until(
    const std::string& url,
    const std::string& target_status,
    int max_attempts,
    int delay_secs) {

    for (int i = 0; i < max_attempts; ++i) {
        auto response = acme_post_as_get(url);
        if (!response) {
            spdlog::warn("[{}] poll request to {} failed on attempt {}/{}",
                          name(), url, i + 1, max_attempts);
            std::this_thread::sleep_for(std::chrono::seconds(delay_secs));
            continue;
        }

        auto body = json::parse(response->body, nullptr, false);
        if (body.is_discarded()) {
            spdlog::warn("[{}] invalid JSON in poll response", name());
            std::this_thread::sleep_for(std::chrono::seconds(delay_secs));
            continue;
        }

        auto status = body.value("status", "");
        spdlog::debug("[{}] poll {}: status='{}' (want '{}')",
                       name(), url, status, target_status);

        if (status == target_status) {
            return body;
        }

        if (status == "invalid") {
            spdlog::error("[{}] resource reached 'invalid' state: {}",
                           name(), body.dump());
            return std::nullopt;
        }

        std::this_thread::sleep_for(std::chrono::seconds(delay_secs));
    }

    spdlog::error("[{}] polling timed out after {} attempts for {}",
                   name(), max_attempts, url);
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Cloudflare DNS API
// ---------------------------------------------------------------------------

std::string AcmeService::extract_base_domain(const std::string& fqdn) {
    // Remove trailing dot if present
    std::string name = fqdn;
    if (!name.empty() && name.back() == '.') {
        name.pop_back();
    }

    // Split by dots and take the last two components
    // This is a simple heuristic. For complex TLDs (co.uk, etc.)
    // a proper public suffix list would be needed.
    auto parts = std::vector<std::string>();
    std::istringstream iss(name);
    std::string part;
    while (std::getline(iss, part, '.')) {
        parts.push_back(part);
    }

    if (parts.size() >= 2) {
        return parts[parts.size() - 2] + "." + parts[parts.size() - 1];
    }
    return name;
}

std::string AcmeService::cf_get_zone_id(const std::string& domain) {
    const char* api_token = std::getenv("CLOUDFLARE_API_TOKEN");
    if (!api_token || std::strlen(api_token) == 0) {
        spdlog::error("[{}] CLOUDFLARE_API_TOKEN environment variable not set", name());
        return {};
    }

    auto base_domain = extract_base_domain(domain);

    httplib::SSLClient client(kCloudflareApiHost, kCloudflareApiPort);
    client.set_connection_timeout(10, 0);
    client.set_read_timeout(10, 0);

    httplib::Headers headers = {
        {"Authorization", std::string("Bearer ") + api_token},
        {"Content-Type", "application/json"}
    };

    std::string path = "/client/v4/zones?name=" + base_domain;
    auto res = client.Get(path, headers);

    if (!res || res->status != 200) {
        spdlog::error("[{}] Cloudflare zone lookup failed (status: {})",
                       name(), res ? res->status : 0);
        return {};
    }

    auto body = json::parse(res->body, nullptr, false);
    if (body.is_discarded() || !body.value("success", false)) {
        spdlog::error("[{}] Cloudflare zone lookup response error: {}", name(), res->body);
        return {};
    }

    auto result = body.value("result", json::array());
    if (result.empty()) {
        spdlog::error("[{}] no Cloudflare zone found for domain '{}'",
                       name(), base_domain);
        return {};
    }

    auto zone_id = result[0].value("id", "");
    spdlog::debug("[{}] Cloudflare zone ID for '{}': {}", name(), base_domain, zone_id);
    return zone_id;
}

std::string AcmeService::cf_create_txt_record(const std::string& zone_id,
                                                 const std::string& fqdn,
                                                 const std::string& value) {
    const char* api_token = std::getenv("CLOUDFLARE_API_TOKEN");
    if (!api_token) return {};

    httplib::SSLClient client(kCloudflareApiHost, kCloudflareApiPort);
    client.set_connection_timeout(10, 0);
    client.set_read_timeout(10, 0);

    httplib::Headers headers = {
        {"Authorization", std::string("Bearer ") + api_token},
        {"Content-Type", "application/json"}
    };

    json record;
    record["type"] = "TXT";
    record["name"] = fqdn;
    record["content"] = value;
    record["ttl"] = 120;

    std::string path = "/client/v4/zones/" + zone_id + "/dns_records";
    auto res = client.Post(path, headers, record.dump(), "application/json");

    if (!res || (res->status != 200 && res->status != 201)) {
        spdlog::error("[{}] Cloudflare DNS record creation failed (status: {}): {}",
                       name(), res ? res->status : 0,
                       res ? res->body : "network error");
        return {};
    }

    auto body = json::parse(res->body, nullptr, false);
    if (body.is_discarded() || !body.value("success", false)) {
        spdlog::error("[{}] Cloudflare DNS record creation error: {}", name(), res->body);
        return {};
    }

    auto record_id = body["result"].value("id", "");
    spdlog::info("[{}] created Cloudflare TXT record '{}' = '{}' (id: {})",
                  name(), fqdn, value, record_id);
    return record_id;
}

bool AcmeService::cf_delete_record(const std::string& zone_id,
                                     const std::string& record_id) {
    const char* api_token = std::getenv("CLOUDFLARE_API_TOKEN");
    if (!api_token) return false;

    httplib::SSLClient client(kCloudflareApiHost, kCloudflareApiPort);
    client.set_connection_timeout(10, 0);
    client.set_read_timeout(10, 0);

    httplib::Headers headers = {
        {"Authorization", std::string("Bearer ") + api_token},
        {"Content-Type", "application/json"}
    };

    std::string path = "/client/v4/zones/" + zone_id + "/dns_records/" + record_id;
    auto res = client.Delete(path, headers);

    if (!res || (res->status != 200 && res->status != 204)) {
        spdlog::error("[{}] Cloudflare DNS record deletion failed (status: {})",
                       name(), res ? res->status : 0);
        return false;
    }

    spdlog::info("[{}] deleted Cloudflare DNS record {}", name(), record_id);
    return true;
}

// ---------------------------------------------------------------------------
// IAcmeProvider: DNS TXT record management
// ---------------------------------------------------------------------------

bool AcmeService::do_set_dns_txt_record(const std::string& fqdn,
                                          const std::string& value) {
    std::lock_guard lock(mutex_);
    return set_dns_txt_record_unlocked(fqdn, value);
}

bool AcmeService::do_remove_dns_txt_record(const std::string& fqdn) {
    std::lock_guard lock(mutex_);
    return remove_dns_txt_record_unlocked(fqdn);
}

// Internal non-locking versions for use within do_request_certificate
bool AcmeService::set_dns_txt_record_unlocked(const std::string& fqdn,
                                                const std::string& value) {
    spdlog::info("[{}] setting DNS TXT record '{}' = '{}'", name(), fqdn, value);

    if (dns_provider_ == "local") {
        return set_local_dns_txt(fqdn, value);
    }
    if (dns_provider_ == "cloudflare") {
        auto zone_id = cf_get_zone_id(fqdn);
        if (zone_id.empty()) return false;

        auto record_id = cf_create_txt_record(zone_id, fqdn, value);
        if (record_id.empty()) return false;

        dns_records_[fqdn] = DnsRecordInfo{zone_id, record_id};

        spdlog::info("[{}] waiting 15 seconds for DNS propagation...", name());
        std::this_thread::sleep_for(std::chrono::seconds(15));
        return true;
    }

    spdlog::error("[{}] unsupported DNS provider '{}'", name(), dns_provider_);
    return false;
}

bool AcmeService::remove_dns_txt_record_unlocked(const std::string& fqdn) {
    spdlog::info("[{}] removing DNS TXT record '{}'", name(), fqdn);

    if (dns_provider_ == "local") {
        return remove_local_dns_txt(fqdn);
    }
    if (dns_provider_ == "cloudflare") {
        auto it = dns_records_.find(fqdn);
        if (it == dns_records_.end()) {
            spdlog::warn("[{}] no tracked DNS record for '{}', nothing to remove",
                          name(), fqdn);
            return true;
        }
        bool ok = cf_delete_record(it->second.zone_id, it->second.record_id);
        dns_records_.erase(it);
        return ok;
    }

    spdlog::error("[{}] unsupported DNS provider '{}'", name(), dns_provider_);
    return false;
}

// ---------------------------------------------------------------------------
// Local DNS (via DnsService + gossip sync)
// ---------------------------------------------------------------------------

bool AcmeService::set_local_dns_txt(const std::string& fqdn, const std::string& value) {
    if (!dns_service_) {
        spdlog::error("[{}] dns_provider is 'local' but no DnsService configured", name());
        return false;
    }

    // Set the TXT record in local DNS — this triggers gossip broadcast
    // to all Tier 1 nameservers automatically via the record callback
    bool ok = dns_service_->set_record(fqdn, "TXT", value, 60);
    if (!ok) {
        spdlog::error("[{}] failed to set local DNS TXT for '{}'", name(), fqdn);
        return false;
    }

    // Brief wait for gossip propagation to peer nameservers
    spdlog::info("[{}] waiting 5 seconds for gossip DNS propagation...", name());
    std::this_thread::sleep_for(std::chrono::seconds(5));

    return true;
}

bool AcmeService::remove_local_dns_txt(const std::string& fqdn) {
    if (!dns_service_) {
        spdlog::error("[{}] dns_provider is 'local' but no DnsService configured", name());
        return false;
    }

    dns_service_->remove_record(fqdn, "TXT");
    return true;
}

// ---------------------------------------------------------------------------
// IAcmeProvider: certificate request (full ACME flow)
// ---------------------------------------------------------------------------

bool AcmeService::is_valid_domain(const std::string& domain) {
    if (domain.empty() || domain.size() > 253) return false;
    static const std::regex domain_re(R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$)");
    return std::regex_match(domain, domain_re);
}

AcmeResult AcmeService::do_request_certificate(const std::string& domain) {
    std::lock_guard lock(mutex_);

    spdlog::info("[{}] requesting certificate for '{}'", name(), domain);

    AcmeResult result;
    result.domain = domain;

    // Validate domain to prevent path traversal
    if (!is_valid_domain(domain)) {
        result.error_message = "Invalid domain name: " + domain;
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    auto cert_dir = storage_.data_root() / "certs" / domain;
    result.cert_path = (cert_dir / "fullchain.pem").string();
    result.key_path  = (cert_dir / "privkey.pem").string();

    // Step 1: Get ACME directory
    if (!get_directory()) {
        result.error_message = "Failed to fetch ACME directory";
        return result;
    }

    // Step 2: Ensure account key exists
    if (!ensure_account_key()) {
        result.error_message = "Failed to create/load ACME account key";
        return result;
    }

    // Step 3: Register/load account
    if (!create_account()) {
        result.error_message = "Failed to register ACME account";
        return result;
    }

    // Step 4: Create new order
    spdlog::info("[{}] creating new order for '{}'", name(), domain);

    json order_payload;
    order_payload["identifiers"] = json::array({
        {{"type", "dns"}, {"value", domain}}
    });

    auto order_response = acme_post(new_order_url_, order_payload.dump());
    if (!order_response || (order_response->status != 200 && order_response->status != 201)) {
        result.error_message = "Failed to create ACME order: "
            + (order_response ? order_response->body : "network error");
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    auto order = json::parse(order_response->body, nullptr, false);
    if (order.is_discarded()) {
        result.error_message = "Invalid JSON in order response";
        return result;
    }

    auto order_url = order_response->location;
    auto finalize_url = order.value("finalize", "");
    auto authorizations = order.value("authorizations", json::array());

    spdlog::info("[{}] order created at {} with {} authorization(s)",
                  name(), order_url, authorizations.size());

    // Step 5: Process each authorization
    for (const auto& auth_url_val : authorizations) {
        std::string auth_url = auth_url_val.get<std::string>();

        auto auth_response = acme_post_as_get(auth_url);
        if (!auth_response || auth_response->status != 200) {
            result.error_message = "Failed to fetch authorization from " + auth_url;
            spdlog::error("[{}] {}", name(), result.error_message);
            return result;
        }

        auto auth = json::parse(auth_response->body, nullptr, false);
        if (auth.is_discarded()) {
            result.error_message = "Invalid JSON in authorization response";
            return result;
        }

        // Check if already valid
        if (auth.value("status", "") == "valid") {
            spdlog::info("[{}] authorization already valid for '{}'", name(), domain);
            continue;
        }

        // Find the DNS-01 challenge
        auto challenges = auth.value("challenges", json::array());
        json dns01_challenge;
        bool found_dns01 = false;

        for (const auto& challenge : challenges) {
            if (challenge.value("type", "") == "dns-01") {
                dns01_challenge = challenge;
                found_dns01 = true;
                break;
            }
        }

        if (!found_dns01) {
            result.error_message = "No dns-01 challenge found in authorization";
            spdlog::error("[{}] {}", name(), result.error_message);
            return result;
        }

        auto token = dns01_challenge.value("token", "");
        auto challenge_url = dns01_challenge.value("url", "");

        if (token.empty() || challenge_url.empty()) {
            result.error_message = "DNS-01 challenge missing token or URL";
            return result;
        }

        // Step 5a: Compute key authorization digest for DNS-01
        auto digest = compute_key_authorization_digest(token);
        if (digest.empty()) {
            result.error_message = "Failed to compute key authorization digest";
            return result;
        }

        // Step 5b: Set the DNS TXT record
        std::string acme_fqdn = "_acme-challenge." + domain;
        spdlog::info("[{}] setting DNS-01 challenge: {} = {}", name(), acme_fqdn, digest);

        {
            bool dns_ok = set_dns_txt_record_unlocked(acme_fqdn, digest);
            if (!dns_ok) {
                result.error_message = "Failed to set DNS TXT record for " + acme_fqdn;
                spdlog::error("[{}] {}", name(), result.error_message);
                return result;
            }
        }

        // Step 5c: Notify ACME server that challenge is ready
        spdlog::info("[{}] notifying ACME server challenge is ready", name());

        json challenge_payload = json::object(); // empty JSON object = {}
        auto challenge_response = acme_post(challenge_url, challenge_payload.dump());
        if (!challenge_response ||
            (challenge_response->status != 200 && challenge_response->status != 202)) {
            result.error_message = "Failed to notify challenge ready";
            spdlog::error("[{}] {} (status: {})", name(), result.error_message,
                           challenge_response ? challenge_response->status : 0);
            // Clean up DNS record
            (void)remove_dns_txt_record_unlocked(acme_fqdn);
            return result;
        }

        // Step 5d: Poll authorization until valid
        spdlog::info("[{}] polling authorization until valid...", name());
        auto valid_auth = poll_until(auth_url, "valid", 30, 2);
        if (!valid_auth) {
            result.error_message = "Authorization validation timed out or failed for " + domain;
            spdlog::error("[{}] {}", name(), result.error_message);
            (void)remove_dns_txt_record_unlocked(acme_fqdn);
            return result;
        }

        // Step 5e: Clean up DNS record
        spdlog::info("[{}] authorization valid, cleaning up DNS record", name());
        (void)remove_dns_txt_record_unlocked(acme_fqdn);
    }

    // Step 6: Wait for order to be ready (all authorizations valid)
    spdlog::info("[{}] waiting for order to become ready...", name());
    auto ready_order = poll_until(order_url, "ready", 15, 2);
    if (!ready_order) {
        result.error_message = "Order did not become ready";
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    // Step 7: Generate certificate key and CSR
    spdlog::info("[{}] generating certificate key and CSR for '{}'", name(), domain);
    std::string cert_privkey_pem;
    auto csr_der = create_csr(domain, cert_privkey_pem);
    if (csr_der.empty()) {
        result.error_message = "Failed to generate CSR";
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    // Step 8: Finalize order with CSR
    spdlog::info("[{}] finalizing order with CSR", name());

    json finalize_payload;
    finalize_payload["csr"] = base64url_encode(csr_der);

    auto finalize_response = acme_post(finalize_url, finalize_payload.dump());
    if (!finalize_response ||
        (finalize_response->status != 200 && finalize_response->status != 202)) {
        result.error_message = "Failed to finalize order: "
            + (finalize_response ? finalize_response->body : "network error");
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    // Step 9: Poll order until valid (certificate issued)
    spdlog::info("[{}] waiting for certificate to be issued...", name());
    auto valid_order = poll_until(order_url, "valid", 30, 2);
    if (!valid_order) {
        result.error_message = "Order did not reach valid state (certificate not issued)";
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    auto certificate_url = valid_order->value("certificate", "");
    if (certificate_url.empty()) {
        result.error_message = "No certificate URL in valid order";
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    // Step 10: Download certificate
    spdlog::info("[{}] downloading certificate from {}", name(), certificate_url);

    auto cert_response = acme_post_as_get(certificate_url);
    if (!cert_response || cert_response->status != 200) {
        result.error_message = "Failed to download certificate";
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    std::string fullchain_pem = cert_response->body;

    // Step 11: Store certificate files
    spdlog::info("[{}] storing certificate files for '{}'", name(), domain);

    if (!fs::exists(cert_dir)) {
        fs::create_directories(cert_dir);
    }

    auto fullchain_path = cert_dir / "fullchain.pem";
    auto privkey_path = cert_dir / "privkey.pem";
    auto meta_path = cert_dir / "meta.json";

    if (!write_raw_file(fullchain_path, fullchain_pem)) {
        result.error_message = "Failed to write fullchain.pem";
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    if (!write_raw_file(privkey_path, cert_privkey_pem)) {
        result.error_message = "Failed to write privkey.pem";
        spdlog::error("[{}] {}", name(), result.error_message);
        return result;
    }

    // Set restrictive permissions on the private key
    fs::permissions(privkey_path,
                     fs::perms::owner_read | fs::perms::owner_write,
                     fs::perm_options::replace);

    // Step 12: Write meta.json with expiry
    auto expiry = parse_cert_expiry(fullchain_pem);
    json meta;
    meta["domain"] = domain;
    meta["issued_at"] = now_unix();
    meta["expires_at"] = expiry;
    meta["staging"] = provider_config_.staging;

    if (!write_raw_file(meta_path, meta.dump(2))) {
        spdlog::warn("[{}] failed to write meta.json (certificate still saved)", name());
    }

    result.success = true;
    spdlog::info("[{}] certificate for '{}' issued successfully (expires: {})",
                  name(), domain, expiry);
    return result;
}

// ---------------------------------------------------------------------------
// IAcmeProvider: certificate renewal
// ---------------------------------------------------------------------------

AcmeResult AcmeService::do_renew_certificate(const std::string& domain) {
    spdlog::info("[{}] certificate renewal requested for '{}'", name(), domain);

    // Check existing certificate
    auto cert_dir = storage_.data_root() / "certs" / domain;
    auto fullchain_path = cert_dir / "fullchain.pem";
    auto privkey_path   = cert_dir / "privkey.pem";

    if (!fs::exists(fullchain_path) || !fs::exists(privkey_path)) {
        spdlog::warn("[{}] no existing certificate for '{}', performing initial request",
                      name(), domain);
        return do_request_certificate(domain);
    }

    // Check expiry from meta.json or from the certificate itself
    auto meta_path = cert_dir / "meta.json";
    uint64_t expires_at = 0;

    if (fs::exists(meta_path)) {
        auto meta_contents = read_raw_file(meta_path);
        if (!meta_contents.empty()) {
            auto j = json::parse(meta_contents, nullptr, false);
            if (!j.is_discarded()) {
                expires_at = j.value("expires_at", uint64_t{0});
            }
        }
    }

    if (expires_at == 0) {
        // Try parsing from the certificate
        auto pem = read_raw_file(fullchain_path);
        if (!pem.empty()) {
            expires_at = parse_cert_expiry(pem);
        }
    }

    auto now = now_unix();
    if (expires_at > 0 && expires_at > now + kRenewalThresholdSecs) {
        AcmeResult result;
        result.domain = domain;
        result.success = true;
        result.cert_path = fullchain_path.string();
        result.key_path = privkey_path.string();
        spdlog::info("[{}] certificate for '{}' is still valid (expires in {} days), "
                      "skipping renewal",
                      name(), domain, (expires_at - now) / 86400);
        return result;
    }

    spdlog::info("[{}] certificate for '{}' expires in {} days, renewing...",
                  name(), domain,
                  expires_at > now ? (expires_at - now) / 86400 : 0);

    // Renewal is the same flow as a fresh request
    return do_request_certificate(domain);
}

// ---------------------------------------------------------------------------
// IAcmeProvider: get certificate
// ---------------------------------------------------------------------------

std::optional<CertBundle> AcmeService::do_get_certificate(const std::string& domain) {
    std::lock_guard lock(mutex_);

    auto cert_dir = storage_.data_root() / "certs" / domain;
    auto fullchain_path = cert_dir / "fullchain.pem";
    auto privkey_path   = cert_dir / "privkey.pem";

    if (!fs::exists(fullchain_path) || !fs::exists(privkey_path)) {
        spdlog::debug("[{}] no certificate files found for '{}'", name(), domain);
        return std::nullopt;
    }

    auto fullchain = read_raw_file(fullchain_path);
    auto privkey   = read_raw_file(privkey_path);

    if (fullchain.empty() || privkey.empty()) {
        spdlog::warn("[{}] certificate files for '{}' exist but are empty or unreadable",
                      name(), domain);
        return std::nullopt;
    }

    CertBundle bundle;
    bundle.fullchain_pem = std::move(fullchain);
    bundle.privkey_pem   = std::move(privkey);

    // Attempt to read the expiry timestamp from a metadata file
    auto meta_path = cert_dir / "meta.json";
    if (fs::exists(meta_path)) {
        auto meta_contents = read_raw_file(meta_path);
        if (!meta_contents.empty()) {
            try {
                auto j = json::parse(meta_contents, nullptr, false);
                if (!j.is_discarded()) {
                    bundle.expires_at = j.value("expires_at", uint64_t{0});
                }
            } catch (const std::exception& e) {
                spdlog::debug("[{}] failed to parse meta.json for '{}': {}",
                               name(), domain, e.what());
            }
        }
    }

    spdlog::debug("[{}] loaded certificate bundle for '{}' (expires_at: {})",
                   name(), domain, bundle.expires_at);
    return bundle;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

void AcmeService::scan_existing_certs() {
    auto certs_dir = storage_.data_root() / "certs";

    if (!fs::exists(certs_dir) || !fs::is_directory(certs_dir)) {
        spdlog::debug("[{}] no certs directory found at '{}'", name(), certs_dir.string());
        return;
    }

    std::size_t count = 0;
    for (const auto& entry : fs::directory_iterator(certs_dir)) {
        if (!entry.is_directory()) {
            continue;
        }

        const auto domain = entry.path().filename().string();
        auto fullchain_path = entry.path() / "fullchain.pem";
        auto privkey_path   = entry.path() / "privkey.pem";

        bool has_fullchain = fs::exists(fullchain_path);
        bool has_privkey   = fs::exists(privkey_path);

        if (has_fullchain && has_privkey) {
            // Check expiry
            auto pem = read_raw_file(fullchain_path);
            uint64_t expiry = 0;
            if (!pem.empty()) {
                expiry = parse_cert_expiry(pem);
            }

            auto now = now_unix();
            if (expiry > 0 && expiry <= now) {
                spdlog::warn("[{}] certificate for '{}' has EXPIRED", name(), domain);
            } else if (expiry > 0 && expiry <= now + kRenewalThresholdSecs) {
                spdlog::warn("[{}] certificate for '{}' expires in {} days (renewal recommended)",
                              name(), domain, (expiry - now) / 86400);
            } else {
                spdlog::info("[{}] found valid certificate for '{}'", name(), domain);
            }
            ++count;
        } else {
            spdlog::warn("[{}] incomplete certificate for '{}' "
                          "(fullchain: {}, privkey: {})",
                          name(), domain,
                          has_fullchain ? "present" : "missing",
                          has_privkey   ? "present" : "missing");
        }
    }

    spdlog::info("[{}] scanned certs directory: {} valid certificate(s) found",
                  name(), count);
}

} // namespace nexus::acme
