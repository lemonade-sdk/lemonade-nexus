#include <LemonadeNexus/Crypto/ShamirSecretSharing.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <sodium.h>

#include <array>
#include <cstring>

namespace nexus::crypto {

// ---------------------------------------------------------------------------
// GF(256) log/exp tables — AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B
// ---------------------------------------------------------------------------

static constexpr uint16_t kGF256Poly = 0x11B;

static std::array<uint8_t, 512> s_exp_table{};  // exp[i] for i in [0,511)
static std::array<uint8_t, 256> s_log_table{};  // log[x] for x in [0,255]
static bool s_tables_initialized = false;

static void init_tables() {
    if (s_tables_initialized) return;

    uint16_t x = 1;
    for (int i = 0; i < 255; ++i) {
        s_exp_table[i] = static_cast<uint8_t>(x);
        s_log_table[x] = static_cast<uint8_t>(i);
        x <<= 1;
        if (x & 0x100) {
            x ^= kGF256Poly;
        }
    }
    // Extend exp table for easy mod-free lookups
    for (int i = 255; i < 512; ++i) {
        s_exp_table[i] = s_exp_table[i - 255];
    }
    s_log_table[0] = 0; // convention: log(0) = 0, but mul(0,x) = 0 handled separately
    s_tables_initialized = true;
}

const uint8_t* ShamirSecretSharing::exp_table() {
    init_tables();
    return s_exp_table.data();
}

const uint8_t* ShamirSecretSharing::log_table() {
    init_tables();
    return s_log_table.data();
}

uint8_t ShamirSecretSharing::gf256_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    init_tables();
    int sum = static_cast<int>(s_log_table[a]) + static_cast<int>(s_log_table[b]);
    return s_exp_table[sum]; // table is extended to 512, handles sum up to 508
}

uint8_t ShamirSecretSharing::gf256_inv(uint8_t a) {
    if (a == 0) return 0;
    init_tables();
    return s_exp_table[255 - s_log_table[a]];
}

// ---------------------------------------------------------------------------
// Polynomial evaluation over GF(256) using Horner's method
// ---------------------------------------------------------------------------

uint8_t ShamirSecretSharing::eval_polynomial(const std::vector<uint8_t>& coefficients, uint8_t x) {
    // coefficients[0] = constant term, coefficients[k-1] = highest degree
    // Horner's: result = c[k-1]; for i = k-2..0: result = result*x + c[i]
    uint8_t result = 0;
    for (auto it = coefficients.rbegin(); it != coefficients.rend(); ++it) {
        result = gf256_add(gf256_mul(result, x), *it);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Lagrange interpolation at x=0 over GF(256)
// ---------------------------------------------------------------------------

uint8_t ShamirSecretSharing::lagrange_interpolate(const std::vector<uint8_t>& xs,
                                                    const std::vector<uint8_t>& ys) {
    const auto k = xs.size();
    uint8_t result = 0;

    for (std::size_t i = 0; i < k; ++i) {
        // Compute Lagrange basis polynomial L_i(0)
        // L_i(0) = product_{j!=i} (0 - x_j) / (x_i - x_j)
        //        = product_{j!=i} x_j / (x_i ^ x_j)   [in GF(256), -x = x, sub = XOR]
        uint8_t numerator = 1;
        uint8_t denominator = 1;
        for (std::size_t j = 0; j < k; ++j) {
            if (i == j) continue;
            numerator = gf256_mul(numerator, xs[j]);            // * x_j
            denominator = gf256_mul(denominator, gf256_add(xs[i], xs[j])); // * (x_i - x_j)
        }
        // L_i(0) = numerator / denominator = numerator * inv(denominator)
        uint8_t basis = gf256_mul(numerator, gf256_inv(denominator));
        result = gf256_add(result, gf256_mul(ys[i], basis));
    }

    return result;
}

// ---------------------------------------------------------------------------
// Split
// ---------------------------------------------------------------------------

std::vector<ShamirShare> ShamirSecretSharing::split(const std::vector<uint8_t>& secret,
                                                     uint8_t threshold,
                                                     uint8_t num_shares) {
    if (secret.empty() || threshold < 2 || num_shares < threshold) {
        return {};
    }

    init_tables();

    const auto secret_len = secret.size();
    std::vector<ShamirShare> shares(num_shares);
    for (uint8_t i = 0; i < num_shares; ++i) {
        shares[i].x = static_cast<uint8_t>(i + 1); // x = 1..N
        shares[i].y.resize(secret_len);
    }

    // For each byte of the secret, create a random polynomial and evaluate
    std::vector<uint8_t> coefficients(threshold);
    for (std::size_t byte_idx = 0; byte_idx < secret_len; ++byte_idx) {
        // coefficients[0] = secret byte (constant term)
        coefficients[0] = secret[byte_idx];

        // coefficients[1..k-1] = random
        randombytes_buf(coefficients.data() + 1, threshold - 1);

        // Evaluate polynomial at x = 1..N
        for (uint8_t i = 0; i < num_shares; ++i) {
            shares[i].y[byte_idx] = eval_polynomial(coefficients, shares[i].x);
        }
    }

    // Wipe polynomial coefficients
    sodium_memzero(coefficients.data(), coefficients.size());

    return shares;
}

// ---------------------------------------------------------------------------
// Reconstruct
// ---------------------------------------------------------------------------

std::optional<std::vector<uint8_t>> ShamirSecretSharing::reconstruct(
    const std::vector<ShamirShare>& shares, uint8_t threshold) {

    if (shares.size() < threshold || threshold < 2) {
        return std::nullopt;
    }

    init_tables();

    // Use exactly threshold shares
    const auto k = static_cast<std::size_t>(threshold);
    const auto secret_len = shares[0].y.size();

    // Validate all shares have same length
    for (std::size_t i = 1; i < k; ++i) {
        if (shares[i].y.size() != secret_len) {
            return std::nullopt;
        }
    }

    // Collect x-coordinates
    std::vector<uint8_t> xs(k);
    for (std::size_t i = 0; i < k; ++i) {
        xs[i] = shares[i].x;
    }

    // Check for duplicate x-coordinates
    for (std::size_t i = 0; i < k; ++i) {
        for (std::size_t j = i + 1; j < k; ++j) {
            if (xs[i] == xs[j]) return std::nullopt;
        }
    }

    // Interpolate each byte
    std::vector<uint8_t> secret(secret_len);
    std::vector<uint8_t> ys(k);

    for (std::size_t byte_idx = 0; byte_idx < secret_len; ++byte_idx) {
        for (std::size_t i = 0; i < k; ++i) {
            ys[i] = shares[i].y[byte_idx];
        }
        secret[byte_idx] = lagrange_interpolate(xs, ys);
    }

    return secret;
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

std::string ShamirSecretSharing::share_to_string(const ShamirShare& share) {
    std::string b64 = to_base64(share.y);
    return std::to_string(share.x) + ":" + b64;
}

std::optional<ShamirShare> ShamirSecretSharing::share_from_string(const std::string& s) {
    auto colon = s.find(':');
    if (colon == std::string::npos || colon == 0) return std::nullopt;

    ShamirShare share;
    int x_val = 0;
    try {
        x_val = std::stoi(s.substr(0, colon));
    } catch (...) {
        return std::nullopt;
    }
    if (x_val < 1 || x_val > 255) return std::nullopt;
    share.x = static_cast<uint8_t>(x_val);

    share.y = from_base64(s.substr(colon + 1));
    if (share.y.empty()) return std::nullopt;

    return share;
}

} // namespace nexus::crypto
