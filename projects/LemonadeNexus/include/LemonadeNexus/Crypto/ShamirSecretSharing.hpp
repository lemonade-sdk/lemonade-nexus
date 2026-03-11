#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nexus::crypto {

/// A single share from Shamir's Secret Sharing.
/// The x-coordinate identifies which share this is (1-based).
struct ShamirShare {
    uint8_t              x;      // share index (1..N), never 0
    std::vector<uint8_t> y;      // share data (same length as the secret)
};

/// Shamir's Secret Sharing over GF(2^8) using the AES irreducible polynomial.
///
/// Splits a secret byte-vector into N shares such that any K shares can
/// reconstruct the original. Fewer than K shares reveal no information
/// about the secret (information-theoretic security).
///
/// Implementation:
///   - Each byte of the secret is independently split using a random
///     polynomial of degree (K-1) evaluated at x = 1..N over GF(256).
///   - Reconstruction uses Lagrange interpolation over GF(256).
///   - GF(256) arithmetic uses the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1.
///
/// Constraints:
///   - 2 <= threshold <= num_shares <= 255  (x-coordinates are uint8_t, 0 is reserved)
///   - Secret must not be empty
class ShamirSecretSharing {
public:
    /// Split a secret into shares.
    /// @param secret      The secret bytes to split.
    /// @param threshold   Minimum number of shares needed to reconstruct (K).
    /// @param num_shares  Total number of shares to generate (N).
    /// @return Vector of N shares, or empty on invalid parameters.
    [[nodiscard]] static std::vector<ShamirShare>
    split(const std::vector<uint8_t>& secret, uint8_t threshold, uint8_t num_shares);

    /// Reconstruct a secret from K or more shares.
    /// @param shares  At least K shares (can provide more, only first K used).
    /// @param threshold  The K value used during split.
    /// @return The reconstructed secret, or nullopt if parameters are invalid.
    [[nodiscard]] static std::optional<std::vector<uint8_t>>
    reconstruct(const std::vector<ShamirShare>& shares, uint8_t threshold);

    /// Serialize a share to base64 string: "x:base64(y)"
    [[nodiscard]] static std::string share_to_string(const ShamirShare& share);

    /// Deserialize a share from "x:base64(y)" format.
    [[nodiscard]] static std::optional<ShamirShare> share_from_string(const std::string& s);

    // --- GF(256) arithmetic (public for testing) ---

    /// Multiply two elements in GF(2^8) with AES polynomial.
    [[nodiscard]] static uint8_t gf256_mul(uint8_t a, uint8_t b);

    /// Multiplicative inverse in GF(2^8). inv(0) = 0 by convention.
    [[nodiscard]] static uint8_t gf256_inv(uint8_t a);

    /// Addition in GF(2^8) = XOR.
    [[nodiscard]] static constexpr uint8_t gf256_add(uint8_t a, uint8_t b) { return a ^ b; }

private:
    /// Evaluate polynomial at x over GF(256).
    /// coefficients[0] = constant term (the secret byte).
    [[nodiscard]] static uint8_t
    eval_polynomial(const std::vector<uint8_t>& coefficients, uint8_t x);

    /// Lagrange interpolation at x=0 over GF(256).
    [[nodiscard]] static uint8_t
    lagrange_interpolate(const std::vector<uint8_t>& xs,
                         const std::vector<uint8_t>& ys);

    // GF(256) log/exp tables (initialized on first use)
    static const uint8_t* exp_table();
    static const uint8_t* log_table();
};

} // namespace nexus::crypto
