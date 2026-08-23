#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdint>
#include <vector>

using nexus::security::CanonicalEncoder;
using nexus::security::Digest;

namespace {

void append_lp(std::vector<uint8_t>& out, std::initializer_list<uint8_t> field) {
    const auto n = static_cast<uint32_t>(field.size());
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((n >> (i * 8)) & 0xFF));
    out.insert(out.end(), field.begin(), field.end());
}

TEST(CanonicalEncoding, ExactByteLayout) {
    CanonicalEncoder encoder("D");
    encoder.add_u16(0x0201);
    encoder.add_u32(0x04030201);
    encoder.add_u64(0x0807060504030201ULL);
    const std::vector<uint8_t> payload{0xAA, 0xBB};
    encoder.add_bytes(payload);
    encoder.add_string("x");

    std::vector<uint8_t> expected;
    append_lp(expected, {'D'});
    append_lp(expected, {0x01, 0x02});
    append_lp(expected, {0x01, 0x02, 0x03, 0x04});
    append_lp(expected, {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
    append_lp(expected, {0xAA, 0xBB});
    append_lp(expected, {'x'});

    EXPECT_EQ(encoder.bytes(), expected);
}

TEST(CanonicalEncoding, DigestIsSha256OfEncodedStream) {
    CanonicalEncoder encoder("nexus-test/domain:v1");
    encoder.add_u64(42);
    encoder.add_string("payload");

    Digest expected{};
    crypto_hash_sha256(expected.data(), encoder.bytes().data(), encoder.bytes().size());
    EXPECT_EQ(encoder.digest(), expected);
}

TEST(CanonicalEncoding, FieldBoundariesCannotShift) {
    // "ab" + "c" and "a" + "bc" concatenate to the same raw bytes; the length
    // prefixes must keep the digests distinct.
    CanonicalEncoder left("D");
    left.add_string("ab");
    left.add_string("c");

    CanonicalEncoder right("D");
    right.add_string("a");
    right.add_string("bc");

    EXPECT_NE(left.digest(), right.digest());
}

TEST(CanonicalEncoding, DomainSeparatesDigests) {
    CanonicalEncoder left("domain-one");
    left.add_u64(7);
    CanonicalEncoder right("domain-two");
    right.add_u64(7);
    EXPECT_NE(left.digest(), right.digest());
}

TEST(CanonicalEncoding, FieldOrderMatters) {
    CanonicalEncoder left("D");
    left.add_string("a");
    left.add_string("b");
    CanonicalEncoder right("D");
    right.add_string("b");
    right.add_string("a");
    EXPECT_NE(left.digest(), right.digest());
}

TEST(CanonicalEncoding, IntegerWidthMatters) {
    // The same numeric value at different declared widths must not collide.
    CanonicalEncoder as_u16("D");
    as_u16.add_u16(5);
    CanonicalEncoder as_u32("D");
    as_u32.add_u32(5);
    CanonicalEncoder as_u64("D");
    as_u64.add_u64(5);

    EXPECT_NE(as_u16.digest(), as_u32.digest());
    EXPECT_NE(as_u32.digest(), as_u64.digest());
    EXPECT_NE(as_u16.digest(), as_u64.digest());
}

TEST(CanonicalEncoding, EmptyFieldIsEncodedNotSkipped) {
    CanonicalEncoder with_empty("D");
    with_empty.add_string("");
    with_empty.add_string("tail");

    CanonicalEncoder without("D");
    without.add_string("tail");

    EXPECT_NE(with_empty.digest(), without.digest());
}

TEST(CanonicalEncoding, DeterministicAcrossInstances) {
    auto build = [] {
        CanonicalEncoder encoder("nexus-test/deterministic:v1");
        encoder.add_u16(1);
        encoder.add_u64(0xFFFFFFFFFFFFFFFFULL);
        encoder.add_string("same-input");
        return encoder.digest();
    };
    EXPECT_EQ(build(), build());
}

}  // namespace
