// The single-use identity hand-off (lnsdk::IdentityHandoff and the
// ln_identity_handoff_* C ABI): the round trip, the single-use rule, the
// binding of an envelope to its request, expiry, and malformed input. No
// test prints or compares seed bytes in the open.

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <LemonadeNexusSDK/Identity.hpp>
#include <LemonadeNexusSDK/IdentityHandoff.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

using nlohmann::json;
using lnsdk::Identity;
using lnsdk::IdentityHandoff;
using Open = IdentityHandoff::OpenResult;

namespace {

std::string take_str(char* out) {
    std::string s = out ? out : "";
    ln_free(out);
    return s;
}

struct IdentityHandle {
    ln_identity_t* id{nullptr};
    explicit IdentityHandle(ln_identity_t* p = nullptr) : id(p) {}
    ~IdentityHandle() { ln_identity_destroy(id); }
    IdentityHandle(const IdentityHandle&) = delete;
    IdentityHandle& operator=(const IdentityHandle&) = delete;
};

/// A receiver-side hand-off through the C ABI.
struct Receiver {
    ln_handoff_t* h{nullptr};
    std::string request;
    Receiver() {
        char* out = nullptr;
        h = ln_identity_handoff_begin(&out);
        request = take_str(out);
    }
    ~Receiver() { ln_identity_handoff_destroy(h); }
    Receiver(const Receiver&) = delete;
    Receiver& operator=(const Receiver&) = delete;

    ln_identity_t* open(const std::string& envelope, ln_error_t& err) {
        err = LN_ERR_INTERNAL;
        return ln_identity_handoff_open(h, envelope.c_str(), &err);
    }
};

std::string pubkey_of(ln_identity_t* id) {
    return take_str(ln_identity_pubkey(id));
}

std::vector<uint8_t> sign_probe(const Identity& id) {
    static const uint8_t message[] = "hand-off probe";
    return id.sign(std::span<const uint8_t>(message, sizeof message - 1));
}

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

class SdkIdentityHandoffTest : public ::testing::Test {
protected:
    Identity sender;
    IdentityHandle sender_abi;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        sender.generate();
        sender_abi.id = ln_identity_from_seed(sender.seed().data(), 32);
        ASSERT_NE(sender_abi.id, nullptr);
    }

    std::string seal(const std::string& request) const {
        return take_str(ln_identity_handoff_seal(sender_abi.id, request.c_str()));
    }
};

}  // namespace

TEST_F(SdkIdentityHandoffTest, RoundTripGivesTheSameIdentity) {
    Receiver receiver;
    ASSERT_NE(receiver.h, nullptr);
    const json request = json::parse(receiver.request);
    EXPECT_EQ(request.at("alg").get<std::string>(), "x25519-sealedbox-v1");
    EXPECT_EQ(Identity::from_base64(request.at("pubkey").get<std::string>()).size(), 32u);
    EXPECT_EQ(Identity::from_base64(request.at("nonce").get<std::string>()).size(), 24u);
    const auto expires_at = request.at("expires_at").get<std::int64_t>();
    EXPECT_GE(expires_at, now_seconds() + 55);
    EXPECT_LE(expires_at, now_seconds() + 61);

    const std::string envelope = seal(receiver.request);
    ASSERT_FALSE(envelope.empty());
    const json env = json::parse(envelope);
    EXPECT_EQ(env.at("alg").get<std::string>(), "x25519-sealedbox-v1");
    EXPECT_EQ(env.at("nonce").get<std::string>(), request.at("nonce").get<std::string>());
    EXPECT_EQ(Identity::from_base64(env.at("sealed").get<std::string>()).size(), 48u + 24u + 32u);
    // Nothing secret in the clear: neither the seed nor the full key.
    EXPECT_EQ(envelope.find(Identity::to_base64(sender.seed())), std::string::npos);
    EXPECT_EQ(envelope.find(Identity::to_base64(sender.private_key())), std::string::npos);
    EXPECT_EQ(receiver.request.find(Identity::to_base64(sender.seed())), std::string::npos);

    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle received(receiver.open(envelope, err));
    ASSERT_EQ(err, LN_OK);
    ASSERT_NE(received.id, nullptr);
    EXPECT_EQ(pubkey_of(received.id), sender.pubkey_string());
}

TEST_F(SdkIdentityHandoffTest, RoundTripInCppRestoresThePrivateKey) {
    IdentityHandoff handoff;
    ASSERT_TRUE(handoff.valid());
    EXPECT_FALSE(handoff.used());
    const auto envelope = IdentityHandoff::seal(sender, handoff.request_json());
    ASSERT_TRUE(envelope.has_value());
    Identity received;
    ASSERT_EQ(handoff.open(*envelope, received), Open::Ok);
    EXPECT_TRUE(handoff.used());
    EXPECT_EQ(received.private_key(), sender.private_key());
    EXPECT_EQ(sign_probe(received), sign_probe(sender));
}

TEST_F(SdkIdentityHandoffTest, SecondOpenOnTheSameHandleFails) {
    Receiver receiver;
    const std::string envelope = seal(receiver.request);
    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle first(receiver.open(envelope, err));
    ASSERT_EQ(err, LN_OK);
    ASSERT_NE(first.id, nullptr);

    IdentityHandle second(receiver.open(envelope, err));
    EXPECT_EQ(second.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED);

    // A fresh envelope for the same request fails as well: the key is gone.
    IdentityHandle third(receiver.open(seal(receiver.request), err));
    EXPECT_EQ(third.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED);
}

TEST_F(SdkIdentityHandoffTest, FailedOpenConsumesTheHandle) {
    Receiver receiver;
    const std::string envelope = seal(receiver.request);
    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle garbage(receiver.open("not json", err));
    EXPECT_EQ(garbage.id, nullptr);
    EXPECT_EQ(err, LN_ERR_PARSE);

    IdentityHandle valid(receiver.open(envelope, err));
    EXPECT_EQ(valid.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED);
}

TEST_F(SdkIdentityHandoffTest, EnvelopeForAnotherRequestFails) {
    Receiver a;
    Receiver b;
    const std::string for_a = seal(a.request);
    const std::string for_b = seal(b.request);

    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle cross(b.open(for_a, err));
    EXPECT_EQ(cross.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED) << "the envelope names another request";

    // A's sealed box relabeled with B's nonce: the nonce under the seal
    // still names A, and B's key cannot open a box sealed to A anyway.
    Receiver c;
    json relabeled = json::parse(for_a);
    relabeled["nonce"] = json::parse(c.request).at("nonce");
    IdentityHandle substituted(c.open(relabeled.dump(), err));
    EXPECT_EQ(substituted.id, nullptr);
    EXPECT_EQ(err, LN_ERR_AUTH);

    // The right envelope still opens for A.
    IdentityHandle right(a.open(for_a, err));
    ASSERT_EQ(err, LN_OK);
    ASSERT_NE(right.id, nullptr);
    EXPECT_EQ(pubkey_of(right.id), sender.pubkey_string());
}

TEST_F(SdkIdentityHandoffTest, SealedBoxForTheSameRequestButAnotherKeyFails) {
    // Two receivers with identical nonces cannot be made through the API, so
    // forge a request that reuses A's nonce with a different key: the
    // envelope passes the nonce check and fails to open.
    IdentityHandoff a;
    IdentityHandoff other;
    json forged = json::parse(other.request_json());
    forged["nonce"] = json::parse(a.request_json()).at("nonce");
    const auto envelope = IdentityHandoff::seal(sender, forged.dump());
    ASSERT_TRUE(envelope.has_value());
    Identity received;
    EXPECT_EQ(a.open(*envelope, received), Open::Unsealable);
    EXPECT_FALSE(received.is_valid());
}

TEST_F(SdkIdentityHandoffTest, ExpiredRequestFails) {
    IdentityHandoff expired(std::chrono::seconds(-1));
    ASSERT_TRUE(expired.valid());
    const auto envelope = IdentityHandoff::seal(sender, expired.request_json());
    ASSERT_TRUE(envelope.has_value()) << "the sender does not judge expiry";
    Identity received;
    EXPECT_EQ(expired.open(*envelope, received), Open::Expired);
    EXPECT_FALSE(received.is_valid());
    EXPECT_TRUE(expired.used());
    EXPECT_EQ(expired.open(*envelope, received), Open::AlreadyUsed);
}

TEST_F(SdkIdentityHandoffTest, WrongAlgFails) {
    Receiver receiver;
    json request = json::parse(receiver.request);
    request["alg"] = "x25519-sealedbox-v0";
    EXPECT_TRUE(seal(request.dump()).empty()) << "the sender refuses an unknown alg";

    json envelope = json::parse(seal(receiver.request));
    envelope["alg"] = "x25519-sealedbox-v0";
    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle opened(receiver.open(envelope.dump(), err));
    EXPECT_EQ(opened.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED);
}

TEST_F(SdkIdentityHandoffTest, TamperedEnvelopeFails) {
    Receiver receiver;
    json envelope = json::parse(seal(receiver.request));
    auto sealed = Identity::from_base64(envelope["sealed"].get<std::string>());
    sealed[sealed.size() - 1] ^= 0x01;
    envelope["sealed"] = Identity::to_base64(sealed);
    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle opened(receiver.open(envelope.dump(), err));
    EXPECT_EQ(opened.id, nullptr);
    EXPECT_EQ(err, LN_ERR_AUTH);

    Receiver other;
    json short_box = json::parse(seal(other.request));
    short_box["sealed"] = Identity::to_base64(std::vector<uint8_t>(10, 1));
    IdentityHandle opened_short(other.open(short_box.dump(), err));
    EXPECT_EQ(opened_short.id, nullptr);
    EXPECT_EQ(err, LN_ERR_PARSE);

    Receiver third;
    json missing = json::parse(seal(third.request));
    missing.erase("nonce");
    IdentityHandle opened_missing(third.open(missing.dump(), err));
    EXPECT_EQ(opened_missing.id, nullptr);
    EXPECT_EQ(err, LN_ERR_PARSE);
}

TEST_F(SdkIdentityHandoffTest, SealRefusesMalformedRequests) {
    Receiver receiver;
    json request = json::parse(receiver.request);

    json no_nonce = request;
    no_nonce.erase("nonce");
    EXPECT_TRUE(seal(no_nonce.dump()).empty());

    json short_key = request;
    short_key["pubkey"] = Identity::to_base64(std::vector<uint8_t>(16, 7));
    EXPECT_TRUE(seal(short_key.dump()).empty());

    json no_expiry = request;
    no_expiry.erase("expires_at");
    EXPECT_TRUE(seal(no_expiry.dump()).empty());

    EXPECT_TRUE(seal("[]").empty());
    EXPECT_TRUE(seal("not json").empty());

    Identity invalid;
    EXPECT_FALSE(IdentityHandoff::seal(invalid, receiver.request).has_value());
    EXPECT_FALSE(seal(receiver.request).empty()) << "the unchanged request still seals";
}

TEST_F(SdkIdentityHandoffTest, CApiNullArguments) {
    EXPECT_EQ(ln_identity_handoff_begin(nullptr), nullptr);
    Receiver receiver;
    ASSERT_NE(receiver.h, nullptr);
    EXPECT_EQ(ln_identity_handoff_seal(nullptr, receiver.request.c_str()), nullptr);
    EXPECT_EQ(ln_identity_handoff_seal(sender_abi.id, nullptr), nullptr);

    ln_error_t err = LN_OK;
    EXPECT_EQ(ln_identity_handoff_open(nullptr, "{}", &err), nullptr);
    EXPECT_EQ(err, LN_ERR_NULL_ARG);
    err = LN_OK;
    EXPECT_EQ(ln_identity_handoff_open(receiver.h, nullptr, &err), nullptr);
    EXPECT_EQ(err, LN_ERR_NULL_ARG);

    // A NULL argument does not consume the handle, and out_err may be NULL.
    const std::string envelope = seal(receiver.request);
    IdentityHandle opened(ln_identity_handoff_open(receiver.h, envelope.c_str(), nullptr));
    ASSERT_NE(opened.id, nullptr);
    EXPECT_EQ(pubkey_of(opened.id), sender.pubkey_string());

    ln_identity_handoff_destroy(nullptr);
}
