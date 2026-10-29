// Replicated link token events (Auth/LinkTokenLedger.hpp): the token hash,
// the signed event form, and the ledger state that every replica derives the
// same way from the same events, in any arrival order.

#include <LemonadeNexus/Auth/LinkTokenLedger.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <span>
#include <string>
#include <vector>

using namespace nexus;
using auth::LinkTokenEvent;
using auth::LinkTokenEventKind;
using auth::LinkTokenLedger;

namespace {

constexpr uint64_t kNow = 1'800'000'000;
const std::string kNetwork(64, 'a');

LinkTokenEvent mint_event(const std::string& token = "lnk_a", uint64_t created = kNow,
                          uint64_t ttl = 600) {
    LinkTokenEvent e;
    e.kind = LinkTokenEventKind::Mint;
    e.token_hash = auth::link_token_hash_hex(token);
    e.network_id = kNetwork;
    e.expires_at = created + ttl;
    e.group_node_id = "customer-a";
    e.permissions = {"read", "connect_private"};
    e.owner_user_id = "owner";
    e.owner_pubkey = "ed25519:OWNER";
    e.created_at = created;
    e.timestamp = created;
    e.origin_pubkey = "M";
    e.origin_seq = 1;
    e.signature = "sig";
    return e;
}

LinkTokenEvent follow_up(const LinkTokenEvent& mint, LinkTokenEventKind kind,
                         uint32_t generation, const std::string& origin) {
    LinkTokenEvent e;
    e.kind = kind;
    e.token_hash = mint.token_hash;
    e.generation = generation;
    e.network_id = mint.network_id;
    e.expires_at = mint.expires_at;
    e.timestamp = mint.created_at + 1;
    e.origin_pubkey = origin;
    e.origin_seq = 2 + generation;
    e.signature = "sig";
    return e;
}

}  // namespace

TEST(LinkTokenLedgerTest, TheTokenHashIsDomainSeparated) {
    crypto::SodiumCryptoService crypto;
    crypto.start();
    const std::string token = "lnk_0123";
    const auto hash = auth::link_token_hash_hex(token);
    EXPECT_EQ(hash.size(), 64u);
    EXPECT_EQ(hash, auth::link_token_hash_hex(token));
    EXPECT_NE(hash, auth::link_token_hash_hex("lnk_0124"));
    const auto plain = crypto.sha256(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(token.data()), token.size()));
    EXPECT_NE(hash, crypto::to_hex(std::span<const uint8_t>(plain)))
        << "a legacy file name must not equal a replicated token hash";
    crypto.stop();
}

TEST(LinkTokenLedgerTest, SignaturesCoverEveryFieldAndTheWireFormRoundTrips) {
    crypto::SodiumCryptoService crypto;
    crypto.start();
    const auto kp = crypto.ed25519_keygen();
    auto e = mint_event();
    e.origin_pubkey = crypto::to_base64(kp.public_key);
    const auto bytes = auth::link_token_event_signing_bytes(e);
    e.signature = crypto::to_base64(crypto.ed25519_sign(kp.private_key,
                                                        std::span<const uint8_t>(bytes)));
    EXPECT_TRUE(auth::link_token_event_signature_valid(crypto, e));

    const auto back = auth::link_token_event_from_wire(auth::link_token_event_to_wire(e));
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(*back, e);

    for (auto tamper : std::vector<std::function<void(LinkTokenEvent&)>>{
             [](LinkTokenEvent& x) { x.permissions.push_back("add_child"); },
             [](LinkTokenEvent& x) { x.group_node_id = "customer-b"; },
             [](LinkTokenEvent& x) { x.expires_at += 1; },
             [](LinkTokenEvent& x) { x.network_id = std::string(64, 'b'); },
             [](LinkTokenEvent& x) { x.owner_pubkey = "ed25519:OTHER"; },
             [](LinkTokenEvent& x) { x.origin_seq += 1; },
         }) {
        auto t = e;
        tamper(t);
        EXPECT_FALSE(auth::link_token_event_signature_valid(crypto, t));
    }

    // Without a code the wire form is the one an earlier release writes.
    auto wire = auth::link_token_event_to_wire(e);
    EXPECT_FALSE(wire.contains("code_hash"));
    EXPECT_FALSE(wire.contains("code_signature"));

    // With a code: the binding is signed on its own, the event signature is
    // unchanged, and the wire form carries both fields.
    auto coded = e;
    coded.code_hash = auth::link_code_hash_hex("12345678");
    const auto binding = auth::link_code_binding_bytes(coded);
    coded.code_signature = crypto::to_base64(
        crypto.ed25519_sign(kp.private_key, std::span<const uint8_t>(binding)));
    EXPECT_EQ(auth::link_token_event_signing_bytes(coded), bytes);
    EXPECT_TRUE(auth::link_token_event_signature_valid(crypto, coded));
    EXPECT_FALSE(auth::link_token_event_shape_error(coded).has_value());
    const auto coded_back = auth::link_token_event_from_wire(auth::link_token_event_to_wire(coded));
    ASSERT_TRUE(coded_back.has_value());
    EXPECT_EQ(*coded_back, coded);
    for (auto tamper : std::vector<std::function<void(LinkTokenEvent&)>>{
             [](LinkTokenEvent& x) { x.code_hash = auth::link_code_hash_hex("12345679"); },
             [](LinkTokenEvent& x) { x.code_signature = x.signature; },
             [](LinkTokenEvent& x) { x.code_signature.clear(); },
             [](LinkTokenEvent& x) { x.origin_seq += 1; },
             [&](LinkTokenEvent& x) { x.code_hash.clear(); },
         }) {
        auto t = coded;
        tamper(t);
        EXPECT_FALSE(auth::link_token_event_signature_valid(crypto, t));
    }
    // A release without codes drops the fields and keeps a valid event.
    auto stripped = coded;
    stripped.code_hash.clear();
    stripped.code_signature.clear();
    EXPECT_TRUE(auth::link_token_event_signature_valid(crypto, stripped));

    // The wire parser refuses wrong types and oversized fields.
    wire = auth::link_token_event_to_wire(coded);
    wire["code_hash"] = 7;
    EXPECT_FALSE(auth::link_token_event_from_wire(wire).has_value());
    wire = auth::link_token_event_to_wire(e);
    wire["expires_at"] = "soon";
    EXPECT_FALSE(auth::link_token_event_from_wire(wire).has_value());
    wire = auth::link_token_event_to_wire(e);
    wire["group_node_id"] = std::string(auth::kLinkTokenMaxFieldBytes + 1, 'g');
    EXPECT_FALSE(auth::link_token_event_from_wire(wire).has_value());
    wire = auth::link_token_event_to_wire(e);
    wire["permissions"] = nlohmann::json::array({"a", "b", "c", "d", "e", "f", "g", "h", "i"});
    EXPECT_FALSE(auth::link_token_event_from_wire(wire).has_value());
    crypto.stop();
}

TEST(LinkTokenLedgerTest, TheCodeHashIsDomainSeparatedAndTheCodeFormIsEightDigits) {
    EXPECT_TRUE(auth::is_link_code("00000000"));
    EXPECT_TRUE(auth::is_link_code("12345678"));
    EXPECT_FALSE(auth::is_link_code("1234567"));
    EXPECT_FALSE(auth::is_link_code("123456789"));
    EXPECT_FALSE(auth::is_link_code("1234567a"));
    EXPECT_FALSE(auth::is_link_code("1234 5678"));
    EXPECT_FALSE(auth::is_link_code(""));
    EXPECT_FALSE(auth::is_link_code("lnk_12345678"));
    const auto code_hash = auth::link_code_hash_hex("12345678");
    EXPECT_EQ(code_hash.size(), 64u);
    EXPECT_NE(code_hash, auth::link_token_hash_hex("12345678"))
        << "a code and a token with equal text hash differently";
    EXPECT_NE(code_hash, auth::link_code_hash_hex("12345679"));
}

TEST(LinkTokenLedgerTest, ACodeBindingBelongsToASignedMintOnly) {
    auto signed_mint = mint_event();
    signed_mint.code_hash = auth::link_code_hash_hex("12345678");
    EXPECT_TRUE(auth::link_token_event_shape_error(signed_mint).has_value())
        << "a signed mint signs its code binding";
    signed_mint.code_signature = "sig";
    EXPECT_FALSE(auth::link_token_event_shape_error(signed_mint).has_value());
    signed_mint.code_hash = "not-hex";
    EXPECT_TRUE(auth::link_token_event_shape_error(signed_mint).has_value());

    auto local_mint = mint_event();
    local_mint.signature.clear();
    local_mint.code_hash = auth::link_code_hash_hex("12345678");
    EXPECT_FALSE(auth::link_token_event_shape_error(local_mint).has_value())
        << "an unsigned local mint signs neither";
    local_mint.code_signature = "sig";
    EXPECT_TRUE(auth::link_token_event_shape_error(local_mint).has_value());

    auto no_hash = mint_event();
    no_hash.code_signature = "sig";
    EXPECT_TRUE(auth::link_token_event_shape_error(no_hash).has_value());

    auto spend = follow_up(mint_event(), LinkTokenEventKind::Spend, 0, "A");
    spend.code_hash = auth::link_code_hash_hex("12345678");
    spend.code_signature = "sig";
    EXPECT_TRUE(auth::link_token_event_shape_error(spend).has_value());
}

// A code resolves to exactly one unexpired mint, or to nothing. A code lives
// at most kLinkCodeMaxTtlSec, and prune forgets it with its token.
TEST(LinkTokenLedgerTest, ACodeResolvesToOneUnexpiredMintOrFailsClosed) {
    const auto code_hash = auth::link_code_hash_hex("12345678");
    auto a = mint_event("lnk_a", kNow, 3600);
    a.code_hash = code_hash;
    a.code_signature = "sig";
    auto b = mint_event("lnk_b", kNow + 300, 600);
    b.code_hash = code_hash;
    b.code_signature = "sig";
    b.origin_pubkey = "N";

    LinkTokenLedger ledger;
    EXPECT_FALSE(ledger.code_in_use(code_hash, kNow));
    ASSERT_EQ(ledger.add(a, kNow), LinkTokenLedger::AddResult::Added);
    EXPECT_TRUE(ledger.code_in_use(code_hash, kNow));
    EXPECT_TRUE(ledger.holds_code(code_hash));
    auto live = ledger.live_by_code(code_hash, kNow);
    ASSERT_TRUE(live.has_value());
    EXPECT_EQ(live->mint.token_hash, a.token_hash);
    EXPECT_EQ(auth::link_code_expires_at(a), kNow + auth::kLinkCodeMaxTtlSec);
    EXPECT_FALSE(ledger.live_by_code(code_hash, kNow + auth::kLinkCodeMaxTtlSec).has_value())
        << "the code ends after ten minutes";
    EXPECT_TRUE(ledger.live(a.token_hash, kNow + auth::kLinkCodeMaxTtlSec).has_value())
        << "the token goes on";
    EXPECT_FALSE(ledger.code_in_use(code_hash, kNow + auth::kLinkCodeMaxTtlSec));

    ASSERT_EQ(ledger.add(b, kNow + 300), LinkTokenLedger::AddResult::Added);
    EXPECT_FALSE(ledger.live_by_code(code_hash, kNow + 300).has_value())
        << "two unexpired mints share the code: refused";
    EXPECT_TRUE(ledger.live(a.token_hash, kNow + 300).has_value());
    EXPECT_TRUE(ledger.live(b.token_hash, kNow + 300).has_value());
    live = ledger.live_by_code(code_hash, kNow + 650);
    ASSERT_TRUE(live.has_value()) << "a's code expired; b's is the only one left";
    EXPECT_EQ(live->mint.token_hash, b.token_hash);

    // A spend by the token spends the code; a spent token's code resolves to
    // nothing but still blocks the code for a new mint.
    ASSERT_EQ(ledger.add(follow_up(b, LinkTokenEventKind::Spend, 0, "N"), kNow + 650),
              LinkTokenLedger::AddResult::Added);
    EXPECT_FALSE(ledger.live_by_code(code_hash, kNow + 650).has_value());
    EXPECT_TRUE(ledger.code_in_use(code_hash, kNow + 650));

    EXPECT_EQ(ledger.prune(kNow + 300 + 600 + auth::kLinkTokenRetentionSec), 1u);
    EXPECT_TRUE(ledger.holds_code(code_hash)) << "a still carries it";
    EXPECT_EQ(ledger.prune(kNow + 3600 + auth::kLinkTokenRetentionSec), 1u);
    EXPECT_FALSE(ledger.holds_code(code_hash));
}

// A replica from a release before codes strips the binding and passes the
// mint on. Whichever copy arrives first, the copy with the binding is kept.
TEST(LinkTokenLedgerTest, TheCopyWithTheCodeBindingIsKeptInAnyArrivalOrder) {
    auto full = mint_event();
    full.code_hash = auth::link_code_hash_hex("12345678");
    full.code_signature = "sig";
    auto stripped = full;
    stripped.code_hash.clear();
    stripped.code_signature.clear();

    LinkTokenLedger first_stripped;
    EXPECT_EQ(first_stripped.add(stripped, kNow), LinkTokenLedger::AddResult::Added);
    EXPECT_FALSE(first_stripped.live_by_code(full.code_hash, kNow).has_value());
    EXPECT_EQ(first_stripped.add(full, kNow), LinkTokenLedger::AddResult::Added);
    EXPECT_TRUE(first_stripped.live_by_code(full.code_hash, kNow).has_value());
    EXPECT_EQ(first_stripped.add(stripped, kNow), LinkTokenLedger::AddResult::Duplicate);
    EXPECT_EQ(first_stripped.mints().size(), 1u);
    EXPECT_EQ(first_stripped.mints().front(), full);

    LinkTokenLedger first_full;
    EXPECT_EQ(first_full.add(full, kNow), LinkTokenLedger::AddResult::Added);
    EXPECT_EQ(first_full.add(stripped, kNow), LinkTokenLedger::AddResult::Duplicate);
    EXPECT_EQ(first_full.mints().front(), full);

    // A mint that differs in anything else is still refused.
    auto other_code = full;
    other_code.code_hash = auth::link_code_hash_hex("87654321");
    EXPECT_EQ(first_full.add(other_code, kNow), LinkTokenLedger::AddResult::Duplicate)
        << "the held copy already carries a binding; a second one is not taken";
    auto other_group = full;
    other_group.group_node_id = "customer-b";
    EXPECT_EQ(first_full.add(other_group, kNow), LinkTokenLedger::AddResult::Refused);
}

TEST(LinkTokenLedgerTest, TheStateDoesNotDependOnArrivalOrder) {
    const auto mint = mint_event();
    // Generation 0 is spent by "B" and "C" at once; "B" counts and refunds;
    // generation 1 is spent by "Z" and refunded by "Y" (which does not count).
    std::vector<LinkTokenEvent> events = {
        mint,
        follow_up(mint, LinkTokenEventKind::Spend, 0, "C"),
        follow_up(mint, LinkTokenEventKind::Spend, 0, "B"),
        follow_up(mint, LinkTokenEventKind::Refund, 0, "C"),
        follow_up(mint, LinkTokenEventKind::Refund, 0, "B"),
        follow_up(mint, LinkTokenEventKind::Spend, 1, "Z"),
        follow_up(mint, LinkTokenEventKind::Refund, 1, "Y"),
    };
    std::sort(events.begin(), events.end(), [](const auto& a, const auto& b) {
        return auth::link_token_event_key(a) < auth::link_token_event_key(b);
    });
    std::size_t orders = 0;
    do {
        LinkTokenLedger ledger;
        for (const auto& e : events) {
            ASSERT_EQ(ledger.add(e, kNow), LinkTokenLedger::AddResult::Added);
        }
        EXPECT_EQ(ledger.spend_winner(mint.token_hash, 0), std::optional<std::string>("B"));
        EXPECT_EQ(ledger.spend_winner(mint.token_hash, 1), std::optional<std::string>("Z"));
        EXPECT_FALSE(ledger.live(mint.token_hash, kNow).has_value());
        ++orders;
    } while (std::next_permutation(events.begin(), events.end(), [](const auto& a, const auto& b) {
        return auth::link_token_event_key(a) < auth::link_token_event_key(b);
    }) && orders < 720);
    EXPECT_GT(orders, 100u);

    // Z restores generation 1: the token is live again as generation 2.
    LinkTokenLedger ledger;
    for (const auto& e : events) (void)ledger.add(e, kNow);
    ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Refund, 1, "Z"), kNow),
              LinkTokenLedger::AddResult::Added);
    const auto live = ledger.live(mint.token_hash, kNow);
    ASSERT_TRUE(live.has_value());
    EXPECT_EQ(live->generation, 2u);
    EXPECT_EQ(live->mint, mint);
}

// A revoke ends the token whatever its generation, and a refund cannot
// bring it back.
TEST(LinkTokenLedgerTest, ARevokeEndsTheTokenForGood) {
    const auto mint = mint_event();
    LinkTokenLedger ledger;
    ASSERT_EQ(ledger.add(mint, kNow), LinkTokenLedger::AddResult::Added);
    ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Spend, 0, "B"), kNow),
              LinkTokenLedger::AddResult::Added);
    ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Revoke, 0, "C"), kNow),
              LinkTokenLedger::AddResult::Added);
    ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Refund, 0, "B"), kNow),
              LinkTokenLedger::AddResult::Added);
    EXPECT_TRUE(ledger.revoked(mint.token_hash));
    EXPECT_FALSE(ledger.live(mint.token_hash, kNow).has_value());
    ASSERT_EQ(ledger.mints().size(), 1u);

    auto bad = follow_up(mint, LinkTokenEventKind::Revoke, 1, "D");
    EXPECT_TRUE(auth::link_token_event_shape_error(bad).has_value());
}

TEST(LinkTokenLedgerTest, ASpendWithoutItsMintAndAnExpiredTokenAreNotLive) {
    const auto mint = mint_event();
    LinkTokenLedger ledger;
    ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Spend, 0, "B"), kNow),
              LinkTokenLedger::AddResult::Added);
    EXPECT_TRUE(ledger.holds(mint.token_hash));
    EXPECT_FALSE(ledger.live(mint.token_hash, kNow).has_value());

    LinkTokenLedger fresh;
    ASSERT_EQ(fresh.add(mint, kNow), LinkTokenLedger::AddResult::Added);
    EXPECT_TRUE(fresh.live(mint.token_hash, mint.expires_at - 1).has_value());
    EXPECT_FALSE(fresh.live(mint.token_hash, mint.expires_at).has_value());
}

TEST(LinkTokenLedgerTest, MalformedOrInconsistentEventsAreRefused) {
    using R = LinkTokenLedger::AddResult;
    const auto mint = mint_event();
    LinkTokenLedger ledger;
    ASSERT_EQ(ledger.add(mint, kNow), R::Added);
    EXPECT_EQ(ledger.add(mint, kNow), R::Duplicate);

    auto changed = mint;
    changed.group_node_id = "customer-b";
    EXPECT_EQ(ledger.add(changed, kNow), R::Refused) << "one mint per token";

    auto other_network = follow_up(mint, LinkTokenEventKind::Spend, 0, "B");
    other_network.network_id = std::string(64, 'b');
    EXPECT_EQ(ledger.add(other_network, kNow), R::Refused);
    auto other_expiry = follow_up(mint, LinkTokenEventKind::Spend, 0, "B");
    other_expiry.expires_at += 60;
    EXPECT_EQ(ledger.add(other_expiry, kNow), R::Refused);

    std::vector<LinkTokenEvent> bad;
    auto e = mint_event("lnk_b");
    e.token_hash = "XYZ";
    bad.push_back(e);
    e = mint_event("lnk_c");
    e.generation = 1;
    bad.push_back(e);
    e = mint_event("lnk_d", kNow, auth::kLinkTokenMaxTtlSec + 1);
    bad.push_back(e);
    e = follow_up(mint_event("lnk_e"), LinkTokenEventKind::Spend, 0, "B");
    e.group_node_id = "customer-a";
    bad.push_back(e);
    e = follow_up(mint_event("lnk_f"), LinkTokenEventKind::Refund,
                  auth::kLinkTokenMaxGeneration, "B");
    bad.push_back(e);
    e = mint_event("lnk_g");
    e.origin_seq = 0;
    bad.push_back(e);
    for (const auto& b : bad) {
        EXPECT_TRUE(auth::link_token_event_shape_error(b).has_value());
        EXPECT_EQ(ledger.add(b, kNow), R::Refused);
    }

    // Outside the retention window, or too far ahead of this clock.
    const auto old = mint_event("lnk_old", kNow - 2 * 3600, 600);
    EXPECT_EQ(ledger.add(old, kNow), R::Refused);
    auto future = mint_event("lnk_future", kNow + 2 * 3600, 600);
    EXPECT_EQ(ledger.add(future, kNow), R::Refused);
}

TEST(LinkTokenLedgerTest, GenerationsAndEventsAreBounded) {
    using R = LinkTokenLedger::AddResult;
    const auto mint = mint_event();
    LinkTokenLedger ledger;
    ASSERT_EQ(ledger.add(mint, kNow), R::Added);
    for (uint32_t g = 0; g < auth::kLinkTokenMaxGeneration; ++g) {
        ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Spend, g, "B"), kNow), R::Added);
        ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Refund, g, "B"), kNow), R::Added);
    }
    const auto last = ledger.live(mint.token_hash, kNow);
    ASSERT_TRUE(last.has_value());
    EXPECT_EQ(last->generation, auth::kLinkTokenMaxGeneration);
    ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Spend,
                                   auth::kLinkTokenMaxGeneration, "B"),
                         kNow),
              R::Added);
    EXPECT_FALSE(ledger.live(mint.token_hash, kNow).has_value());

    // Spends from many origins fill the per-token cap.
    const auto crowded = mint_event("lnk_crowded");
    LinkTokenLedger busy;
    ASSERT_EQ(busy.add(crowded, kNow), R::Added);
    std::size_t added = 1;
    for (int i = 0; added < auth::kLinkTokenMaxEventsPerToken; ++i, ++added) {
        ASSERT_EQ(busy.add(follow_up(crowded, LinkTokenEventKind::Spend, 0,
                                     "origin-" + std::to_string(i)),
                           kNow),
                  R::Added);
    }
    EXPECT_EQ(busy.add(follow_up(crowded, LinkTokenEventKind::Spend, 0, "one-more"), kNow),
              R::Full);

    // The token cap.
    LinkTokenLedger full;
    for (std::size_t i = 0; i < auth::kLinkTokenMaxTokens; ++i) {
        ASSERT_EQ(full.add(mint_event("lnk_" + std::to_string(i)), kNow), R::Added);
    }
    EXPECT_EQ(full.add(mint_event("lnk_overflow"), kNow), R::Full);
}

TEST(LinkTokenLedgerTest, PruneDropsTokensWhoseRetentionEnded) {
    const auto mint = mint_event();
    LinkTokenLedger ledger;
    ASSERT_EQ(ledger.add(mint, kNow), LinkTokenLedger::AddResult::Added);
    ASSERT_EQ(ledger.add(follow_up(mint, LinkTokenEventKind::Spend, 0, "B"), kNow),
              LinkTokenLedger::AddResult::Added);
    EXPECT_EQ(ledger.prune(mint.expires_at + auth::kLinkTokenRetentionSec - 1), 0u);
    EXPECT_EQ(ledger.prune(mint.expires_at + auth::kLinkTokenRetentionSec), 1u);
    EXPECT_FALSE(ledger.holds(mint.token_hash));
    EXPECT_TRUE(ledger.events().empty());
}
