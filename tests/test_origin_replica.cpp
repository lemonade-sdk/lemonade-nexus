// OriginReplica: origin-sequenced last-writer-wins replica, digest comparison,
// catch-up planning and the bounded wire codec; and the entry chunk codec and
// assembler. Pure logic, no I/O.

#include <LemonadeNexus/Sync/EntryChunks.hpp>
#include <LemonadeNexus/Sync/OriginReplica.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace nexus::sync;

namespace {

ReplicaEntry entry(std::string key, std::string origin, uint64_t seq, uint64_t ts,
                   bool tombstone = false) {
    return {std::move(key), std::move(origin), seq, ts, tombstone, {0x01, 0x02}};
}

// Copies every entry of `from` that `to` would request, the way a responder
// answers plan_catch_up.
void catch_up(OriginReplica& to, const OriginReplica& from) {
    for (const auto& req : to.plan_catch_up(from.digest())) {
        for (auto& e : from.entries_since(req.origin, req.since, 1000)) {
            (void)to.offer(std::move(e));
        }
    }
}

}  // namespace

TEST(OriginReplica, LocalSequenceIsStrictlyIncreasingAndFollowsTheClock) {
    OriginReplica r("me");
    EXPECT_EQ(r.next_local_seq(1000), 1000u);
    EXPECT_EQ(r.next_local_seq(1000), 1001u);  // same millisecond
    EXPECT_EQ(r.next_local_seq(900), 1002u);   // clock stepped back
    EXPECT_EQ(r.next_local_seq(5000), 5000u);  // clock moved on
}

TEST(OriginReplica, NewestByTimestampThenSequenceWins) {
    OriginReplica r("me");
    EXPECT_EQ(r.offer(entry("A:x", "o1", 10, 100)), OfferResult::Stored);
    EXPECT_EQ(r.offer(entry("A:x", "o1", 9, 100)), OfferResult::Stale);
    EXPECT_EQ(r.offer(entry("A:x", "o1", 10, 100)), OfferResult::Stale);  // replay
    EXPECT_EQ(r.offer(entry("A:x", "o1", 11, 100)), OfferResult::Stored); // same second
    EXPECT_EQ(r.offer(entry("A:x", "o1", 5, 101)), OfferResult::Stored);  // later second
    EXPECT_TRUE(r.holds_newer("A:x", 100, 999));
    EXPECT_FALSE(r.holds_newer("A:x", 101, 6));
    EXPECT_FALSE(r.holds_newer("A:other", 0, 0));
}

TEST(OriginReplica, TombstoneIsNotUndoneByAnOlderEntry) {
    OriginReplica r("me");
    ASSERT_EQ(r.offer(entry("A:x", "o1", 10, 100)), OfferResult::Stored);
    ASSERT_EQ(r.offer(entry("A:x", "o1", 11, 100, /*tombstone=*/true)), OfferResult::Stored);
    EXPECT_TRUE(r.holds_newer("A:x", 100, 10));
    EXPECT_EQ(r.offer(entry("A:x", "o1", 10, 100)), OfferResult::Stale);
    ASSERT_EQ(r.entries_since("o1", 0, 10).size(), 1u);
    EXPECT_TRUE(r.entries_since("o1", 0, 10)[0].tombstone);
}

TEST(OriginReplica, InvalidAndFullOffersAreRefused) {
    OriginReplica r("me", /*max_entries=*/2);
    EXPECT_EQ(r.offer(entry("", "o1", 1, 1)), OfferResult::Invalid);
    EXPECT_EQ(r.offer(entry("A:x", "", 1, 1)), OfferResult::Invalid);
    EXPECT_EQ(r.offer(entry("A:x", "o1", 1, 1)), OfferResult::Stored);
    EXPECT_EQ(r.offer(entry("A:y", "o1", 2, 1)), OfferResult::Stored);
    EXPECT_EQ(r.offer(entry("A:z", "o1", 3, 1)), OfferResult::Full);
    // Replacing an existing key still works at the cap.
    EXPECT_EQ(r.offer(entry("A:x", "o1", 4, 1)), OfferResult::Stored);
    EXPECT_EQ(r.size(), 2u);
}

TEST(OriginReplica, LegacyEntriesOrderButAreNotSynced) {
    OriginReplica r("me");
    ASSERT_EQ(r.offer(entry("A:x", "o1", 0, 100)), OfferResult::Stored);
    EXPECT_TRUE(r.digest().empty());
    EXPECT_TRUE(r.entries_since("o1", 0, 10).empty());
    // A sequenced entry in the same second supersedes the legacy one.
    EXPECT_EQ(r.offer(entry("A:x", "o1", 1, 100)), OfferResult::Stored);
    EXPECT_EQ(r.digest().at("o1").count, 1u);
}

TEST(OriginReplica, EqualContentsGiveEqualDigests) {
    OriginReplica a("a"), b("b");
    for (auto* r : {&a, &b}) {
        (void)r->offer(entry("A:x", "o1", 10, 100));
        (void)r->offer(entry("A:y", "o1", 12, 100));
        (void)r->offer(entry("A:z", "o2", 3, 100));
    }
    EXPECT_EQ(a.digest(), b.digest());
    // Same maximum and count, different contents below the maximum.
    ASSERT_EQ(b.offer(entry("A:x", "o1", 11, 100)), OfferResult::Stored);
    EXPECT_EQ(a.digest().at("o1").max_seq, b.digest().at("o1").max_seq);
    EXPECT_EQ(a.digest().at("o1").count, b.digest().at("o1").count);
    EXPECT_NE(a.digest().at("o1"), b.digest().at("o1"));
}

TEST(OriginReplica, LateJoinerCatchesUpFromAhead) {
    OriginReplica ahead("a"), joiner("j");
    (void)ahead.offer(entry("A:x", "o1", 10, 100));
    (void)ahead.offer(entry("A:y", "o1", 20, 100));
    (void)ahead.offer(entry("A:z", "o2", 5, 100));

    const auto reqs = joiner.plan_catch_up(ahead.digest());
    ASSERT_EQ(reqs.size(), 2u);
    EXPECT_EQ(reqs[0], (CatchUpRequest{"o1", 0}));
    EXPECT_EQ(reqs[1], (CatchUpRequest{"o2", 0}));

    catch_up(joiner, ahead);
    EXPECT_EQ(joiner.digest(), ahead.digest());
    EXPECT_TRUE(joiner.plan_catch_up(ahead.digest()).empty());
}

TEST(OriginReplica, IncrementalRequestStartsAfterOurMaximum) {
    OriginReplica ahead("a"), behind("b");
    (void)ahead.offer(entry("A:x", "o1", 10, 100));
    (void)behind.offer(entry("A:x", "o1", 10, 100));
    (void)ahead.offer(entry("A:y", "o1", 30, 100));
    const auto reqs = behind.plan_catch_up(ahead.digest());
    ASSERT_EQ(reqs.size(), 1u);
    EXPECT_EQ(reqs[0], (CatchUpRequest{"o1", 10}));
}

TEST(OriginReplica, LostEntryBelowTheMaximumTriggersAFullRequest) {
    OriginReplica full("f"), gap("g");
    (void)full.offer(entry("A:x", "o1", 10, 100));
    (void)full.offer(entry("A:y", "o1", 20, 100));
    (void)gap.offer(entry("A:y", "o1", 20, 100));  // missed seq 10

    const auto reqs = gap.plan_catch_up(full.digest());
    ASSERT_EQ(reqs.size(), 1u);
    EXPECT_EQ(reqs[0], (CatchUpRequest{"o1", 0}));
    catch_up(gap, full);
    EXPECT_EQ(gap.digest(), full.digest());
}

TEST(OriginReplica, AheadSideRequestsNothing) {
    OriginReplica ahead("a"), behind("b");
    (void)ahead.offer(entry("A:x", "o1", 10, 100));
    EXPECT_TRUE(ahead.plan_catch_up(behind.digest()).empty());
}

TEST(OriginReplica, EntriesSinceIsAscendingAndCapped) {
    OriginReplica r("me");
    (void)r.offer(entry("A:c", "o1", 30, 100));
    (void)r.offer(entry("A:a", "o1", 10, 100));
    (void)r.offer(entry("A:b", "o1", 20, 100));
    (void)r.offer(entry("A:z", "o2", 15, 100));
    const auto two = r.entries_since("o1", 0, 2);
    ASSERT_EQ(two.size(), 2u);
    EXPECT_EQ(two[0].seq, 10u);
    EXPECT_EQ(two[1].seq, 20u);
    const auto after = r.entries_since("o1", 10, 10);
    ASSERT_EQ(after.size(), 2u);
    EXPECT_EQ(after[0].seq, 20u);
}

TEST(OriginReplica, PeerStatusTracksSyncState) {
    OriginReplica me("me"), peer("p");
    (void)peer.offer(entry("A:x", "o1", 10, 100));
    (void)me.offer(entry("A:y", "o2", 5, 100));

    EXPECT_TRUE(me.record_peer_digest("p", peer.digest(), 1000));   // first digest
    auto s = me.peer_status().at("p");
    EXPECT_FALSE(s.in_sync);
    EXPECT_EQ(s.origins_we_lack, 1u);
    EXPECT_EQ(s.origins_peer_lacks, 1u);
    EXPECT_EQ(s.last_digest_ms, 1000u);
    EXPECT_FALSE(me.record_peer_digest("p", peer.digest(), 2000));  // unchanged

    catch_up(me, peer);
    catch_up(peer, me);
    EXPECT_TRUE(me.record_peer_digest("p", peer.digest(), 3000));   // flipped to in sync
    s = me.peer_status().at("p");
    EXPECT_TRUE(s.in_sync);
    EXPECT_EQ(s.origins_we_lack, 0u);
    EXPECT_EQ(s.origins_peer_lacks, 0u);
}

TEST(OriginReplica, TombstonesExpireByAgeOnly) {
    OriginReplica r("me");
    (void)r.offer(entry("A:old-gone", "o1", 1, 100, /*tombstone=*/true));
    (void)r.offer(entry("A:new-gone", "o1", 2, 500, /*tombstone=*/true));
    (void)r.offer(entry("A:old-live", "o1", 3, 100));
    const auto before = r.version();
    EXPECT_EQ(r.prune_tombstones(200), 1u);
    EXPECT_NE(r.version(), before);
    EXPECT_EQ(r.size(), 2u);
    EXPECT_FALSE(r.holds_newer("A:old-gone", 0, 0));   // marker gone
    EXPECT_TRUE(r.holds_newer("A:new-gone", 500, 1));  // recent marker kept
    EXPECT_TRUE(r.holds_newer("A:old-live", 100, 2));  // live entries never expire
    const auto unchanged = r.version();
    EXPECT_EQ(r.prune_tombstones(200), 0u);
    EXPECT_EQ(r.version(), unchanged);
}

// A stream whose entries carry their expiry as the timestamp (link tokens)
// drops live entries and tombstones alike once they expire.
TEST(OriginReplica, PruneExpiredDropsEveryEntryPastTheCutoff) {
    OriginReplica r("me");
    (void)r.offer(entry("lt:a:m", "o1", 1, 100));
    (void)r.offer(entry("lt:a:s", "o2", 2, 100, /*tombstone=*/true));
    (void)r.offer(entry("lt:b:m", "o1", 3, 500));
    const auto before = r.version();
    EXPECT_EQ(r.prune_expired(200), 2u);
    EXPECT_NE(r.version(), before);
    EXPECT_EQ(r.size(), 1u);
    EXPECT_TRUE(r.holds_newer("lt:b:m", 0, 0));
    const auto unchanged = r.version();
    EXPECT_EQ(r.prune_expired(200), 0u);
    EXPECT_EQ(r.version(), unchanged);
}

TEST(OriginReplica, SnapshotRestoresAnEqualReplica) {
    OriginReplica a("a");
    (void)a.offer(entry("A:x", "o1", 10, 100));
    (void)a.offer(entry("A:y", "o2", 5, 100, /*tombstone=*/true));
    (void)a.offer(entry("A:z", "o1", 0, 90));  // legacy
    OriginReplica b("b");
    for (auto& e : a.snapshot()) (void)b.offer(std::move(e));
    EXPECT_EQ(b.size(), a.size());
    EXPECT_EQ(b.digest(), a.digest());
    EXPECT_TRUE(b.holds_newer("A:y", 100, 4));
}

TEST(OriginReplica, DigestPagesAccumulatePerRound) {
    OriginReplica me("me"), peer("p");
    for (int i = 0; i < 40; ++i) {
        (void)peer.offer(entry("A:" + std::to_string(i), "origin-" + std::to_string(i), 10, 100));
    }
    // A small page budget forces several pages.
    const auto pages = encode_digest_pages("dns", peer.digest(), 7, 400);
    ASSERT_GT(pages.size(), 2u);
    std::vector<DigestPage> decoded;
    for (const auto& p : pages) {
        EXPECT_LE(nlohmann::json::to_msgpack(p).size(), 400u);
        auto d = decode_digest_page(p);
        ASSERT_TRUE(d.has_value());
        decoded.push_back(*d);
    }

    // Every page but the last leaves the peer's digest unrecorded.
    for (std::size_t i = 0; i + 1 < decoded.size(); ++i) {
        EXPECT_FALSE(me.record_peer_digest_page("p", decoded[i], 1000));
        EXPECT_EQ(me.peer_status().count("p") ? me.peer_status().at("p").last_digest_ms : 0u, 0u);
    }
    // A repeated page does not complete the round.
    EXPECT_FALSE(me.record_peer_digest_page("p", decoded[0], 1000));
    EXPECT_TRUE(me.record_peer_digest_page("p", decoded.back(), 1000));
    const auto s = me.peer_status().at("p");
    EXPECT_EQ(s.origins_we_lack, 40u);
    EXPECT_EQ(s.last_digest_ms, 1000u);

    // Each page plans its own catch-up.
    std::size_t planned = 0;
    for (const auto& d : decoded) planned += me.plan_catch_up(d.origins).size();
    EXPECT_EQ(planned, 40u);
}

TEST(OriginReplica, NewerDigestRoundSupersedesAnIncompleteOne) {
    OriginReplica me("me");
    Digest full{{"o1", {10, 1, 1}}, {"o2", {20, 1, 2}}};
    DigestPage old_first{"dns", 1, 0, 2, {{"o1", {10, 1, 1}}}};
    DigestPage new_only{"dns", 2, 0, 1, full};
    DigestPage old_second{"dns", 1, 1, 2, {{"o2", {20, 1, 2}}}};
    EXPECT_FALSE(me.record_peer_digest_page("p", old_first, 1000));
    EXPECT_TRUE(me.record_peer_digest_page("p", new_only, 2000));   // round 2 complete
    EXPECT_FALSE(me.record_peer_digest_page("p", old_second, 3000)); // stale round ignored
    EXPECT_EQ(me.peer_status().at("p").last_digest_ms, 2000u);
    EXPECT_EQ(me.peer_status().at("p").origins_we_lack, 2u);
}

TEST(OriginReplicaWire, DigestPageAndRequestRoundTrip) {
    Digest d{{"o1", {10, 2, 0xABCDEF}}, {"o2", {5, 1, 42}}};
    const auto pages = encode_digest_pages("dns", d, 3, 60000);
    ASSERT_EQ(pages.size(), 1u);
    const auto dec = decode_digest_page(pages[0]);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(dec->stream, "dns");
    EXPECT_EQ(dec->round, 3u);
    EXPECT_EQ(dec->page, 0u);
    EXPECT_EQ(dec->pages, 1u);
    EXPECT_EQ(dec->origins, d);

    const auto empty = encode_digest_pages("dns", {}, 4, 60000);
    ASSERT_EQ(empty.size(), 1u);
    EXPECT_TRUE(decode_digest_page(empty[0])->origins.empty());

    // A budget too small for one row refuses rather than overflowing.
    EXPECT_TRUE(encode_digest_pages("dns", d, 5, 50).empty());

    std::vector<CatchUpRequest> reqs{{"o1", 10}, {"o2", 0}};
    const auto rdec = decode_catch_up(encode_catch_up("dns", reqs));
    ASSERT_TRUE(rdec.has_value());
    EXPECT_EQ(rdec->second, reqs);
}

TEST(OriginReplicaWire, MalformedAndOversizedMessagesAreRefused) {
    const auto good = encode_digest_page({"dns", 1, 0, 1, {{"o1", {1, 1, 1}}}});
    ASSERT_TRUE(decode_digest_page(good).has_value());

    auto bad_version = good;
    bad_version["v"] = 2;
    EXPECT_FALSE(decode_digest_page(bad_version).has_value());

    auto no_stream = good;
    no_stream.erase("stream");
    EXPECT_FALSE(decode_digest_page(no_stream).has_value());

    auto long_stream = good;
    long_stream["stream"] = std::string(kMaxStreamNameBytes + 1, 's');
    EXPECT_FALSE(decode_digest_page(long_stream).has_value());

    auto page_out_of_range = good;
    page_out_of_range["page"] = 1;
    EXPECT_FALSE(decode_digest_page(page_out_of_range).has_value());

    auto zero_pages = good;
    zero_pages["pages"] = 0;
    EXPECT_FALSE(decode_digest_page(zero_pages).has_value());

    auto too_many_pages = good;
    too_many_pages["pages"] = kMaxDigestPages + 1;
    EXPECT_FALSE(decode_digest_page(too_many_pages).has_value());

    auto short_row = good;
    short_row["origins"] = nlohmann::json::array({nlohmann::json::array({"o1", 1, 1})});
    EXPECT_FALSE(decode_digest_page(short_row).has_value());

    auto negative = good;
    negative["origins"] = nlohmann::json::array({nlohmann::json::array({"o1", -1, 1, 1})});
    EXPECT_FALSE(decode_digest_page(negative).has_value());

    auto duplicate = good;
    duplicate["origins"] = nlohmann::json::array(
        {nlohmann::json::array({"o1", 1, 1, 1}), nlohmann::json::array({"o1", 2, 1, 1})});
    EXPECT_FALSE(decode_digest_page(duplicate).has_value());

    auto long_origin = good;
    long_origin["origins"] = nlohmann::json::array(
        {nlohmann::json::array({std::string(kMaxOriginIdBytes + 1, 'o'), 1, 1, 1})});
    EXPECT_FALSE(decode_digest_page(long_origin).has_value());

    nlohmann::json too_many = good;
    too_many["origins"] = nlohmann::json::array();
    for (std::size_t i = 0; i <= kMaxWireOrigins; ++i) {
        too_many["origins"].push_back({"o" + std::to_string(i), 1, 1, 1});
    }
    EXPECT_FALSE(decode_digest_page(too_many).has_value());

    EXPECT_FALSE(decode_digest_page(nlohmann::json::array()).has_value());

    auto dup_req = encode_catch_up("dns", {{"o1", 1}, {"o1", 2}});
    EXPECT_FALSE(decode_catch_up(dup_req).has_value());
}

// ---------------------------------------------------------------------------
// Entry chunks (the tree stream's transport for entries above one datagram)
// ---------------------------------------------------------------------------

namespace {

std::vector<uint8_t> pattern(std::size_t size) {
    std::vector<uint8_t> out(size);
    for (std::size_t i = 0; i < size; ++i) out[i] = static_cast<uint8_t>(i * 31 + 7);
    return out;
}

std::vector<EntryChunk> chunks_of(const std::vector<uint8_t>& entry, std::size_t chunk_bytes,
                                  uint64_t seq = 9) {
    std::vector<EntryChunk> out;
    for (const auto& j : encode_entry_chunks("tree", seq, entry, chunk_bytes)) {
        const auto c = decode_entry_chunk(nlohmann::json::from_msgpack(nlohmann::json::to_msgpack(j)),
                                          1u << 20);
        EXPECT_TRUE(c.has_value());
        out.push_back(*c);
    }
    return out;
}

}  // namespace

TEST(EntryChunks, AnEntryReassemblesInAnyOrder) {
    const auto entry = pattern(10'000);
    auto chunks = chunks_of(entry, 1'000);
    ASSERT_EQ(chunks.size(), 10u);
    std::reverse(chunks.begin(), chunks.end());
    EntryAssembler assembler(1u << 20, 60'000);
    std::optional<std::vector<uint8_t>> whole;
    for (const auto& c : chunks) {
        EXPECT_FALSE(whole.has_value());
        whole = assembler.add("peer", c, 1);
    }
    ASSERT_TRUE(whole.has_value());
    EXPECT_EQ(*whole, entry);
    EXPECT_EQ(assembler.buffered_bytes(), 0u);
}

TEST(EntryChunks, MalformedChunksAreRefused) {
    const auto entry = pattern(3'000);
    auto j = encode_entry_chunks("tree", 1, entry, 1'000).front();
    EXPECT_TRUE(decode_entry_chunk(j, 1u << 20).has_value());
    EXPECT_FALSE(decode_entry_chunk(j, 100).has_value());  // declared size above the cap
    auto bad = j;
    bad["index"] = 3;  // index >= count
    EXPECT_FALSE(decode_entry_chunk(bad, 1u << 20).has_value());
    bad = j;
    bad["count"] = kMaxEntryChunks + 1;
    EXPECT_FALSE(decode_entry_chunk(bad, 1u << 20).has_value());
    bad = j;
    bad["v"] = 2;
    EXPECT_FALSE(decode_entry_chunk(bad, 1u << 20).has_value());
    EXPECT_TRUE(encode_entry_chunks("tree", 1, {}, 1'000).empty());
}

TEST(EntryChunks, ATamperedChunkNeverYieldsAnEntry) {
    const auto entry = pattern(3'000);
    auto chunks = chunks_of(entry, 1'000);
    chunks[1].data[0] ^= 0x01;
    EntryAssembler assembler(1u << 20, 60'000);
    for (const auto& c : chunks) EXPECT_FALSE(assembler.add("peer", c, 1).has_value());
    EXPECT_EQ(assembler.buffered_bytes(), 0u);
}

TEST(EntryChunks, ContradictingAndDuplicateChunksAreDropped) {
    const auto entry = pattern(3'000);
    auto chunks = chunks_of(entry, 1'000);
    EntryAssembler assembler(1u << 20, 60'000);
    EXPECT_FALSE(assembler.add("peer", chunks[0], 1).has_value());
    EXPECT_FALSE(assembler.add("peer", chunks[0], 1).has_value());  // duplicate
    EXPECT_EQ(assembler.buffered_bytes(), 1'000u);
    auto other = chunks[1];
    other.count = 4;  // contradicts the first chunk's count
    EXPECT_FALSE(assembler.add("peer", other, 1).has_value());
    EXPECT_EQ(assembler.buffered_bytes(), 0u);
}

TEST(EntryChunks, BufferedBytesStayWithinTheBudgetAndAge) {
    EntryAssembler assembler(2'500, 1'000);
    // Two partial entries from two senders fill the budget; a third drops
    // the oldest instead of growing past it.
    const auto a = chunks_of(pattern(3'000), 1'000, 1);
    const auto b = chunks_of(pattern(3'001), 1'000, 2);
    const auto c = chunks_of(pattern(3'002), 1'000, 3);
    (void)assembler.add("x", a[0], 1);
    (void)assembler.add("y", b[0], 2);
    (void)assembler.add("z", c[0], 3);
    EXPECT_LE(assembler.buffered_bytes(), 2'500u);
    // Old partial entries expire.
    (void)assembler.add("z", c[1], 5'000);
    EXPECT_EQ(assembler.buffered_bytes(), 1'000u);
}
