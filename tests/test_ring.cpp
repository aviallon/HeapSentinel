#include "harness.h"

#include "Ipc/Sampling.h"
#include "Ipc/ShmRing.h"
#include "Ipc/ShmSession.h"

#include <atomic>
#include <cstring>
#include <thread>
#include <vector>

using namespace hs::ipc;

namespace
{
	// A region that behaves like the shared mapping: plain zero-filled bytes. The
	// ring protocol stores offsets and never dereferences anything out of the
	// region, so a heap buffer is a faithful stand-in - which is what lets the
	// protocol be tested on a platform that has no CreateFileMapping at all.
	struct TestRegion
	{
		std::vector<std::uint8_t> bytes;
		ShmLayout                 layout;

		explicit TestRegion(std::uint64_t a_slotsPerRing = 64, std::uint64_t a_memcache = 0)
		{
			layout = ShmLayout::Compute(a_slotsPerRing, a_memcache);
			bytes.assign(static_cast<std::size_t>(layout.totalBytes), 0);
			InitialiseSession(
				bytes.data(), layout,
				/*sessionId*/ 0xABCDEF, /*gamePid*/ 4242,
				/*createdAtUnix*/ 1700000000, /*createdAtTick*/ 1000,
				TickFrequency(), hs::kDefaultSamplePrime);
		}

		[[nodiscard]] void* base() noexcept { return bytes.data(); }
	};

	[[nodiscard]] ShmEvent MakeEvent(EventKind a_kind, std::uint64_t a_ptr, std::uint64_t a_tick, std::uint64_t a_size = 64)
	{
		ShmEvent event{};
		event.kind = static_cast<std::uint32_t>(a_kind);
		event.ptr = a_ptr;
		event.tick = a_tick;
		event.size = a_size;
		event.site = 0x1400123456ull;
		event.threadId = 7;
		return event;
	}

	struct SinkState
	{
		std::vector<ShmEvent>      events;
		std::vector<std::uint32_t> rings;
	};

	void CollectSink(void* a_context, std::uint32_t a_ring, const ShmEvent& a_event)
	{
		auto* state = static_cast<SinkState*>(a_context);
		state->events.push_back(a_event);
		state->rings.push_back(a_ring);
	}
}

HS_TEST(ring_session_init_sets_the_header_and_every_ring)
{
	TestRegion region(256, 4096);
	const auto& header = HeaderAt(region.base());

	HS_CHECK_EQ(header.magic, kShmMagic);
	HS_CHECK_EQ(header.layoutVersion, kShmLayoutVersion);
	HS_CHECK_EQ(header.totalSize, region.layout.totalBytes);
	HS_CHECK_EQ(header.ringCount, kMaxRings);
	HS_CHECK_EQ(header.slotCountPerRing, 256ull);
	HS_CHECK_EQ(header.memcacheBytes, 4096ull);
	HS_CHECK_EQ(header.samplePrime, hs::kDefaultSamplePrime);
	HS_CHECK(Validate(header, region.layout, region.layout.totalBytes).empty());

	for (std::uint32_t i = 0; i < kMaxRings; ++i) {
		const auto& ring = RingAt(region.base(), region.layout, i);
		HS_CHECK_EQ(ring.ownerThread, 0ull);  // free
		HS_CHECK_EQ(ring.capacity, 256ull);
		HS_CHECK_EQ(ring.slotsOffset, region.layout.RingSlotsOffset(i));
		HS_CHECK_EQ(ring.writeSeq, 0ull);
		HS_CHECK_EQ(ring.readSeq, 0ull);
		HS_CHECK_EQ(ring.generation, 0ull);
	}
}

HS_TEST(ring_spsc_roundtrip_is_lossless_and_in_order)
{
	TestRegion  region(1024);
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, /*threadId*/ 100, 0, 0));
	HS_CHECK(producer.Owned());
	HS_CHECK_EQ(producer.RingIndex(), 0u);

	constexpr int kCount = 1000;  // comfortably below capacity: this test is about exactness
	for (int i = 0; i < kCount; ++i) {
		producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, 0x1000ull + static_cast<std::uint64_t>(i), static_cast<std::uint64_t>(i)));
	}

	SinkState  sink;
	const auto stats = DrainAll(region.base(), region.layout, CollectSink, &sink);

	HS_CHECK_EQ(stats.consumed, static_cast<std::uint64_t>(kCount));
	HS_CHECK_EQ(stats.dropped, 0ull);
	HS_CHECK_EQ(stats.deferredRings, 0ull);
	HS_CHECK_EQ(sink.events.size(), static_cast<std::size_t>(kCount));
	HS_CHECK_EQ(sink.rings.size(), static_cast<std::size_t>(kCount));

	for (int i = 0; i < kCount; ++i) {
		HS_CHECK_EQ(sink.events[static_cast<std::size_t>(i)].seq, static_cast<std::uint64_t>(i + 1));
		HS_CHECK_EQ(sink.events[static_cast<std::size_t>(i)].ptr, 0x1000ull + static_cast<std::uint64_t>(i));
		HS_CHECK_EQ(sink.rings[static_cast<std::size_t>(i)], 0u);
	}

	// Final state, asserted rather than assumed: cursors agree, nothing was
	// dropped, and the session counters reflect exactly this run.
	const auto& ring = RingAt(region.base(), region.layout, 0);
	HS_CHECK_EQ(LoadRelaxed(ring.writeSeq), static_cast<std::uint64_t>(kCount));
	HS_CHECK_EQ(LoadRelaxed(ring.readSeq), static_cast<std::uint64_t>(kCount));
	HS_CHECK_EQ(LoadRelaxed(ring.drops), 0ull);
	HS_CHECK_EQ(LoadRelaxed(HeaderAt(region.base()).eventsConsumed), static_cast<std::uint64_t>(kCount));
	HS_CHECK_EQ(LoadRelaxed(HeaderAt(region.base()).eventsDropped), 0ull);
}

// When the producer outruns the consumer, the OLDEST records are lost and the
// loss is reported. A tracer that hid this - by blocking the producer, or by
// silently restarting the cursor - would be worse than one that admits it.
HS_TEST(ring_overwrite_gap_is_counted_not_hidden)
{
	TestRegion  region(64);
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, 100, 0, 0));

	constexpr std::uint64_t kCount = 100;
	for (std::uint64_t i = 0; i < kCount; ++i) {
		producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, i, i));
	}

	SinkState  sink;
	const auto stats = DrainAll(region.base(), region.layout, CollectSink, &sink);

	// The consumer starts at slot 0, which by now holds record 65, so it jumps
	// straight to the oldest record that is still resident and counts the rest
	// as lost. The semantics being pinned here are "newest survives" and "the
	// gap is exact".
	HS_CHECK_EQ(stats.dropped, 64ull);
	HS_CHECK_EQ(stats.consumed, 36ull);
	HS_CHECK_EQ(stats.consumed + stats.dropped, kCount);
	// Guarded on purpose: reading front() of an empty vector would abort the
	// whole runner and hide every later result, which is a worse failure mode
	// than the check simply failing.
	if (!sink.events.empty()) {
		HS_CHECK_EQ(sink.events.front().seq, 65ull);
		HS_CHECK_EQ(sink.events.back().seq, kCount);
	}
	HS_CHECK_EQ(LoadRelaxed(HeaderAt(region.base()).eventsDropped), 64ull);
	HS_CHECK_EQ(LoadRelaxed(HeaderAt(region.base()).eventsConsumed), 36ull);
}

// A slot that is being written right now stops the drain of that ring and is
// retried later. With one ring per thread, deferring costs nothing - so this is
// the difference between "a slow producer costs us a record" and "a slow
// producer costs us nothing".
HS_TEST(ring_defers_an_in_flight_slot_instead_of_dropping_it)
{
	TestRegion  region(64);
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, 100, 0, 0));

	constexpr std::uint64_t kCount = 10;
	for (std::uint64_t i = 0; i < kCount; ++i) {
		producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, i, i));
	}

	// Pretend the producer is halfway through record 5: the slot is invalidated
	// (odd version) but not yet published.
	Slot* slotForFive = SlotAt(region.base(), region.layout, 0, 5);
	const std::uint64_t publishedVersion = LoadRelaxed(slotForFive->version);
	StoreRelaxed(slotForFive->version, VersionFor(5, true));

	SinkState  firstSink;
	const auto first = DrainAll(region.base(), region.layout, CollectSink, &firstSink);
	HS_CHECK_EQ(first.consumed, 4ull);
	HS_CHECK_EQ(first.dropped, 0ull);
	HS_CHECK_EQ(first.deferredRings, 1ull);

	// ... and now the producer finishes.
	StoreRelease(slotForFive->version, publishedVersion);

	SinkState  secondSink;
	const auto second = DrainAll(region.base(), region.layout, CollectSink, &secondSink);
	HS_CHECK_EQ(second.consumed, 6ull);
	HS_CHECK_EQ(second.dropped, 0ull);
	HS_CHECK_EQ(second.deferredRings, 0ull);

	// Final state: everything arrived, nothing was lost, in order.
	HS_CHECK_EQ(firstSink.events.size() + secondSink.events.size(), static_cast<std::size_t>(kCount));
	if (!secondSink.events.empty()) {
		HS_CHECK_EQ(secondSink.events.back().seq, kCount);
	}
	HS_CHECK_EQ(LoadRelaxed(HeaderAt(region.base()).eventsDropped), 0ull);
	HS_CHECK_EQ(LoadRelaxed(HeaderAt(region.base()).eventsConsumed), kCount);
}

// The case the whole seqlock exists for: a producer that dies mid-record. The
// slot stays invalidated forever, and the consumer must defer it rather than
// read whatever half-written bytes are there. The payload is filled with a
// pattern that must never reach the sink.
HS_TEST(ring_never_reads_a_record_abandoned_mid_write)
{
	TestRegion  region(64);
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, 100, 0, 0));

	for (std::uint64_t i = 0; i < 3; ++i) {
		producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, i, i));
	}

	// Record 2 is abandoned: invalidated, then the producer "dies".
	Slot* slotForTwo = SlotAt(region.base(), region.layout, 0, 2);
	std::memset(&slotForTwo->event, 0xAB, sizeof(ShmEvent));
	StoreRelaxed(slotForTwo->version, VersionFor(2, true));

	SinkState  sink;
	const auto stats = DrainAll(region.base(), region.layout, CollectSink, &sink);

	HS_CHECK_EQ(stats.consumed, 1ull);   // only record 1 is safely readable
	HS_CHECK_EQ(stats.dropped, 0ull);    // deferred, not lost
	HS_CHECK_EQ(stats.deferredRings, 1ull);
	HS_CHECK_EQ(sink.events.size(), 1u);
	if (!sink.events.empty()) {
		HS_CHECK_EQ(sink.events.front().seq, 1ull);
	}

	// Repeating the drain must not "discover" the abandoned slot later: the
	// version is still odd, so it stays deferred forever rather than being read.
	const auto again = DrainAll(region.base(), region.layout, CollectSink, &sink);
	HS_CHECK_EQ(again.consumed, 0ull);
	HS_CHECK_EQ(again.deferredRings, 1ull);
	HS_CHECK_EQ(sink.events.size(), 1u);
}

// A property test for the tear: every payload field is a pure function of the
// record's own seq, and the ring is deliberately tiny so the producer overwrites
// constantly while the consumer copies. Any accepted tear - a pointer from one
// record with a size from another - fails the check inside the sink.
HS_TEST(ring_never_emits_a_torn_record)
{
	TestRegion  region(8);  // tiny on purpose: overwrites are continuous
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, 500, 0, 0));

	constexpr std::uint64_t kCount = 200000;

	struct SinkCtx
	{
		std::atomic<std::uint64_t>* emitted;
		std::atomic<std::uint64_t>* torn;
	};
	std::atomic<std::uint64_t> emitted{ 0 };
	std::atomic<std::uint64_t> torn{ 0 };
	SinkCtx                    ctx{ &emitted, &torn };

	EventSink sink = [](void* a_context, std::uint32_t, const ShmEvent& a_event) {
		auto* state = static_cast<SinkCtx*>(a_context);
		const std::uint64_t seq = a_event.seq;
		const bool consistent =
			a_event.ptr == (seq * 0x1000ull) + 0x5A5Aull &&
			a_event.size == seq &&
			a_event.site == (seq ^ 0xDEADBEEFull) &&
			a_event.aux == (seq * 3ull) &&
			a_event.tick == seq;
		if (!consistent) {
			state->torn->fetch_add(1, std::memory_order_relaxed);
		}
		state->emitted->fetch_add(1, std::memory_order_relaxed);
	};

	std::atomic<bool> stop{ false };
	std::thread       consumer([&] {
		while (!stop.load(std::memory_order_relaxed)) {
			DrainAll(region.base(), region.layout, sink, &ctx);
		}
	});

	for (std::uint64_t i = 0; i < kCount; ++i) {
		const std::uint64_t seq = producer.Published() + 1;
		ShmEvent            event{};
		event.kind = static_cast<std::uint32_t>(EventKind::kAlloc);
		event.ptr = (seq * 0x1000ull) + 0x5A5Aull;
		event.size = seq;
		event.site = seq ^ 0xDEADBEEFull;
		event.aux = seq * 3ull;
		event.tick = seq;
		producer.Publish(region.base(), region.layout, event);
	}

	stop.store(true, std::memory_order_relaxed);
	consumer.join();

	// Drain whatever is still resident, then assert the accounting invariant:
	// every record the producer wrote is either consumed or counted as dropped.
	DrainAll(region.base(), region.layout, sink, &ctx);

	const std::uint64_t consumed = LoadRelaxed(HeaderAt(region.base()).eventsConsumed);
	const std::uint64_t dropped = LoadRelaxed(HeaderAt(region.base()).eventsDropped);

	HS_CHECK_EQ(torn.load(), 0ull);
	HS_CHECK(emitted.load() > 0);
	HS_CHECK_EQ(emitted.load(), consumed);
	HS_CHECK_EQ(consumed + dropped, kCount);
}

HS_TEST(ring_concurrent_producer_and_consumer_keep_the_invariant)
{
	TestRegion  region(65536);
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, 900, 0, 0));

	constexpr std::uint64_t kCount = 200000;

	struct SinkCtx
	{
		std::atomic<std::uint64_t>* consumed;
		std::atomic<std::uint64_t>* outOfOrder;
	};
	std::atomic<std::uint64_t> consumed{ 0 };
	std::atomic<std::uint64_t> outOfOrder{ 0 };
	SinkCtx                    ctx{ &consumed, &outOfOrder };

	EventSink sink = [](void* a_context, std::uint32_t, const ShmEvent& a_event) {
		auto* state = static_cast<SinkCtx*>(a_context);
		// Records must arrive in strictly increasing seq order within a ring.
		const std::uint64_t previous = state->consumed->fetch_add(1, std::memory_order_relaxed);
		if (a_event.seq <= previous) {
			state->outOfOrder->fetch_add(1, std::memory_order_relaxed);
		}
	};

	std::atomic<bool> stop{ false };
	std::thread       consumer([&] {
		while (!stop.load(std::memory_order_relaxed)) {
			DrainAll(region.base(), region.layout, sink, &ctx);
		}
	});

	for (std::uint64_t i = 0; i < kCount; ++i) {
		producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, i, i));
	}

	stop.store(true, std::memory_order_relaxed);
	consumer.join();
	DrainAll(region.base(), region.layout, sink, &ctx);

	const std::uint64_t drained = LoadRelaxed(HeaderAt(region.base()).eventsConsumed);
	const std::uint64_t dropped = LoadRelaxed(HeaderAt(region.base()).eventsDropped);

	HS_CHECK_EQ(outOfOrder.load(), 0ull);
	HS_CHECK_EQ(drained + dropped, kCount);
	// A 64 Ki slot ring drained continuously should lose essentially nothing.
	// The bound is generous so the test cannot flake on a loaded CI machine, but
	// it is tight enough that a ring which never recycles, or one that silently
	// restarts its cursor, fails loudly.
	HS_CHECK(dropped < kCount / 100);
}

HS_TEST(ring_registry_claims_releases_and_exhausts)
{
	TestRegion region(64);

	// Every ring is claimable exactly once, and the next claim must fail rather
	// than hand out a ring that is already in use.
	std::vector<std::int32_t> claimed;
	for (std::uint32_t i = 0; i < kMaxRings; ++i) {
		claimed.push_back(ClaimRing(region.base(), region.layout, /*threadId*/ 1000 + i, 0, 0));
	}
	for (std::uint32_t i = 0; i < kMaxRings; ++i) {
		HS_CHECK_EQ(claimed[i], static_cast<std::int32_t>(i));
	}

	HS_CHECK_EQ(ClaimRing(region.base(), region.layout, 999999, 0, 0), -1);
	// A thread that already owns a ring must not be handed the same one again:
	// that would silently create a second producer on one buffer.
	HS_CHECK_EQ(ClaimRing(region.base(), region.layout, 1000, 0, 0), -1);
	// A thread id of 0 encodes "free", so it can never own a ring.
	HS_CHECK_EQ(ClaimRing(region.base(), region.layout, 0, 0, 0), -1);

	// Releasing one frees exactly one.
	ReleaseRing(region.base(), region.layout, 5, 1005);
	HS_CHECK_EQ(LoadRelaxed(RingAt(region.base(), region.layout, 5).ownerThread), 0ull);
	HS_CHECK_EQ(ClaimRing(region.base(), region.layout, 4242, 0, 0), 5);

	// A late release by the original owner must not steal the ring back.
	ReleaseRing(region.base(), region.layout, 5, 1005);
	HS_CHECK_EQ(LoadRelaxed(RingAt(region.base(), region.layout, 5).ownerThread), 4242ull);
}

HS_TEST(ring_stale_takeover_reclaims_an_abandoned_ring)
{
	TestRegion region(64);

	// Ring 0 belongs to a thread that is about to go silent.
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, /*threadId*/ 2000, /*nowTick*/ 1000, 0));
	HS_CHECK_EQ(producer.RingIndex(), 0u);
	producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, 1, 1000));
	HS_CHECK_EQ(LoadRelaxed(RingAt(region.base(), region.layout, 0).writeSeq), 1ull);

	// Fill the rest, so the registry is completely busy.
	for (std::uint32_t i = 1; i < kMaxRings; ++i) {
		HS_CHECK_EQ(ClaimRing(region.base(), region.layout, 2000 + i, 1000, 0), static_cast<std::int32_t>(i));
	}

	// A brand new thread arrives while every ring is busy, and the owners have
	// been silent since tick 1000.
	const std::uint64_t staleTicks = 1000;
	HS_CHECK_EQ(ClaimRing(region.base(), region.layout, 7777, 1000, staleTicks), -1);  // not stale yet

	// Once the silence exceeds the window, a ring is taken over rather than the
	// new thread being refused outright.
	const std::int32_t taken = ClaimRing(region.base(), region.layout, 7777, 1000 + staleTicks + 1, staleTicks);
	HS_CHECK_EQ(taken, 0);
	HS_CHECK_EQ(LoadRelaxed(RingAt(region.base(), region.layout, 0).ownerThread), 7777ull);

	// Taking over starts a fresh generation: the old cursors and the stale
	// backlog must be gone, not inherited.
	const auto& ring = RingAt(region.base(), region.layout, 0);
	HS_CHECK_EQ(LoadRelaxed(ring.writeSeq), 0ull);
	HS_CHECK_EQ(LoadRelaxed(ring.readSeq), 0ull);
	HS_CHECK_EQ(LoadRelaxed(ring.generation), 2ull);  // bumped by the first claim and by this one
}

HS_TEST(ring_a_reclaimed_generation_is_not_read)
{
	TestRegion  region(64);
	RingProducer first;
	HS_CHECK(first.Claim(region.base(), region.layout, 3000, 0, 0));

	for (std::uint64_t i = 0; i < 10; ++i) {
		first.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, i, i));
	}

	first.Release(region.base(), region.layout);

	RingProducer second;
	HS_CHECK(second.Claim(region.base(), region.layout, 3001, 0, 0));
	HS_CHECK_EQ(second.RingIndex(), 0u);

	for (std::uint64_t i = 0; i < 5; ++i) {
		second.Publish(region.base(), region.layout, MakeEvent(EventKind::kFree, i, i));
	}

	SinkState  sink;
	const auto stats = DrainAll(region.base(), region.layout, CollectSink, &sink);

	// Only the new generation's five records, even though the slots still hold
	// the previous generation's versions.
	HS_CHECK_EQ(stats.consumed, 5ull);
	HS_CHECK_EQ(stats.dropped, 0ull);
	HS_CHECK_EQ(sink.events.size(), 5u);
	if (!sink.events.empty()) {
		HS_CHECK_EQ(sink.events.front().seq, 1ull);
		HS_CHECK_EQ(sink.events.back().seq, 5ull);
	}
	for (const auto& event : sink.events) {
		HS_CHECK_EQ(event.kind, static_cast<std::uint32_t>(EventKind::kFree));
	}
}

// A producer whose ring was taken over while it was idle must re-claim rather
// than keep writing into a ring that now belongs to somebody else. Two producers
// on one buffer is the one failure the design cannot tolerate.
HS_TEST(ring_producer_reclaims_itself_after_losing_its_ring)
{
	TestRegion  region(64);
	RingProducer producer;
	HS_CHECK(producer.Claim(region.base(), region.layout, 4000, 0, 0));
	HS_CHECK_EQ(producer.RingIndex(), 0u);
	producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, 1, 1));

	// Simulate the takeover out of band.
	StoreRelaxed(RingAt(region.base(), region.layout, 0).ownerThread, 4001);

	producer.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, 2, 2));

	HS_CHECK(producer.Owned());
	HS_CHECK_NE(producer.RingIndex(), 0u);
	// The stolen ring must be untouched, and the new one must hold exactly the
	// one record published after the loss.
	HS_CHECK_EQ(LoadRelaxed(RingAt(region.base(), region.layout, 0).writeSeq), 1ull);
	HS_CHECK_EQ(LoadRelaxed(RingAt(region.base(), region.layout, producer.RingIndex()).writeSeq), 1ull);
}

HS_TEST(ring_drain_all_covers_every_ring)
{
	TestRegion region(64);

	RingProducer first;
	RingProducer second;
	RingProducer third;
	HS_CHECK(first.Claim(region.base(), region.layout, 5000, 0, 0));
	HS_CHECK(second.Claim(region.base(), region.layout, 5001, 0, 0));
	HS_CHECK(third.Claim(region.base(), region.layout, 5002, 0, 0));

	for (std::uint64_t i = 0; i < 7; ++i) {
		first.Publish(region.base(), region.layout, MakeEvent(EventKind::kAlloc, i, i));
	}
	for (std::uint64_t i = 0; i < 3; ++i) {
		second.Publish(region.base(), region.layout, MakeEvent(EventKind::kFree, i, i));
	}
	for (std::uint64_t i = 0; i < 11; ++i) {
		third.Publish(region.base(), region.layout, MakeEvent(EventKind::kReport, i, i));
	}

	SinkState  sink;
	const auto stats = DrainAll(region.base(), region.layout, CollectSink, &sink);

	HS_CHECK_EQ(stats.consumed, 21ull);
	HS_CHECK_EQ(stats.dropped, 0ull);
	HS_CHECK_EQ(sink.events.size(), 21u);
	HS_CHECK_EQ(sink.rings.size(), 21u);

	int inFirst = 0;
	int inSecond = 0;
	int inThird = 0;
	for (auto ring : sink.rings) {
		if (ring == first.RingIndex()) {
			++inFirst;
		} else if (ring == second.RingIndex()) {
			++inSecond;
		} else if (ring == third.RingIndex()) {
			++inThird;
		}
	}
	HS_CHECK_EQ(inFirst, 7);
	HS_CHECK_EQ(inSecond, 3);
	HS_CHECK_EQ(inThird, 11);
}
