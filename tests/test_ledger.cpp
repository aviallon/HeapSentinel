// Off-game tests for the shadow ledger, including the new Scaleform allocation
// source. The ledger is plain C++ (no Windows, no logger) so tests/ can build
// and run it on Linux and Windows, which is what makes "the ledger handles two
// allocation sources" a checked claim rather than an assumption.

#include "harness.h"

#include "Core/ShadowLedger.h"

#include <atomic>
#include <chrono>
#include <thread>

using namespace hs;

namespace
{
	constexpr std::uintptr_t kKeyA = 0x1000;
	constexpr std::uintptr_t kKeyB = 0x2000;
	constexpr std::uintptr_t kKeyC = 0x3000;

	void ResetLedger(std::size_t a_capacity = 1024, std::size_t a_shards = 8, std::size_t a_stackDepth = 0)
	{
		ShadowLedger::Get().Shutdown();
		HS_CHECK(ShadowLedger::Get().Init(a_capacity, a_shards, a_stackDepth));
		HS_CHECK(ShadowLedger::Get().Ready());
	}

	AllocationInfo MakeInfo(std::uintptr_t a_ptr, std::size_t a_size, std::uint32_t a_flags)
	{
		AllocationInfo info;
		info.ptr = a_ptr;
		info.size = a_size;
		info.threadId = 42;
		info.flags = a_flags;
		info.allocSite = reinterpret_cast<void*>(0xA110C);
		return info;
	}
}

HS_TEST(ledger_insert_find_erase_roundtrip)
{
	ResetLedger();

	ShadowLedger::Get().Insert(kKeyA, MakeInfo(kKeyA, 0x40, kFlagLive));
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 1 });

	AllocationInfo out;
	HS_CHECK(ShadowLedger::Get().Find(kKeyA, out));
	HS_CHECK_EQ(out.size, std::size_t{ 0x40 });
	HS_CHECK_EQ(out.threadId, 42u);
	HS_CHECK_EQ(out.flags, kFlagLive);

	HS_CHECK(ShadowLedger::Get().Erase(kKeyA, out));
	HS_CHECK_EQ(out.size, std::size_t{ 0x40 });
	HS_CHECK(!ShadowLedger::Get().Find(kKeyA, out));
	// Erase leaves a tombstone; Count() is occupancy (live + tombstones), which
	// is exactly the number the saturation/insert-failure accounting is about.
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 1 });

	ShadowLedger::Get().Shutdown();
}

HS_TEST(ledger_rejects_the_reserved_empty_and_tombstone_keys)
{
	ResetLedger();

	// 0 is the empty marker and 1 is the tombstone marker; neither may become a
	// key, or a lookup could never terminate on the correct state.
	ShadowLedger::Get().Insert(0, MakeInfo(0, 0x10, kFlagLive));
	ShadowLedger::Get().Insert(1, MakeInfo(1, 0x10, kFlagLive));

	AllocationInfo out;
	HS_CHECK(!ShadowLedger::Get().Find(0, out));
	HS_CHECK(!ShadowLedger::Get().Find(1, out));
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 0 });

	ShadowLedger::Get().Shutdown();
}

HS_TEST(ledger_two_allocation_sources_coexist)
{
	ResetLedger();

	// One entry as the engine hooks write it, one as the new Scaleform hooks do.
	ShadowLedger::Get().Insert(kKeyA, MakeInfo(kKeyA, 0x30, kFlagLive));
	ShadowLedger::Get().Insert(kKeyB, MakeInfo(kKeyB, 0x80, kFlagLive | kFlagScaleform));
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 2 });

	AllocationInfo engine;
	AllocationInfo scaleform;
	HS_CHECK(ShadowLedger::Get().Find(kKeyA, engine));
	HS_CHECK(ShadowLedger::Get().Find(kKeyB, scaleform));
	HS_CHECK_EQ(engine.flags & kFlagScaleform, 0u);
	HS_CHECK(scaleform.flags & kFlagScaleform);
	HS_CHECK(scaleform.flags & kFlagLive);
	HS_CHECK_EQ(scaleform.size, std::size_t{ 0x80 });

	// Freeing the Scaleform block must not disturb the engine block.
	ShadowLedger::Get().Insert(kKeyB, MakeInfo(kKeyB, 0x80, kFlagLive | kFlagScaleform | kFlagFreed));
	HS_CHECK(ShadowLedger::Get().Find(kKeyB, scaleform));
	HS_CHECK(scaleform.flags & kFlagFreed);
	HS_CHECK(ShadowLedger::Get().Find(kKeyA, engine));
	HS_CHECK_EQ(engine.flags & kFlagFreed, 0u);
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 2 });

	ShadowLedger::Get().Shutdown();
}

HS_TEST(ledger_reports_effective_capacity)
{
	ResetLedger(1024, 8, 0);
	// 1024 entries over 8 shards = 128 slots per shard.
	HS_CHECK_EQ(ShadowLedger::Get().Capacity(), std::size_t{ 1024 });

	ResetLedger(100, 8, 0);
	// 100/8 rounds up to 16 per shard, 8 shards = 128.
	HS_CHECK_EQ(ShadowLedger::Get().Capacity(), std::size_t{ 128 });

	ShadowLedger::Get().Shutdown();
}

HS_TEST(ledger_saturates_and_counts_insert_failures)
{
	// One shard of 16 slots: exactly 16 live entries fit, the 17th cannot.
	ResetLedger(16, 1, 0);
	HS_CHECK_EQ(ShadowLedger::Get().Capacity(), std::size_t{ 16 });

	for (std::uintptr_t i = 0; i < 16; ++i) {
		const auto key = 0x10000 + i * 0x40;
		ShadowLedger::Get().Insert(key, MakeInfo(key, 0x10, kFlagLive));
	}
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 16 });
	HS_CHECK_EQ(ShadowLedger::Get().InsertFailures(), std::uint64_t{ 0 });

	ShadowLedger::Get().Insert(0x99999, MakeInfo(0x99999, 0x10, kFlagLive));
	HS_CHECK_EQ(ShadowLedger::Get().InsertFailures(), std::uint64_t{ 1 });
	// Fail open: the table is unchanged, nothing was dropped from it.
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 16 });

	ShadowLedger::Get().Shutdown();
}

HS_TEST(ledger_reuses_a_freed_entry_when_the_probe_window_is_full)
{
	ResetLedger(16, 1, 0);

	for (std::uintptr_t i = 0; i < 16; ++i) {
		const auto key = 0x20000 + i * 0x40;
		ShadowLedger::Get().Insert(key, MakeInfo(key, 0x10, kFlagLive));
	}
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 16 });

	// Mark one block freed; the ledger now holds a reusable quarantine entry.
	const auto freedKey = 0x20000;
	AllocationInfo freed;
	HS_CHECK(ShadowLedger::Get().Find(freedKey, freed));
	freed.flags |= kFlagFreed;
	ShadowLedger::Get().Insert(freedKey, freed);

	// A new allocation that probes the (full) table must evict the freed entry
	// rather than fail, because that is the ledger's bounded quarantine.
	ShadowLedger::Get().Insert(0x77777, MakeInfo(0x77777, 0x20, kFlagLive));
	HS_CHECK_EQ(ShadowLedger::Get().InsertFailures(), std::uint64_t{ 0 });
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 16 });

	AllocationInfo out;
	HS_CHECK(ShadowLedger::Get().Find(0x77777, out));
	HS_CHECK(!ShadowLedger::Get().Find(freedKey, out));

	ShadowLedger::Get().Shutdown();
}

HS_TEST(ledger_stack_ring_round_trips)
{
	ResetLedger(1024, 8, 8);

	Stack empty;
	HS_CHECK_EQ(ShadowLedger::Get().StoreStack(empty), 0u);

	Stack stack;
	stack.count = 3;
	stack.frames[0] = reinterpret_cast<void*>(0xDEAD);
	stack.frames[1] = reinterpret_cast<void*>(0xBEEF);
	stack.frames[2] = reinterpret_cast<void*>(0xC0FFEE);

	const auto index = ShadowLedger::Get().StoreStack(stack);
	HS_CHECK_NE(index, 0u);

	const auto* stored = ShadowLedger::Get().GetStack(index);
	HS_CHECK(stored != nullptr);
	HS_CHECK_EQ(stored->count, 3u);
	HS_CHECK_EQ(reinterpret_cast<std::uintptr_t>(stored->frames[1]), std::uintptr_t{ 0xBEEF });

	HS_CHECK(ShadowLedger::Get().GetStack(0) == nullptr);

	ShadowLedger::Get().Shutdown();
}

HS_TEST(ledger_is_fail_open_before_init)
{
	ShadowLedger::Get().Shutdown();
	HS_CHECK(!ShadowLedger::Get().Ready());

	AllocationInfo out;
	HS_CHECK(!ShadowLedger::Get().Find(kKeyA, out));
	// These must be no-ops, not crashes: the hooks call them before Init and
	// after Shutdown.
	ShadowLedger::Get().Insert(kKeyA, MakeInfo(kKeyA, 0x10, kFlagLive));
	AllocationInfo erased;
	HS_CHECK(!ShadowLedger::Get().Erase(kKeyA, erased));
	HS_CHECK_EQ(ShadowLedger::Get().Count(), std::size_t{ 0 });
}

HS_TEST(ledger_records_the_vtable_and_tick_attribution_fields)
{
	ResetLedger();

	AllocationInfo info = MakeInfo(kKeyA, 0x280, kFlagLive | kFlagScaleform);
	info.vtableAtAlloc = 0xDEAD;                  // pre-construction garbage
	info.vtableAtFree = 0x140D0000;               // the real vtable at death
	info.lastKnownVtable = 0x140D0000;
	info.allocTick = 100;
	info.freeTick = 250;
	info.poisonIndex = 7;
	ShadowLedger::Get().Insert(kKeyA, info);

	AllocationInfo out;
	HS_CHECK(ShadowLedger::Get().Find(kKeyA, out));
	HS_CHECK_EQ(out.vtableAtAlloc, std::uintptr_t{ 0xDEAD });
	HS_CHECK_EQ(out.vtableAtFree, std::uintptr_t{ 0x140D0000 });
	HS_CHECK_EQ(out.lastKnownVtable, std::uintptr_t{ 0x140D0000 });
	HS_CHECK_EQ(out.allocTick, std::uint64_t{ 100 });
	HS_CHECK_EQ(out.freeTick, std::uint64_t{ 250 });
	HS_CHECK_EQ(out.poisonIndex, 7u);

	ShadowLedger::Get().Shutdown();
}

// The VEH reads the ledger with NO lock. The per-entry seqlock must therefore
// guarantee that a successful Find never returns a record whose fields were
// written by two different Insert calls (a torn record). The writer keeps two
// fields equal on every write; the reader asserts that invariant on every
// successful read. A plain data race would fail this frequently.
HS_TEST(ledger_find_is_lock_free_and_never_returns_a_torn_record)
{
	ResetLedger(1024, 8, 0);

	std::atomic<bool> stop{ false };
	std::atomic<std::uint64_t> reads{ 0 };
	std::atomic<std::uint64_t> mismatches{ 0 };

	std::thread writer([&] {
		for (std::uint64_t i = 1; i <= 200000; ++i) {
			AllocationInfo info = MakeInfo(kKeyA, 0x40, kFlagLive);
			info.poisonIndex = static_cast<std::uint32_t>(i);
			info.size = static_cast<std::size_t>(i);
			ShadowLedger::Get().Insert(kKeyA, info);
		}
		stop.store(true, std::memory_order_release);
	});

	while (!stop.load(std::memory_order_acquire)) {
		AllocationInfo out;
		if (ShadowLedger::Get().Find(kKeyA, out)) {
			reads.fetch_add(1, std::memory_order_relaxed);
			if (static_cast<std::uint64_t>(out.size) != static_cast<std::uint64_t>(out.poisonIndex)) {
				mismatches.fetch_add(1, std::memory_order_relaxed);
			}
		}
	}
	writer.join();

	HS_CHECK_NE(reads.load(), std::uint64_t{ 0 });
	HS_CHECK_EQ(mismatches.load(), std::uint64_t{ 0 });

	ShadowLedger::Get().Shutdown();
}