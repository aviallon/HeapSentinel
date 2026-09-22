// Off-game tests for the durable Scaleform free ring: the eviction bound, the
// newest-match lookup, the retention window, and fail-open before Init. This is
// the general-purpose attribution store for a delayed use-after-free, so its
// loss must be bounded AND legible.

#include "harness.h"

#include "Core/ScaleformFreeRing.h"

using namespace hs;

namespace
{
	void Reset(std::size_t a_capacity = 4)
	{
		ScaleformFreeRing::Get().Shutdown();
		HS_CHECK(ScaleformFreeRing::Get().Init(a_capacity));
		HS_CHECK(ScaleformFreeRing::Get().Ready());
	}

	ScaleformFreeRecord MakeRecord(std::uintptr_t a_ptr, std::uint64_t a_tick)
	{
		ScaleformFreeRecord record;
		record.ptr = a_ptr;
		record.vtableAtFree = 0x140D0000;
		record.size = 0x30;
		record.freeSite = reinterpret_cast<void*>(0x140D0001);
		record.freeStack = 1;
		record.freeTick = a_tick;
		record.threadId = 7;
		return record;
	}
}

HS_TEST(free_ring_rounds_capacity_up_to_a_power_of_two)
{
	Reset(5);
	HS_CHECK_EQ(ScaleformFreeRing::Get().Capacity(), std::size_t{ 8 });
	ScaleformFreeRing::Get().Shutdown();
}

HS_TEST(free_ring_evicts_oldest_and_counts_evictions)
{
	Reset(4);

	for (std::uintptr_t i = 1; i <= 6; ++i) {
		ScaleformFreeRing::Get().Record(MakeRecord(0x1000 * i, i));
	}

	HS_CHECK_EQ(ScaleformFreeRing::Get().Count(), std::size_t{ 4 });
	HS_CHECK_EQ(ScaleformFreeRing::Get().Evictions(), std::uint64_t{ 2 });

	ScaleformFreeRecord out;
	// The two oldest are gone; the newest four are present.
	HS_CHECK(!ScaleformFreeRing::Get().Find(0x1000, out));
	HS_CHECK(!ScaleformFreeRing::Get().Find(0x2000, out));
	HS_CHECK(ScaleformFreeRing::Get().Find(0x3000, out));
	HS_CHECK_EQ(out.freeTick, std::uint64_t{ 3 });
	HS_CHECK(ScaleformFreeRing::Get().Find(0x6000, out));
	HS_CHECK_EQ(out.freeTick, std::uint64_t{ 6 });

	// Retention window = newest tick - oldest retained tick.
	std::uint64_t oldest = 0;
	std::uint64_t newest = 0;
	HS_CHECK(ScaleformFreeRing::Get().RetentionTicks(oldest, newest));
	HS_CHECK_EQ(oldest, std::uint64_t{ 3 });
	HS_CHECK_EQ(newest, std::uint64_t{ 6 });

	ScaleformFreeRing::Get().Shutdown();
}

HS_TEST(free_ring_find_returns_the_newest_record_for_a_reused_pointer)
{
	Reset(8);

	ScaleformFreeRing::Get().Record(MakeRecord(0xABC0, 10));
	ScaleformFreeRing::Get().Record(MakeRecord(0xABC0, 20));

	ScaleformFreeRecord out;
	HS_CHECK(ScaleformFreeRing::Get().Find(0xABC0, out));
	HS_CHECK_EQ(out.freeTick, std::uint64_t{ 20 });

	// Unknown pointer is a clean negative, not a wrong record.
	HS_CHECK(!ScaleformFreeRing::Get().Find(0xDEAD, out));

	ScaleformFreeRing::Get().Shutdown();
}

HS_TEST(free_ring_is_fail_open_before_init)
{
	ScaleformFreeRing::Get().Shutdown();
	HS_CHECK(!ScaleformFreeRing::Get().Ready());
	HS_CHECK_EQ(ScaleformFreeRing::Get().Count(), std::size_t{ 0 });

	// Must not crash, and must not record.
	ScaleformFreeRing::Get().Record(MakeRecord(0x1, 1));
	HS_CHECK_EQ(ScaleformFreeRing::Get().Count(), std::size_t{ 0 });

	ScaleformFreeRecord out;
	HS_CHECK(!ScaleformFreeRing::Get().Find(0x1, out));

	std::uint64_t oldest = 0;
	std::uint64_t newest = 0;
	HS_CHECK(!ScaleformFreeRing::Get().RetentionTicks(oldest, newest));
}