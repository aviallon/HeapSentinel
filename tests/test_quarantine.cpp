// Off-game tests for the poison-on-free quarantine: the poison encode/decode,
// the bounded budget (blocks and bytes), the FIFO drain order, and the
// fail-open behaviour when the ring is at capacity.

#include "harness.h"

#include "Core/PoisonQuarantine.h"

using namespace hs;

namespace
{
	constexpr std::uintptr_t kBase = 0x7F0000000000ull;
	constexpr std::size_t    kStride = 0x1000;

	void Reset(std::size_t a_blocks = 4, std::size_t a_bytes = 0)
	{
		PoisonQuarantine::Get().Shutdown();
		HS_CHECK(PoisonQuarantine::Get().Init(a_blocks, a_bytes, kBase, kStride));
		HS_CHECK(PoisonQuarantine::Get().Ready());
	}

	QuarantineRecord MakeRecord(std::uint32_t a_index, std::uintptr_t a_ptr, std::size_t a_size, std::uint64_t a_tick)
	{
		QuarantineRecord record;
		record.ptr = a_ptr;
		record.heap = reinterpret_cast<void*>(0x1234);
		record.size = a_size;
		record.vtableAtFree = 0x140D0000;
		record.freeSite = reinterpret_cast<void*>(0x140D0001);
		record.freeStack = a_index;
		record.index = a_index;
		record.freeTick = a_tick;
		return record;
	}
}

HS_TEST(quarantine_poison_encodes_and_decodes_back_to_the_record)
{
	Reset(16, 0);

	// A poison value is an address in the reserved region, and the fault address
	// decodes to the owning slot even when the fault was at a vtable offset.
	std::uint32_t index = 0;
	HS_CHECK_EQ(PoisonQuarantine::Get().PoisonFor(1), kBase);
	HS_CHECK(PoisonQuarantine::Get().DecodeFault(kBase, index));
	HS_CHECK_EQ(index, 1u);
	HS_CHECK(PoisonQuarantine::Get().DecodeFault(kBase + 0x18, index));
	HS_CHECK_EQ(index, 1u);
	HS_CHECK(PoisonQuarantine::Get().DecodeFault(kBase + kStride, index));
	HS_CHECK_EQ(index, 2u);
	HS_CHECK_EQ(PoisonQuarantine::Get().PoisonFor(3), kBase + 2 * kStride);

	// Outside the region is not a poison address.
	HS_CHECK(!PoisonQuarantine::Get().DecodeFault(kBase - 1, index));
	HS_CHECK(!PoisonQuarantine::Get().DecodeFault(kBase + 16 * kStride, index));
	HS_CHECK(!PoisonQuarantine::Get().DecodeFault(0x1000, index));

	PoisonQuarantine::Get().Shutdown();
}

HS_TEST(quarantine_publish_and_getslot_round_trip)
{
	Reset(16, 0);

	const auto index = PoisonQuarantine::Get().Reserve();
	HS_CHECK_EQ(index, 1u);

	QuarantineRecord record;
	HS_CHECK(!PoisonQuarantine::Get().GetSlot(1, record));  // published only after Publish

	PoisonQuarantine::Get().Publish(MakeRecord(1, 0xA000, 0x40, 100));
	HS_CHECK(PoisonQuarantine::Get().GetSlot(1, record));
	HS_CHECK_EQ(record.ptr, std::uintptr_t{ 0xA000 });
	HS_CHECK_EQ(record.size, std::size_t{ 0x40 });
	HS_CHECK_EQ(record.freeTick, std::uint64_t{ 100 });

	HS_CHECK(!PoisonQuarantine::Get().GetSlot(2, record));  // never reserved
	HS_CHECK(!PoisonQuarantine::Get().GetSlot(0, record));

	PoisonQuarantine::Get().Shutdown();
}

HS_TEST(quarantine_is_bounded_by_blocks_and_fails_open_at_capacity)
{
	Reset(4, 0);

	for (std::uint32_t i = 1; i <= 4; ++i) {
		const auto index = PoisonQuarantine::Get().Reserve();
		HS_CHECK_EQ(index, i);
		PoisonQuarantine::Get().Publish(MakeRecord(index, 0xB000 + i, 0x20, i));
	}
	HS_CHECK_EQ(PoisonQuarantine::Get().Count(), std::size_t{ 4 });
	HS_CHECK(PoisonQuarantine::Get().OverBudget(0x20));

	// At capacity the next reservation is refused: the caller drains or fails
	// open, never blocks.
	HS_CHECK_EQ(PoisonQuarantine::Get().Reserve(), 0u);

	PoisonQuarantine::Get().Shutdown();
}

HS_TEST(quarantine_drains_oldest_first_and_reports_bytes)
{
	Reset(4, 200);

	for (std::uint32_t i = 1; i <= 3; ++i) {
		const auto index = PoisonQuarantine::Get().Reserve();
		PoisonQuarantine::Get().Publish(MakeRecord(index, 0xC000 + i, 40, i));
	}
	HS_CHECK_EQ(PoisonQuarantine::Get().Bytes(), std::size_t{ 120 });
	// 120 + 100 > 200: the byte budget, not the block budget, is the limit.
	HS_CHECK(PoisonQuarantine::Get().OverBudget(100));
	HS_CHECK(!PoisonQuarantine::Get().OverBudget(80));

	QuarantineRecord record;
	HS_CHECK(PoisonQuarantine::Get().PopOldest(record));
	HS_CHECK_EQ(record.ptr, std::uintptr_t{ 0xC001 });  // FIFO
	HS_CHECK_EQ(record.freeTick, std::uint64_t{ 1 });
	HS_CHECK_EQ(PoisonQuarantine::Get().Bytes(), std::size_t{ 80 });
	HS_CHECK(!PoisonQuarantine::Get().OverBudget(100));  // 80 + 100 <= 200

	HS_CHECK(PoisonQuarantine::Get().PopOldest(record));
	HS_CHECK_EQ(record.ptr, std::uintptr_t{ 0xC002 });
	HS_CHECK(PoisonQuarantine::Get().PopOldest(record));
	HS_CHECK_EQ(record.ptr, std::uintptr_t{ 0xC003 });
	HS_CHECK(!PoisonQuarantine::Get().PopOldest(record));
	HS_CHECK_EQ(PoisonQuarantine::Get().Bytes(), std::size_t{ 0 });

	PoisonQuarantine::Get().Shutdown();
}

HS_TEST(quarantine_skips_an_unpublished_reservation)
{
	Reset(4, 0);

	// Reservation 1 is never published (simulating a crash mid-free); draining
	// must skip it and still make progress, not wedge.
	HS_CHECK_EQ(PoisonQuarantine::Get().Reserve(), 1u);
	const auto second = PoisonQuarantine::Get().Reserve();
	HS_CHECK_EQ(second, 2u);
	PoisonQuarantine::Get().Publish(MakeRecord(2, 0xD000, 0x10, 7));

	QuarantineRecord record;
	HS_CHECK(PoisonQuarantine::Get().PopOldest(record));
	HS_CHECK_EQ(record.ptr, std::uintptr_t{ 0xD000 });
	HS_CHECK(!PoisonQuarantine::Get().PopOldest(record));
	HS_CHECK_EQ(PoisonQuarantine::Get().Count(), std::size_t{ 0 });

	PoisonQuarantine::Get().Shutdown();
}

HS_TEST(quarantine_is_fail_open_before_init)
{
	PoisonQuarantine::Get().Shutdown();
	HS_CHECK(!PoisonQuarantine::Get().Ready());

	// Every operation is a safe no-op before Init / after Shutdown.
	HS_CHECK_EQ(PoisonQuarantine::Get().Reserve(), 0u);
	HS_CHECK_EQ(PoisonQuarantine::Get().Count(), std::size_t{ 0 });

	QuarantineRecord record;
	HS_CHECK(!PoisonQuarantine::Get().PopOldest(record));
	HS_CHECK(!PoisonQuarantine::Get().GetSlot(1, record));

	std::uint32_t index = 0;
	HS_CHECK(!PoisonQuarantine::Get().DecodeFault(kBase, index));
}