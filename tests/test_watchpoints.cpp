#include "harness.h"

#include "Core/WatchpointEncoding.h"
#include "Core/WatchpointPlan.h"
#include "Core/WatchpointReports.h"
#include "Core/WatchpointSlots.h"
#include "Ipc/Sampling.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#if defined(_WIN32)
#	ifndef WIN32_LEAN_AND_MEAN
#		define WIN32_LEAN_AND_MEAN
#	endif
#	ifndef NOMINMAX
#		define NOMINMAX
#	endif
#	include <Windows.h>

#	include "Core/HwWatchpoint.h"
#endif

namespace
{
	[[nodiscard]] std::uintptr_t Aligned(std::size_t a_index) noexcept
	{
		return static_cast<std::uintptr_t>(0x0000020000000000ull + a_index * 16u);
	}
}

// ---------------------------------------------------------------------------
// DR7 / DR6 encoding (checked on BOTH toolchains: this is a claim about the
// ISA, and Linux can check the arithmetic even though it cannot call
// SetThreadContext).
// ---------------------------------------------------------------------------

HS_TEST(watchpoint_dr7_slot_zero_is_a_write_watch_on_eight_bytes)
{
	// DR7 for slot 0 with RW=01b (write) and LEN=10b (8 bytes): L0 = bit 0,
	// RW0 = bits 16-17, LEN0 = bits 18-19.
	constexpr std::uint64_t expected = 0x1ull | (0b01ull << 16) | (0b10ull << 18);
	HS_CHECK_EQ(hs::Dr7LocalEnableBit(0), 0x1ull);
	HS_CHECK_EQ(hs::Dr7WriteBits(0), expected & ~0x1ull);
	HS_CHECK_EQ(hs::Dr7LocalEnableBit(0) | hs::Dr7WriteBits(0), expected);
	HS_CHECK_EQ(expected, 0x90001ull);
}

HS_TEST(watchpoint_dr7_slots_do_not_overlap)
{
	// Each slot owns its own pair of enable bits and its own RW/LEN nibble.
	HS_CHECK_EQ(hs::Dr7LocalEnableBit(0), 0x1ull);
	HS_CHECK_EQ(hs::Dr7LocalEnableBit(1), 0x4ull);
	HS_CHECK_EQ(hs::Dr7LocalEnableBit(2), 0x10ull);
	HS_CHECK_EQ(hs::Dr7LocalEnableBit(3), 0x40ull);
	HS_CHECK_EQ(hs::Dr7WriteBits(1), hs::Dr7WriteBits(0) << 4);
	HS_CHECK_EQ(hs::Dr7WriteBits(2), hs::Dr7WriteBits(0) << 8);
	HS_CHECK_EQ(hs::Dr7WriteBits(3), hs::Dr7WriteBits(0) << 12);
}

HS_TEST(watchpoint_dr7_enables_only_non_zero_addresses)
{
	const std::uintptr_t all[hs::kWatchpointSlotCount] = { 0x1000, 0x2000, 0x3000, 0x4000 };
	const auto           full = hs::BuildDr7(all, hs::kWatchpointSlotCount);
	// Per slot: L_i | RW=01b | LEN=10b. Slot 0 is 0x90001, slot 1 0x900004,
	// slot 2 0x9000010, slot 3 0x90000040; their union is 0x99990055.
	HS_CHECK_EQ(full, 0x99990055ull);

	const std::uintptr_t sparse[hs::kWatchpointSlotCount] = { 0x1000, 0, 0x3000, 0 };
	const auto           partial = hs::BuildDr7(sparse, hs::kWatchpointSlotCount);
	HS_CHECK_EQ(partial, 0x9090011ull);
	HS_CHECK_EQ(partial & hs::Dr7LocalEnableBit(1), 0ull);
	HS_CHECK_EQ(partial & hs::Dr7LocalEnableBit(3), 0ull);
}

HS_TEST(watchpoint_dr7_disable_clears_the_slot_completely)
{
	const std::uintptr_t all[hs::kWatchpointSlotCount] = { 0x1000, 0x2000, 0x3000, 0x4000 };
	const auto           full = hs::BuildDr7(all, hs::kWatchpointSlotCount);
	const auto           cleared = hs::Dr7ClearSlot(full, 1);
	HS_CHECK_EQ(cleared & hs::Dr7LocalEnableBit(1), 0ull);
	HS_CHECK_EQ(cleared & hs::Dr7WriteBits(1), 0ull);
	HS_CHECK_EQ(cleared & hs::Dr7LocalEnableBit(0), hs::Dr7LocalEnableBit(0));
	HS_CHECK_EQ(cleared & hs::Dr7LocalEnableBit(3), hs::Dr7LocalEnableBit(3));
}

HS_TEST(watchpoint_dr6_decodes_the_firing_slot)
{
	HS_CHECK_EQ(hs::Dr6TriggeredSlot(0), -1);
	HS_CHECK_EQ(hs::Dr6TriggeredSlot(1), 0);
	HS_CHECK_EQ(hs::Dr6TriggeredSlot(2), 1);
	HS_CHECK_EQ(hs::Dr6TriggeredSlot(4), 2);
	HS_CHECK_EQ(hs::Dr6TriggeredSlot(8), 3);
	// Non-breakpoint DR6 bits (BS, BD, ...) must not be mistaken for a slot.
	HS_CHECK_EQ(hs::Dr6TriggeredSlot(0x4000), -1);
}

HS_TEST(watchpoint_only_an_aligned_eight_byte_block_is_watchable)
{
	HS_CHECK(hs::WatchableAddress(0x1000));
	HS_CHECK(!hs::WatchableAddress(0x1004));
	HS_CHECK(hs::WatchableSize(8));
	HS_CHECK(hs::WatchableSize(64));
	HS_CHECK(!hs::WatchableSize(4));
	HS_CHECK_EQ(hs::kWatchpointLength, 8u);
}

// ---------------------------------------------------------------------------
// Selection policy
// ---------------------------------------------------------------------------

HS_TEST(watchpoint_sample_modulus_is_a_prime_and_mixes_before_reducing)
{
	// The project rule: the modulus is a prime, never a power of two, and the
	// pointer is mixed first because heap pointers are 16-byte aligned.
	HS_CHECK(hs::IsListedSamplePrime(hs::kDefaultSamplePrime));
	HS_CHECK(!hs::IsListedSamplePrime(64));
	HS_CHECK(!hs::IsListedSamplePrime(100));

	int sampled = 0;
	for (std::size_t i = 0; i < 61000; ++i) {
		if (hs::ShouldWatchSample(Aligned(i), hs::kDefaultSamplePrime)) {
			++sampled;
		}
	}
	// ~1/61 of 61000 = 1000. Wide band: this asserts the RATE, not the exact
	// hash (an exact count would just restate the implementation).
	HS_CHECK(sampled > 800);
	HS_CHECK(sampled < 1200);

	// The bug the prime exists to avoid: raw `ptr % 64` on aligned pointers
	// reaches only 4 buckets. The watchpoint path must not do that.
	int rawBuckets = 0;
	std::array<bool, 64> seen{};
	for (std::size_t i = 0; i < 61000; ++i) {
		seen[Aligned(i) % 64] = true;
	}
	for (auto v : seen) {
		rawBuckets += v ? 1 : 0;
	}
	HS_CHECK_EQ(rawBuckets, 4);
}

HS_TEST(watchpoint_plan_sample_only_rejects_most_allocations)
{
	hs::WatchpointPlan plan;
	plan.Configure(hs::WatchpointMode::kSampleOnly, hs::kDefaultSamplePrime, 16);

	for (std::size_t i = 0; i < 61000; ++i) {
		(void)plan.Consider(Aligned(i), /*allocSiteMatch=*/false);
	}
	const auto stats = plan.Stats();
	HS_CHECK_EQ(stats.considered, 61000ull);
	HS_CHECK(stats.selected > 800 && stats.selected < 1200);
	// The queue is bounded, so most selected candidates are lost; that must be
	// visible and not silent.
	HS_CHECK(stats.queueEvictions > 0);
	HS_CHECK(stats.notSampled == stats.considered - stats.selected);
}

HS_TEST(watchpoint_plan_filter_only_ignores_every_non_matching_site)
{
	hs::WatchpointPlan plan;
	plan.Configure(hs::WatchpointMode::kFilterOnly, hs::kDefaultSamplePrime, 16);

	for (std::size_t i = 0; i < 1000; ++i) {
		HS_CHECK_EQ(plan.Consider(Aligned(i), /*allocSiteMatch=*/false), hs::WatchDecision::kFilteredOut);
	}
	HS_CHECK_EQ(plan.Stats().selected, 0ull);
	HS_CHECK_EQ(plan.Stats().filteredOut, 1000ull);
	HS_CHECK_EQ(plan.PendingCount(), 0u);

	HS_CHECK_EQ(plan.Consider(Aligned(12345), /*allocSiteMatch=*/true), hs::WatchDecision::kSelected);
	std::uintptr_t popped = 0;
	HS_CHECK(plan.PopCandidate(popped));
	HS_CHECK_EQ(popped, Aligned(12345));
}

HS_TEST(watchpoint_plan_filter_preferred_lets_a_matching_site_bypass_the_sample)
{
	hs::WatchpointPlan plan;
	plan.Configure(hs::WatchpointMode::kFilterPreferred, hs::kDefaultSamplePrime, 16);

	// Find a pointer the prime sample rejects, so "bypass" is a real difference.
	std::uintptr_t unsampled = 0;
	for (std::size_t i = 0; i < 1000; ++i) {
		if (!hs::ShouldWatchSample(Aligned(i), hs::kDefaultSamplePrime)) {
			unsampled = Aligned(i);
			break;
		}
	}
	HS_CHECK(unsampled != 0);

	HS_CHECK_EQ(plan.Consider(unsampled, /*allocSiteMatch=*/false), hs::WatchDecision::kNotSampled);
	HS_CHECK_EQ(plan.Consider(unsampled, /*allocSiteMatch=*/true), hs::WatchDecision::kSelected);
}

HS_TEST(watchpoint_plan_deduplicates_a_pointer_already_queued)
{
	hs::WatchpointPlan plan;
	plan.Configure(hs::WatchpointMode::kFilterOnly, hs::kDefaultSamplePrime, 16);

	HS_CHECK_EQ(plan.Consider(Aligned(7), true), hs::WatchDecision::kSelected);
	HS_CHECK_EQ(plan.Consider(Aligned(7), true), hs::WatchDecision::kDuplicate);
	HS_CHECK_EQ(plan.Stats().duplicates, 1ull);
}

HS_TEST(watchpoint_plan_pop_is_oldest_first_and_the_queue_is_bounded)
{
	hs::WatchpointPlan plan;
	plan.Configure(hs::WatchpointMode::kFilterOnly, hs::kDefaultSamplePrime, 4);

	for (std::size_t i = 0; i < 4; ++i) {
		HS_CHECK_EQ(plan.Consider(Aligned(i), true), hs::WatchDecision::kSelected);
	}
	std::uintptr_t popped = 0;
	for (std::size_t i = 0; i < 4; ++i) {
		HS_CHECK(plan.PopCandidate(popped));
		HS_CHECK_EQ(popped, Aligned(i));
	}
	HS_CHECK(!plan.PopCandidate(popped));
	HS_CHECK_EQ(plan.PendingCount(), 0u);
	HS_CHECK_EQ(plan.Stats().popped, 4ull);

	// Overflow the ring: the oldest unread candidate is evicted and counted.
	for (std::size_t i = 0; i < 10; ++i) {
		(void)plan.Consider(Aligned(100 + i), true);
	}
	HS_CHECK(plan.Stats().queueEvictions > 0);
	HS_CHECK(plan.PendingCount() <= 4u);
}

// ---------------------------------------------------------------------------
// The four DR slots as a lock-free table
// ---------------------------------------------------------------------------

HS_TEST(watchpoint_slots_claim_all_four_then_drop_and_count)
{
	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();

	std::size_t index = 0;
	for (std::size_t i = 0; i < hs::kWatchpointSlotCount; ++i) {
		HS_CHECK(slots.Claim(Aligned(i), 0xAAAA0000ull + i, 0, 100 + i, 1, 42, index));
		HS_CHECK_EQ(index, i);
	}
	HS_CHECK_EQ(slots.OccupiedCount(), hs::kWatchpointSlotCount);
	HS_CHECK_EQ(slots.Claims(), static_cast<std::uint64_t>(hs::kWatchpointSlotCount));

	// The fifth claim must fail: four DR slots exist, hard stop.
	HS_CHECK(!slots.Claim(Aligned(99), 0, 0, 200, 1, 42, index));
	HS_CHECK_EQ(slots.ClaimDrops(), 1ull);

	// A released slot is reusable.
	HS_CHECK(slots.Release(Aligned(1), 300));
	HS_CHECK_EQ(slots.OccupiedCount(), 3u);
	HS_CHECK_EQ(slots.Releases(), 1ull);
	HS_CHECK(slots.Claim(Aligned(100), 0, 0, 301, 1, 42, index));
	HS_CHECK_EQ(slots.OccupiedCount(), 4u);

	slots.ResetForTesting();
}

HS_TEST(watchpoint_slots_snapshot_excludes_released_and_tripped)
{
	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();

	std::size_t index = 0;
	for (std::size_t i = 0; i < 4; ++i) {
		HS_CHECK(slots.Claim(Aligned(i), 0, 0, i, 1, 1, index));
	}
	HS_CHECK(slots.Release(Aligned(2), 10));
	HS_CHECK(slots.MarkTripped(3, 11));

	hs::WatchSlotSnapshot snap[hs::kWatchpointSlotCount];
	const auto            count = slots.Snapshot(snap);
	HS_CHECK_EQ(count, 2u);
	HS_CHECK_EQ(snap[0].address, Aligned(0));
	HS_CHECK_EQ(snap[1].address, Aligned(1));
	HS_CHECK_EQ(snap[2].address, 0u);  // released -> BuildDr7 must disable it
	HS_CHECK_EQ(snap[3].address, 0u);  // tripped  -> BuildDr7 must disable it

	// The trap path reads by index, and it must still see a tripped slot so a
	// report that races the tripping has something to name.
	hs::WatchSlotSnapshot byIndex;
	HS_CHECK(slots.ReadSlot(3, byIndex));
	HS_CHECK_EQ(byIndex.address, Aligned(3));
	HS_CHECK((byIndex.flags & hs::kWatchSlotTripped) != 0);

	slots.ResetForTesting();
}

HS_TEST(watchpoint_slots_rotate_a_block_that_is_never_freed)
{
	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();

	std::size_t index = 0;
	HS_CHECK(slots.Claim(Aligned(0), 0, 0, /*tick=*/1000, 1, 1, index));
	HS_CHECK(!slots.RotateOldest(1100, 1000));  // too soon
	HS_CHECK_EQ(slots.OccupiedCount(), 1u);
	HS_CHECK(slots.RotateOldest(2100, 1000));  // held for 1100 ms >= 1000 ms
	HS_CHECK_EQ(slots.OccupiedCount(), 0u);
	HS_CHECK_EQ(slots.Rotations(), 1ull);

	slots.ResetForTesting();
}

HS_TEST(watchpoint_slots_clear_all_reports_what_it_cleared)
{
	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();

	std::size_t index = 0;
	for (std::size_t i = 0; i < 3; ++i) {
		HS_CHECK(slots.Claim(Aligned(i), 0, 0, i, 1, 1, index));
	}
	HS_CHECK_EQ(slots.ClearAll(999), 3u);
	HS_CHECK_EQ(slots.OccupiedCount(), 0u);
	HS_CHECK_EQ(slots.ClearAll(1000), 0u);

	slots.ResetForTesting();
}

// ---------------------------------------------------------------------------
// The preallocated trap report ring + its deterministic encoding
// ---------------------------------------------------------------------------

HS_TEST(watchpoint_reports_drain_oldest_first)
{
	auto& reports = hs::WatchpointReports::Get();
	reports.Init(8);
	reports.ResetForTesting();

	for (std::size_t i = 0; i < 5; ++i) {
		hs::WatchpointReport report;
		report.watchedAddress = Aligned(i);
		report.writerRip = 0x7FF600000000ull + i;
		report.valueAfterWrite = 0x1000ull + i;
		reports.Record(report);
	}
	HS_CHECK_EQ(reports.Recorded(), 5ull);
	HS_CHECK_EQ(reports.Count(), 5u);

	hs::WatchpointReport out[8]{};
	const auto            drained = reports.Drain(out, 8);
	HS_CHECK_EQ(drained, 5u);
	for (std::size_t i = 0; i < 5; ++i) {
		HS_CHECK_EQ(out[i].watchedAddress, Aligned(i));
		HS_CHECK_EQ(out[i].writerRip, 0x7FF600000000ull + i);
		HS_CHECK_EQ(out[i].seq, i + 1);
	}
	HS_CHECK_EQ(reports.Drain(out, 8), 0u);

	reports.Shutdown();
}

HS_TEST(watchpoint_reports_bound_the_ring_and_count_losses)
{
	auto& reports = hs::WatchpointReports::Get();
	reports.Init(4);
	reports.ResetForTesting();

	for (std::size_t i = 0; i < 4; ++i) {
		hs::WatchpointReport report;
		report.watchedAddress = Aligned(i);
		reports.Record(report);
	}
	// Two more overwrite the two oldest slots before anyone drained them.
	for (std::size_t i = 4; i < 6; ++i) {
		hs::WatchpointReport report;
		report.watchedAddress = Aligned(i);
		reports.Record(report);
	}
	HS_CHECK(reports.Dropped() > 0);

	hs::WatchpointReport out[4]{};
	const auto            drained = reports.Drain(out, 4);
	HS_CHECK_EQ(drained, 4u);  // the ring is never larger than its bound
	HS_CHECK_EQ(out[3].watchedAddress, Aligned(5));  // newest survives

	reports.Shutdown();
}

HS_TEST(watchpoint_report_encoding_carries_the_writer_and_the_value)
{
	hs::WatchpointReport report;
	report.slotIndex = 2;
	report.watchedAddress = 0x1234567800000003ull;
	report.valueAtArm = 0x6FFFFB89DDB8ull;
	// The observed corruption: the low 32 bits decremented by 4.
	report.valueAfterWrite = 0x6FFFFB89DDB4ull;
	report.writerRip = 0x7FF6AABBCCDDull;
	report.dr6 = 0x4;
	report.threadId = 99;
	report.armedTick = 111;
	report.tick = 222;

	char buffer[512]{};
	const auto written = hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	HS_CHECK(written > 0);
	HS_CHECK(written < sizeof(buffer));

	const std::string text{ buffer };
	HS_CHECK(text.find("slot=2") != std::string::npos);
	HS_CHECK(text.find("watched=0x1234567800000003") != std::string::npos);
	HS_CHECK(text.find("before=0x6FFFFB89DDB8") != std::string::npos);
	HS_CHECK(text.find("after=0x6FFFFB89DDB4") != std::string::npos);
	HS_CHECK(text.find("writer_rip=0x7FF6AABBCCDD") != std::string::npos);
	HS_CHECK(text.find("dr6=0x4") != std::string::npos);
	HS_CHECK(text.find("tid=99") != std::string::npos);

	// An unreadable value is labelled rather than silently reported as zero.
	report.flags = hs::kWatchReportValueUnreadable;
	const auto labelled = hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	HS_CHECK(labelled > 0);
	HS_CHECK(std::string{ buffer }.find("(unreadable)") != std::string::npos);

	// A truncated buffer must still be NUL-terminated and must not overrun.
	char small[8]{};
	HS_CHECK(hs::EncodeWatchpointReport(report, small, sizeof(small)) >= 8u);
	HS_CHECK_EQ(small[sizeof(small) - 1], '\0');
}

// ---------------------------------------------------------------------------
// Windows-only: arm a REAL watchpoint, write to the watched address, assert the
// trap fired with the writer's RIP. This is the claim the whole feature rests
// on, and it is deliberately a test that can fail: break the DR7 write and the
// trap never arrives.
// ---------------------------------------------------------------------------

#if defined(_WIN32)
namespace
{
	volatile std::uint64_t g_watchedQword = 0x1111111111111111ull;
	volatile LONG          g_trapCount = 0;
	std::uintptr_t         g_trapRip = 0;
	std::uint64_t          g_trapValue = 0;
	std::uint64_t          g_trapDr6 = 0;
	std::uint64_t          g_trapDr7 = 0;

	// The store lives in its own noinline function so the test can assert the
	// trapped RIP is inside the writer, not merely non-zero.
	__declspec(noinline) void WriteToWatchedQword()
	{
		g_watchedQword = 0xAABBCCDD11223344ull;
	}

	LONG CALLBACK TestTrapHandler(EXCEPTION_POINTERS* a_info)
	{
		if (!a_info || !a_info->ExceptionRecord || a_info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
			return EXCEPTION_CONTINUE_SEARCH;
		}
		if (hs::Dr6TriggeredSlot(static_cast<std::uint64_t>(a_info->ContextRecord->Dr6)) != 0) {
			return EXCEPTION_CONTINUE_SEARCH;
		}
		++g_trapCount;
		g_trapRip = static_cast<std::uintptr_t>(a_info->ContextRecord->Rip);
		g_trapValue = g_watchedQword;
		g_trapDr6 = static_cast<std::uint64_t>(a_info->ContextRecord->Dr6);
		g_trapDr7 = static_cast<std::uint64_t>(a_info->ContextRecord->Dr7);
		// Same discipline as the production trap path: disable this slot and
		// clear DR6, then resume at the next instruction (the store completed).
		a_info->ContextRecord->Dr7 = static_cast<DWORD64>(hs::Dr7ClearSlot(g_trapDr7, 0));
		a_info->ContextRecord->Dr6 = 0;
		// Belt-and-braces for the assertion below: the production path relies on
		// the context edit plus the sweeper's re-arm, but the test asserts the
		// post-state deterministically.
		hs::hw::DisarmCurrentThread();
		return EXCEPTION_CONTINUE_EXECUTION;
	}
}

HS_TEST(hw_watchpoint_traps_the_writer_of_a_watched_qword)
{
	g_watchedQword = 0x1111111111111111ull;
	g_trapCount = 0;
	g_trapRip = 0;
	g_trapValue = 0;
	g_trapDr6 = 0;
	g_trapDr7 = 0;

	const auto handler = ::AddVectoredExceptionHandler(1, &TestTrapHandler);
	HS_CHECK(handler != nullptr);

	std::uintptr_t addresses[hs::kWatchpointSlotCount] = { reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword)), 0, 0, 0 };
	std::uint64_t  dr7 = 0;
	hs::hw::ThreadDebugState state;
	HS_CHECK(hs::hw::ArmCurrentThread(addresses, hs::kWatchpointSlotCount, dr7, &state));
	HS_CHECK_EQ(dr7, hs::BuildDr7(addresses, hs::kWatchpointSlotCount));
	HS_CHECK((dr7 & hs::Dr7LocalEnableBit(0)) != 0);
	HS_CHECK_EQ(state.dr0, static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword))));

	const auto writerStart = reinterpret_cast<std::uintptr_t>(&WriteToWatchedQword);
	WriteToWatchedQword();

	// The trap should have fired exactly once, caught the write, and named the
	// writer. If arming is broken this is zero; that is the failure the test is
	// for.
	HS_CHECK_EQ(static_cast<int>(g_trapCount), 1);
	HS_CHECK_EQ(static_cast<std::uint64_t>(g_watchedQword), 0xAABBCCDD11223344ull);
	HS_CHECK_EQ(g_trapValue, 0xAABBCCDD11223344ull);
	HS_CHECK(g_trapDr6 != 0);
	HS_CHECK(g_trapRip >= writerStart);
	HS_CHECK(g_trapRip < writerStart + 64);

	// The handler disabled slot 0 (and, in the test, disarmed explicitly). Reading
	// the thread now must show it cleared.
	hs::hw::ThreadDebugState after;
	HS_CHECK(hs::hw::ReadCurrentThread(after));
	HS_CHECK_EQ(after.dr7 & hs::Dr7LocalEnableBit(0), 0ull);

	HS_CHECK(hs::hw::DisarmCurrentThread());
	HS_CHECK(hs::hw::ReadCurrentThread(after));
	HS_CHECK_EQ(after.dr7, 0ull);
	HS_CHECK_EQ(after.dr0, 0ull);
	HS_CHECK_EQ(after.dr1, 0ull);
	HS_CHECK_EQ(after.dr2, 0ull);
	HS_CHECK_EQ(after.dr3, 0ull);

	::RemoveVectoredExceptionHandler(handler);
}
#else
HS_TEST(hw_watchpoint_traps_the_writer_of_a_watched_qword)
{
	hstest::Note("Windows-only: GetThreadContext/SetThreadContext have no Linux equivalent; the DR7 encoding and the plan/slots/reports logic above are the Linux-checkable part");
	HS_CHECK_EQ(hs::kWatchpointSlotCount, 4u);
	HS_CHECK_EQ(hs::Dr7ClearSlot(0x90001ull, 0), 0ull);
}
#endif