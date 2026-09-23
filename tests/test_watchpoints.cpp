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
// FIX 3: the benign-vs-degradation classifier. A data breakpoint fires on ANY
// write; only a code pointer that became a non-code value is the corruption.
// ---------------------------------------------------------------------------

HS_TEST(watchpoint_write_classifier_reports_only_a_clobbered_code_pointer)
{
	using hs::WatchpointWriteKind;
	// Unchanged: the observed VCRUNTIME140 write of 0 into an already-zero qword
	// is benign BY CONSTRUCTION, not merely by luck.
	HS_CHECK(hs::ClassifyWatchedWrite(0x0, false, 0x0, true, false) == WatchpointWriteKind::kBenign);
	// Changed but the armed value was never code: construction of a fresh block.
	HS_CHECK(hs::ClassifyWatchedWrite(0x1111, false, 0x0, true, false) == WatchpointWriteKind::kBenign);
	// Code -> non-code: the clobbered vtable this feature exists to catch.
	HS_CHECK(hs::ClassifyWatchedWrite(0x6FFFFB89DDB8ull, true, 0x0, true, false) == WatchpointWriteKind::kDegradation);
	HS_CHECK(hs::ClassifyWatchedWrite(0x6FFFFB89DDB8ull, true, 0x6FFFFB89DDB4ull, true, false) == WatchpointWriteKind::kDegradation);
	// Code -> different code: a legitimate vtable swap, not a clobber.
	HS_CHECK(hs::ClassifyWatchedWrite(0x6FFFFB89DDB8ull, true, 0x7FF600001234ull, true, true) == WatchpointWriteKind::kBenign);
	// A value we cannot read is never claimed to be a degradation.
	HS_CHECK(hs::ClassifyWatchedWrite(0x6FFFFB89DDB8ull, true, 0xDEAD, false, false) == WatchpointWriteKind::kBenign);
}

// ---------------------------------------------------------------------------
// FIX 1/2: stale-arm bookkeeping. A #DB on a slot WE EVER ARMED on this thread
// is ours even when the table has moved on or the entry is gone. Only a slot we
// never touched is foreign (CONTINUE_SEARCH).
// ---------------------------------------------------------------------------

HS_TEST(watchpoint_trap_owner_recognises_a_stale_arm_as_ours)
{
	using hs::WatchpointTrapOwner;
	constexpr auto kOld = static_cast<std::uintptr_t>(0x27D0F000);
	constexpr auto kNew = static_cast<std::uintptr_t>(0xA4B95980);

	// The 0.6.1 fatal case: table slot 0 has been re-armed for kNew, but this
	// thread's DR0 still holds kOld from an earlier arm. OURS, and stale.
	const auto stale = hs::ClassifyTrapOwner(
		/*dr7SlotEnabled=*/true, kOld,
		/*everArmedThisSlot=*/true, /*threadArmValid=*/true, kOld,
		/*tableValid=*/true, kNew, /*tableReleased=*/false);
	HS_CHECK(stale == WatchpointTrapOwner::kStaleThreadArm);
	HS_CHECK(hs::WatchpointOwnerIsOurs(stale));
	HS_CHECK(hs::WatchpointOwnerIsStale(stale));

	// The table still holds the address, and it is live: a current arm.
	HS_CHECK(hs::ClassifyTrapOwner(true, kOld, true, true, kOld, true, kOld, false) == WatchpointTrapOwner::kTableCurrent);
	// The table holds it but it was released: a write-after-free.
	HS_CHECK(hs::ClassifyTrapOwner(true, kOld, true, true, kOld, true, kOld, true) == WatchpointTrapOwner::kTableReleased);

	// We armed the slot here but have no address record left (the entry was
	// reused/partially cleared): still ours, just bare.
	const auto bare = hs::ClassifyTrapOwner(true, kOld, true, false, 0, false, 0, false);
	HS_CHECK(bare == WatchpointTrapOwner::kStaleBareArm);
	HS_CHECK(hs::WatchpointOwnerIsOurs(bare));
}

HS_TEST(watchpoint_trap_owner_never_claims_a_foreign_breakpoint)
{
	using hs::WatchpointTrapOwner;
	// Slot not enabled in DR7: not a data watchpoint of ours.
	HS_CHECK(hs::ClassifyTrapOwner(false, 0x1000, true, true, 0x1000, true, 0x1000, false) == WatchpointTrapOwner::kForeign);
	// Enabled but DRi is zero: nothing was armed.
	HS_CHECK(hs::ClassifyTrapOwner(true, 0, true, true, 0x1000, true, 0x1000, false) == WatchpointTrapOwner::kForeign);
	// A foreign breakpoint on a slot this thread was never armed with.
	const auto foreign = hs::ClassifyTrapOwner(true, 0x1000, false, false, 0, false, 0, false);
	HS_CHECK(foreign == WatchpointTrapOwner::kForeign);
	HS_CHECK(!hs::WatchpointOwnerIsOurs(foreign));
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
		HS_CHECK(slots.Claim(Aligned(i), 0xAAAA0000ull + i, /*armedWasCode=*/true, 0, 100 + i, 1, 42, index));
		HS_CHECK_EQ(index, i);
	}
	HS_CHECK_EQ(slots.OccupiedCount(), hs::kWatchpointSlotCount);
	HS_CHECK_EQ(slots.Claims(), static_cast<std::uint64_t>(hs::kWatchpointSlotCount));

	// The fifth claim must fail: four DR slots exist, hard stop.
	HS_CHECK(!slots.Claim(Aligned(99), 0, false, 0, 200, 1, 42, index));
	HS_CHECK_EQ(slots.ClaimDrops(), 1ull);

	// A released slot is reusable.
	HS_CHECK(slots.Release(Aligned(1), 300));
	HS_CHECK_EQ(slots.OccupiedCount(), 3u);
	HS_CHECK_EQ(slots.Releases(), 1ull);
	HS_CHECK(slots.Claim(Aligned(100), 0, false, 0, 301, 1, 42, index));
	HS_CHECK_EQ(slots.OccupiedCount(), 4u);

	slots.ResetForTesting();
}

HS_TEST(watchpoint_slots_round_trip_the_armed_was_code_snapshot)
{
	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();

	// FIX 3: the classification of the first qword at arming must survive the
	// table and be readable by index from the trap path.
	std::size_t index = 0;
	HS_CHECK(slots.Claim(Aligned(1), 0x6FFFFB89DDB8ull, /*armedWasCode=*/true, 0xDEAD, 500, 7, 42, index));
	HS_CHECK(slots.Claim(Aligned(2), 0x0, /*armedWasCode=*/false, 0xBEEF, 501, 7, 42, index));

	hs::WatchSlotSnapshot snap[hs::kWatchpointSlotCount];
	HS_CHECK_EQ(slots.Snapshot(snap), 2u);
	HS_CHECK(snap[0].armedWasCode);
	HS_CHECK(!snap[1].armedWasCode);
	HS_CHECK_EQ(snap[0].allocSite, 0xDEADu);
	HS_CHECK_EQ(snap[1].allocSite, 0xBEEFu);

	hs::WatchSlotSnapshot byIndex;
	HS_CHECK(slots.ReadSlot(0, byIndex));
	HS_CHECK(byIndex.armedWasCode);
	HS_CHECK_EQ(byIndex.valueAtArm, 0x6FFFFB89DDB8ull);
	HS_CHECK_EQ(byIndex.generation, 7u);

	// A released-then-reclaimed slot must not inherit the old classification.
	HS_CHECK(slots.Release(Aligned(1), 600));
	HS_CHECK(slots.Claim(Aligned(3), 0x0, /*armedWasCode=*/false, 0, 601, 8, 42, index));
	HS_CHECK_EQ(index, 0u);
	HS_CHECK(slots.ReadSlot(0, byIndex));
	HS_CHECK(!byIndex.armedWasCode);
	HS_CHECK_EQ(byIndex.address, Aligned(3));

	slots.ResetForTesting();
}

HS_TEST(watchpoint_slots_snapshot_excludes_released_and_tripped)
{
	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();

	std::size_t index = 0;
	for (std::size_t i = 0; i < 4; ++i) {
		HS_CHECK(slots.Claim(Aligned(i), 0, false, 0, i, 1, 1, index));
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
	HS_CHECK(slots.Claim(Aligned(0), 0, false, 0, /*tick=*/1000, 1, 1, index));
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
		HS_CHECK(slots.Claim(Aligned(i), 0, false, 0, i, 1, 1, index));
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
	// A current arm is not stale and names no different table address.
	HS_CHECK(text.find("stale_arm=0") != std::string::npos);
	HS_CHECK(text.find("table=0x0") != std::string::npos);

	// FIX 4: the stale-arm case must be legible. `watched` is the address that
	// actually trapped; `table` is what the live slot holds now.
	report.flags = hs::kWatchReportStaleArm;
	report.watchedAddress = 0x27D0F000ull;
	report.tableAddress = 0xA4B95980ull;
	report.valueAtArm = 0x0;
	report.valueAfterWrite = 0x0;
	const auto staleWritten = hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	HS_CHECK(staleWritten > 0);
	const std::string staleText{ buffer };
	HS_CHECK(staleText.find("watched=0x27D0F000") != std::string::npos);
	HS_CHECK(staleText.find("stale_arm=1") != std::string::npos);
	HS_CHECK(staleText.find("table=0xA4B95980") != std::string::npos);

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

// ---------------------------------------------------------------------------
// FIX 1/2/3 on REAL hardware watchpoints: the three claims the 0.6.1 session
// falsified. Each test uses the SAME hs::ClassifyTrapOwner / WatchpointSlots
// decision the plugin uses, driven by a real #DB, so breaking the production
// decision breaks the test.
// ---------------------------------------------------------------------------
namespace
{
	// A second watched qword: the table moves to it while this thread's DR0 still
	// holds the first (the sweep had not reached this thread). That is the exact
	// 0.6.1 stale-arm state.
	volatile std::uint64_t g_otherQword = 0;

	struct TrapModel
	{
		bool           everArmed[hs::kWatchpointSlotCount] = {};
		std::uintptr_t armAddress[hs::kWatchpointSlotCount] = {};
		std::uintptr_t armValueAtArm[hs::kWatchpointSlotCount] = {};
		bool           armWasCode[hs::kWatchpointSlotCount] = {};

		bool           consumed = false;
		int            recorded = 0;
		std::uintptr_t reportWatched = 0;
		std::uintptr_t reportTable = 0;
		bool           reportStale = false;
		bool           reportReleased = false;
		std::uintptr_t reportValueAtArm = 0;
		bool           reportArmedWasCode = false;
		std::uintptr_t reportValueAfter = 0;
		bool           reportReadable = true;
	};
	TrapModel g_model;

	[[nodiscard]] bool TestSafeRead(std::uintptr_t a_addr, std::uintptr_t& a_out) noexcept
	{
		__try {
			a_out = *reinterpret_cast<const std::uintptr_t*>(a_addr);
			return true;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			a_out = 0;
			return false;
		}
	}

	LONG CALLBACK ModelTrapHandler(EXCEPTION_POINTERS* a_info)
	{
		if (!a_info || !a_info->ExceptionRecord || a_info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
			return EXCEPTION_CONTINUE_SEARCH;
		}
		auto*          context = a_info->ContextRecord;
		const auto     dr6 = static_cast<std::uint64_t>(context->Dr6);
		const auto     dr7 = static_cast<std::uint64_t>(context->Dr7);
		const std::uint64_t drAddress[hs::kWatchpointSlotCount] = {
			static_cast<std::uint64_t>(context->Dr0),
			static_cast<std::uint64_t>(context->Dr1),
			static_cast<std::uint64_t>(context->Dr2),
			static_cast<std::uint64_t>(context->Dr3),
		};

		bool          handled = false;
		std::uint64_t cleared = dr7;

		for (std::size_t slot = 0; slot < hs::kWatchpointSlotCount; ++slot) {
			if ((dr6 & (1ull << slot)) == 0) {
				continue;
			}
			hs::WatchSlotSnapshot snap{};
			const bool tableValid = hs::WatchpointSlots::Get().ReadSlot(slot, snap);
			const bool tableReleased = tableValid && (snap.flags & hs::kWatchSlotReleased) != 0;
			const bool armValid = g_model.everArmed[slot] && g_model.armAddress[slot] != 0;

			const auto owner = hs::ClassifyTrapOwner(
				hs::Dr7SlotEnabled(dr7, slot), static_cast<std::uintptr_t>(drAddress[slot]),
				g_model.everArmed[slot], armValid, g_model.armAddress[slot],
				tableValid, snap.address, tableReleased);
			if (!hs::WatchpointOwnerIsOurs(owner)) {
				continue;
			}
			handled = true;

			const bool     stale = hs::WatchpointOwnerIsStale(owner);
			std::uintptr_t watched = static_cast<std::uintptr_t>(drAddress[slot]);
			std::uintptr_t valueAtArm = g_model.armValueAtArm[slot];
			bool           armedWasCode = g_model.armWasCode[slot];
			if (tableValid && !stale) {
				watched = snap.address;
				valueAtArm = snap.valueAtArm;
				armedWasCode = snap.armedWasCode;
			}
			std::uintptr_t after = 0;
			const bool     readable = TestSafeRead(watched, after);
			const bool     record = armedWasCode && readable && after != valueAtArm;
			if (record) {
				++g_model.recorded;
				g_model.reportWatched = watched;
				g_model.reportTable = (tableValid && stale) ? snap.address : 0;
				g_model.reportStale = stale;
				g_model.reportReleased = tableReleased;
				g_model.reportValueAtArm = valueAtArm;
				g_model.reportArmedWasCode = armedWasCode;
				g_model.reportValueAfter = after;
				g_model.reportReadable = readable;
			}
			g_model.consumed = true;
			if (stale || record) {
				cleared = hs::Dr7ClearSlot(cleared, slot);
			}
		}

		if (!handled) {
			return EXCEPTION_CONTINUE_SEARCH;
		}
		context->Dr7 = cleared;
		context->Dr6 = 0;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// Arm the current thread's DR0 and the model's per-thread record for slot 0.
	void ModelArmSlotZero(std::uintptr_t a_address, std::uintptr_t a_valueAtArm, bool a_armedWasCode)
	{
		g_model = TrapModel{};
		auto& slots = hs::WatchpointSlots::Get();
		slots.ResetForTesting();
		std::size_t index = 0;
		HS_CHECK(slots.Claim(a_address, a_valueAtArm, a_armedWasCode, 0, 1000, 1, 1, index));
		HS_CHECK_EQ(index, 0u);
		g_model.everArmed[0] = true;
		g_model.armAddress[0] = a_address;
		g_model.armValueAtArm[0] = a_valueAtArm;
		g_model.armWasCode[0] = a_armedWasCode;

		std::uintptr_t addresses[hs::kWatchpointSlotCount] = { a_address, 0, 0, 0 };
		std::uint64_t  dr7 = 0;
		HS_CHECK(hs::hw::ArmCurrentThread(addresses, hs::kWatchpointSlotCount, dr7));
		HS_CHECK_EQ(dr7, hs::BuildDr7(addresses, hs::kWatchpointSlotCount));
	}
}

HS_TEST(hw_watchpoint_consumes_a_stale_arm_and_the_process_survives)
{
	g_watchedQword = 0;
	g_otherQword = 0;
	ModelArmSlotZero(reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword)), 0x0, false);

	// The table moves on: slot 0 is released and re-armed for a different block,
	// while this thread's DR0 still holds the first. The sweep has not reached it.
	auto&       slots = hs::WatchpointSlots::Get();
	const auto  oldAddress = reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword));
	const auto  newAddress = reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_otherQword));
	HS_CHECK(slots.Release(oldAddress, 1001));
	std::size_t index = 0;
	HS_CHECK(slots.Claim(newAddress, 0x0, false, 0, 1002, 2, 2, index));
	HS_CHECK_EQ(index, 0u);

	const auto handler = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(handler != nullptr);

	// This store traps on the stale DR0. If the handler returns CONTINUE_SEARCH
	// (the 0.6.1 behaviour) the process dies of EXCEPTION_SINGLE_STEP and the
	// checks below never run: that is exactly how this test can fail.
	g_watchedQword = 0x1;

	HS_CHECK(g_model.consumed);
	HS_CHECK_EQ(g_model.recorded, 0);  // the armed value was not code -> benign, silent

	// The stale arm was cleared in this thread's context.
	hs::hw::ThreadDebugState after;
	HS_CHECK(hs::hw::ReadCurrentThread(after));
	HS_CHECK_EQ(after.dr7 & hs::Dr7LocalEnableBit(0), 0ull);
	HS_CHECK(hs::hw::DisarmCurrentThread());
	::RemoveVectoredExceptionHandler(handler);
}

HS_TEST(hw_watchpoint_benign_write_is_silent_and_keeps_the_slot_armed)
{
	g_watchedQword = 0x1111;
	ModelArmSlotZero(reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword)), 0x1111, false);

	const auto handler = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(handler != nullptr);

	g_watchedQword = 0x0;  // the observed VCRUNTIME140-style construction write

	HS_CHECK(g_model.consumed);
	HS_CHECK_EQ(g_model.recorded, 0);  // no report

	// The logical slot stays armed (occupied, not released)...
	hs::WatchSlotSnapshot snap{};
	HS_CHECK(hs::WatchpointSlots::Get().ReadSlot(0, snap));
	HS_CHECK_EQ(snap.address, reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword)));
	HS_CHECK_EQ(snap.flags & hs::kWatchSlotReleased, 0u);

	// ...and the hardware watch is still enabled on this thread.
	hs::hw::ThreadDebugState after;
	HS_CHECK(hs::hw::ReadCurrentThread(after));
	HS_CHECK((after.dr7 & hs::Dr7LocalEnableBit(0)) != 0);

	HS_CHECK(hs::hw::DisarmCurrentThread());
	::RemoveVectoredExceptionHandler(handler);
}

HS_TEST(hw_watchpoint_reports_a_code_pointer_clobber)
{
	g_watchedQword = 0x6FFFFB89DDB8ull;
	ModelArmSlotZero(reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword)), 0x6FFFFB89DDB8ull, true);

	const auto handler = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(handler != nullptr);

	g_watchedQword = 0x0;  // a code pointer became non-code

	HS_CHECK(g_model.consumed);
	HS_CHECK_EQ(g_model.recorded, 1);
	HS_CHECK_EQ(g_model.reportWatched, reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword)));
	HS_CHECK(!g_model.reportStale);

	// The drainer's final call: code -> non-code is a degradation.
	HS_CHECK(hs::ClassifyWatchedWrite(g_model.reportValueAtArm, g_model.reportArmedWasCode,
			g_model.reportValueAfter, g_model.reportReadable, /*afterIsCode=*/false) == hs::WatchpointWriteKind::kDegradation);

	HS_CHECK(hs::hw::DisarmCurrentThread());
	::RemoveVectoredExceptionHandler(handler);
}
#else
HS_TEST(hw_watchpoint_traps_the_writer_of_a_watched_qword)
{
	hstest::Note("Windows-only: GetThreadContext/SetThreadContext have no Linux equivalent; the DR7 encoding and the plan/slots/reports logic above are the Linux-checkable part");
	HS_CHECK_EQ(hs::kWatchpointSlotCount, 4u);
	HS_CHECK_EQ(hs::Dr7ClearSlot(0x90001ull, 0), 0ull);
}

HS_TEST(hw_watchpoint_consumes_a_stale_arm_and_the_process_survives)
{
	hstest::Note("Windows-only: needs a real #DB; the pure ClassifyTrapOwner test above is the Linux-checkable half");
	const auto stale = hs::ClassifyTrapOwner(true, 0x27D0F000, true, true, 0x27D0F000, true, 0xA4B95980, false);
	HS_CHECK(stale == hs::WatchpointTrapOwner::kStaleThreadArm);
}

HS_TEST(hw_watchpoint_benign_write_is_silent_and_keeps_the_slot_armed)
{
	hstest::Note("Windows-only: needs a real #DB; ClassifyWatchedWrite above is the Linux-checkable half");
	HS_CHECK(hs::ClassifyWatchedWrite(0x1111, false, 0x0, true, false) == hs::WatchpointWriteKind::kBenign);
}

HS_TEST(hw_watchpoint_reports_a_code_pointer_clobber)
{
	hstest::Note("Windows-only: needs a real #DB; ClassifyWatchedWrite above is the Linux-checkable half");
	HS_CHECK(hs::ClassifyWatchedWrite(0x6FFFFB89DDB8ull, true, 0x0, true, false) == hs::WatchpointWriteKind::kDegradation);
}
#endif