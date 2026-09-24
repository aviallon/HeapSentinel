#include "harness.h"

#include "Core/WatchpointEncoding.h"
#include "Core/WatchpointPlan.h"
#include "Core/WatchpointReports.h"
#include "Core/WatchpointSlots.h"
#include "Core/ScaleformFreeRing.h"
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
// 0.6.3: the structural survival rule and the allocator post-free window.
// ---------------------------------------------------------------------------

HS_TEST(watchpoint_structural_consume_rule_is_independent_of_classification)
{
	// The 0.6.2 bug: survival depended on ClassifyTrapOwner being right about a
	// #DB, and it was wrong for the one that killed the session. 0.6.3 makes the
	// survival decision structural: the ONLY state that permits passing a #DB on
	// is "this process has never programmed a debug register". No classifier is
	// consulted, so no classification bug can be fatal.
	HS_CHECK(!hs::MustConsumeDebugException(false));
	HS_CHECK(hs::MustConsumeDebugException(true));

	// A disabled feature arms nothing, so DR7 is zero and nothing can be masked.
	const std::uintptr_t nothing[hs::kWatchpointSlotCount] = { 0, 0, 0, 0 };
	HS_CHECK_EQ(hs::BuildDr7(nothing, hs::kWatchpointSlotCount), 0ull);
}

HS_TEST(watchpoint_free_classifier_keeps_the_two_allocator_cases_apart)
{
	using hs::WatchpointFreeContext;
	constexpr std::uint64_t kWindow = hs::kAllocatorBookkeepingWindowMs;
	using hs::ClassifyWriteAgainstFree;

	// The evidence that started this (2026-09-23 21:37:41): freed at 188333102, the
	// link written at 188333103 -- one tick later. That MUST be silent, and it is
	// the POST-FREE side. (armedTick is 0 here: unknown, which disables the
	// predates-arm test.)
	HS_CHECK(ClassifyWriteAgainstFree(188333102ull, 0, 188333103ull, kWindow) == WatchpointFreeContext::kPostFreeLink);
	// Same tick and the end of the window are also the allocator linking.
	HS_CHECK(ClassifyWriteAgainstFree(100ull, 0, 100ull, kWindow) == WatchpointFreeContext::kPostFreeLink);
	HS_CHECK(ClassifyWriteAgainstFree(100ull, 0, 100ull + kWindow, kWindow) == WatchpointFreeContext::kPostFreeLink);
	// One tick past the window is a genuine delayed use-after-free, reported.
	HS_CHECK(ClassifyWriteAgainstFree(100ull, 0, 100ull + kWindow + 1ull, kWindow) == WatchpointFreeContext::kDelayedWriteAfterFree);
	// No recorded free: not attributable to the allocator at all.
	HS_CHECK(ClassifyWriteAgainstFree(0ull, 0, 12345ull, kWindow) == WatchpointFreeContext::kLive);

	// RECALL vs FORWARD: the free record landing AFTER the trap is the realloc
	// case (hk_SfRealloc calls o_SfRealloc first), a DIFFERENT context from the
	// post-free link -- forcing it through the post-free window is the 0.6.3 bug.
	// The 17:56:55 corpus rows: trap 261486322 / 261486342, ring free 261486289.
	HS_CHECK(ClassifyWriteAgainstFree(261486289ull, 0, 261486322ull, kWindow) == WatchpointFreeContext::kPostFreeLink);
	HS_CHECK(ClassifyWriteAgainstFree(261486322ull, 0, 261486289ull, kWindow) == WatchpointFreeContext::kReallocInProgress);
	HS_CHECK(ClassifyWriteAgainstFree(261486289ull, 0, 261486289ull, kWindow) == WatchpointFreeContext::kPostFreeLink);
	// A free far in the future is not a realloc: it is not bookkeeping, so it is
	// never suppressed.
	HS_CHECK(ClassifyWriteAgainstFree(100ull + kWindow + 1ull, 0, 100ull, kWindow) == WatchpointFreeContext::kDelayedWriteAfterFree);

	// Only the two allocator orderings are bookkeeping. `kFreePredatesArm` and
	// `kDelayedWriteAfterFree` are NOT: silencing them would hide a real write.
	HS_CHECK(hs::FreeContextIsAllocatorBookkeeping(WatchpointFreeContext::kPostFreeLink));
	HS_CHECK(hs::FreeContextIsAllocatorBookkeeping(WatchpointFreeContext::kReallocInProgress));
	HS_CHECK(!hs::FreeContextIsAllocatorBookkeeping(WatchpointFreeContext::kFreePredatesArm));
	HS_CHECK(!hs::FreeContextIsAllocatorBookkeeping(WatchpointFreeContext::kDelayedWriteAfterFree));
	HS_CHECK(!hs::FreeContextIsAllocatorBookkeeping(WatchpointFreeContext::kLive));

	// A free record that PREDATES this arm is stale evidence about this watch
	// (rows 2 and 8 of the corpus: 0xA34DF900, 0xA33C04B0). It is reported and
	// labelled, never assigned to the allocator.
	HS_CHECK(ClassifyWriteAgainstFree(1000ull, 2000ull, 9000ull, kWindow) == WatchpointFreeContext::kFreePredatesArm);
	// ...but a write before the arm that is ALSO before the free is the realloc
	// ordering, because the free is not older than the arm in that case.
	HS_CHECK(ClassifyWriteAgainstFree(2000ull, 1000ull, 1900ull, kWindow) == WatchpointFreeContext::kReallocInProgress);

	// The window is one bound, used on BOTH sides (0.6.4). It is larger than the
	// 0.6.3 32 ms because the trip measured our own free hook's latency between
	// the tick we record and the original free call / o_SfRealloc return.
	HS_CHECK(hs::kAllocatorBookkeepingWindowMs >= 165ull);
}

HS_TEST(watchpoint_prefers_the_free_rings_newest_record_over_the_slot_tick)
{
	// The concrete 2026-09-24 17:56:56 case: slot Release tick 261486289, free ring
	// 261487115, trap 261487115. 0.6.3 used the slot tick and reported a delta of
	// 826 ms instead of 0. The ring's newest record must win.
	HS_CHECK_EQ(hs::PreferNewestFreeTick(261486289ull, 261487115ull), 261487115ull);
	// When the ring's record is OLDER it is from a previous life of a recycled
	// address, so the slot's own (later) Release is the better evidence.
	HS_CHECK_EQ(hs::PreferNewestFreeTick(2000ull, 1000ull), 2000ull);
	HS_CHECK_EQ(hs::PreferNewestFreeTick(0ull, 1000ull), 1000ull);
	HS_CHECK_EQ(hs::PreferNewestFreeTick(1000ull, 0ull), 1000ull);
	HS_CHECK_EQ(hs::PreferNewestFreeTick(0ull, 0ull), 0ull);

	// End to end through the real ring: record a free, then classify the trap that
	// the stale slot tick would have mis-labelled.
	auto& ring = hs::ScaleformFreeRing::Get();
	ring.Init(64);
	hs::ScaleformFreeRecord record;
	record.ptr = 0xA3AC1410ull;
	record.freeTick = 261487115ull;
	ring.Record(record);

	hs::ScaleformFreeRecord found;
	HS_CHECK(ring.Find(0xA3AC1410ull, found));
	HS_CHECK_EQ(found.freeTick, 261487115ull);

	const auto slotTick = 261486289ull;                 // the stale slot Release tick
	const auto trap = 261487115ull;                     // the run's trap tick
	const auto freeTick = hs::PreferNewestFreeTick(slotTick, found.freeTick);
	HS_CHECK_EQ(freeTick, 261487115ull);
	HS_CHECK_EQ(trap - freeTick, 0ull);
	HS_CHECK(hs::FreeContextIsAllocatorBookkeeping(
		hs::ClassifyWriteAgainstFree(freeTick, 0, trap, hs::kAllocatorBookkeepingWindowMs)));
	// The 0.6.3 behaviour, for contrast: 32 ms was the old window, and the slot
	// tick alone is 826 ms early, so the write was reported as a clobber.
	HS_CHECK_EQ(slotTick + 826ull, trap);
	HS_CHECK(!hs::FreeContextIsAllocatorBookkeeping(
		hs::ClassifyWriteAgainstFree(slotTick, 0, trap, /*0.6.3 window, for contrast=*/32ull)));

	// Every free tick source has a name (the log says which one won).
	HS_CHECK(std::string{ hs::FreeTickSourceName(hs::FreeTickSource::kFreeRing) } == "free-ring");
	HS_CHECK(std::string{ hs::FreeTickSourceName(hs::FreeTickSource::kSlotSnapshot) } == "slot-release");
	HS_CHECK(std::string{ hs::FreeTickSourceName(hs::FreeTickSource::kNone) } == "none");
	// ...and every free context does too (the report prints it).
	HS_CHECK(std::string{ hs::WatchpointFreeContextName(hs::WatchpointFreeContext::kReallocInProgress) } ==
		"allocator-realloc-in-progress");
	HS_CHECK(std::string{ hs::WatchpointFreeContextName(hs::WatchpointFreeContext::kFreePredatesArm) } == "free-predates-arm");

	ring.Shutdown();
}

HS_TEST(watchpoint_debug_register_measurement_distinguishes_failed_from_zero)
{
	using hs::DebugRegisterMeasurement;
	using hs::ClassifyDebugRegisterMeasurement;

	const std::uintptr_t none[hs::kWatchpointSlotCount] = { 0, 0, 0, 0 };
	const std::uintptr_t some[hs::kWatchpointSlotCount] = { 0x27D0F000, 0, 0, 0 };

	// The 0.6.3 hole: 104/104 records printed dr6=dr7=dr0-3=0, and nothing said
	// whether that was a FAILED read or a successful read that returned zero. The
	// two are now different outcomes of the same input.
	HS_CHECK(ClassifyDebugRegisterMeasurement(hs::kDrSourceCurrentThread, hs::kDrReadFailed, 0, none, 4) ==
		DebugRegisterMeasurement::kReadFailed);
	HS_CHECK(ClassifyDebugRegisterMeasurement(hs::kDrSourceCurrentThread, hs::kDrReadOk, 0, none, 4) ==
		DebugRegisterMeasurement::kReadZero);
	// A successful read that found a breakpoint armed is a real measurement.
	HS_CHECK(ClassifyDebugRegisterMeasurement(hs::kDrSourceCurrentThread, hs::kDrReadOk, 0x2, none, 4) ==
		DebugRegisterMeasurement::kReadNonZero);
	HS_CHECK(ClassifyDebugRegisterMeasurement(hs::kDrSourceCurrentThread, hs::kDrReadOk, 0, some, 4) ==
		DebugRegisterMeasurement::kReadNonZero);
	// The exception-context fallback is a source, so a failing read from it is
	// still "failed", not "no attempt".
	HS_CHECK(ClassifyDebugRegisterMeasurement(hs::kDrSourceExceptionContext, hs::kDrReadFailed, 0, none, 4) ==
		DebugRegisterMeasurement::kReadFailed);
	// A record with no provenance at all is not a measurement, and must not be
	// mistaken for a successful zero read (that was the 0.6.3 misreading).
	HS_CHECK(ClassifyDebugRegisterMeasurement(hs::kDrSourceNone, hs::kDrReadNotAttempted, 0, none, 4) ==
		DebugRegisterMeasurement::kNotAttempted);
}

HS_TEST(watchpoint_slot_records_the_block_free_tick)
{
	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();

	std::size_t index = 0;
	HS_CHECK(slots.Claim(Aligned(1), 0x6FFFFB89DDB8ull, /*armedWasCode=*/true, 0, 100, 1, 7, index));

	hs::WatchSlotSnapshot snap[hs::kWatchpointSlotCount];
	HS_CHECK_EQ(slots.Snapshot(snap), 1u);
	HS_CHECK_EQ(snap[0].freeTick, 0ull);  // live: no free

	hs::WatchSlotSnapshot byIndex;
	HS_CHECK(slots.ReadSlot(0, byIndex));
	HS_CHECK_EQ(byIndex.freeTick, 0ull);

	// Release records the block's own free tick, which the trap path uses to
	// silence the allocator's post-free link.
	HS_CHECK(slots.Release(Aligned(1), 188333102ull));
	HS_CHECK(slots.ReadSlot(0, byIndex));
	HS_CHECK_EQ(byIndex.freeTick, 188333102ull);
	HS_CHECK((byIndex.flags & hs::kWatchSlotReleased) != 0u);

	// A slot reclaimed for another block must not inherit the old free tick.
	HS_CHECK(slots.Claim(Aligned(2), 0x0, false, 0, 200, 2, 7, index));
	HS_CHECK_EQ(index, 0u);
	HS_CHECK(slots.ReadSlot(0, byIndex));
	HS_CHECK_EQ(byIndex.freeTick, 0ull);
	HS_CHECK_EQ(byIndex.address, Aligned(2));

	slots.ResetForTesting();
}

HS_TEST(watchpoint_unattributed_report_encoding_carries_the_raw_dr_state)
{
	// 0.6.3 Deliverable 1: a #DB the classifier could not attribute is recorded
	// with DR6, DR7, this thread's ever-armed mask, whether any DR was ever
	// programmed, the raw DR0-DR3 and the RIP -- so the fatal case leaves data.
	hs::WatchpointReport report;
	report.flags = hs::kWatchReportUnattributed;
	report.slotIndex = 0;
	report.watchedAddress = 0;
	report.writerRip = 0x7FF6AABBCCDDull;
	report.threadId = 4242;
	report.dr6 = 0;
	report.dr7 = 0x00000004ull;
	report.everArmedMask = 0;
	report.anyDrProgrammed = true;
	report.freeTick = 0;
	report.tick = 188333103ull;
	report.drAddress[0] = 0x27D0F000ull;
	report.drAddress[1] = 0x0;
	report.drAddress[2] = 0x0;
	report.drAddress[3] = 0x0;

	char buffer[1024]{};
	const auto written = hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	HS_CHECK(written > 0);
	HS_CHECK(written < sizeof(buffer));

	const std::string text{ buffer };
	HS_CHECK(text.find("unattributed=1") != std::string::npos);
	HS_CHECK(text.find("dr6=0x0") != std::string::npos);
	HS_CHECK(text.find("dr7=0x4") != std::string::npos);
	HS_CHECK(text.find("ever_armed=0x0") != std::string::npos);
	HS_CHECK(text.find("any_dr=1") != std::string::npos);
	HS_CHECK(text.find("tid=4242") != std::string::npos);
	HS_CHECK(text.find("writer_rip=0x7FF6AABBCCDD") != std::string::npos);
	HS_CHECK(text.find("dr0=0x27D0F000") != std::string::npos);

	// 0.6.4 FIX A: a record with no provenance says nothing about the DR fields
	// (the second line is absent), which is exactly why 0.6.3's zeros were
	// unreadable. Case 1 is the 0.6.3 hole: the exception record carries nothing
	// AND the explicit read of the faulting thread FAILED -- so the fields are not
	// a measurement, and the record now says so with the error code.
	report.drReadSource = hs::kDrSourceExceptionContext;
	report.drReadStatus = hs::kDrReadFailed;
	report.drReadError = 87;  // ERROR_INVALID_PARAMETER, as GetThreadContext would set it
	report.contextDr6 = 0;
	report.contextDr7 = 0;
	report.contextEFlags = 0x246;
	report.contextDrAddress[0] = 0;
	report.drReadFlags = 0;
	report.flags = hs::kWatchReportUnattributed | hs::kWatchReportDrMeasured;
	const auto provenance = hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	HS_CHECK(provenance > 0);
	HS_CHECK(provenance < sizeof(buffer));
	const std::string provText{ buffer };
	HS_CHECK(provText.find("dr_used=exception-record") != std::string::npos);
	HS_CHECK(provText.find("dr_read=FAILED") != std::string::npos);
	HS_CHECK(provText.find("dr_err=87") != std::string::npos);
	HS_CHECK(provText.find("trap_flag=0") != std::string::npos);
	HS_CHECK(provText.find("free_from=none") != std::string::npos);
	HS_CHECK(hs::ClassifyDebugRegisterMeasurement(report.drReadSource, report.drReadStatus, report.dr6,
				report.drAddress, hs::kWatchpointSlotCount) == hs::DebugRegisterMeasurement::kReadFailed);

	// Case 2: the host DID populate the exception record, the explicit read
	// succeeded too, and the two disagree. BOTH sets must be in the encoding (that
	// comparison is the answer 0.6.3 could not produce) and EFlags is recorded.
	report.drReadStatus = hs::kDrReadOk;
	report.drReadError = 0;
	report.dr6 = 0xFFFF0FF2;
	report.dr7 = 0x99990055;
	report.drAddress[0] = 0x12340000;
	report.contextDr6 = 0xFFFF0FF2;
	report.contextDr7 = 0x99990055;
	report.contextEFlags = 0x10246;  // TF (0x100) is set
	report.contextDrAddress[0] = 0x12340000;
	report.threadDr6 = 0x99990055;
	report.threadDr7 = 0x00000001;
	report.threadDrAddress[0] = 0;
	report.drReadFlags = hs::kWatchReportDrContextDisagrees;
	report.flags = hs::kWatchReportUnattributed | hs::kWatchReportDrMeasured | hs::kWatchReportTrapFlagSet;
	(void)hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	const std::string bothText{ buffer };
	HS_CHECK(bothText.find("disagrees=1") != std::string::npos);
	HS_CHECK(bothText.find("trap_flag=1") != std::string::npos);
	HS_CHECK(bothText.find("exception-record: dr6=0xFFFF0FF2 dr7=0x99990055 dr0=0x12340000") != std::string::npos);
	HS_CHECK(bothText.find("faulting-thread-read: dr6=0x99990055 dr7=0x1 dr0=0x0") != std::string::npos);
	HS_CHECK(bothText.find("eflags=0x10246") != std::string::npos);
	HS_CHECK(hs::ClassifyDebugRegisterMeasurement(report.drReadSource, report.drReadStatus, report.dr6,
				report.drAddress, hs::kWatchpointSlotCount) == hs::DebugRegisterMeasurement::kReadNonZero);

	// The free-tick source is carried too (FIX B): which free the classifier used.
	report.freeTickSource = static_cast<std::uint32_t>(hs::FreeTickSource::kFreeRing);
	(void)hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	HS_CHECK(std::string{ buffer }.find("free_from=free-ring") != std::string::npos);

	// Case 3: the explicit read SUCCEEDED and genuinely returned zero while the
	// exception record was empty. This is a DIFFERENT record from a failed read --
	// the distinction FIX A exists to make -- and it means the host delivered a
	// single step with no debug register set at all.
	report.drReadSource = hs::kDrSourceCurrentThread;
	report.drReadStatus = hs::kDrReadOk;
	report.drReadError = 0;
	report.dr6 = 0;
	report.dr7 = 0;
	report.drAddress[0] = 0;
	report.contextDr6 = 0;
	report.contextDr7 = 0;
	report.contextDrAddress[0] = 0;
	report.threadDr6 = 0;
	report.threadDr7 = 0;
	report.threadDrAddress[0] = 0;
	report.drReadFlags = 0;
	report.flags = hs::kWatchReportUnattributed | hs::kWatchReportDrMeasured;
	(void)hs::EncodeWatchpointReport(report, buffer, sizeof(buffer));
	const std::string zeroText{ buffer };
	HS_CHECK(zeroText.find("dr_used=faulting-thread-read(no-suspend)") != std::string::npos);
	HS_CHECK(zeroText.find("dr_read=ok") != std::string::npos);
	HS_CHECK(zeroText.find("trap_flag=0") != std::string::npos);
	HS_CHECK(hs::ClassifyDebugRegisterMeasurement(report.drReadSource, report.drReadStatus, report.dr6,
				report.drAddress, hs::kWatchpointSlotCount) == hs::DebugRegisterMeasurement::kReadZero);

	// The two counters the stats line reports are driven by the classifier, so a
	// regression in either surfaces as a number in the log.
	auto& reportsForCounters = hs::WatchpointReports::Get();
	reportsForCounters.ResetSuppressionCountersForTesting();
	reportsForCounters.NoteUnattributedMeasured(hs::DebugRegisterMeasurement::kReadFailed);
	reportsForCounters.NoteUnattributedMeasured(hs::DebugRegisterMeasurement::kReadZero);
	reportsForCounters.NoteUnattributedMeasured(hs::DebugRegisterMeasurement::kReadZero);
	reportsForCounters.NotePostFreeSuppressed();
	reportsForCounters.NoteReallocSuppressed();
	reportsForCounters.NoteReallocSuppressed();
	reportsForCounters.NoteFreePredatesArm();
	HS_CHECK_EQ(reportsForCounters.UnattributedDrReadFailed(), 1ull);
	HS_CHECK_EQ(reportsForCounters.UnattributedDrReadZero(), 2ull);
	HS_CHECK_EQ(reportsForCounters.PostFreeSuppressed(), 1ull);
	HS_CHECK_EQ(reportsForCounters.ReallocSuppressed(), 2ull);
	HS_CHECK_EQ(reportsForCounters.FreePredatesArm(), 1ull);

	// The record survives the ring with BOTH DR sets and the provenance.
	report.dr7 = 0x99990055;
	report.drAddress[0] = 0x27D0F000ull;
	report.threadDr6 = 0x2;
	report.threadDr7 = 0x1;
	report.threadDrAddress[0] = 0ull;
	auto& reports = hs::WatchpointReports::Get();
	reports.Init(8);
	reports.ResetForTesting();
	reports.Record(report);
	hs::WatchpointReport out[8]{};
	HS_CHECK_EQ(reports.Drain(out, 8), 1u);
	HS_CHECK((out[0].flags & hs::kWatchReportUnattributed) != 0u);
	HS_CHECK_EQ(out[0].dr7, 0x99990055u);
	HS_CHECK(out[0].anyDrProgrammed);
	HS_CHECK_EQ(out[0].drAddress[0], 0x27D0F000ull);
	HS_CHECK_EQ(out[0].threadDr6, 0x2u);
	HS_CHECK_EQ(out[0].threadDr7, 0x1u);
	HS_CHECK_EQ(out[0].threadDrAddress[0], 0ull);
	HS_CHECK_EQ(out[0].drReadSource, hs::kDrSourceCurrentThread);
	HS_CHECK_EQ(out[0].drReadStatus, hs::kDrReadOk);
	reports.Shutdown();
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

HS_TEST(watchpoint_live_corpus_2026_09_24_write_reports_are_classified_as_designed)
{
	// The v0.6.3 in-game trip (2026-09-24, build 4f409330007c) produced 21
	// watchpoint-write reports. 18 of them share the allocator-bookkeeping shape:
	// the armed value was a genuine vtable in the exe range and the value after
	// the write was a heap pointer or 0. The ticks below are the run's own
	// numbers, read out of HeapSentinel.log / HeapSentinel-reports.log:
	//   trapTick      = trap_tick
	//   slotFreeTick  = the 0.6.3 report's free_tick (the slot's Release tick)
	//   ringFreeTick  = "Scaleform free record: freed at tick X" (the free ring)
	//   armTick       = armed_tick
	// The expectation is the 0.6.4 rule: free = max(slot, ring), one bounded
	// window on both sides, and only the two ALLOCATOR orderings suppressed.
	struct Row
	{
		std::uint64_t           trap;
		std::uint64_t           slotFree;
		std::uint64_t           ringFree;
		std::uint64_t           arm;
		bool                    staleArm;
		const char*             writer;
		hs::WatchpointFreeContext expected;
	};

	const Row rows[] = {
		{ 261331396ull, 261331347ull, 261331427ull, 261331347ull, false, "SkyrimSE.exe+0x1193AD5", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261343708ull, 261331329ull, 261331329ull, 261332401ull, false, "VCRUNTIME140.dll+0x1294B", hs::WatchpointFreeContext::kFreePredatesArm },
		{ 261350107ull, 261350022ull, 261350022ull, 261350022ull, false, "SkyrimSE.exe+0x1191FD6", hs::WatchpointFreeContext::kPostFreeLink },
		{ 261373926ull, 261373860ull, 261373860ull, 261372940ull, true, "SkyrimSE.exe+0x11920D9", hs::WatchpointFreeContext::kPostFreeLink },
		{ 261373974ull, 261373860ull, 261373860ull, 261372940ull, true, "SkyrimSE.exe+0x11920D9", hs::WatchpointFreeContext::kPostFreeLink },
		{ 261418699ull, 261418666ull, 261418719ull, 261418666ull, false, "SkyrimSE.exe+0x11918CE", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261418718ull, 261418666ull, 261418719ull, 261418666ull, false, "SkyrimSE.exe+0x11920CA", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261420558ull, 261418700ull, 261418700ull, 261418808ull, false, "SkyrimSE.exe+0x11922AB", hs::WatchpointFreeContext::kFreePredatesArm },
		{ 261423083ull, 261423031ull, 261423177ull, 261423031ull, false, "SkyrimSE.exe+0x11920F4", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261452716ull, 261452663ull, 261452751ull, 261452663ull, false, "SkyrimSE.exe+0x1193C08", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261452719ull, 261452645ull, 261452884ull, 261452645ull, false, "SkyrimSE.exe+0x1193AD5", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261452740ull, 261452663ull, 261452751ull, 261452663ull, false, "SkyrimSE.exe+0x1193C08", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261452748ull, 261452645ull, 261452884ull, 261452645ull, false, "SkyrimSE.exe+0x1193AD5", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261452793ull, 261452645ull, 261452884ull, 261452645ull, false, "SkyrimSE.exe+0x1193AD5", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261452824ull, 261452645ull, 261452884ull, 261452645ull, false, "SkyrimSE.exe+0x1193AD5", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261486322ull, 261486163ull, 261486289ull, 261486163ull, false, "SkyrimSE.exe+0x119234E", hs::WatchpointFreeContext::kPostFreeLink },
		{ 261486342ull, 261486163ull, 261486289ull, 261486163ull, false, "SkyrimSE.exe+0x11922D0", hs::WatchpointFreeContext::kPostFreeLink },
		// The case named in the 0.6.3 report: the stale slot Release tick (826 ms
		// early) shadowed the ring's newest record, so a delta of 0 was reported
		// with a delta of 826.
		{ 261487115ull, 261486289ull, 261487115ull, 261486555ull, false, "SkyrimSE.exe+0x119214E", hs::WatchpointFreeContext::kPostFreeLink },
		{ 261745821ull, 261745750ull, 261745985ull, 261745750ull, false, "SkyrimSE.exe+0x11917BA", hs::WatchpointFreeContext::kReallocInProgress },
		{ 261788348ull, 261788288ull, 261788288ull, 261788288ull, false, "SkyrimSE.exe+0x1193AD5", hs::WatchpointFreeContext::kPostFreeLink },
		// 12.4 s after the free, and its `after` value is a code pointer, so the
		// drainer's benign shape rule drops it anyway. It is kept here as the
		// corpus's genuine delayed-write row.
		{ 261826937ull, 261817722ull, 261817722ull, 261817722ull, false, "SkyrimSE.exe+0x140D177B5", hs::WatchpointFreeContext::kDelayedWriteAfterFree },
	};

	std::size_t suppressed = 0;
	std::size_t delayed = 0;
	std::size_t predatesArm = 0;
	std::size_t postFree = 0;
	std::size_t reallocInProgress = 0;
	for (const auto& row : rows) {
		const auto freeTick = hs::PreferNewestFreeTick(row.slotFree, row.ringFree);
		const auto got = hs::ClassifyWriteAgainstFree(freeTick, row.arm, row.trap, hs::kAllocatorBookkeepingWindowMs);
		// HS_CHECK_EQ on the enum would not say which row failed, so compare the
		// names and let a failure print the row's identity.
		HS_CHECK_MSG(std::string{ hs::WatchpointFreeContextName(got) } ==
				std::string{ hs::WatchpointFreeContextName(row.expected) },
			std::string{ "corpus row trap=" } + std::to_string(row.trap) + " writer=" + row.writer + " expected=" +
				hs::WatchpointFreeContextName(row.expected) + " got=" + hs::WatchpointFreeContextName(got));
		if (hs::FreeContextIsAllocatorBookkeeping(got)) {
			++suppressed;
			if (got == hs::WatchpointFreeContext::kReallocInProgress) {
				++reallocInProgress;
			} else {
				++postFree;
			}
		} else if (got == hs::WatchpointFreeContext::kDelayedWriteAfterFree) {
			++delayed;
		} else if (got == hs::WatchpointFreeContext::kFreePredatesArm) {
			++predatesArm;
		}
	}

	// The honest headline, asserted as a NUMBER so it cannot drift silently: of
	// the 21 writes the trip produced, 18 are allocator bookkeeping and go silent
	// (7 post-free links and 11 realloc-in-progress writes, a split DESIGN 13.4
	// states), 2 report because their free evidence predates the arm, and 1 is a
	// genuine delayed write (which the shape rule drops in the drainer).
	HS_CHECK_EQ(suppressed, std::size_t{ 18 });
	HS_CHECK_EQ(postFree, std::size_t{ 7 });
	HS_CHECK_EQ(reallocInProgress, std::size_t{ 11 });
	HS_CHECK_EQ(predatesArm, std::size_t{ 2 });
	HS_CHECK_EQ(delayed, std::size_t{ 1 });
	HS_CHECK_EQ(sizeof(rows) / sizeof(rows[0]), std::size_t{ 21 });

	// The 18 shape-conforming, non-stale rows named in the task: 16 go silent and
	// 2 remain (the two whose free record predates the arm). This is stated as a
	// check rather than left implicit, because "the 18 should go silent" was the
	// expectation and the truth is 16 + 2 labelled.
	std::size_t shapeConforming = 0;
	std::size_t shapeConformingSuppressed = 0;
	for (const auto& row : rows) {
		if (row.staleArm) {
			continue;
		}
		if (std::string{ row.writer }.rfind("SkyrimSE.exe+0x140D", 0) == 0) {
			continue;  // the one row whose `after` was a code pointer, not heap/0
		}
		++shapeConforming;
		if (hs::FreeContextIsAllocatorBookkeeping(
				hs::ClassifyWriteAgainstFree(hs::PreferNewestFreeTick(row.slotFree, row.ringFree), row.arm, row.trap,
					hs::kAllocatorBookkeepingWindowMs))) {
			++shapeConformingSuppressed;
		}
	}
	HS_CHECK_EQ(shapeConforming, std::size_t{ 18 });
	HS_CHECK_EQ(shapeConformingSuppressed, std::size_t{ 16 });
}

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

		// 0.6.3 structural state + the counters the new tests assert.
		bool           anyDrProgrammed = false;
		int            unattributedRecorded = 0;
		int            postFreeSuppressed = 0;
		int            reallocSuppressed = 0;
		int            freePredatesArm = 0;

		// 0.6.4 FIX A: the model records BOTH DR sets, exactly as the plugin does, so
		// a test can assert the measurement exists on real hardware AND that the
		// explicit read itself worked.
		std::uint32_t  drReadSource = hs::kDrSourceNone;
		std::uint32_t  drReadStatus = hs::kDrReadNotAttempted;
		std::uint32_t  drReadError = 0;
		std::uint32_t  threadDr6 = 0;
		std::uint32_t  threadDr7 = 0;
		hs::DebugRegisterMeasurement measurement = hs::DebugRegisterMeasurement::kNotAttempted;

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
		hs::WatchpointFreeContext reportFreeContext = hs::WatchpointFreeContext::kLive;
		hs::FreeTickSource        reportFreeSource = hs::FreeTickSource::kNone;
	};
	TrapModel g_model;

	LONG g_outerSawUnattributed = 0;

	// The "does the #DB escape?" witness. Registered BEFORE the model handler so
	// it runs AFTER it (Windows calls the most recently added VEH first). If the
	// model handler returns CONTINUE_SEARCH -- the 0.6.2 behaviour, and the exact
	// mutation target -- this sees the exception and consumes it so the test can
	// report a failure instead of the process dying.
	LONG CALLBACK UnattributedOuterObserver(EXCEPTION_POINTERS* a_info)
	{
		if (!a_info || !a_info->ExceptionRecord || a_info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
			return EXCEPTION_CONTINUE_SEARCH;
		}
		++g_outerSawUnattributed;
		hs::hw::DisarmCurrentThread();
		a_info->ContextRecord->Dr6 = 0;
		a_info->ContextRecord->EFlags &= ~0x100u;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

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
		// 0.6.3 structural gate: the PRODUCTION rule, not a classifier. Break
		// MustConsumeDebugException or this input and an unattributed #DB escapes
		// to the outer observer (or, without one, kills the process).
		if (!hs::MustConsumeDebugException(g_model.anyDrProgrammed)) {
			return EXCEPTION_CONTINUE_SEARCH;
		}
		auto*          context = a_info->ContextRecord;

		// 0.6.4 FIX A, the PRODUCTION measurement: read the faulting thread's own
		// debug state (no suspension needed) and keep the outcome. The model uses the
		// same read the plugin uses, so breaking the read breaks this test.
		hs::hw::ThreadDebugState drState;
		g_model.drReadError = 0;
		const bool drReadOk = hs::hw::ReadCurrentThread(drState, &g_model.drReadError);
		g_model.drReadStatus = drReadOk ? hs::kDrReadOk : hs::kDrReadFailed;

		const std::uint64_t contextDrAddress[hs::kWatchpointSlotCount] = {
			static_cast<std::uint64_t>(context->Dr0),
			static_cast<std::uint64_t>(context->Dr1),
			static_cast<std::uint64_t>(context->Dr2),
			static_cast<std::uint64_t>(context->Dr3),
		};
		const std::uint64_t contextDr6 = static_cast<std::uint64_t>(context->Dr6);
		const std::uint64_t contextDr7 = static_cast<std::uint64_t>(context->Dr7);
		// The PRODUCTION source selection: the exception record wins whenever it
		// carries anything (on real Windows it does for a data breakpoint), and the
		// faulting-thread read supplies the fields only when it does not.
		const bool contextHasDr = contextDr6 != 0 || contextDr7 != 0 || contextDrAddress[0] != 0 ||
			contextDrAddress[1] != 0 || contextDrAddress[2] != 0 || contextDrAddress[3] != 0;
		const bool useThreadRead = drReadOk && !contextHasDr;
		g_model.drReadSource = useThreadRead ? hs::kDrSourceCurrentThread : hs::kDrSourceExceptionContext;
		g_model.threadDr6 = drReadOk ? static_cast<std::uint32_t>(drState.dr6) : 0u;
		g_model.threadDr7 = drReadOk ? static_cast<std::uint32_t>(drState.dr7) : 0u;

		const auto    dr6 = useThreadRead ? drState.dr6 : contextDr6;
		const auto    dr7 = useThreadRead ? drState.dr7 : contextDr7;
		const std::uint64_t threadDrAddress[hs::kWatchpointSlotCount] = {
			static_cast<std::uint64_t>(drState.dr0),
			static_cast<std::uint64_t>(drState.dr1),
			static_cast<std::uint64_t>(drState.dr2),
			static_cast<std::uint64_t>(drState.dr3),
		};
		std::uint64_t drAddress[hs::kWatchpointSlotCount] = {};
		for (std::size_t slot = 0; slot < hs::kWatchpointSlotCount; ++slot) {
			drAddress[slot] = useThreadRead ? threadDrAddress[slot] : contextDrAddress[slot];
		}
		g_model.measurement = hs::ClassifyDebugRegisterMeasurement(
			g_model.drReadSource, g_model.drReadStatus, static_cast<std::uint32_t>(dr6), drAddress, hs::kWatchpointSlotCount);

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
			// 0.6.4 FIX B, the PRODUCTION resolution: always consult the free ring and
			// prefer its newest record over the slot's Release tick.
			std::uint64_t         freeTick = tableValid ? snap.freeTick : 0;
			hs::FreeTickSource    freeSource = freeTick != 0 ? hs::FreeTickSource::kSlotSnapshot : hs::FreeTickSource::kNone;
			hs::ScaleformFreeRecord freeRecord;
			if (hs::ScaleformFreeRing::Get().Find(watched, freeRecord) && freeRecord.freeTick != 0) {
				const auto preferred = hs::PreferNewestFreeTick(freeTick, freeRecord.freeTick);
				if (preferred != freeTick || freeSource == hs::FreeTickSource::kNone) {
					freeSource = hs::FreeTickSource::kFreeRing;
				}
				freeTick = preferred;
			}
			const auto armTick = tableValid ? snap.armedTick : 0ull;
			const auto freeContext = hs::ClassifyWriteAgainstFree(freeTick, armTick, ::GetTickCount64(),
				hs::kAllocatorBookkeepingWindowMs);
			// Recorded even when the write is then SUPPRESSED: "which context was it" is
			// part of the evidence, and the suppression counter alone does not say
			// whether it was the post-free or the realloc ordering.
			g_model.reportFreeContext = freeContext;
			g_model.reportFreeSource = freeSource;
			std::uintptr_t after = 0;
			const bool     readable = TestSafeRead(watched, after);
			bool           record = armedWasCode && readable && after != valueAtArm;
			if (record && hs::FreeContextIsAllocatorBookkeeping(freeContext)) {
				record = false;
				if (freeContext == hs::WatchpointFreeContext::kReallocInProgress) {
					++g_model.reallocSuppressed;
				} else {
					++g_model.postFreeSuppressed;
				}
			}
			if (record && freeContext == hs::WatchpointFreeContext::kFreePredatesArm) {
				++g_model.freePredatesArm;
			}
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
			// 0.6.3 Deliverable 1: unattributed, but structurally ours. Record
			// the raw evidence BEFORE dealing with it, then consume.
			++g_model.unattributedRecorded;
			g_model.consumed = true;
			hs::WatchpointReport report;
			report.tick = ::GetTickCount64();
			report.writerRip = static_cast<std::uintptr_t>(context->Rip);
			report.threadId = ::GetCurrentThreadId();
			report.dr6 = static_cast<std::uint32_t>(dr6);
			report.dr7 = static_cast<std::uint32_t>(dr7);
			report.anyDrProgrammed = g_model.anyDrProgrammed;
			report.flags = hs::kWatchReportUnattributed;
			report.drReadSource = g_model.drReadSource;
			report.drReadStatus = g_model.drReadStatus;
			report.drReadError = g_model.drReadError;
			report.contextDr6 = static_cast<std::uint32_t>(context->Dr6);
			report.contextDr7 = static_cast<std::uint32_t>(context->Dr7);
			report.contextEFlags = static_cast<std::uint32_t>(context->EFlags);
			report.threadDr6 = g_model.threadDr6;
			report.threadDr7 = g_model.threadDr7;
			report.drReadFlags = ((drReadOk && g_model.threadDr6 != report.contextDr6) ? hs::kWatchReportDrContextDisagrees : 0u);
			report.flags |= hs::kWatchReportDrMeasured;
			if ((context->EFlags & 0x100u) != 0) {
				report.flags |= hs::kWatchReportTrapFlagSet;
			}
			for (std::size_t slot = 0; slot < hs::kWatchpointSlotCount; ++slot) {
				report.drAddress[slot] = static_cast<std::uintptr_t>(drAddress[slot]);
				report.contextDrAddress[slot] = static_cast<std::uintptr_t>(contextDrAddress[slot]);
				report.threadDrAddress[slot] = drReadOk ? static_cast<std::uintptr_t>(threadDrAddress[slot]) : 0u;
			}
			g_model.measurement = hs::ClassifyDebugRegisterMeasurement(
				report.drReadSource, report.drReadStatus, report.dr6, report.drAddress, hs::kWatchpointSlotCount);
			hs::WatchpointReports::Get().Record(report);
			context->Dr6 = 0;
			context->EFlags &= ~0x100u;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		context->Dr7 = cleared;
		context->Dr6 = 0;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// Arm the current thread's DR0 and the model's per-thread record for slot 0.
	void ModelArmSlotZero(std::uintptr_t a_address, std::uintptr_t a_valueAtArm, bool a_armedWasCode)
	{
		g_model = TrapModel{};
		g_model.anyDrProgrammed = true;  // we are about to write a DR
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

// ---------------------------------------------------------------------------
// 0.6.3: the four claims the new design rests on, each on a REAL hardware #DB.
// ---------------------------------------------------------------------------

HS_TEST(hw_watchpoint_unattributed_db_is_consumed_and_recorded)
{
	// (a) The bug that killed the session twice: a #DB the classifier cannot
	// attribute. The structural rule must consume it (process survives) AND
	// write a record. A real hardware watchpoint is armed but deliberately NOT
	// registered in the per-thread model or the slot table, so the classifier
	// genuinely cannot name it.
	g_watchedQword = 0;
	g_outerSawUnattributed = 0;
	g_model = TrapModel{};
	g_model.anyDrProgrammed = true;  // a DR is about to be programmed

	auto& reports = hs::WatchpointReports::Get();
	reports.Init(8);
	reports.ResetForTesting();
	hs::WatchpointSlots::Get().ResetForTesting();

	// Outer observer registered first, model handler second: the model runs first.
	const auto outer = ::AddVectoredExceptionHandler(1, &UnattributedOuterObserver);
	HS_CHECK(outer != nullptr);
	const auto inner = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(inner != nullptr);

	const auto     watched = reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword));
	std::uintptr_t addresses[hs::kWatchpointSlotCount] = { watched, 0, 0, 0 };
	std::uint64_t  dr7 = 0;
	HS_CHECK(hs::hw::ArmCurrentThread(addresses, hs::kWatchpointSlotCount, dr7));
	HS_CHECK_EQ(dr7, hs::BuildDr7(addresses, hs::kWatchpointSlotCount));

	g_watchedQword = 0x1;  // the real #DB, unattributable

	HS_CHECK(g_model.consumed);                 // the process survived the #DB
	HS_CHECK_EQ(g_model.unattributedRecorded, 1);
	HS_CHECK_EQ(g_outerSawUnattributed, 0);     // it never escaped to the next handler

	hs::WatchpointReport out[8]{};
	HS_CHECK_EQ(reports.Drain(out, 8), 1u);
	HS_CHECK((out[0].flags & hs::kWatchReportUnattributed) != 0u);
	HS_CHECK(out[0].anyDrProgrammed);
	HS_CHECK_EQ(out[0].drAddress[0], static_cast<std::uintptr_t>(watched));
	HS_CHECK_NE(out[0].writerRip, 0u);

	// 0.6.4 FIX A on REAL hardware: the record says HOW the debug registers were
	// measured AND carries both sets. On this platform the exception record carried
	// the trap's DR state (so it is the source the classifier uses), while the
	// faulting-thread read's values are carried next to it. Break the explicit
	// read and `drReadStatus` fails; break the classification and `measurement`
	// fails.
	HS_CHECK_EQ(g_model.drReadSource, hs::kDrSourceExceptionContext);
	HS_CHECK_EQ(g_model.drReadStatus, hs::kDrReadOk);
	HS_CHECK_EQ(g_model.drReadError, 0u);
	HS_CHECK(g_model.measurement == hs::DebugRegisterMeasurement::kReadNonZero);
	HS_CHECK((out[0].flags & hs::kWatchReportDrMeasured) != 0u);
	HS_CHECK_EQ(out[0].drReadSource, hs::kDrSourceExceptionContext);
	HS_CHECK_EQ(out[0].drReadStatus, hs::kDrReadOk);
	HS_CHECK_NE(out[0].dr6, 0u);          // a delivered hardware #DB always sets a B bit
	HS_CHECK_NE(out[0].contextDr6, 0u);   // ...and the exception record carried it
	// ...and the independent read RAN and its values are in the record. Whether
	// they are non-zero is deliberately NOT asserted: this test proves the
	// measurement happened and is carried, not what the host returned. (If the
	// read returns zero on real Windows, that is a finding, not a test failure.)
	HS_CHECK_EQ(out[0].threadDr6, g_model.threadDr6);
	HS_CHECK_EQ(out[0].threadDr7, g_model.threadDr7);

	hs::hw::DisarmCurrentThread();
	::RemoveVectoredExceptionHandler(inner);
	::RemoveVectoredExceptionHandler(outer);
	reports.Shutdown();
}

HS_TEST(hw_watchpoint_disabled_db_is_not_masked_and_no_dr_is_programmed)
{
	// (b) With the feature disabled nothing is armed, so a #DB is genuinely
	// foreign and MUST reach the next handler. (This test drives the structural
	// rule with anyDrProgrammed=false; the plugin calls Init only when
	// bEnabled=1, so "disabled" == "we never programmed a DR".)
	g_outerSawUnattributed = 0;
	g_model = TrapModel{};  // anyDrProgrammed stays false

	hs::hw::ThreadDebugState before;
	HS_CHECK(hs::hw::ReadCurrentThread(before));
	HS_CHECK_EQ(before.dr7, 0ull);
	HS_CHECK_EQ(before.dr0, 0ull);
	HS_CHECK_EQ(before.dr1, 0ull);
	HS_CHECK_EQ(before.dr2, 0ull);
	HS_CHECK_EQ(before.dr3, 0ull);

	const auto outer = ::AddVectoredExceptionHandler(1, &UnattributedOuterObserver);
	HS_CHECK(outer != nullptr);
	const auto inner = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(inner != nullptr);

	// A single-step with no debug register programmed: the same exception class,
	// delivered through the same dispatcher without any hardware watch.
	::RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, nullptr);

	HS_CHECK_EQ(g_outerSawUnattributed, 1);  // passed on, not masked
	HS_CHECK(!g_model.consumed);
	HS_CHECK_EQ(g_model.unattributedRecorded, 0);

	hs::hw::ThreadDebugState after;
	HS_CHECK(hs::hw::ReadCurrentThread(after));
	HS_CHECK_EQ(after.dr7, 0ull);

	::RemoveVectoredExceptionHandler(inner);
	::RemoveVectoredExceptionHandler(outer);
}

HS_TEST(hw_watchpoint_silences_the_allocator_post_free_link)
{
	// (c) A write within the bounded window after the block's own recorded free
	// is the free-list next pointer. Silent, and the watch stays armed.
	g_watchedQword = 0x6FFFFB89DDB8ull;  // the vtable before the link
	g_model = TrapModel{};
	g_model.anyDrProgrammed = true;

	// Deterministic free evidence: no stale ring record for this static address
	// from another test may win the PreferNewestFreeTick comparison.
	hs::ScaleformFreeRing::Get().Shutdown();

	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();
	const auto watched = reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword));
	std::size_t index = 0;
	HS_CHECK(slots.Claim(watched, 0x6FFFFB89DDB8ull, /*armedWasCode=*/true, 0, 1000, 1, 1, index));
	HS_CHECK_EQ(index, 0u);
	// Freed now: the allocator is about to link the block one tick later.
	const auto freeAt = ::GetTickCount64();
	HS_CHECK(slots.Release(watched, freeAt));

	g_model.everArmed[0] = true;
	g_model.armAddress[0] = watched;
	g_model.armValueAtArm[0] = 0x6FFFFB89DDB8ull;
	g_model.armWasCode[0] = true;
	std::uintptr_t addresses[hs::kWatchpointSlotCount] = { watched, 0, 0, 0 };
	std::uint64_t  dr7 = 0;
	HS_CHECK(hs::hw::ArmCurrentThread(addresses, hs::kWatchpointSlotCount, dr7));

	const auto handler = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(handler != nullptr);

	g_watchedQword = 0x0;  // the allocator's free-list link, a heap address

	HS_CHECK(g_model.consumed);
	HS_CHECK_EQ(g_model.recorded, 0);            // silent
	HS_CHECK_EQ(g_model.postFreeSuppressed, 1);  // and known to be suppressed
	HS_CHECK_EQ(g_model.unattributedRecorded, 0);

	// 0.6.4 FIX B: WHICH free the classifier used, and that it decided post-free.
	HS_CHECK(hs::FreeContextIsAllocatorBookkeeping(g_model.reportFreeContext));
	HS_CHECK(g_model.reportFreeContext == hs::WatchpointFreeContext::kPostFreeLink);

	// The slot was NOT released by us and the hardware watch is still enabled.
	hs::hw::ThreadDebugState after;
	HS_CHECK(hs::hw::ReadCurrentThread(after));
	HS_CHECK((after.dr7 & hs::Dr7LocalEnableBit(0)) != 0);

	// The PRODUCTION measurement path, asserted directly: the exception record
	// supplied the classification, and the independent read of the faulting thread
	// ALSO succeeded and found the breakpoint. That second fact is what makes the
	// 0.6.3 zeros readable if they ever recur.
	HS_CHECK_EQ(g_model.drReadSource, hs::kDrSourceExceptionContext);
	HS_CHECK_EQ(g_model.drReadStatus, hs::kDrReadOk);
	HS_CHECK(g_model.measurement == hs::DebugRegisterMeasurement::kReadNonZero);

	hs::hw::DisarmCurrentThread();
	::RemoveVectoredExceptionHandler(handler);
	slots.ResetForTesting();
}

HS_TEST(hw_watchpoint_reports_a_clobber_on_a_block_freed_earlier)
{
	// (d) A write to a block freed EARLIER than the window is a genuine
	// use-after-free and must still report.
	g_watchedQword = 0x6FFFFB89DDB8ull;
	g_model = TrapModel{};
	g_model.anyDrProgrammed = true;

	// Deterministic free evidence: no stale ring record for this static address
	// from another test may win the PreferNewestFreeTick comparison.
	hs::ScaleformFreeRing::Get().Shutdown();

	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();
	const auto watched = reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword));
	std::size_t index = 0;
	HS_CHECK(slots.Claim(watched, 0x6FFFFB89DDB8ull, /*armedWasCode=*/true, 0, 1000, 1, 1, index));
	HS_CHECK_EQ(index, 0u);
	HS_CHECK(slots.Release(watched, /*old free tick=*/1u));  // long before the window

	g_model.everArmed[0] = true;
	g_model.armAddress[0] = watched;
	g_model.armValueAtArm[0] = 0x6FFFFB89DDB8ull;
	g_model.armWasCode[0] = true;
	std::uintptr_t addresses[hs::kWatchpointSlotCount] = { watched, 0, 0, 0 };
	std::uint64_t  dr7 = 0;
	HS_CHECK(hs::hw::ArmCurrentThread(addresses, hs::kWatchpointSlotCount, dr7));

	const auto handler = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(handler != nullptr);

	g_watchedQword = 0x0;  // a delayed use-after-free clobber

	HS_CHECK(g_model.consumed);
	HS_CHECK_EQ(g_model.recorded, 1);
	HS_CHECK_EQ(g_model.postFreeSuppressed, 0);
	HS_CHECK(hs::ClassifyWatchedWrite(g_model.reportValueAtArm, g_model.reportArmedWasCode,
			g_model.reportValueAfter, g_model.reportReadable, /*afterIsCode=*/false) == hs::WatchpointWriteKind::kDegradation);

	hs::hw::DisarmCurrentThread();
	::RemoveVectoredExceptionHandler(handler);
	slots.ResetForTesting();
}

HS_TEST(hw_watchpoint_silences_a_realloc_in_progress_write)
{
	// (e) 0.6.4 FIX B, the case the 0.6.3 post-free window could never cover: the
	// allocator's link write happens INSIDE o_SfRealloc, so the free record lands
	// AFTER the trap (the reverse ordering of a plain free). This is a real #DB
	// with the ring's newest record placed in the future, exactly as the trip's
	// realloc rows showed.
	g_watchedQword = 0x6FFFFB89DDB8ull;
	g_model = TrapModel{};
	g_model.anyDrProgrammed = true;

	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();
	auto& ring = hs::ScaleformFreeRing::Get();
	ring.Init(64);

	const auto watched = reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword));
	std::size_t index = 0;
	HS_CHECK(slots.Claim(watched, 0x6FFFFB89DDB8ull, /*armedWasCode=*/true, 0, 1000, 1, 1, index));
	HS_CHECK_EQ(index, 0u);
	// A stale slot Release tick, and a free ring record that lands AFTER the trap.
	HS_CHECK(slots.Release(watched, /*slot tick=*/1000));
	hs::ScaleformFreeRecord future;
	future.ptr = watched;
	future.freeTick = ::GetTickCount64() + 100;  // the realloc's free record lands later
	ring.Record(future);

	g_model.everArmed[0] = true;
	g_model.armAddress[0] = watched;
	g_model.armValueAtArm[0] = 0x6FFFFB89DDB8ull;
	g_model.armWasCode[0] = true;
	std::uintptr_t addresses[hs::kWatchpointSlotCount] = { watched, 0, 0, 0 };
	std::uint64_t  dr7 = 0;
	HS_CHECK(hs::hw::ArmCurrentThread(addresses, hs::kWatchpointSlotCount, dr7));

	const auto handler = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(handler != nullptr);

	g_watchedQword = 0x0;  // the free-list link, written while the realloc runs

	HS_CHECK(g_model.consumed);
	HS_CHECK_EQ(g_model.recorded, 0);           // silent
	HS_CHECK_EQ(g_model.reallocSuppressed, 1);  // and labelled as the realloc case
	HS_CHECK_EQ(g_model.postFreeSuppressed, 0);
	HS_CHECK(g_model.reportFreeContext == hs::WatchpointFreeContext::kReallocInProgress);
	HS_CHECK(g_model.reportFreeSource == hs::FreeTickSource::kFreeRing);

	hs::hw::DisarmCurrentThread();
	::RemoveVectoredExceptionHandler(handler);
	ring.Shutdown();
	slots.ResetForTesting();
}

HS_TEST(hw_watchpoint_reports_a_write_whose_free_predates_the_arm)
{
	// (f) The free ring's only record for the address is OLDER than the arm (a
	// recycled address, or a watch armed on an already-freed block). That is not
	// the allocator's bookkeeping for this write, so it is REPORTED and labelled
	// rather than silenced -- the two corpus rows this leaves (0xA34DF900 and
	// 0xA33C04B0) are exactly this shape.
	g_watchedQword = 0x6FFFFB89DDB8ull;
	g_model = TrapModel{};
	g_model.anyDrProgrammed = true;

	auto& slots = hs::WatchpointSlots::Get();
	slots.ResetForTesting();
	auto& ring = hs::ScaleformFreeRing::Get();
	ring.Init(64);

	const auto watched = reinterpret_cast<std::uintptr_t>(const_cast<std::uint64_t*>(&g_watchedQword));
	std::size_t index = 0;
	HS_CHECK(slots.Claim(watched, 0x6FFFFB89DDB8ull, /*armedWasCode=*/true, 0, /*arm tick=*/5000, 1, 1, index));
	HS_CHECK_EQ(index, 0u);
	hs::ScaleformFreeRecord old;
	old.ptr = watched;
	old.freeTick = 1000;  // one tick-scale BEFORE the arm: stale evidence
	ring.Record(old);

	g_model.everArmed[0] = true;
	g_model.armAddress[0] = watched;
	g_model.armValueAtArm[0] = 0x6FFFFB89DDB8ull;
	g_model.armWasCode[0] = true;
	std::uintptr_t addresses[hs::kWatchpointSlotCount] = { watched, 0, 0, 0 };
	std::uint64_t  dr7 = 0;
	HS_CHECK(hs::hw::ArmCurrentThread(addresses, hs::kWatchpointSlotCount, dr7));

	const auto handler = ::AddVectoredExceptionHandler(1, &ModelTrapHandler);
	HS_CHECK(handler != nullptr);

	g_watchedQword = 0x0;

	HS_CHECK(g_model.consumed);
	HS_CHECK_EQ(g_model.recorded, 1);
	HS_CHECK_EQ(g_model.freePredatesArm, 1);
	HS_CHECK(g_model.reportFreeContext == hs::WatchpointFreeContext::kFreePredatesArm);
	HS_CHECK(g_model.reportFreeSource == hs::FreeTickSource::kFreeRing);
	HS_CHECK(hs::ClassifyWatchedWrite(g_model.reportValueAtArm, g_model.reportArmedWasCode,
			g_model.reportValueAfter, g_model.reportReadable, /*afterIsCode=*/false) == hs::WatchpointWriteKind::kDegradation);

	hs::hw::DisarmCurrentThread();
	::RemoveVectoredExceptionHandler(handler);
	ring.Shutdown();
	slots.ResetForTesting();
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

HS_TEST(hw_watchpoint_silences_a_realloc_in_progress_write)
{
	hstest::Note("Windows-only: needs a real #DB; ClassifyWriteAgainstFree above is the Linux-checkable half");
	HS_CHECK(hs::FreeContextIsAllocatorBookkeeping(
		hs::ClassifyWriteAgainstFree(20000ull, 10000ull, 19900ull, hs::kAllocatorBookkeepingWindowMs)));
}

HS_TEST(hw_watchpoint_reports_a_write_whose_free_predates_the_arm)
{
	hstest::Note("Windows-only: needs a real #DB; ClassifyWriteAgainstFree above is the Linux-checkable half");
	HS_CHECK(hs::ClassifyWriteAgainstFree(1000ull, 5000ull, 90000ull, hs::kAllocatorBookkeepingWindowMs) ==
		hs::WatchpointFreeContext::kFreePredatesArm);
}
#endif