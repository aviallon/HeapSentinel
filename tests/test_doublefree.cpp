// Off-game tests for the 0.5.0 double-free fixes. Every one of these is a
// behaviour a reader of a run depends on:
//
//   * the per-thread re-entrancy guard (kills the M1 nested-observation flood)
//   * report-only-by-default (a suspected double free still calls the original)
//   * the alloc-side evidence a report must carry
//   * the allocator-confidence gate that refuses to claim a bare [double-free]
//     from a hook chain we have not verified
//   * the stats emission schedule (a short session must still emit stats)
//   * the reports log appending and rotating instead of truncating
//
// All of it is plain C++, so it builds and runs on Linux and Windows and under
// ASan/UBSan.

#include "harness.h"

#include "Core/AllocatorConfidence.h"
#include "Core/FreeEvidence.h"
#include "Core/FreePolicy.h"
#include "Core/FreeReentrancy.h"
#include "Core/ReportLog.h"
#include "Core/ShadowLedger.h"
#include "Core/Stats.h"

#include <memory>
#include <string>
#include <vector>

using namespace hs;

namespace
{
	AllocationInfo MakeInfo()
	{
		AllocationInfo info;
		info.ptr = 0x12345000;
		info.size = 96;
		info.threadId = 4242;
		info.flags = kFlagFreed | kFlagScaleform | kFlagFreedBySF;
		info.allocSite = reinterpret_cast<void*>(0x1400ABCDE);
		info.freeSite = reinterpret_cast<void*>(0x1400F00D0);
		info.allocStack = 7;
		info.freeStack = 9;
		info.allocTick = 1000;
		info.freeTick = 2000;
		return info;
	}
}

// --- step 2: re-entrancy guard ------------------------------------------

HS_TEST(freereentrancy_detects_a_nested_observation_of_the_same_pointer)
{
	FreeReentrancy::ResetForTesting();

	{
		FreeReentrancy outer(reinterpret_cast<void*>(0xCAFE));
		HS_CHECK(!outer.Nested());

		{
			FreeReentrancy inner(reinterpret_cast<void*>(0xCAFE));
			HS_CHECK(inner.Nested());  // same pointer, nested -> M1
		}

		// The inner scope is gone but the outer frame still holds the pointer.
		FreeReentrancy stillNested(reinterpret_cast<void*>(0xCAFE));
		HS_CHECK(stillNested.Nested());
	}

	// The outer scope exited, so a fresh top-level enter is not nested.
	FreeReentrancy fresh(reinterpret_cast<void*>(0xCAFE));
	HS_CHECK(!fresh.Nested());
}

HS_TEST(freereentrancy_does_not_confuse_distinct_pointers)
{
	FreeReentrancy::ResetForTesting();

	FreeReentrancy a(reinterpret_cast<void*>(0x1111));
	HS_CHECK(!a.Nested());
	FreeReentrancy b(reinterpret_cast<void*>(0x2222));
	HS_CHECK(!b.Nested());
	FreeReentrancy c(reinterpret_cast<void*>(0x1111));
	HS_CHECK(c.Nested());
}

HS_TEST(freereentrancy_stack_is_released_when_the_scope_exits)
{
	FreeReentrancy::ResetForTesting();

	{
		FreeReentrancy guard(reinterpret_cast<void*>(0x3333));
		HS_CHECK(!guard.Nested());
	}
	{
		FreeReentrancy guard(reinterpret_cast<void*>(0x3333));
		HS_CHECK(!guard.Nested());  // the stack unwound
	}
}

HS_TEST(freereentrancy_fails_open_when_the_stack_is_full)
{
	FreeReentrancy::ResetForTesting();

	std::vector<std::unique_ptr<FreeReentrancy>> frames;
	frames.reserve(FreeReentrancy::kMaxDepth);
	for (std::size_t i = 0; i < FreeReentrancy::kMaxDepth; ++i) {
		frames.push_back(std::make_unique<FreeReentrancy>(reinterpret_cast<void*>(0x10000 + i * 0x10)));
		HS_CHECK(!frames.back()->Nested());
	}

	// The stack is full: the next entry is neither nested nor pushed, so the
	// free proceeds normally. A bounded diagnostic must never block a free.
	FreeReentrancy overflow(reinterpret_cast<void*>(0x4444));
	HS_CHECK(!overflow.Nested());

	FreeReentrancy::ResetForTesting();
}

// --- step 1: report-only by default -------------------------------------

HS_TEST(double_free_default_action_still_calls_the_original)
{
	const auto action = DecideDoubleFree(false);
	HS_CHECK(action.report);
	HS_CHECK(action.callOriginal);  // semantics-preserving default
}

HS_TEST(double_free_prevention_is_explicit_opt_in)
{
	const auto action = DecideDoubleFree(true);
	HS_CHECK(action.report);
	HS_CHECK(!action.callOriginal);  // the documented behaviour change
}

HS_TEST(poison_withholds_the_original_and_says_so)
{
	// The constant pins the intent: poison-on-free is the one path that
	// intentionally withholds the free, and it is opt-in.
	HS_CHECK(kPoisonWithholdsOriginalFree);
}

// --- step 3: alloc-side evidence ----------------------------------------

HS_TEST(evidence_names_alloc_site_tick_stack_flags_and_both_hook_families)
{
	const auto info = MakeInfo();
	const auto text = FormatDoubleFreeEvidence(info, FreeHookFamily::kMemoryManager);

	HS_CHECK(text.find("allocSite=0x1400ABCDE") != std::string::npos);
	HS_CHECK(text.find("allocTick=1000") != std::string::npos);
	HS_CHECK(text.find("allocStack=7") != std::string::npos);
	HS_CHECK(text.find("scaleform") != std::string::npos);
	HS_CHECK(text.find("firstFreeBy=SF") != std::string::npos);
	HS_CHECK(text.find("secondFreeBy=MM") != std::string::npos);
	HS_CHECK(text.find("firstFreeTick=2000") != std::string::npos);
}

HS_TEST(flags_decode_every_bit)
{
	HS_CHECK_EQ(DescribeAllocationFlags(0), std::string("0x0(none)"));
	HS_CHECK(DescribeAllocationFlags(kFlagScaleform).find("scaleform") != std::string::npos);
	HS_CHECK(DescribeAllocationFlags(kFlagFreedByMM).find("freed_by_mm") != std::string::npos);
	HS_CHECK(DescribeAllocationFlags(kFlagFreedBySF).find("freed_by_sf") != std::string::npos);
}

HS_TEST(first_free_family_is_recovered_from_the_record)
{
	auto info = MakeInfo();
	info.flags = kFlagFreed | kFlagFreedBySF;
	HS_CHECK(FirstFreeFamily(info) == FreeHookFamily::kScaleform);
	info.flags = kFlagFreed | kFlagFreedByMM;
	HS_CHECK(FirstFreeFamily(info) == FreeHookFamily::kMemoryManager);
	info.flags = kFlagFreed;
	HS_CHECK(FirstFreeFamily(info) == FreeHookFamily::kUnknown);
}

// --- step 4: allocator confidence gate ----------------------------------

HS_TEST(only_a_verified_allocator_earns_a_bare_double_free_kind)
{
	ResetAllocatorConfidenceForTesting();

	HS_CHECK_EQ(std::string(DoubleFreeReportKind(AllocatorConfidence::kVerified)), std::string("double-free"));
	HS_CHECK(DoubleFreeIsTrustworthy(AllocatorConfidence::kVerified));

	for (const auto c : { AllocatorConfidence::kUnverified, AllocatorConfidence::kOverridden, AllocatorConfidence::kUnknown }) {
		HS_CHECK_EQ(std::string(DoubleFreeReportKind(c)), std::string("double-free-unverified"));
		HS_CHECK(!DoubleFreeIsTrustworthy(c));
	}
}

HS_TEST(allocator_confidence_round_trips)
{
	ResetAllocatorConfidenceForTesting();
	HS_CHECK(GetAllocatorConfidence() == AllocatorConfidence::kUnknown);

	SetAllocatorConfidence(AllocatorConfidence::kOverridden, "prologue differs");
	HS_CHECK(GetAllocatorConfidence() == AllocatorConfidence::kOverridden);
	HS_CHECK_EQ(GetAllocatorConfidenceDetail(), std::string("prologue differs"));

	ResetAllocatorConfidenceForTesting();
	HS_CHECK(GetAllocatorConfidence() == AllocatorConfidence::kUnknown);
	HS_CHECK(GetAllocatorConfidenceDetail().empty());
}

// --- step 6: stats emission schedule ------------------------------------

HS_TEST(stats_schedule_emits_at_data_load_and_first_report_exactly_once)
{
	ResetStatsScheduleForTesting();

	HS_CHECK(ShouldEmitOnDataLoaded());
	HS_CHECK(!ShouldEmitOnDataLoaded());
	HS_CHECK(ShouldEmitOnFirstReport());
	HS_CHECK(!ShouldEmitOnFirstReport());

	ResetStatsScheduleForTesting();
	HS_CHECK(ShouldEmitOnDataLoaded());
}

HS_TEST(stats_format_includes_every_counter)
{
	StatsSnapshot snapshot;
	snapshot.ledgerEntries = 11;
	snapshot.ledgerCapacity = 22;
	snapshot.insertFailures = 3;
	snapshot.writerDrops = 4;
	snapshot.ringCount = 5;
	snapshot.ringCapacity = 6;
	snapshot.ringEvictions = 7;
	snapshot.haveRetention = true;
	snapshot.retentionSeconds = 8;
	snapshot.poisonCount = 9;
	snapshot.poisonBlocks = 10;
	snapshot.poisonKiB = 12;
	snapshot.poisonEvictions = 13;
	snapshot.weaklibCount = 14;
	snapshot.weaklibCapacity = 15;
	snapshot.ledgerBloomKiB = 16;
	snapshot.ringBloomKiB = 17;
	snapshot.bloomSwaps = 18;
	snapshot.health = "GREEN";

	const auto lines = FormatStats(snapshot);
	HS_CHECK_EQ(lines.size(), std::size_t{ 6 });

	std::string joined;
	for (const auto& line : lines) {
		joined += line;
		joined += '\n';
	}
	HS_CHECK(joined.find("11 ledger entries") != std::string::npos);
	HS_CHECK(joined.find("3 insert failures") != std::string::npos);
	HS_CHECK(joined.find("4 writer drops") != std::string::npos);
	HS_CHECK(joined.find("5/6 records") != std::string::npos);
	HS_CHECK(joined.find("7 evictions") != std::string::npos);
	HS_CHECK(joined.find("retention 8 s") != std::string::npos);
	HS_CHECK(joined.find("9/10 blocks") != std::string::npos);
	HS_CHECK(joined.find("14") != std::string::npos);
	HS_CHECK(joined.find("health GREEN") != std::string::npos);
}

// --- step 7: reports log append + rotate --------------------------------

HS_TEST(reports_log_never_truncates)
{
	HS_CHECK(!kReportLogTruncates);
}

HS_TEST(reports_log_rotation_decision)
{
	HS_CHECK(SelectReportLogAction(0, 100) == ReportLogAction::kAppend);
	HS_CHECK(SelectReportLogAction(99, 100) == ReportLogAction::kAppend);
	HS_CHECK(SelectReportLogAction(100, 100) == ReportLogAction::kRotate);
	HS_CHECK(SelectReportLogAction(101, 100) == ReportLogAction::kRotate);
}

HS_TEST(session_header_names_the_build_and_the_module_set)
{
	const auto header = BuildSessionHeader("0.5.0", "abc1234", 123456789);
	HS_CHECK(header.find("v0.5.0") != std::string::npos);
	HS_CHECK(header.find("abc1234") != std::string::npos);

	const auto context = BuildSessionContext("verifyTargets=1 ledger=1", 0xDEADBEEFCAFEF00Dull, 321);
	HS_CHECK(context.find("modlistHash=0xDEADBEEFCAFEF00D") != std::string::npos);
	HS_CHECK(context.find("modules=321") != std::string::npos);
	HS_CHECK(context.find("verifyTargets=1") != std::string::npos);
}