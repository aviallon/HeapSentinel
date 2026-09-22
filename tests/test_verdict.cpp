// Off-game tests for the verdict: the freed-vs-corrupted discriminator that the
// crash report rests on. Each branch is asserted explicitly, including the
// negative "unknown" answer.

#include "harness.h"

#include "Core/Verdict.h"

using namespace hs;

namespace
{
	VerdictFacts Base()
	{
		VerdictFacts facts;
		facts.regName = "rcx";
		facts.value = 0xA6733F10;
		facts.known = true;
		facts.size = 0x280;
		facts.hasFreeSite = true;
		facts.freeSiteName = "SomeMod.dll+0x1234";
		facts.vtableAtFree = 0x140D0000;
		facts.vtableAtFreePlausible = true;
		return facts;
	}
}

HS_TEST(verdict_unknown_is_an_explicit_negative)
{
	VerdictFacts facts;
	facts.regName = "rcx";
	facts.value = 0x1234;
	facts.known = false;

	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kUnknown);
	HS_CHECK(verdict.reason.find("unknown") != std::string::npos);
	HS_CHECK(verdict.reason.find("unhooked") != std::string::npos);
}

HS_TEST(verdict_freed_with_poison_is_a_deterministic_use_after_free)
{
	auto facts = Base();
	facts.freed = true;
	facts.poisoned = true;
	facts.poisonMatch = true;

	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kUseAfterFreePoison);
	HS_CHECK(verdict.reason.find("use-after-free") != std::string::npos);
	HS_CHECK(verdict.reason.find("SomeMod.dll+0x1234") != std::string::npos);
	HS_CHECK(verdict.reason.find("poison") != std::string::npos);
}

HS_TEST(verdict_freed_healthy_object_is_a_use_after_free_naming_the_free_site)
{
	auto facts = Base();
	facts.freed = true;

	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kUseAfterFree);
	HS_CHECK(verdict.reason.find("use-after-free") != std::string::npos);
	HS_CHECK(verdict.reason.find("SomeMod.dll+0x1234") != std::string::npos);
}

HS_TEST(verdict_freed_but_already_corrupt_is_still_a_use_after_free)
{
	auto facts = Base();
	facts.freed = true;
	facts.vtableAtFreePlausible = false;

	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kUseAfterFreeAlreadyCorrupt);
	HS_CHECK(verdict.reason.find("already") != std::string::npos);
}

HS_TEST(verdict_live_object_with_non_code_first_qword_is_a_stray_write)
{
	auto facts = Base();
	facts.freed = false;
	facts.currentReadable = true;
	facts.currentFirstQword = 0xA37C9C00;
	facts.currentPlausible = false;

	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kStrayWriteLive);
	HS_CHECK(verdict.reason.find("stray WRITE") != std::string::npos);
	HS_CHECK(verdict.reason.find("not a use-after-free") != std::string::npos);
}

HS_TEST(verdict_live_object_whose_first_qword_changed)
{
	auto facts = Base();
	facts.freed = false;
	facts.currentReadable = true;
	facts.currentFirstQword = 0x140D1234;
	facts.currentPlausible = true;
	facts.lastKnownVtable = 0x140D0000;
	facts.lastKnownVtablePlausible = true;

	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kLiveFirstQwordChanged);
	HS_CHECK(verdict.reason.find("changed") != std::string::npos);
}

HS_TEST(verdict_live_and_plausible_is_not_explained_by_a_free)
{
	auto facts = Base();
	facts.freed = false;
	facts.currentReadable = true;
	facts.currentFirstQword = 0x140D0000;
	facts.currentPlausible = true;
	facts.lastKnownVtable = 0x140D0000;
	facts.lastKnownVtablePlausible = true;

	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kLiveHealthy);
	HS_CHECK(verdict.reason.find("NOT explained by a free") != std::string::npos);
}