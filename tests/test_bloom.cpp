// Off-game tests for the bloom pre-filter. Its only authoritative answer is
// "definitely not present", so these tests pin that: no false negatives for
// inserted keys, fail-open before Init, the aging/swap behaviour, and - via the
// ledger - that a filter miss never becomes a positive verdict and that a
// possible-positive still has to be confirmed by the exact store.

#include "harness.h"

#include "Core/BloomFilter.h"
#include "Core/ShadowLedger.h"
#include "Core/Verdict.h"

using namespace hs;

namespace
{
	constexpr std::uintptr_t kKeyA = 0x11110000;
	constexpr std::uintptr_t kKeyB = 0x22220000;
}

HS_TEST(bloom_has_no_false_negatives_for_inserted_keys)
{
	BloomFilter filter;
	HS_CHECK(filter.Init(100000, 10, false));
	HS_CHECK(filter.Ready());

	for (std::uintptr_t i = 0; i < 50000; ++i) {
		filter.Add(0x1000 + i * 0x40);
	}
	// Every inserted key must be reported present; otherwise the filter would
	// hide a record the ledger still holds.
	for (std::uintptr_t i = 0; i < 50000; ++i) {
		HS_CHECK(filter.MightContain(0x1000 + i * 0x40));
	}

	filter.Shutdown();
}

HS_TEST(bloom_false_positive_rate_is_bounded)
{
	BloomFilter filter;
	HS_CHECK(filter.Init(100000, 10, false));

	for (std::uintptr_t i = 0; i < 100000; ++i) {
		filter.Add(0x1000 + i * 0x40);
	}

	std::uint64_t falsePositives = 0;
	for (std::uintptr_t i = 0; i < 100000; ++i) {
		if (filter.MightContain(0xF0000000 + i * 0x40)) {
			++falsePositives;
		}
	}
	// ~10 bits/element is ~1%; allow generous margin but fail if it is not a
	// filter at all (e.g. returning true unconditionally).
	HS_CHECK(falsePositives < 5000);

	filter.Shutdown();
}

HS_TEST(bloom_is_fail_open_before_init)
{
	BloomFilter filter;
	HS_CHECK(!filter.Ready());

	// Never suppress a lookup because the filter is unavailable.
	HS_CHECK(filter.MightContain(kKeyA));
	HS_CHECK(filter.MightContain(kKeyB));
	HS_CHECK_EQ(filter.Bytes(), std::size_t{ 0 });
	HS_CHECK_EQ(filter.Swaps(), std::uint64_t{ 0 });

	// Add must be a no-op, not a crash.
	filter.Add(kKeyA);
	HS_CHECK_EQ(filter.Bytes(), std::size_t{ 0 });
}

HS_TEST(bloom_aging_swaps_and_loses_only_the_older_half)
{
	BloomFilter filter;
	HS_CHECK(filter.Init(64, 10, true));

	filter.Add(kKeyA);
	HS_CHECK(filter.MightContain(kKeyA));

	// First swap clears the (empty) inactive half; kKeyA is still in the
	// retained half and remains visible.
	filter.ForceAge();
	HS_CHECK(filter.MightContain(kKeyA));

	filter.Add(kKeyB);
	HS_CHECK(filter.MightContain(kKeyB));

	// Second swap clears the half holding kKeyA. This is the designed false
	// negative of an aging filter: the key maps to "unknown", never to a bug.
	filter.ForceAge();
	HS_CHECK(filter.MightContain(kKeyB));
	HS_CHECK(!filter.MightContain(kKeyA));
	HS_CHECK_EQ(filter.Swaps(), std::uint64_t{ 2 });

	filter.Shutdown();
}

HS_TEST(bloom_miss_never_becomes_a_positive_verdict)
{
	// A filter HIT is not evidence: BuildVerdict with known=false (which is what
	// a miss - and a filter hit that the exact store then refutes - produces)
	// must be "unknown", never a use-after-free.
	VerdictFacts facts;
	facts.regName = "rcx";
	facts.value = kKeyA;
	facts.known = false;
	const auto verdict = BuildVerdict(facts);
	HS_CHECK(verdict.kind == VerdictKind::kUnknown);
}

HS_TEST(ledger_bloom_accelerates_but_stays_exact)
{
	ShadowLedger::Get().Shutdown();
	HS_CHECK(ShadowLedger::Get().Init(4096, 8, 0));
	HS_CHECK(ShadowLedger::Get().BloomBytes() > 0);

	// Inserted keys are always found (no false negative from the filter).
	for (std::uintptr_t i = 0; i < 500; ++i) {
		const auto key = 0x400000 + i * 0x100;
		AllocationInfo info;
		info.ptr = key;
		info.size = 0x40;
		info.flags = kFlagLive;
		ShadowLedger::Get().Insert(key, info);
	}
	AllocationInfo out;
	for (std::uintptr_t i = 0; i < 500; ++i) {
		HS_CHECK(ShadowLedger::Get().Find(0x400000 + i * 0x100, out));
	}

	// Keys that were never inserted stay absent: the filter may produce a false
	// POSITIVE, but the exact table (the authority) must still say no.
	for (std::uintptr_t i = 0; i < 500; ++i) {
		HS_CHECK(!ShadowLedger::Get().Find(0x900000 + i * 0x100, out));
	}

	ShadowLedger::Get().Shutdown();
}