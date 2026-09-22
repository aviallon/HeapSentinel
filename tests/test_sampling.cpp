#include "harness.h"

#include "Ipc/Sampling.h"

#include <array>
#include <cstdint>

namespace
{
	// The address pattern that actually occurs: real heap pointers come out of
	// an allocator that rounds to 16 bytes, so their low four bits are always
	// zero.
	[[nodiscard]] std::uintptr_t AlignedPointer(std::size_t a_index) noexcept
	{
		return static_cast<std::uintptr_t>(0x0000014000000000ull + (a_index * 16u));
	}
}

// This is the bug the prime modulus exists to avoid, asserted rather than
// described. With 16-byte-aligned pointers, `ptr % 64` can only ever land in 4
// of the 64 buckets, so a "1 in 64" sample is really "these four address
// classes, always" - a systematic slice, not a sample.
HS_TEST(sampling_power_of_two_modulus_is_a_systematic_subset)
{
	std::array<int, 64> raw{};
	for (std::size_t i = 0; i < 100000; ++i) {
		++raw[AlignedPointer(i) % 64];
	}
	int rawUsed = 0;
	for (auto count : raw) {
		if (count > 0) {
			++rawUsed;
		}
	}
	HS_CHECK_EQ(rawUsed, 4);

	// Mixing first fixes it even for a power-of-two modulus, which is what shows
	// the fault was the reduction and not the range.
	std::array<int, 64> mixed{};
	for (std::size_t i = 0; i < 100000; ++i) {
		++mixed[hs::Mix64(AlignedPointer(i)) % 64];
	}
	int mixedUsed = 0;
	for (auto count : mixed) {
		if (count > 0) {
			++mixedUsed;
		}
	}
	HS_CHECK_EQ(mixedUsed, 64);
}

// The bucket distribution is a property of the MIXER, over every pointer, not
// of the sampled subset - which is why this counts all of them. (Conflating the
// two was a bug in the first version of this test: it summed the sampled
// pointers into buckets and then asserted ~10000 per bucket, when 610000/61
// samples can only average ~163 per bucket.)
HS_TEST(sampling_mixed_buckets_are_uniform_over_the_prime)
{
	constexpr std::uint32_t prime = hs::kDefaultSamplePrime;
	std::array<int, prime>  buckets{};

	constexpr std::size_t kPointers = 610000;  // ~10000 per bucket
	for (std::size_t i = 0; i < kPointers; ++i) {
		++buckets[hs::Mix64(AlignedPointer(i)) % prime];
	}

	int minBucket = buckets[0];
	int maxBucket = buckets[0];
	for (auto count : buckets) {
		if (count < minBucket) {
			minBucket = count;
		}
		if (count > maxBucket) {
			maxBucket = count;
		}
	}

	// ~10000 per bucket with a standard deviation of ~100, so a 15% spread is a
	// ~15 sigma bound: it will not flake, and it still catches a reduction that
	// is correlated with the address layout (the power-of-two case above is
	// 100% correlated and would be caught instantly).
	HS_CHECK(maxBucket < 11500);
	HS_CHECK(minBucket > 8500);
}

HS_TEST(sampling_rate_matches_the_configured_prime)
{
	constexpr std::uint32_t prime = hs::kDefaultSamplePrime;
	constexpr std::size_t   kPointers = 610000;

	std::size_t sampled = 0;
	for (std::size_t i = 0; i < kPointers; ++i) {
		if (hs::SamplePointer(AlignedPointer(i), prime)) {
			++sampled;
		}
	}

	const double expected = static_cast<double>(kPointers) / static_cast<double>(prime);
	const double actual = static_cast<double>(sampled);

	// The count is deterministic for a fixed pointer set, and the pointer set
	// here is synthetic and perfectly regular, so a band is the honest assertion
	// rather than pretending the count is exactly kPointers/prime.
	HS_CHECK(actual > expected * 0.95);
	HS_CHECK(actual < expected * 1.05);

	// And the sampler must actually be a sampler: one that kept everything or
	// nothing would be caught here rather than passing as "uniform enough".
	HS_CHECK(sampled > 0);
	HS_CHECK(sampled < kPointers / 2);
}

// The property the timeline depends on: a pointer is in or out for its whole
// life, so an allocation and its matching free are both kept or both dropped.
// Without this, the log contains frees whose allocations were sampled away,
// which is worse than no log at all.
HS_TEST(sampling_is_stable_per_pointer)
{
	for (std::size_t i = 0; i < 1000; ++i) {
		const std::uintptr_t ptr = AlignedPointer(i);
		const bool           first = hs::SamplePointer(ptr, hs::kDefaultSamplePrime);
		for (int repeat = 0; repeat < 4; ++repeat) {
			HS_CHECK_EQ(hs::SamplePointer(ptr, hs::kDefaultSamplePrime), first);
		}
	}
}

HS_TEST(sampling_default_prime_is_on_the_ladder_and_not_a_power_of_two)
{
	// This is the guard on the guard: the other sampling tests check the MIXER and
	// the LADDER, so without this one somebody could change the default modulus to
	// 64 and every other test would still pass. The mixed reduction is uniform
	// even modulo a power of two - which is exactly why the aliasing bug is easy
	// to reintroduce - so the default has to be asserted directly.
	HS_CHECK_NE(hs::kDefaultSamplePrime & (hs::kDefaultSamplePrime - 1), 0u);

	bool onLadder = false;
	for (auto prime : hs::kSamplePrimes) {
		if (prime == hs::kDefaultSamplePrime) {
			onLadder = true;
		}
	}
	HS_CHECK(onLadder);

	// The ladder has to start at the default, or FinerPrime's saturation point
	// and the configured default disagree.
	HS_CHECK_EQ(hs::kSamplePrimes[0], hs::kDefaultSamplePrime);
}

HS_TEST(sampling_ladder_never_contains_a_power_of_two)
{
	for (auto prime : hs::kSamplePrimes) {
		// p & (p-1) == 0 exactly when p is a power of two.
		HS_CHECK_NE(prime & (prime - 1), 0u);
		HS_CHECK_NE(prime, 64u);
		HS_CHECK_NE(prime, 128u);
	}
}

HS_TEST(sampling_ladder_steps_are_monotonic_and_saturate)
{
	HS_CHECK(hs::CoarserPrime(hs::kDefaultSamplePrime) > hs::kDefaultSamplePrime);
	// 61 is the finest rung, so asking for something finer saturates there rather
	// than running off the ladder (or, worse, wrapping around to coarser).
	HS_CHECK_EQ(hs::FinerPrime(hs::kSamplePrimes[0]), hs::kSamplePrimes[0]);
	// From a middle rung it really does step down and up.
	HS_CHECK(hs::FinerPrime(97) < 97);
	HS_CHECK(hs::CoarserPrime(97) > 97);

	// Walking up from the first rung must reach the last and then stop, and
	// walking down must reach the first and then stop: a ladder that runs off
	// its end would silently stop sampling or start sampling everything.
	std::uint32_t prime = hs::kSamplePrimes[0];
	for (int i = 0; i < 64; ++i) {
		const std::uint32_t next = hs::CoarserPrime(prime);
		HS_CHECK(next >= prime);
		prime = next;
	}
	const auto last = hs::kSamplePrimes[(sizeof(hs::kSamplePrimes) / sizeof(hs::kSamplePrimes[0])) - 1];
	HS_CHECK_EQ(prime, last);

	prime = last;
	for (int i = 0; i < 64; ++i) {
		const std::uint32_t next = hs::FinerPrime(prime);
		HS_CHECK(next <= prime);
		prime = next;
	}
	HS_CHECK_EQ(prime, hs::kSamplePrimes[0]);
}
