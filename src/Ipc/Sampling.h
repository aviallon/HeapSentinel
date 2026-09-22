#pragma once

// Deterministic per-pointer sampling for the timeline tier.
//
// Two things are being avoided here, and both are real:
//
//  1. A power-of-two modulus is a stroboscopic bug, not a tuning choice. 64 is
//     a page divisor, a common struct stride and a size-class rounding, so a
//     sample taken modulo 64 lands in lock-step with page-aligned allocations,
//     with one size class and with every other power-of-two structure in the
//     plugin. perf defaults to 993 Hz rather than 1000 Hz for exactly this
//     reason. Use a prime.
//
//  2. Heap pointers are 8- or 16-byte aligned, so their low bits are always
//     zero. Reducing a raw pointer modulo 64 therefore reaches only 4 of the 64
//     buckets (2 of them for a 32-byte-aligned allocator). The subset is not
//     merely biased, it is a systematic slice of the address space. Mix first,
//     then reduce.
//
// The pointer alone is hashed, never the tick, size, thread or call site: a
// given pointer must be consistently in or out for its whole life, otherwise
// the timeline loses alloc/free pairing and becomes unreadable. A reused
// address inheriting the previous decision is fine - it is still coherent.
//
// Coverage does NOT depend on any of this. Detection and provenance live in the
// exact, pointer-keyed state table; only the narrative is sampled.

#include <cstdint>

namespace hs
{
	// MurmurHash3 fmix64. Cheap, strong, and it avalanches the low bits that
	// alignment zeroes out.
	[[nodiscard]] constexpr std::uint64_t Mix64(std::uint64_t a_value) noexcept
	{
		a_value ^= a_value >> 33;
		a_value *= 0xFF51AFD7ED558CCDull;
		a_value ^= a_value >> 33;
		a_value *= 0xC4CEB9FE1A85EC53ull;
		a_value ^= a_value >> 33;
		return a_value;
	}

	// The default timeline sampling modulus. Prime, not a power of two, not a
	// round decimal, and not a divisor of the page size or of any structure in
	// the plugin.
	inline constexpr std::uint32_t kDefaultSamplePrime = 61;

	// The ladder the adaptive sampler steps along. Every step is a prime and a
	// roughly 10% resolution change, which is the right granularity for a knob
	// that has to stay legible in the health line. Note that the ladder never
	// contains a power of two.
	inline constexpr std::uint32_t kSamplePrimes[] = { 61, 67, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163 };

	// True when this pointer is in the sampled subset. `a_prime` must be prime;
	// pass a value from kSamplePrimes so the ladder stays consistent.
	[[nodiscard]] constexpr bool SamplePointer(std::uintptr_t a_ptr, std::uint32_t a_prime) noexcept
	{
		return (Mix64(static_cast<std::uint64_t>(a_ptr)) % a_prime) == 0;
	}

	// Coarser step (fewer records kept). Returns the same value when already at
	// the end of the ladder.
	[[nodiscard]] constexpr std::uint32_t CoarserPrime(std::uint32_t a_prime) noexcept
	{
		for (auto prime : kSamplePrimes) {
			if (prime > a_prime) {
				return prime;
			}
		}
		return kSamplePrimes[sizeof(kSamplePrimes) / sizeof(kSamplePrimes[0]) - 1];
	}

	// Finer step (more records kept), never below the first rung.
	[[nodiscard]] constexpr std::uint32_t FinerPrime(std::uint32_t a_prime) noexcept
	{
		std::uint32_t previous = kSamplePrimes[0];
		for (auto prime : kSamplePrimes) {
			if (prime >= a_prime) {
				return previous;
			}
			previous = prime;
		}
		return previous;
	}
}
