#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace hs
{
	// A lock-free bloom pre-filter. Its ONLY authoritative answer is "definitely
	// not present": a set bit may be a false positive, but a clear bit means the
	// key was never added (for a non-aging filter, or not within the retained
	// window for an aging one). It is therefore safe to use as a fast path on the
	// read side - a MISS maps to "unknown / not tracked", never to a verdict -
	// while the exact answer still comes from the store behind it.
	//
	// It is deliberately NOT used on the alloc/dealloc write path: there the
	// common case is a HIT, which a bloom filter cannot confirm, so it would be
	// pure added cost.
	//
	// READ-ONLY use (the VEH) touches only relaxed atomic loads: no lock, no
	// seqlock, no allocation. Add() is a relaxed fetch_or. Aging (optional) is a
	// two-half filter: Add() sets bits in the active half; when it fills past the
	// threshold the OTHER half is cleared and the halves swap, so the filter
	// covers a bounded recent window and never grows.
	class BloomFilter
	{
	public:
		bool Init(std::size_t a_expectedElements, std::uint32_t a_bitsPerElement, bool a_aging = false);
		void Shutdown();

		[[nodiscard]] bool Ready() const { return _ready.load(std::memory_order_acquire); }

		void Add(std::uintptr_t a_key) noexcept;

		// Lock-free. Returns true when the key MIGHT have been added. When the
		// filter is not ready it returns true unconditionally (fail-open: never
		// suppress a lookup because the filter is unavailable).
		[[nodiscard]] bool MightContain(std::uintptr_t a_key) const noexcept;

		// Clear the older half and make the other active. Exposed so the aging
		// policy is testable; Add() calls it automatically when a_aging is set.
		void ForceAge() noexcept;

		[[nodiscard]] std::size_t Bytes() const { return _totalWords * sizeof(std::uint64_t); }
		[[nodiscard]] std::uint64_t Swaps() const { return _swaps.load(std::memory_order_relaxed); }

	private:
		static constexpr std::uint32_t kHashes = 7;

		void SetIn(std::uint32_t a_half, std::uintptr_t a_key) noexcept;
		[[nodiscard]] bool TestIn(std::uint32_t a_half, std::uintptr_t a_key) const noexcept;
		[[nodiscard]] std::size_t BitsPerHalf() const noexcept { return _wordsPerHalf * 64u; }

		std::unique_ptr<std::atomic<std::uint64_t>[]> _bits[2];
		std::size_t                _wordsPerHalf = 0;
		std::size_t                _totalWords = 0;
		std::uint32_t              _active = 0;
		std::uint32_t              _halfCount = 1;
		bool                       _aging = false;
		std::size_t                _ageAt = 0;
		std::atomic<std::uint64_t> _addsInActive{ 0 };
		std::atomic<std::uint64_t> _swaps{ 0 };
		std::atomic<bool>          _ready{ false };
	};
}