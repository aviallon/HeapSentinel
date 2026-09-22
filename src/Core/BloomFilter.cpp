#if defined(HS_NO_PCH)
#	include "Core/BloomFilter.h"

#	include <algorithm>
#	include <atomic>
#else
#	include "PCH.h"

#	include "Core/BloomFilter.h"
#endif

namespace hs
{
	namespace
	{
		[[nodiscard]] constexpr std::uint64_t Mix(std::uint64_t a_value)
		{
			a_value ^= a_value >> 30;
			a_value *= 0xBF58476D1CE4E5B9ull;
			a_value ^= a_value >> 27;
			a_value *= 0x94D049BB133111EBull;
			a_value ^= a_value >> 31;
			return a_value;
		}
	}

	bool BloomFilter::Init(std::size_t a_expectedElements, std::uint32_t a_bitsPerElement, bool a_aging)
	{
		if (_ready.load(std::memory_order_acquire)) {
			return true;
		}
		if (a_expectedElements == 0) {
			a_expectedElements = 1;
		}
		if (a_bitsPerElement == 0) {
			a_bitsPerElement = 10;
		}

		const auto totalBits = a_expectedElements * static_cast<std::size_t>(a_bitsPerElement);
		std::size_t totalWords = (totalBits + 63u) / 64u;
		if (totalWords == 0) {
			totalWords = 1;
		}

		_aging = a_aging;
		_halfCount = a_aging ? 2u : 1u;
		_wordsPerHalf = a_aging ? ((totalWords + 1u) / 2u) : totalWords;
		if (_wordsPerHalf == 0) {
			_wordsPerHalf = 1;
		}
		_totalWords = _wordsPerHalf * _halfCount;
		_ageAt = std::max<std::size_t>(a_expectedElements, 1);

		for (std::uint32_t i = 0; i < _halfCount; ++i) {
			_bits[i] = std::make_unique<std::atomic<std::uint64_t>[]>(_wordsPerHalf);
			for (std::size_t w = 0; w < _wordsPerHalf; ++w) {
				_bits[i][w].store(0, std::memory_order_relaxed);
			}
		}

		_active = 0;
		_addsInActive.store(0, std::memory_order_relaxed);
		_swaps.store(0, std::memory_order_relaxed);
		_ready.store(true, std::memory_order_release);
#if !defined(HS_NO_PCH)
		logger::info("bloom filter: {} words x 64 bits, ~{} bits/element, {} halves, {} KiB",
			_totalWords, a_bitsPerElement, _halfCount, (_totalWords * 8) / 1024);
#endif
		return true;
	}

	void BloomFilter::Shutdown()
	{
		_ready.store(false, std::memory_order_release);
		_bits[0].reset();
		_bits[1].reset();
		_wordsPerHalf = 0;
		_totalWords = 0;
		_halfCount = 1;
		_aging = false;
	}

	void BloomFilter::SetIn(std::uint32_t a_half, std::uintptr_t a_key) noexcept
	{
		const auto bits = BitsPerHalf();
		if (bits == 0 || !_bits[a_half]) {
			return;
		}
		const std::uint64_t h1 = Mix(static_cast<std::uint64_t>(a_key));
		const std::uint64_t h2 = Mix(static_cast<std::uint64_t>(a_key) ^ 0x9E3779B97F4A7C15ull) | 1ull;

		for (std::uint32_t i = 0; i < kHashes; ++i) {
			const auto bit = (h1 + static_cast<std::uint64_t>(i) * h2) % bits;
			auto&      word = _bits[a_half][bit / 64u];
			const auto mask = 1ull << (bit % 64u);
			word.fetch_or(mask, std::memory_order_relaxed);
		}
	}

	bool BloomFilter::TestIn(std::uint32_t a_half, std::uintptr_t a_key) const noexcept
	{
		const auto bits = BitsPerHalf();
		if (bits == 0 || !_bits[a_half]) {
			return true;  // no filter: never report a false negative
		}
		const std::uint64_t h1 = Mix(static_cast<std::uint64_t>(a_key));
		const std::uint64_t h2 = Mix(static_cast<std::uint64_t>(a_key) ^ 0x9E3779B97F4A7C15ull) | 1ull;

		for (std::uint32_t i = 0; i < kHashes; ++i) {
			const auto bit = (h1 + static_cast<std::uint64_t>(i) * h2) % bits;
			const auto mask = 1ull << (bit % 64u);
			if ((_bits[a_half][bit / 64u].load(std::memory_order_relaxed) & mask) == 0) {
				return false;
			}
		}
		return true;
	}

	void BloomFilter::Add(std::uintptr_t a_key) noexcept
	{
		if (!_ready.load(std::memory_order_relaxed)) {
			return;
		}
		SetIn(_active, a_key);

		if (_aging) {
			if ((_addsInActive.fetch_add(1, std::memory_order_relaxed) + 1) >= _ageAt) {
				ForceAge();
			}
		}
	}

	bool BloomFilter::MightContain(std::uintptr_t a_key) const noexcept
	{
		if (!_ready.load(std::memory_order_acquire)) {
			return true;  // fail-open
		}
		// The two halves are a UNION: the key is present if EITHER half has all
		// its bits. A key added before the last swap is still covered by the
		// inactive half until that half is cleared.
		if (TestIn(0, a_key)) {
			return true;
		}
		if (_halfCount > 1 && TestIn(1, a_key)) {
			return true;
		}
		return false;
	}

	void BloomFilter::ForceAge() noexcept
	{
		if (!_ready.load(std::memory_order_relaxed) || !_aging) {
			return;
		}
		const std::uint32_t next = _active ^ 1u;
		auto&               stale = _bits[next];
		if (stale) {
			for (std::size_t w = 0; w < _wordsPerHalf; ++w) {
				stale[w].store(0, std::memory_order_relaxed);
			}
		}
		_active = next;
		_addsInActive.store(0, std::memory_order_relaxed);
		_swaps.fetch_add(1, std::memory_order_relaxed);
	}
}