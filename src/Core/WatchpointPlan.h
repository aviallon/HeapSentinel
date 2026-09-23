#pragma once

#include "Ipc/Sampling.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

// Selection policy for the hardware watchpoint feature (DESIGN §13).
//
// The hard constraint is the hardware: four DR slots exist, they are per-thread,
// and a block's lifetime is not ours to choose. So the policy cannot watch
// "the Scaleform heap"; it must pick a small, moving subset of blocks and say
// so. This class is the pure part of that decision -- which allocations are
// worth a slot, and a bounded queue of selected-but-not-yet-armed candidates --
// and it is deliberately free of Windows so the sampling, the queue bound and
// the drop counters are exercised off-game on both toolchains.
//
// The sampling rule reuses the project's existing one (src/Ipc/Sampling.h):
//
//   * Mix64 FIRST, because heap pointers are 8/16-byte aligned and a raw
//     `ptr % prime` reaches only a slice of the buckets (see test_sampling.cpp);
//   * a PRIME modulus, never a power of two, so the sample does not lock step
//     with the page size, a struct stride or a size-class rounding.
//
// Coverage is partial by construction: arming 1-in-N of the blocks a site
// allocates and holding four at a time is a detector, not a shadow heap. The
// health line and DESIGN §13 state the fraction.

namespace hs
{
	// How a candidate is judged. The alloc-site filter is the crash-directed
	// mode: the two sites in the observed crashes are a Scaleform allocation
	// site (SkyrimSE.exe+0xDF49F7) and the GMemoryHeapPT free path.
	enum class WatchpointMode : std::uint8_t
	{
		kSampleOnly,       // every allocation is subject to the prime sample
		kFilterPreferred,  // matching alloc sites bypass the sample; others are sampled
		kFilterOnly,       // only matching alloc sites are considered at all
	};

	enum class WatchDecision : std::uint8_t
	{
		kSelected,     // enqueued for a DR slot
		kFilteredOut,  // alloc-site filter rejected it
		kNotSampled,   // prime sample rejected it
		kDuplicate,    // this pointer is already queued
	};

	// Hard bound on the pending queue. It is an overwrite-oldest ring: the
	// consumer is the watchpoint sweeper, and losing the OLDEST unarmed
	// candidate is the honest failure mode for a sampling diagnostic. Each loss
	// is counted (`queueEvictions`) so a lossy run is legible.
	inline constexpr std::size_t kWatchpointMaxPending = 64;

	struct WatchpointPlanStats
	{
		std::uint64_t considered = 0;
		std::uint64_t selected = 0;
		std::uint64_t filteredOut = 0;
		std::uint64_t notSampled = 0;
		std::uint64_t duplicates = 0;
		std::uint64_t queueEvictions = 0;
		std::uint64_t popped = 0;
	};

	// True when a pointer is in the sampled subset. `a_prime` must be prime;
	// pass a value from hs::kSamplePrimes so the ladder stays consistent.
	[[nodiscard]] constexpr bool ShouldWatchSample(std::uintptr_t a_ptr, std::uint32_t a_prime) noexcept
	{
		return a_prime != 0 && (Mix64(static_cast<std::uint64_t>(a_ptr)) % a_prime) == 0;
	}

	class WatchpointPlan
	{
	public:
		void Configure(WatchpointMode a_mode, std::uint32_t a_samplePrime, std::size_t a_maxPending) noexcept;

		// Judge one allocation. `a_allocSiteMatch` is computed by the caller,
		// which owns the module+RVA filter table. The decision is returned; on
		// kSelected the pointer is in the queue.
		WatchDecision Consider(std::uintptr_t a_ptr, bool a_allocSiteMatch) noexcept;

		// Single-consumer pop of the oldest unarmed candidate. Returns false
		// when the queue is empty. Lock-free; multiple producer threads are safe.
		bool PopCandidate(std::uintptr_t& a_out) noexcept;

		[[nodiscard]] std::size_t PendingCount() const noexcept;

		[[nodiscard]] WatchpointPlanStats Stats() const noexcept;
		[[nodiscard]] std::uint32_t       SamplePrime() const noexcept { return _prime; }
		[[nodiscard]] WatchpointMode      Mode() const noexcept { return _mode; }

		// Off-game tests reconfigure a single process-wide instance between
		// cases; this drops queued candidates and resets every counter.
		void ResetForTesting() noexcept;

	private:
		struct Candidate
		{
			std::atomic<std::uint64_t> seq{ 0 };
			std::atomic<std::uintptr_t> ptr{ 0 };
		};

		[[nodiscard]] bool AlreadyQueued(std::uintptr_t a_ptr, std::uint64_t a_written) const noexcept;

		WatchpointMode _mode = WatchpointMode::kSampleOnly;
		std::uint32_t  _prime = kDefaultSamplePrime;

		std::unique_ptr<Candidate[]> _pending;
		std::size_t                  _capacity = 0;
		std::atomic<std::uint64_t>   _writeCursor{ 0 };  // 1-based added count
		std::atomic<std::uint64_t>   _readCursor{ 0 };   // 1-based consumed count

		std::atomic<std::uint64_t> _considered{ 0 };
		std::atomic<std::uint64_t> _selected{ 0 };
		std::atomic<std::uint64_t> _filteredOut{ 0 };
		std::atomic<std::uint64_t> _notSampled{ 0 };
		std::atomic<std::uint64_t> _duplicates{ 0 };
		std::atomic<std::uint64_t> _queueEvictions{ 0 };
		std::atomic<std::uint64_t> _popped{ 0 };
	};
}