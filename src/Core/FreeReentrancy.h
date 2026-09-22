#pragma once

#include <cstddef>

// Per-thread, allocation-free re-entrancy tracker for the free hooks.
//
// WHY. We hook two layers of the same allocator (RE::MemoryManager::Deallocate
// and Scaleform's GMemoryHeapPT::Free). Under EngineFixes' allocator replacement
// a single logical Scaleform free is observed TWICE: first by hk_SfFree, then -
// inside the call to the original - by hk_Deallocate. The second observation is
// not a second free; counting it produced the v0.3.0 "[double-free]" flood.
// This guard records the pointers currently being freed on this thread;
// re-entering a free hook for a pointer already on that list is a nested
// observation of the same logical free, not a double free.
//
// LOCK-FREE AND ALLOCATION-FREE: one thread_local fixed array, no heap, no
// spinlock. A full stack fails OPEN (the free is processed normally), so the
// guard can never block a free or grow without bound. This mirrors the project's
// rule that a diagnostic must not risk self-deadlock on a lock the faulting
// thread already holds.

namespace hs
{
	class FreeReentrancy
	{
	public:
		static constexpr std::size_t kMaxDepth = 32;

		// Records a_ptr as "being freed on this thread", unless it is already
		// there. Use Nested() to learn which case applied.
		explicit FreeReentrancy(const void* a_ptr) noexcept;
		~FreeReentrancy() noexcept;

		FreeReentrancy(const FreeReentrancy&) = delete;
		FreeReentrancy& operator=(const FreeReentrancy&) = delete;

		// True when a_ptr was already on this thread's free stack: this call is a
		// nested observation of the same logical free and must not be recorded or
		// reported again.
		[[nodiscard]] bool Nested() const noexcept { return _nested; }

		// Tests only: clear this thread's stack.
		static void ResetForTesting() noexcept;

	private:
		bool _nested = false;
		bool _pushed = false;
	};
}