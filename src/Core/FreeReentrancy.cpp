#include "Core/FreeReentrancy.h"

namespace hs
{
	namespace
	{
		// One fixed, allocation-free stack per thread. The plugin is a DLL and the
		// tests are an executable; thread_local storage is fine in both.
		thread_local const void* t_freeStack[FreeReentrancy::kMaxDepth]{};
		thread_local std::size_t t_freeDepth = 0;
	}

	FreeReentrancy::FreeReentrancy(const void* a_ptr) noexcept
	{
		for (std::size_t i = 0; i < t_freeDepth; ++i) {
			if (t_freeStack[i] == a_ptr) {
				_nested = true;
				return;
			}
		}

		if (t_freeDepth < kMaxDepth) {
			t_freeStack[t_freeDepth++] = a_ptr;
			_pushed = true;
		}
		// else: full stack, fail open. The free proceeds normally and is not
		// treated as nested; the guard never grows and never blocks.
	}

	FreeReentrancy::~FreeReentrancy() noexcept
	{
		if (_pushed && t_freeDepth > 0) {
			--t_freeDepth;
		}
	}

	void FreeReentrancy::ResetForTesting() noexcept
	{
		t_freeDepth = 0;
	}
}