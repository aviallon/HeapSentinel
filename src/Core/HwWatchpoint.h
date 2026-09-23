#pragma once

// Privileged layer for the hardware watchpoint feature: the Windows
// debug-register API. Kept separate from the manager so the off-game Windows
// test can arm a real watchpoint, write to the watched address, and assert the
// trap without dragging in the plugin's configuration, logging or hook code.
//
// This is the ONE part of the watchpoint feature that cannot be tested on
// Linux: GetThreadContext/SetThreadContext have no equivalent. The bit layout
// it writes is in Core/WatchpointEncoding.h and is checked on both toolchains;
// what is Windows-specific is only the syscall plumbing.

#if !defined(_WIN32)
#	error "Core/HwWatchpoint.h is Windows-only; include it behind #if defined(_WIN32)"
#endif

#if defined(HS_NO_PCH)
#	include <Windows.h>
#endif

#include "Core/WatchpointEncoding.h"

#include <cstddef>
#include <cstdint>

namespace hs::hw
{
	// The debug state of one thread, as Windows exposes it.
	struct ThreadDebugState
	{
		std::uint64_t dr0 = 0;
		std::uint64_t dr1 = 0;
		std::uint64_t dr2 = 0;
		std::uint64_t dr3 = 0;
		std::uint64_t dr6 = 0;
		std::uint64_t dr7 = 0;
	};

	// Arm DR0-DR3 with up to four write watchpoints on the CALLING thread.
	// `a_addresses[i]` may be 0 to leave DRi unused. On success `a_outDr7` is
	// the value written and `a_outState` the full resulting state.
	[[nodiscard]] bool ArmCurrentThread(const std::uintptr_t a_addresses[kWatchpointSlotCount], std::size_t a_count,
		std::uint64_t& a_outDr7, ThreadDebugState* a_outState = nullptr);

	// Clear DR0-DR3, DR6 and DR7 on the calling thread. Returns false only when
	// Get/SetThreadContext itself failed.
	[[nodiscard]] bool DisarmCurrentThread();

	// Read the debug state of the calling thread without modifying it.
	[[nodiscard]] bool ReadCurrentThread(ThreadDebugState& a_out);

	// Arm another thread: SuspendThread -> GetThreadContext ->
	// SetThreadContext -> ResumeThread. Suspension is required for the write to
	// be reliable on a running thread, and it is the reason the arming strategy
	// re-arms on a bounded cadence rather than on every allocation (DESIGN §13).
	[[nodiscard]] bool ArmThread(HANDLE a_thread, const std::uintptr_t a_addresses[kWatchpointSlotCount], std::size_t a_count,
		std::uint64_t& a_outDr7, ThreadDebugState* a_outState = nullptr);

	[[nodiscard]] bool DisarmThread(HANDLE a_thread);

	[[nodiscard]] bool ReadThread(HANDLE a_thread, ThreadDebugState& a_out);

	// Enumerate the tids of this process's threads into `a_out` (bounded by
	// `a_capacity`). `a_skipTid` is excluded (the sweeper's own thread).
	// `a_outTotal` receives the number of threads seen before the bound.
	// Returns the number copied, or 0 on failure. Bounded by construction.
	std::size_t EnumerateProcessThreads(std::uint32_t* a_out, std::size_t a_capacity, std::uint32_t a_skipTid,
		std::size_t* a_outTotal);

	// Shutdown assertion: every thread of this process must have DR7 == 0.
	// Returns true when that holds; `a_outChecked` and `a_outStillArmed` carry
	// the raw numbers so the caller can log them rather than merely assert.
	[[nodiscard]] bool VerifyAllThreadsDisarmed(std::size_t* a_outChecked, std::size_t* a_outStillArmed);
}