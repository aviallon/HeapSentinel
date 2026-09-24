#pragma once

#include "Core/WatchpointPlan.h"
#include "Core/WatchpointReports.h"
#include "Core/WatchpointSlots.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

// Hardware data watchpoints: the missing half of HeapSentinel.
//
// The sentinel can already say that an object WAS corrupted. This says WHO
// wrote it, by arming DR0-DR3 write watchpoints on the first 8 bytes (the
// vtable pointer) of a small, moving sample of Scaleform blocks and reporting
// the writer's RIP at the #DB trap.
//
// The constraints are hardware, not policy:
//   * four DR slots, each 8 bytes, PER THREAD. A write by another thread is
//     only caught if that thread's DRs are armed, so every thread is armed and
//     newly created threads are picked up by the sweep.
//   * a per-thread context write (SuspendThread + SetThreadContext) is a real
//     perturbation, so arming happens on a bounded cadence, not per allocation.
//   * the trap path runs in the VEH: no allocation, no locks, no std::string,
//     no spdlog. It copies a POD into a preallocated slot; a watchdog drains.
//
// Opt-in and default OFF. Even when enabled it does not arm until a trigger
// (one report by default), so ordinary play is untouched.
//
// Coverage is partial by construction: see DESIGN §13. This is a detector for a
// sampled subset, not a shadow heap.

namespace hs
{
	struct WatchpointStats
	{
		bool          initialized = false;
		bool          active = false;
		bool          armed = false;
		std::size_t   occupied = 0;
		std::size_t   trackedThreads = 0;
		std::size_t   lastCheckedThreads = 0;
		std::size_t   lastArmedThreads = 0;
		std::uint64_t claims = 0;
		std::uint64_t claimDrops = 0;
		std::uint64_t releases = 0;
		std::uint64_t rotations = 0;
		std::uint64_t trips = 0;
		std::uint64_t reportsRecorded = 0;
		std::uint64_t reportsDropped = 0;
		std::uint64_t reportsDrained = 0;
		std::uint64_t unattributedTraps = 0;
		std::uint64_t postFreeLinksSuppressed = 0;
		std::uint64_t reallocInProgressSuppressed = 0;
		// 0.6.4 FIX A: of the unattributed traps, how many were recorded with a
		// debug-register read that FAILED (the fields are not a measurement) versus
		// one that succeeded and genuinely returned no debug register at all.
		std::uint64_t unattributedDrReadFailed = 0;
		std::uint64_t unattributedDrReadZero = 0;
		std::uint64_t freePredatesArmReports = 0;
		std::uint64_t considerCount = 0;
		std::uint64_t selectedCount = 0;
		std::uint64_t queueEvictions = 0;
		std::uint64_t unwatchable = 0;
		std::uint64_t threadTableOverflow = 0;
	};

	class Watchpoints
	{
	public:
		static Watchpoints& Get();

		// Load-time initialisation. Allocates nothing on the hot path; starts
		// the sweeper only when the feature is enabled. Does NOT arm unless
		// bArmAfterTrigger=0.
		void Init();
		[[nodiscard]] bool Initialized() const noexcept { return _initialized.load(std::memory_order_acquire); }
		[[nodiscard]] bool Active() const noexcept { return _active.load(std::memory_order_acquire); }
		// 0.6.3 structural state: true once this process has ever written a DR.
		// While false, nothing can have been masked and a #DB is passed on; once
		// true, every #DB is consumed (MustConsumeDebugException).
		[[nodiscard]] bool EverProgrammedAnyDr() const noexcept { return _everProgrammedAnyDr.load(std::memory_order_acquire); }

		// Hot path. `a_site` is the Scaleform allocation return address. The
		// first thing each does is one relaxed load of `_active`, so a disabled
		// run pays a load and a predictable branch - not a lock, not an
		// allocation.
		void OnScaleformAlloc(void* a_ptr, std::size_t a_size, void* a_site) noexcept;
		void OnScaleformFree(void* a_ptr) noexcept;

		// Called from Report(): cheap trigger. Sets the arm request when the
		// configured number of report events has been seen.
		void NotifyReportEvent() noexcept;

		// VEH entry point. Returns EXCEPTION_CONTINUE_EXECUTION when it handled
		// one of OUR watchpoints, and EXCEPTION_CONTINUE_SEARCH otherwise, so a
		// trap-flag single step or a foreign #DB is never swallowed.
		[[nodiscard]] long HandleDebugException(void* a_exceptionPointers) noexcept;

		// Stop the sweeper, disarm every thread, and assert DR7 is zero
		// everywhere. Safe to call twice.
		void Shutdown();

		[[nodiscard]] WatchpointStats Stats() const noexcept;

		// Test/diagnostic hooks (used by tests and by the startup summary).
		[[nodiscard]] std::size_t       ResolvedAllocSiteCount() const noexcept { return _filterCount; }
		[[nodiscard]] const WatchpointPlan& Plan() const noexcept { return _plan; }

	private:
		Watchpoints() = default;

		static constexpr std::size_t kMaxTrackedThreads = 256;

		// What we last wrote into one DR slot on one thread. The trap path runs on
		// the faulting thread and reads this without a lock; the sweeper is the
		// only writer. It is the "we ever armed this here" record FIX 1 needed: a
		// DR slot that still holds an address the table has since moved on from is
		// OURS (a stale arm), not a foreign breakpoint, and must be consumed.
		struct ThreadArm
		{
			std::atomic<std::uintptr_t> address{ 0 };
			std::atomic<std::uintptr_t> valueAtArm{ 0 };
			std::atomic<std::uintptr_t> allocSite{ 0 };
			std::atomic<std::uint64_t>  armedAt{ 0 };
			std::atomic<std::uint64_t>  allocInstance{ 0 };  // 0.6.5: allocation instance armed here
			std::atomic<std::uint32_t>  generation{ 0 };
			std::atomic<bool>           armedWasCode{ false };
		};

		struct ThreadEntry
		{
			std::atomic<std::uint32_t> tid{ 0 };
			std::atomic<std::uint32_t> generation{ 0 };
			std::atomic<std::uint64_t> armedAt{ 0 };
			// Bit i is set once we have ever written a nonzero watch into DRi on
			// this thread. Cleared only when the entry is reassigned to a new tid.
			std::atomic<std::uint32_t> everArmedMask{ 0 };
			ThreadArm                  arms[kWatchpointSlotCount];
		};

		void SweeperLoop() noexcept;
		void SweepOnce() noexcept;
		void ArmRequested() noexcept;
		void PromoteCandidates(std::uint64_t a_now) noexcept;
		void RotateHeld(std::uint64_t a_now) noexcept;
		void SweepThreads(std::uint64_t a_now, bool a_force) noexcept;
		void DrainReports() noexcept;
		// 0.6.5 (CHANGE 1+2): resolve the free EVIDENCE the classifier must use.
		// ALWAYS consults ScaleformFreeRing and prefers its newest record for the
		// address over the slot snapshot's Release tick (the 0.6.3 shadowing bug),
		// and returns the allocation INSTANCE paired with the tick that won -- the
		// ring never invalidates a record on recycling, so a tick alone cannot say
		// whether the free belongs to this allocation. Lock-free (Bloom + seqlock),
		// so the trap path may call it; `a_outInstance` and `a_outSource` receive the
		// instance and FreeTickSource that won, for the record and the log.
		[[nodiscard]] static std::uint64_t ResolveFreeEvidence(std::uint64_t a_slotFreeTick,
			std::uint64_t a_slotFreeInstance, std::uintptr_t a_address, std::uint64_t* a_outInstance,
			std::uint32_t* a_outSource) noexcept;
		[[nodiscard]] bool AllocSiteMatches(std::uintptr_t a_site) const noexcept;
		[[nodiscard]] bool ResolveAllocSiteFilter();
		[[nodiscard]] ThreadEntry* FindThread(std::uint32_t a_tid) noexcept;
		// Release a logical watch and ask the next sweep to clear it on EVERY
		// thread, not just the trapping one (FIX 2). No OS call, no lock, no spin:
		// the sweeper owns the suspend/set-context work and does it once per sweep.
		void RequestDisarm() noexcept
		{
			BumpGeneration();
			_forceRearm.store(true, std::memory_order_release);
		}
		void                       BumpGeneration() noexcept { _generation.fetch_add(1, std::memory_order_relaxed); }

		WatchpointPlan      _plan;
		std::atomic<bool>   _initialized{ false };
		std::atomic<bool>   _active{ false };
		// Monotonic: set before the first SetThreadContext that programs a DR, and
		// never cleared. This is the structural survival rule (0.6.3).
		std::atomic<bool>   _everProgrammedAnyDr{ false };
		std::atomic<bool>   _armRequested{ false };
		std::atomic<bool>   _stop{ false };
		std::atomic<bool>   _dirty{ false };
		std::atomic<std::uint64_t> _reportEvents{ 0 };
		std::atomic<std::uint32_t> _generation{ 1 };
		std::atomic<std::uint64_t> _lastRearmTick{ 0 };
		std::atomic<bool>          _forceRearm{ false };
		std::atomic<std::uint64_t> _unwatchable{ 0 };
		std::atomic<std::uint64_t> _threadTableOverflow{ 0 };
		std::atomic<std::uint64_t> _drained{ 0 };
		std::atomic<std::uint64_t> _unattributed{ 0 };
		// NOTE: the suppression and debug-register-measurement counters live in
		// WatchpointReports (0.6.4), not here: the periodic stats line is compiled by
		// the off-game suite too, which does not link this Windows-only unit.
		// See WatchpointReports::NoteUnattributedMeasured.

		// Configuration snapshot, taken once at Init.
		std::size_t   _sweepMs = 250;
		std::size_t   _rearmMs = 500;
		std::size_t   _holdMs = 30000;
		std::size_t   _maxThreads = 256;
		std::size_t   _armAfterReports = 1;
		bool          _armAfterTrigger = true;
		std::size_t   _reportCapacity = 256;
		// How long after an arm we keep a retired (stale) trap legible as a report.
		// Consumption of a stale trap is unconditional (safety); this only bounds
		// how long we keep emitting a report for it.
		std::uint64_t _staleGraceMs = 30000;

		// Alloc-site filter, resolved to absolute addresses at Init. Bounded.
		static constexpr std::size_t kMaxAllocSiteFilters = 8;
		std::uintptr_t               _filter[kMaxAllocSiteFilters]{};
		std::size_t                  _filterCount = 0;

		ThreadEntry  _threads[kMaxTrackedThreads];
		std::atomic<std::uint32_t> _trackedCount{ 0 };  // written only by the sweeper

		std::size_t  _lastCheckedThreads = 0;
		std::size_t  _lastArmedThreads = 0;

		std::thread  _sweeper;
	};
}