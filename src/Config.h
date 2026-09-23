#pragma once

#include "Ipc/Sampling.h"

#include <filesystem>
#include <string>

namespace hs
{
	// Directory containing HeapSentinel.dll (Data/SKSE/Plugins), resolved from
	// the module handle rather than from the current working directory.
	[[nodiscard]] const std::filesystem::path& PluginDir();

	// Configuration, read once from <PluginDir>/HeapSentinel.ini.
	struct Config
	{
		// Master switch. When false the plugin installs nothing at all.
		bool enabled = true;

		// [Hooks] Verify every hook target against the committed table for this
		// exact game build (identity, Address Library id, vtable slot, prologue
		// hash) before installing it. On a mismatch the hook is REFUSED and the
		// sentinel reports DEGRADED instead of patching an address it cannot name.
		// Turning this off is an escape hatch, not a supported mode: it leaves the
		// sentinel DEGRADED and says so in the log.
		bool verifyTargets = true;

		// [Ledger] - shadow allocation ledger (pointer -> metadata).
		bool        ledgerEnabled = true;
		// One entry per live allocation. Skyrim has well over a million live
		// engine allocations, so the default is 4 M; the table is bounded by a
		// probe window and evicts the oldest freed entry when it is full.
		std::size_t ledgerCapacity = 1u << 22;  // entries (power of two)
		std::size_t ledgerShards = 64;
		std::size_t ledgerStackDepth = 12;      // frames recorded per event (0 = off)

		// [GuardPool] - GWP-ASan-style sampled allocations with guard pages.
		// Off by default: sampled blocks are served from our own region, which
		// the engine has never seen before, so it is an opt-in diagnostic mode.
		bool          guardPoolEnabled = false;
		std::uint32_t guardPoolSampleRate = 2000;  // 1 in N allocations
		std::size_t   guardPoolSlots = 64;
		std::size_t   guardPoolMaxSize = 3072;     // larger requests pass through
		bool          guardPoolFixUp = true;       // unprotect + continue on fault

		// [ScaleformHeap] - Scaleform/GFx allocations (GMemoryHeapPT). These do
		// NOT come from RE::MemoryManager, which is why the engine hooks are
		// blind to the GFxResource lifetime crashes. Tier A only (ledger); the
		// guard pool is deliberately not extended to this heap (see DESIGN).
		bool scaleformHeapEnabled = true;
		// Capture call stacks for Scaleform alloc/free events. The free stack is
		// what names the culprit, so this defaults on; turn it off to trade
		// attribution detail for lower hot-path cost.
		bool scaleformCaptureStacks = true;
		// Poison-on-free: on GMemoryHeapPT::Free, overwrite the block's first
		// qword with a recognisable poison address and delay the real free briefly,
		// so a later virtual call through the dead object faults deterministically
		// at an address that maps back to the ledger record. Bounded and fail-open;
		// this is the deterministic FAST PATH for recent frees, while the free ring
		// below is the general-purpose attribution for older ones.
		//
		// DEFAULT OFF (0.5.0). This is the one setting that WITHHOLDS the real free
		// and writes into freed memory, i.e. it changes the allocator's behaviour.
		// It is the plugin's strongest deterministic-attribution mode, but it is
		// opt-in: a diagnostic must not alter the thing it observes unless the
		// operator explicitly asks. See DESIGN.md.
		bool scaleformPoisonEnabled = false;
		// Maximum blocks (power of two rounded up) held poisoned at once. This is
		// address space only; a block is retained in real memory until drained.
		std::size_t scaleformPoisonMaxBlocks = 1u << 16;  // 65536
		// Maximum retained bytes of poisoned blocks. 64 MiB is the default budget;
		// the oldest is really freed when it is reached.
		std::size_t scaleformPoisonMaxBytes = 64u << 20;

		// Durable Scaleform free records. Separate from the main ledger so the
		// main table keeps flowing; evict-oldest when full, with the eviction count
		// and retention window reported so a lossy run is legible.
		std::size_t scaleformFreeCapacity = 1u << 20;  // 1M records (~64 MiB)

		// [WeakLib] GFxResourceWeakLib context hooks (PinResource 82796,
		// RemoveResourceOnRelease 82798, UnpinResource 82802, GFxResource::AddRef
		// 82783). Low frequency (menu load/close), essentially free.
		bool        weakLibHooksEnabled = true;
		std::size_t weakLibEventCapacity = 1u << 14;  // 16384 events

		// [Watchpoints] - x86-64 hardware data watchpoints (DR0-DR3).
		//
		// This is the only feature that says WHO wrote a corrupted block rather
		// than merely that it is corrupt: a write watchpoint on the first 8 bytes
		// of a sampled Scaleform block traps at the writer's instruction and
		// reports its RIP as module+RVA.
		//
		// DEFAULT OFF (bEnabled=0). Four DR slots exist and they are per-thread, so
		// the coverage is partial by construction and the arming cost (briefly
		// suspending every thread to write its context) is real. Even when it is
		// on, it does not arm until a trigger fires (bArmAfterTrigger). A diagnostic
		// must not alter what it observes; see DESIGN.md section 13.
		bool watchpointsEnabled = false;
		// Arm only after `uArmAfterReports` report events, so ordinary play with a
		// healthy install pays nothing at all. 0 arms at load.
		bool        watchpointsArmAfterTrigger = true;
		std::size_t watchpointsArmAfterReports = 1;
		// Sweeper cadence: how often the pending candidates, the hold timeout and
		// thread enumeration are serviced. Bounds the latency of arming a new
		// thread and of draining a trap into the log.
		std::size_t watchpointsSweepMs = 250;
		// Budget for re-writing every thread's context after the watched set
		// changes. Suspending threads is the expensive part, so this is a floor on
		// the re-arm period, not a per-event action.
		std::size_t watchpointsRearmMs = 500;
		// A watched block is given up after this long even if it is never freed,
		// so four immortal allocations cannot occupy the sample forever. 0 keeps
		// a block until it is freed.
		std::size_t watchpointsHoldMs = 30000;
		std::size_t watchpointsMaxThreads = 256;
		// Sampling modulus over Mix64(ptr). Must be a PRIME from
		// hs::kSamplePrimes; a non-prime is refused and the default used (a power
		// of two would lock step with the page size and the size classes).
		std::uint32_t watchpointsSamplePrime = kDefaultSamplePrime;  // 61
		// Alloc-site filter, hex RVAs relative to SkyrimSE.exe (the observed crash
		// allocation site is 0xDF49F7). Comma/space separated. Empty disables it.
		std::string watchpointsAllocSiteRvas;
		// 0: matching sites bypass the sample but other blocks are still sampled
		//    (filter-preferred). 1: ONLY matching sites are considered.
		bool        watchpointsAllocSiteOnly = false;
		std::size_t watchpointsMaxPending = 16;   // selected-but-not-yet-armed queue (bounded)
		std::size_t watchpointsReportCapacity = 256;  // preallocated trap report slots

		// [RefCountGuard] - validate the vtable before a refcounted destructor
		// is dispatched from GRefCountImpl::Release.
		bool refCountGuardEnabled = true;
		// false: log and let the engine do what it was going to do (it will
		//        probably crash, but nothing is hidden).
		// true:  skip the dispatch entirely, turning the crash into a leak.
		bool refCountGuardFailSafe = false;

		// [Reporting]
		bool        reportScreenshot = false;  // save a BMP next to the report
		bool        reportFreeze = false;      // modal dialog instead of continuing
		bool        vehEnabled = true;         // catch and classify any AV
		// Print the freeing/allocating site as module+0xOFFSET and hint that a
		// shipped PDB resolves it to a function. Always useful; no cost.
		bool        reportSymbolHint = true;
		// An untracked free is not necessarily invalid: allocations made before
		// the hooks were installed are untracked too. Off by default.
		bool        reportUntrackedFree = false;
		// When true, a suspected double free is REPORTED and then the original free
		// is NOT called, so the suspected second free never reaches the allocator
		// (it leaks). This changes allocator behaviour, so a false positive becomes
		// a leak; therefore the DEFAULT is false and the original is always called.
		// The report is the product, not the prevention.
		bool        preventDoubleFree = false;
		std::size_t maxReportsPerSecond = 20;  // rate limit so a storm cannot hang the game

		static Config& Get();
		void           Load();

		// One-line summary for the startup log and the reports-log session header.
		// It names the settings that change allocator behaviour so a reader of a
		// run can see that it was not a semantics-preserving configuration.
		[[nodiscard]] std::string Summary() const;
	};
}
