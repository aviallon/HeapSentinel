#pragma once

#include <filesystem>

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
		bool scaleformPoisonEnabled = true;
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
		std::size_t maxReportsPerSecond = 20;  // rate limit so a storm cannot hang the game

		static Config& Get();
		void           Load();
	};
}
