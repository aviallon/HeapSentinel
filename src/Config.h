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
		// An untracked free is not necessarily invalid: allocations made before
		// the hooks were installed are untracked too. Off by default.
		bool        reportUntrackedFree = false;
		std::size_t maxReportsPerSecond = 20;  // rate limit so a storm cannot hang the game

		static Config& Get();
		void           Load();
	};
}
