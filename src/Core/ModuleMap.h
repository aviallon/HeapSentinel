#pragma once

#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace hs
{
	struct ModuleRange
	{
		std::uintptr_t base = 0;
		std::size_t    size = 0;
		std::string    name;
	};

	// Snapshot of the loaded modules, used to answer the questions a memory
	// sentinel asks on the refcount-guard path:
	//   * is this pointer inside an image at all?
	//   * is it inside an executable section (i.e. a plausible function)?
	//   * which module+offset is it (for reports)?
	//
	// The list is taken at plugin load and refreshed on the SKSE kPostLoad /
	// kDataLoaded messages. Readers take a shared lock and get a *copy* of a
	// range (never an interior pointer), so a refresh on another thread cannot
	// invalidate what a reader is looking at.
	class ModuleMap
	{
	public:
		static ModuleMap& Get();

		void Refresh();

		// The list is only complete once every SKSE plugin has been loaded.
		// HeapSentinel loads early (SKSE loads plugins alphabetically), so a
		// snapshot from SKSEPlugin_Load is missing plugins that load after it
		// and every vtable inside one of those looks unmapped.
		void               SetComplete() { _complete = true; }
		[[nodiscard]] bool IsComplete() const { return _complete; }

		[[nodiscard]] bool Find(std::uintptr_t a_addr, ModuleRange& a_out) const;
		[[nodiscard]] bool Contains(std::uintptr_t a_addr) const;
		[[nodiscard]] bool IsExecutable(std::uintptr_t a_addr) const;
		[[nodiscard]] std::string Describe(std::uintptr_t a_addr) const;
		[[nodiscard]] std::size_t Size() const;

	private:
		struct ExecRange
		{
			std::uintptr_t start = 0;
			std::uintptr_t end = 0;
		};

		mutable std::shared_mutex _mutex;
		std::vector<ModuleRange>  _modules;  // sorted by base
		std::vector<ExecRange>    _exec;     // sorted by start
		bool                      _complete = false;
	};

	// A pointer is a plausible vtable pointer when it is 8-byte aligned, lies
	// inside a loaded image (normally .rdata) and its first slot is executable.
	// This is the check that catches the TrueHUD crash, where the "vtable" was
	// 0x141A2E20C (misaligned, inside .rdata) and the first slot resolved to
	// 0xFFFFFFFFFFFFFFFF.
	[[nodiscard]] bool IsPlausibleVTable(std::uintptr_t a_vtable);
}
