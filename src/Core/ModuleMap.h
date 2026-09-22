#pragma once

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
	// sentinel asks constantly and on hot paths:
	//   * is this pointer inside an image at all?
	//   * is it inside an executable section (i.e. a plausible function)?
	//   * which module+offset is it (for reports)?
	//
	// The module list is taken once at plugin load (SKSE has already loaded
	// every plugin DLL by then) and stored sorted, so lookups are binary
	// searches, not linear scans over hundreds of modules.
	class ModuleMap
	{
	public:
		static ModuleMap& Get();

		void Refresh();

		[[nodiscard]] bool Contains(std::uintptr_t a_addr) const;
		[[nodiscard]] bool IsExecutable(std::uintptr_t a_addr) const;
		[[nodiscard]] const ModuleRange* Find(std::uintptr_t a_addr) const;
		[[nodiscard]] std::string Describe(std::uintptr_t a_addr) const;

		[[nodiscard]] std::size_t Size() const { return _modules.size(); }

	private:
		struct ExecRange
		{
			std::uintptr_t start = 0;
			std::uintptr_t end = 0;
		};

		std::vector<ModuleRange> _modules;  // sorted by base
		std::vector<ExecRange>   _exec;     // sorted by start
	};

	// A pointer is a plausible vtable pointer when it is 8-byte aligned, lies
	// inside a loaded image (normally .rdata) and its first slot is executable.
	// This is the check that catches the TrueHUD crash, where the "vtable" was
	// 0x141A2E20C (misaligned, inside .rdata) and the first slot resolved to
	// 0xFFFFFFFFFFFFFFFF.
	[[nodiscard]] bool IsPlausibleVTable(std::uintptr_t a_vtable);
}
