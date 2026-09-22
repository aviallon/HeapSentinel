#include "PCH.h"

#include "Core/ModuleMap.h"

#include <algorithm>
#include <cstdio>

namespace hs
{
	ModuleMap& ModuleMap::Get()
	{
		static ModuleMap map;
		return map;
	}

	void ModuleMap::Refresh()
	{
		std::vector<ModuleRange> modules;
		std::vector<ExecRange>   exec;

		const auto snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ::GetCurrentProcessId());
		if (snapshot == INVALID_HANDLE_VALUE) {
			logger::error("CreateToolhelp32Snapshot failed ({})", ::GetLastError());
			return;
		}

		MODULEENTRY32 entry{};
		entry.dwSize = sizeof(entry);

		if (::Module32First(snapshot, &entry)) {
			do {
				ModuleRange range;
				range.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
				range.name = std::string(entry.szModule);
				range.size = entry.modBaseSize;

				const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(entry.modBaseAddr);
				if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
					const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const std::byte*>(dos) + dos->e_lfanew);
					if (nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.SizeOfImage != 0) {
						range.size = nt->OptionalHeader.SizeOfImage;
						const auto* section = IMAGE_FIRST_SECTION(nt);
						for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
							if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || section->Misc.VirtualSize == 0) {
								continue;
							}
							exec.push_back(ExecRange{
								range.base + section->VirtualAddress,
								range.base + section->VirtualAddress + section->Misc.VirtualSize });
						}
					}
				}

				modules.push_back(std::move(range));
			} while (::Module32Next(snapshot, &entry));
		}

		::CloseHandle(snapshot);

		std::sort(modules.begin(), modules.end(), [](const ModuleRange& a, const ModuleRange& b) { return a.base < b.base; });
		std::sort(exec.begin(), exec.end(), [](const ExecRange& a, const ExecRange& b) { return a.start < b.start; });

		// Diagnostics. A zero-size or overlapping range breaks the binary search
		// and would make valid vtables look unmapped, so report it loudly.
		std::size_t zeroSize = 0;
		std::size_t overlaps = 0;
		std::size_t failures = 0;
		{
			const auto lookup = [&modules](std::uintptr_t a_addr) -> const ModuleRange* {
				const auto it = std::upper_bound(modules.begin(), modules.end(), a_addr,
					[](std::uintptr_t a_value, const ModuleRange& a_range) { return a_value < a_range.base; });
				if (it == modules.begin()) {
					return nullptr;
				}
				const auto& candidate = *(it - 1);
				return a_addr < candidate.base + candidate.size ? &candidate : nullptr;
			};

			for (std::size_t i = 0; i < modules.size(); ++i) {
				if (modules[i].size == 0) {
					++zeroSize;
					continue;
				}
				if (i != 0 && modules[i].base < modules[i - 1].base + modules[i - 1].size) {
					++overlaps;
				}
				// Tolerant of duplicate entries: what matters is that a lookup at
				// the module's first and last byte lands on the same base.
				const auto* first = lookup(modules[i].base);
				const auto* last = lookup(modules[i].base + modules[i].size - 1);
				if (!first || first->base != modules[i].base || !last || last->base != modules[i].base) {
					++failures;
				}
			}
		}

		{
			std::unique_lock lock(_mutex);
			_modules = std::move(modules);
			_exec = std::move(exec);
		}

		logger::info("module map: {} modules, {} executable ranges ({} zero-size, {} overlaps, {} lookup failures)",
			_modules.size(), _exec.size(), zeroSize, overlaps, failures);
		if (zeroSize != 0 || overlaps != 0 || failures != 0) {
			logger::error("module map is malformed (zero-size={} overlaps={} failures={}) - vtable validation may misfire",
				zeroSize, overlaps, failures);
		}
	}

	bool ModuleMap::Find(std::uintptr_t a_addr, ModuleRange& a_out) const
	{
		std::shared_lock lock(_mutex);

		const auto it = std::upper_bound(_modules.begin(), _modules.end(), a_addr,
			[](std::uintptr_t a_value, const ModuleRange& a_range) { return a_value < a_range.base; });
		if (it == _modules.begin()) {
			return false;
		}
		const auto& candidate = *(it - 1);
		if (a_addr < candidate.base + candidate.size) {
			a_out = candidate;
			return true;
		}
		return false;
	}

	bool ModuleMap::Contains(std::uintptr_t a_addr) const
	{
		ModuleRange ignored;
		return Find(a_addr, ignored);
	}

	bool ModuleMap::IsExecutable(std::uintptr_t a_addr) const
	{
		std::shared_lock lock(_mutex);

		const auto it = std::upper_bound(_exec.begin(), _exec.end(), a_addr,
			[](std::uintptr_t a_value, const ExecRange& a_range) { return a_value < a_range.start; });
		if (it == _exec.begin()) {
			return false;
		}
		return a_addr < (it - 1)->end;
	}

	std::string ModuleMap::Describe(std::uintptr_t a_addr) const
	{
		ModuleRange range;
		char        buffer[256]{};
		if (!Find(a_addr, range)) {
			std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(a_addr));
			return buffer;
		}
		std::snprintf(buffer, sizeof(buffer), "%s+0x%llX", range.name.c_str(),
			static_cast<unsigned long long>(a_addr - range.base));
		return buffer;
	}

	std::size_t ModuleMap::Size() const
	{
		std::shared_lock lock(_mutex);
		return _modules.size();
	}

	bool IsPlausibleVTable(std::uintptr_t a_vtable)
	{
		if (a_vtable == 0 || (a_vtable & 0x7) != 0) {
			return false;
		}
		if (!ModuleMap::Get().Contains(a_vtable)) {
			return false;
		}

		// Safe to dereference: the pointer is inside a mapped image.
		const auto first = *reinterpret_cast<const std::uintptr_t*>(a_vtable);
		return ModuleMap::Get().IsExecutable(first);
	}
}
