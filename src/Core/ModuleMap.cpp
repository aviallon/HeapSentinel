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
		_modules.clear();
		_exec.clear();

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
					if (nt->Signature == IMAGE_NT_SIGNATURE) {
						range.size = nt->OptionalHeader.SizeOfImage;
						const auto* section = IMAGE_FIRST_SECTION(nt);
						for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
							if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || section->Misc.VirtualSize == 0) {
								continue;
							}
							_exec.push_back(ExecRange{
								range.base + section->VirtualAddress,
								range.base + section->VirtualAddress + section->Misc.VirtualSize });
						}
					}
				}

				_modules.push_back(std::move(range));
			} while (::Module32Next(snapshot, &entry));
		}

		::CloseHandle(snapshot);

		std::sort(_modules.begin(), _modules.end(), [](const ModuleRange& a, const ModuleRange& b) { return a.base < b.base; });
		std::sort(_exec.begin(), _exec.end(), [](const ExecRange& a, const ExecRange& b) { return a.start < b.start; });

		_lastRefreshTick.store(::GetTickCount64(), std::memory_order_relaxed);

		// Self-test: every module must be findable at its first and last byte.
		// A silent binary-search bug here would make valid vtables look corrupt.
		std::size_t failures = 0;
		for (const auto& mod : _modules) {
			if (Find(mod.base) != &mod) {
				++failures;
			}
			if (mod.size > 0 && Find(mod.base + mod.size - 1) != &mod) {
				++failures;
			}
		}
		if (failures != 0) {
			logger::error("module map self-test: {} lookup failures", failures);
		}

		logger::info("module map: {} modules, {} executable ranges, {} self-test failures",
			_modules.size(), _exec.size(), failures);
	}

	bool ModuleMap::MaybeRefreshLazily(std::uint64_t a_minIntervalMs)
	{
		const auto now = ::GetTickCount64();
		std::uint64_t last = _lastRefreshTick.load(std::memory_order_relaxed);
		if (now - last < a_minIntervalMs) {
			return false;
		}
		if (!_lastRefreshTick.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
			return false;
		}
		Refresh();
		return true;
	}

	const ModuleRange* ModuleMap::Find(std::uintptr_t a_addr) const
	{
		const auto it = std::upper_bound(_modules.begin(), _modules.end(), a_addr,
			[](std::uintptr_t a_value, const ModuleRange& a_range) { return a_value < a_range.base; });
		if (it == _modules.begin()) {
			return nullptr;
		}
		const auto& candidate = *(it - 1);
		if (a_addr < candidate.base + candidate.size) {
			return &candidate;
		}
		return nullptr;
	}

	bool ModuleMap::Contains(std::uintptr_t a_addr) const
	{
		return Find(a_addr) != nullptr;
	}

	bool ModuleMap::IsExecutable(std::uintptr_t a_addr) const
	{
		const auto it = std::upper_bound(_exec.begin(), _exec.end(), a_addr,
			[](std::uintptr_t a_value, const ExecRange& a_range) { return a_value < a_range.start; });
		if (it == _exec.begin()) {
			return false;
		}
		return a_addr < (it - 1)->end;
	}

	std::string ModuleMap::Describe(std::uintptr_t a_addr) const
	{
		const auto* mod = Find(a_addr);
		char        buffer[256]{};
		if (!mod) {
			std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(a_addr));
			return buffer;
		}
		std::snprintf(buffer, sizeof(buffer), "%s+0x%llX", mod->name.c_str(),
			static_cast<unsigned long long>(a_addr - mod->base));
		return buffer;
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
