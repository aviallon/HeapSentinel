#include "PCH.h"

#include "Veh.h"

#include "Core/GuardedPool.h"
#include "Core/ModuleMap.h"
#include "Core/Report.h"
#include "Core/ShadowLedger.h"
#include "Core/StackCapture.h"
#include "Config.h"

#include <cstdio>

namespace hs
{
	namespace
	{
		PVOID g_handler = nullptr;

		// Walk the faulting thread's stack (we run on it) and keep the qwords
		// that point into an executable section. Bounded by the stack region so
		// we never read unmapped memory from inside the handler.
		void ScanStack(std::uintptr_t a_sp, Stack& a_out)
		{
			a_out.count = 0;
			MEMORY_BASIC_INFORMATION mbi{};
			if (!::VirtualQuery(reinterpret_cast<LPCVOID>(a_sp), &mbi, sizeof(mbi))) {
				return;
			}

			const auto regionEnd = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
			auto       limit = a_sp + 0x4000;
			if (limit > regionEnd) {
				limit = regionEnd;
			}

			for (auto p = a_sp; p + sizeof(std::uintptr_t) <= limit && a_out.count < kMaxFrames; p += sizeof(std::uintptr_t)) {
				const auto value = *reinterpret_cast<const std::uintptr_t*>(p);
				if (ModuleMap::Get().IsExecutable(value)) {
					a_out.frames[a_out.count++] = reinterpret_cast<void*>(value);
				}
			}
		}

		[[nodiscard]] std::string DescribeFault(EXCEPTION_POINTERS* a_info, std::uintptr_t a_faultAddr)
		{
			char buffer[1024]{};
			const auto* context = a_info->ContextRecord;
			std::snprintf(buffer, sizeof(buffer),
				"fault address: 0x%llX (%s)\n"
				"  rip=%s  rsp=0x%llX  rbp=0x%llX\n"
				"  rax=0x%llX rcx=0x%llX rdx=0x%llX rbx=0x%llX",
				static_cast<unsigned long long>(a_faultAddr),
				ClassifyAddress(a_faultAddr).c_str(),
				ModuleMap::Get().Describe(context->Rip).c_str(),
				static_cast<unsigned long long>(context->Rsp),
				static_cast<unsigned long long>(context->Rbp),
				static_cast<unsigned long long>(context->Rax),
				static_cast<unsigned long long>(context->Rcx),
				static_cast<unsigned long long>(context->Rdx),
				static_cast<unsigned long long>(context->Rbx));

			std::string result{ buffer };

			Stack stack;
			ScanStack(static_cast<std::uintptr_t>(context->Rsp), stack);
			result += "\n  stack: ";
			result += FormatStack(stack);
			return result;
		}

		LONG CALLBACK Handler(EXCEPTION_POINTERS* a_info)
		{
			__try {
				if (!a_info || !a_info->ExceptionRecord) {
					return EXCEPTION_CONTINUE_SEARCH;
				}
				if (a_info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
					return EXCEPTION_CONTINUE_SEARCH;
				}
				if (a_info->ExceptionRecord->NumberParameters < 2) {
					return EXCEPTION_CONTINUE_SEARCH;
				}

				const auto faultAddr = static_cast<std::uintptr_t>(a_info->ExceptionRecord->ExceptionInformation[1]);

				// 1. Our own guarded pool: this is the deterministic UAF/OOB
				//    case, with the allocation and free stacks on record.
				AllocationInfo slot;
				if (GuardedPool::Get().OnFault(faultAddr, Config::Get().guardPoolFixUp, slot)) {
					std::string detail = DescribeFault(a_info, faultAddr);
					detail += "\n  guarded slot: size=" + std::to_string(slot.size);
					detail += " allocSite=" + ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(slot.allocSite));
					detail += " freeSite=" + ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(slot.freeSite));
					if (const auto* alloc = ShadowLedger::Get().GetStack(slot.allocStack)) {
						detail += "\n  alloc stack: " + FormatStack(*alloc);
					}
					if (const auto* freed = ShadowLedger::Get().GetStack(slot.freeStack)) {
						detail += "\n  free  stack: " + FormatStack(*freed);
					}
					Report("guarded-slot-use-after-free", detail);

					if (Config::Get().guardPoolFixUp) {
						return EXCEPTION_CONTINUE_EXECUTION;
					}
					return EXCEPTION_CONTINUE_SEARCH;
				}

				// 2. Anything else: report and hand over. We do not swallow it.
				if (Config::Get().vehEnabled) {
					Report("access-violation", DescribeFault(a_info, faultAddr));
				}
				return EXCEPTION_CONTINUE_SEARCH;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				// Never let the sentinel's own report path turn one fault into
				// two; fall through to the real handler.
				return EXCEPTION_CONTINUE_SEARCH;
			}
		}
	}

	void InstallVeh()
	{
		if (g_handler) {
			return;
		}
		// 1 = first chance, so we run before Crash Logger SSE.
		g_handler = ::AddVectoredExceptionHandler(1, &Handler);
		if (g_handler) {
			logger::info("vectored exception handler installed");
		} else {
			logger::warn("AddVectoredExceptionHandler failed ({})", ::GetLastError());
		}
	}

	void RemoveVeh()
	{
		if (g_handler) {
			::RemoveVectoredExceptionHandler(g_handler);
			g_handler = nullptr;
		}
	}
}
