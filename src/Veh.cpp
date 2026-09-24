#include "PCH.h"

#include "Veh.h"

#include "Core/GuardedPool.h"
#include "Core/ModuleMap.h"
#include "Core/PoisonQuarantine.h"
#include "Core/Report.h"
#include "Core/ScaleformFreeRing.h"
#include "Core/ShadowLedger.h"
#include "Core/StackCapture.h"
#include "Core/Verdict.h"
#include "Core/Watchpoints.h"
#include "Core/WeakLibEvents.h"
#include "Config.h"

#include <cstdio>
#include <utility>

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

		// Fault-safe read. No C++ objects in this frame, so SEH is legal.
		[[nodiscard]] bool SafeReadQword(std::uintptr_t a_addr, std::uintptr_t& a_out)
		{
			__try {
				a_out = *reinterpret_cast<const std::uintptr_t*>(a_addr);
				return true;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				a_out = 0;
				return false;
			}
		}

		[[nodiscard]] std::string PlausibleText(std::uintptr_t a_value)
		{
			if (a_value == 0) {
				return "none";
			}
			return IsPlausibleVTable(a_value) ? "code" : "NOT code";
		}

		[[nodiscard]] std::string SymbolHint(std::string a_described)
		{
			if (!Config::Get().reportSymbolHint) {
				return a_described;
			}
			// Only a module+offset can be resolved against a PDB, and the engine's
			// own PDB is not shipped, so hint only for plugins.
			if (a_described.rfind("SkyrimSE.exe", 0) == 0 || a_described.find("+0x") == std::string::npos) {
				return a_described;
			}
			return a_described + " [resolve module+offset against that module's shipped PDB]";
		}

		[[nodiscard]] std::string FormatWeakLibEvents(std::uintptr_t a_ptr)
		{
			WeakLibEvent events[16];
			const auto   found = WeakLibEvents::Get().Find(a_ptr, events, 16);
			if (found == 0) {
				return {};
			}
			static constexpr const char* kNames[] = { "?", "PIN", "REMOVE_ON_RELEASE", "UNPIN", "ADDREF" };

			std::string result = "\n    weaklib:";
			for (std::size_t i = 0; i < found; ++i) {
				const auto& event = events[i];
				const auto  kind = (event.kind > 0 && event.kind <= 4) ? kNames[event.kind] : "?";
				result += "\n      ";
				result += kind;
				result += " at tick ";
				result += std::to_string(event.tick);
				result += " from ";
				result += ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(event.site));
			}
			return result;
		}

		// Gather everything the ledger, the durable free ring and the poison
		// quarantine know about a value, and turn it into a verdict. The VEH runs
		// on the faulting thread and takes NO lock: all three readers are
		// lock-free seqlock reads, and a torn read degrades to "unknown".
		struct Provenance
		{
			VerdictResult verdict;
			std::string   details;
			bool          known = false;
			bool          objectIsPoisonAddress = false;
			std::uintptr_t object = 0;
		};

		[[nodiscard]] Provenance DescribeProvenance(const char* a_name, std::uintptr_t a_value)
		{
			Provenance result;
			if (a_value <= 1) {
				return result;
			}

			VerdictFacts facts;
			facts.regName = a_name;
			facts.value = a_value;
			result.object = a_value;

			AllocationInfo ledgerInfo;
			const bool      inLedger = ShadowLedger::Get().Find(a_value, ledgerInfo);

			ScaleformFreeRecord freeRecord;
			const bool inFreeRing = ScaleformFreeRing::Get().Find(a_value, freeRecord);

			// Is the value itself a poison address (i.e. the "vtable" we are
			// looking at is our own poison)? Then it belongs to a quarantined
			// object: report that object, not the poison value.
			std::uint32_t   poisonIndex = 0;
			QuarantineRecord quarantineRecord;
			const bool      isPoisonValue =
				PoisonQuarantine::Get().DecodeFault(a_value, poisonIndex) &&
				PoisonQuarantine::Get().GetSlot(poisonIndex, quarantineRecord);

			if (isPoisonValue) {
				result.objectIsPoisonAddress = true;
				result.object = quarantineRecord.ptr;
				facts.value = quarantineRecord.ptr;
				facts.poisonMatch = true;
				facts.poisoned = true;
				facts.known = true;
				facts.freed = true;
				facts.size = quarantineRecord.size;
				facts.vtableAtFree = quarantineRecord.vtableAtFree;
				if (quarantineRecord.freeSite) {
					facts.hasFreeSite = true;
					facts.freeSiteName = SymbolHint(ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(quarantineRecord.freeSite)));
				}
			}

			if (inLedger) {
				facts.known = true;
				facts.freed = facts.freed || (ledgerInfo.flags & kFlagFreed) != 0;
				facts.poisoned = facts.poisoned || (ledgerInfo.flags & kFlagPoisoned) != 0;
				if (facts.size == 0) {
					facts.size = ledgerInfo.size;
				}
				if (facts.vtableAtFree == 0) {
					facts.vtableAtFree = ledgerInfo.vtableAtFree;
				}
				facts.firstQwordAtAlloc = ledgerInfo.vtableAtAlloc;
				facts.firstQwordAtAllocPlausible = ledgerInfo.vtableAtAlloc != 0 && IsPlausibleVTable(ledgerInfo.vtableAtAlloc);
				facts.lastKnownVtable = ledgerInfo.lastKnownVtable;
				facts.lastKnownVtablePlausible = ledgerInfo.lastKnownVtable != 0 && IsPlausibleVTable(ledgerInfo.lastKnownVtable);
				if (ledgerInfo.allocSite) {
					facts.hasAllocSite = true;
					facts.allocSiteName = SymbolHint(ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(ledgerInfo.allocSite)));
				}
				if (!facts.hasFreeSite && ledgerInfo.freeSite) {
					facts.hasFreeSite = true;
					facts.freeSiteName = SymbolHint(ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(ledgerInfo.freeSite)));
				}
			}

			if (inFreeRing) {
				facts.known = true;
				facts.freed = true;
				if (facts.size == 0) {
					facts.size = freeRecord.size;
				}
				if (facts.vtableAtFree == 0) {
					facts.vtableAtFree = freeRecord.vtableAtFree;
				}
				if (!facts.hasFreeSite && freeRecord.freeSite) {
					facts.hasFreeSite = true;
					facts.freeSiteName = SymbolHint(ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(freeRecord.freeSite)));
				}
				if (freeRecord.poisonIndex != 0) {
					facts.poisoned = true;
				}
			}

			if (!facts.known) {
				result.verdict = BuildVerdict(facts);
				return result;
			}

			// The object's current first qword. For a poison-address candidate the
			// object is the quarantined block; its first qword IS the poison.
			std::uintptr_t current = 0;
			const bool     readable = SafeReadQword(result.object, current);
			facts.currentReadable = readable;
			facts.currentFirstQword = current;
			facts.currentPlausible = readable && IsPlausibleVTable(current);

			// A poison value in the block's first qword that decodes back to a
			// record for THIS object is the deterministic match.
			std::uint32_t currentPoisonIndex = 0;
			if (readable && PoisonQuarantine::Get().DecodeFault(current, currentPoisonIndex)) {
				QuarantineRecord asPoison;
				if (PoisonQuarantine::Get().GetSlot(currentPoisonIndex, asPoison) && asPoison.ptr == result.object) {
					facts.poisonMatch = true;
					facts.poisoned = true;
				}
			}

			facts.vtableAtFreePlausible = facts.vtableAtFree != 0 && IsPlausibleVTable(facts.vtableAtFree);

			result.verdict = BuildVerdict(facts);

			// Human-readable detail block.
			char header[160]{};
			std::snprintf(header, sizeof(header), "\n  %s=0x%llX is a %s%s block (size %zu)",
				a_name, static_cast<unsigned long long>(a_value),
				facts.freed ? "freed" : "live", (inLedger && (ledgerInfo.flags & kFlagScaleform)) || inFreeRing ? " Scaleform" : "",
				facts.size);
			result.details = header;

			if (result.objectIsPoisonAddress) {
				result.details += "\n    (this is our poison address; it maps to quarantined object 0x" +
					std::to_string(result.object) + ")";
			}

			if (facts.hasAllocSite) {
				result.details += "\n    allocSite=" + facts.allocSiteName;
			}
			if (facts.hasFreeSite) {
				result.details += "\n    freeSite=" + facts.freeSiteName;
			}

			char qwords[320]{};
			std::snprintf(qwords, sizeof(qwords),
				"\n    first qword: atAlloc=0x%llX (%s)  atFree=0x%llX (%s)  lastKnown=0x%llX (%s)  current=0x%llX (%s)",
				static_cast<unsigned long long>(facts.firstQwordAtAlloc),
				facts.firstQwordAtAlloc == 0 ? "pre-construction/absent" : PlausibleText(facts.firstQwordAtAlloc).c_str(),
				static_cast<unsigned long long>(facts.vtableAtFree), PlausibleText(facts.vtableAtFree).c_str(),
				static_cast<unsigned long long>(facts.lastKnownVtable), PlausibleText(facts.lastKnownVtable).c_str(),
				static_cast<unsigned long long>(facts.currentFirstQword), facts.currentReadable ? PlausibleText(facts.currentFirstQword).c_str() : "unreadable");
			result.details += qwords;

			result.details += facts.poisonMatch ? "\n    poison: MATCH (the block still holds our poison)" :
				(facts.poisoned ? "\n    poison: record says poisoned, but current first qword is not our poison" : "\n    poison: none");

			if (inLedger) {
				if (const auto* alloc = ShadowLedger::Get().GetStack(ledgerInfo.allocStack)) {
					result.details += "\n    alloc stack: " + FormatStack(*alloc);
				}
				if (const auto* freed = ShadowLedger::Get().GetStack(ledgerInfo.freeStack)) {
					result.details += "\n    free  stack: " + FormatStack(*freed);
				}
			} else if (inFreeRing) {
				if (const auto* freed = ShadowLedger::Get().GetStack(freeRecord.freeStack)) {
					result.details += "\n    free  stack: " + FormatStack(*freed);
				}
			}

			result.details += FormatWeakLibEvents(result.object);
			result.known = true;
			return result;
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

			// The registers most likely to hold the object behind an indirect call
			// (this=rcx, vtable=rax) plus the fault address itself. Only registers
			// the ledger/free-ring/quarantine actually know produce a block, so an
			// ordinary crash is unchanged.
			const std::pair<const char*, std::uintptr_t> candidates[] = {
				{ "rcx", static_cast<std::uintptr_t>(context->Rcx) },
				{ "rax", static_cast<std::uintptr_t>(context->Rax) },
				{ "rdx", static_cast<std::uintptr_t>(context->Rdx) },
				{ "rbx", static_cast<std::uintptr_t>(context->Rbx) },
				{ "fault", a_faultAddr },
			};

			VerdictResult bestVerdict;
			bool          haveBest = false;

			for (const auto& [name, value] : candidates) {
				auto provenance = DescribeProvenance(name, value);
				if (provenance.known) {
					result += provenance.details;
					if (!haveBest) {
						// rcx is the object for an indirect call; the first known
						// candidate in this order is the most relevant.
						bestVerdict = provenance.verdict;
						haveBest = true;
					}
				}
			}

			Stack stack;
			ScanStack(static_cast<std::uintptr_t>(context->Rsp), stack);
			result += "\n  stack: ";
			result += FormatStack(stack);

			result += "\nVERDICT: ";
			result += haveBest ? bestVerdict.reason :
								 "no tracked object among rcx/rax/rdx/rbx/fault - allocated before the hooks were live, via an unhooked entry point, or evicted";
			return result;
		}

		// The reporting body. It allocates (std::string) and therefore cannot
		// live inside the __try frame: MSVC rejects __try in a function that
		// requires object unwinding (C2712). It is called from Handler below,
		// whose SEH frame catches any fault raised here.
		LONG HandleException(EXCEPTION_POINTERS* a_info)
		{
			if (!a_info || !a_info->ExceptionRecord) {
				return EXCEPTION_CONTINUE_SEARCH;
			}
			// Hardware data watchpoints arrive as a single-step debug exception. The
			// watchpoint manager owns the decision. Since 0.6.3 that decision is
			// STRUCTURAL: once this process has ever programmed a debug register, a
			// #DB is consumed (and recorded, attributed or not) rather than handed
			// on -- see DESIGN.md 13.4 for why survival cannot depend on classifying
			// correctly. Before any DR has been programmed nothing can be masked and
			// the manager returns CONTINUE_SEARCH. For every other exception code the
			// old rule stands: we never swallow an exception we do not understand.
			if (a_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
				return Watchpoints::Get().HandleDebugException(a_info);
			}
			if (a_info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
				return EXCEPTION_CONTINUE_SEARCH;
			}
			if (a_info->ExceptionRecord->NumberParameters < 2) {
				return EXCEPTION_CONTINUE_SEARCH;
			}

			const auto faultAddr = static_cast<std::uintptr_t>(a_info->ExceptionRecord->ExceptionInformation[1]);

			// 1. Our own guarded pool: the deterministic UAF/OOB case, with the
			//    allocation and free stacks on record.
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
		}

		LONG CALLBACK Handler(EXCEPTION_POINTERS* a_info)
		{
			__try {
				return HandleException(a_info);
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