#include "PCH.h"

#include "Hooks/Hooks.h"

#include "Core/GuardedPool.h"
#include "Core/Health.h"
#include "Core/ModuleMap.h"
#include "Core/PoisonQuarantine.h"
#include "Core/Report.h"
#include "Core/ScaleformFreeRing.h"
#include "Core/ShadowLedger.h"
#include "Core/StackCapture.h"
#include "Core/WeakLibEvents.h"
#include "Config.h"
#include "Hooks/HookTable.h"
#include "Hooks/HookTableData.gen.h"
#include "Hooks/HookTargets.h"
#include "Hooks/HookVerifier.h"

#include <MinHook.h>
#include <intrin.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace hs
{
	namespace
	{
		// Engine heap: the facade every engine allocation goes through.
		using AllocateFn = void*(*)(RE::MemoryManager*, std::size_t, std::int32_t, bool);
		using DeallocateFn = void(*)(RE::MemoryManager*, void*, bool);
		using ReallocateFn = void*(*)(RE::MemoryManager*, void*, std::size_t, std::int32_t, bool);

		// Scaleform refcounting: the destructor dispatch that crashes.
		using ReleaseFn = void(*)(void*);

		// Scaleform/GFx heap (GMemoryHeapPT). These are virtual-function
		// implementations reached through the GMemoryHeap vtable, so they cannot
		// be inlined away at the call site. Signatures were verified against the
		// engine's own vtable at SkyrimSE.exe + 0x1A9C510: slots 9/0xA/0xB/0xC are
		// Alloc(size,align)/Alloc(size)/Realloc/Free, and 0xD/0xE are the two
		// AllocAutoHeap overloads (see the report for the full derivation).
		using SfAllocFn = void*(*)(void* a_self, std::size_t a_size, std::size_t a_align);                       // 84498
		using SfAlloc1Fn = void*(*)(void* a_self, std::size_t a_size);                                          // 84499
		using SfAutoAllocFn = void*(*)(void* a_self, const void* a_object, std::size_t a_size, std::size_t a_align);  // 84501
		using SfAutoAlloc1Fn = void*(*)(void* a_self, const void* a_object, std::size_t a_size);                 // 84502
		using SfReallocFn = void*(*)(void* a_self, void* a_oldMem, std::size_t a_newSize);                       // 84540
		using SfFreeFn = void(*)(void* a_self, void* a_mem);                                                    // 84520

		// GFxResourceWeakLib context (0.3.0). AE Address Library ids 82783/82796/
		// 82798/82802, re-derived from the engine binary and versionlib-1-7-104-0.bin:
		//   82783 GFxResource::AddRef         0x140D077D0  lock xadd [rcx+8]  (resource)
		//   82796 GFxResourceWeakLib::PinResource            0x140D07F30  (weakLib, resource)
		//   82798 GFxResourceWeakLib::RemoveResourceOnRelease 0x140D08000 (weakLib, resource)
		//   82802 GFxResourceWeakLib::UnpinResource          0x140D08360  (weakLib, resource)
		using WlAddRefFn = std::uint32_t (*)(void* a_resource);
		using WlResourceFn = void (*)(void* a_weakLib, void* a_resource);

		AllocateFn   o_Allocate = nullptr;
		DeallocateFn o_Deallocate = nullptr;
		ReallocateFn o_Reallocate = nullptr;
		ReleaseFn    o_Release = nullptr;

		SfAllocFn      o_SfAlloc = nullptr;
		SfAlloc1Fn     o_SfAlloc1 = nullptr;
		SfAutoAllocFn  o_SfAllocAuto = nullptr;
		SfAutoAlloc1Fn o_SfAllocAuto1 = nullptr;
		SfReallocFn    o_SfRealloc = nullptr;
		SfFreeFn       o_SfFree = nullptr;

		WlAddRefFn   o_WlAddRef = nullptr;
		WlResourceFn o_WlPin = nullptr;
		WlResourceFn o_WlRemove = nullptr;
		WlResourceFn o_WlUnpin = nullptr;

		[[nodiscard]] std::uint32_t CaptureStackIndex(std::uint32_t a_skip)
		{
			const auto depth = Config::Get().ledgerStackDepth;
			if (depth == 0) {
				return 0;
			}
			Stack stack;
			CaptureStack(stack, a_skip, static_cast<std::uint32_t>(depth));
			return ShadowLedger::Get().StoreStack(stack);
		}

		[[nodiscard]] std::string DescribePtr(std::uintptr_t a_ptr)
		{
			char buffer[256]{};
			std::snprintf(buffer, sizeof(buffer), "0x%llX (%s)", static_cast<unsigned long long>(a_ptr),
				ClassifyAddress(a_ptr).c_str());
			return buffer;
		}

		[[nodiscard]] std::uint64_t NowTick()
		{
			return ::GetTickCount64();
		}

		// Fault-safe read of a block's first qword. Used on both the alloc and
		// free hooks; a bad pointer must not turn the sentinel into a second
		// fault. No C++ objects live in this frame, so SEH is legal here.
		[[nodiscard]] std::uintptr_t SafeReadFirstQword(const void* a_ptr)
		{
			__try {
				return *static_cast<const std::uintptr_t*>(a_ptr);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return 0;
			}
		}

		[[nodiscard]] bool IsReadableRegion(const void* a_ptr)
		{
			MEMORY_BASIC_INFORMATION mbi{};
			if (!::VirtualQuery(a_ptr, &mbi, sizeof(mbi))) {
				return false;
			}
			if (mbi.State != MEM_COMMIT) {
				return false;
			}
			constexpr DWORD bad = PAGE_NOACCESS | PAGE_GUARD;
			return (mbi.Protect & bad) == 0;
		}

		void* hk_Allocate(RE::MemoryManager* a_self, std::size_t a_size, std::int32_t a_alignment, bool a_alignmentRequired)
		{
			const auto& config = Config::Get();
			if (!config.enabled) {
				return o_Allocate(a_self, a_size, a_alignment, a_alignmentRequired);
			}

			if (config.guardPoolEnabled && GuardedPool::Get().ShouldSample(a_size)) {
				AllocationInfo info;
				info.threadId = ::GetCurrentThreadId();
				info.allocSite = _ReturnAddress();
				info.allocStack = CaptureStackIndex(1);
				if (auto* sampled = GuardedPool::Get().Allocate(a_size, static_cast<std::size_t>(a_alignment), info)) {
					return sampled;
				}
			}

			auto* result = o_Allocate(a_self, a_size, a_alignment, a_alignmentRequired);

			if (result && config.ledgerEnabled) {
				AllocationInfo info;
				info.ptr = reinterpret_cast<std::uintptr_t>(result);
				info.size = a_size;
				info.threadId = ::GetCurrentThreadId();
				info.flags = kFlagLive;
				info.allocSite = _ReturnAddress();
				info.allocStack = CaptureStackIndex(1);
				info.allocTick = NowTick();
				info.vtableAtAlloc = SafeReadFirstQword(result);
				ShadowLedger::Get().Insert(info.ptr, info);
			}

			return result;
		}

		void hk_Deallocate(RE::MemoryManager* a_self, void* a_mem, bool a_alignmentRequired)
		{
			if (!a_mem) {
				o_Deallocate(a_self, a_mem, a_alignmentRequired);
				return;
			}

			const auto& config = Config::Get();
			const auto  address = reinterpret_cast<std::uintptr_t>(a_mem);

			if (config.guardPoolEnabled && GuardedPool::Get().IsOurs(address)) {
				AllocationInfo known;
				if (ShadowLedger::Get().Find(address, known) && (known.flags & kFlagFreed)) {
					Report("double-free", "guarded block " + DescribePtr(address) +
											 " freed again from " + ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(_ReturnAddress())));
					return;  // fail safe: never hand it back to the pool twice
				}
				GuardedPool::Get().Deallocate(address, _ReturnAddress(), CaptureStackIndex(1));
				return;
			}

			if (config.ledgerEnabled) {
				AllocationInfo info;
				if (ShadowLedger::Get().Find(address, info)) {
					if (info.flags & kFlagFreed) {
						Report("double-free", "block " + DescribePtr(address) +
												  " (size " + std::to_string(info.size) + ") freed again from " +
												  ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(_ReturnAddress())) +
												  "; first free from " + ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(info.freeSite)));
						return;  // fail safe
					}
					info.flags |= kFlagFreed;
					info.freeSite = _ReturnAddress();
					info.freeStack = CaptureStackIndex(1);
					info.freeTick = NowTick();
					info.vtableAtFree = SafeReadFirstQword(a_mem);
					ShadowLedger::Get().Insert(address, info);
				} else if (config.reportUntrackedFree) {
					Report("invalid-free", "block " + DescribePtr(address) + " was never recorded as an allocation");
				}
			}

			o_Deallocate(a_self, a_mem, a_alignmentRequired);
		}

		void* hk_Reallocate(RE::MemoryManager* a_self, void* a_oldMem, std::size_t a_newSize, std::int32_t a_alignment, bool a_aligned)
		{
			const auto& config = Config::Get();

			if (a_oldMem && config.guardPoolEnabled && GuardedPool::Get().IsOurs(reinterpret_cast<std::uintptr_t>(a_oldMem))) {
				AllocationInfo known;
				const auto      oldSize = ShadowLedger::Get().Find(reinterpret_cast<std::uintptr_t>(a_oldMem), known) ? known.size : 0;
				auto*           fresh = o_Allocate(a_self, a_newSize, a_alignment, a_aligned);
				if (fresh) {
					std::memcpy(fresh, a_oldMem, oldSize < a_newSize ? oldSize : a_newSize);
					GuardedPool::Get().Deallocate(reinterpret_cast<std::uintptr_t>(a_oldMem), _ReturnAddress(), CaptureStackIndex(1));
					if (config.ledgerEnabled) {
						AllocationInfo info;
						info.ptr = reinterpret_cast<std::uintptr_t>(fresh);
						info.size = a_newSize;
						info.threadId = ::GetCurrentThreadId();
						info.flags = kFlagLive;
						info.allocSite = _ReturnAddress();
						info.allocStack = CaptureStackIndex(1);
						ShadowLedger::Get().Insert(info.ptr, info);
					}
				}
				return fresh;
			}

			auto* result = o_Reallocate(a_self, a_oldMem, a_newSize, a_alignment, a_aligned);

			if (result && config.ledgerEnabled) {
				if (a_oldMem) {
					AllocationInfo old;
					ShadowLedger::Get().Erase(reinterpret_cast<std::uintptr_t>(a_oldMem), old);
				}
				AllocationInfo info;
				info.ptr = reinterpret_cast<std::uintptr_t>(result);
				info.size = a_newSize;
				info.threadId = ::GetCurrentThreadId();
				info.flags = kFlagLive;
				info.allocSite = _ReturnAddress();
				info.allocStack = CaptureStackIndex(1);
				info.allocTick = NowTick();
				info.vtableAtAlloc = SafeReadFirstQword(result);
				ShadowLedger::Get().Insert(info.ptr, info);
			}

			return result;
		}

		void hk_Release(void* a_object)
		{
			if (!a_object) {
				o_Release(a_object);
				return;
			}

			const auto& config = Config::Get();
			if (!config.refCountGuardEnabled) {
				o_Release(a_object);
				return;
			}

			const auto object = reinterpret_cast<std::uintptr_t>(a_object);
			const auto vtable = *reinterpret_cast<const std::uintptr_t*>(a_object);
			const auto count = *reinterpret_cast<const std::int32_t*>(reinterpret_cast<const std::byte*>(a_object) + 8);

			// The module list is only complete after every SKSE plugin has been
			// loaded (kPostLoad). Until then, fail open: a vtable in a plugin
			// that has not loaded yet would look unmapped.
			if (!ModuleMap::Get().IsComplete()) {
				o_Release(a_object);
				return;
			}

			bool plausible = IsPlausibleVTable(vtable);

			if (!plausible) {
				char detail[768]{};
				std::snprintf(detail, sizeof(detail),
					"object %s has vtable 0x%llX (%s), first slot 0x%llX, refcount %d; releasing from %s",
					DescribePtr(object).c_str(),
					static_cast<unsigned long long>(vtable),
					ClassifyAddress(vtable).c_str(),
					static_cast<unsigned long long>(vtable ? *reinterpret_cast<const std::uintptr_t*>(vtable) : 0),
					count,
					ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(_ReturnAddress())).c_str());
				Report("bad-vtable-release", detail);

				if (config.refCountGuardFailSafe) {
					return;  // leak the object instead of dispatching a destructor through garbage
				}
			}

			o_Release(a_object);
		}

		// --- Scaleform / GFx heap (GMemoryHeapPT) -------------------------
		//
		// Scaleform objects (GFxResource and friends) are allocated by Scaleform's
		// own GMemoryHeapPT, not by RE::MemoryManager, so the engine hooks above
		// are blind to exactly the objects that keep dying. These detours feed the
		// SAME shadow ledger with the SAME fail-open discipline: when the ledger is
		// full or not ready, every operation is a no-op and the original is called.

		[[nodiscard]] bool ScaleformTrackingEnabled()
		{
			const auto& config = Config::Get();
			return config.enabled && config.scaleformHeapEnabled && config.ledgerEnabled;
		}

		void RecordScaleformAlloc(void* a_ptr, std::size_t a_size, void* a_site, std::uint32_t a_stack)
		{
			if (!a_ptr || !Config::Get().ledgerEnabled) {
				return;
			}
			AllocationInfo info;
			info.ptr = reinterpret_cast<std::uintptr_t>(a_ptr);
			info.size = a_size;
			info.threadId = ::GetCurrentThreadId();
			info.flags = kFlagLive | kFlagScaleform;
			info.allocSite = a_site;
			info.allocStack = a_stack;
			info.allocTick = NowTick();
			info.vtableAtAlloc = SafeReadFirstQword(a_ptr);
			ShadowLedger::Get().Insert(info.ptr, info);
		}

		// Returns false when the block is already known to have been freed; the
		// caller then refuses to call the original (fail safe). An untracked block
		// is recorded as a freed-only entry: that is the provenance the stale
		// GFxResource crash needs, and it is the only way to attribute objects
		// allocated before the hooks were live.
		[[nodiscard]] bool RecordScaleformFreeBeforePoison(void* a_mem, void* a_site, std::uint32_t a_stack)
		{
			if (!a_mem || !Config::Get().ledgerEnabled) {
				return true;
			}

			const auto address = reinterpret_cast<std::uintptr_t>(a_mem);
			AllocationInfo info;
			if (ShadowLedger::Get().Find(address, info)) {
				if (info.flags & kFlagFreed) {
					Report("double-free", "Scaleform block " + DescribePtr(address) +
										  " (size " + std::to_string(info.size) + ") freed again from " +
										  ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(a_site)) +
										  "; first free from " +
										  ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(info.freeSite)));
					return false;  // fail safe: never hand it back to the heap twice
				}
			}
			return true;
		}

		[[nodiscard]] std::size_t KnownScaleformSize(std::uintptr_t a_address)
		{
			AllocationInfo info;
			return ShadowLedger::Get().Find(a_address, info) ? info.size : 0;
		}

		void RecordScaleformFree(void* a_mem, std::size_t a_size, std::uintptr_t a_vtableAtFree, void* a_site,
			std::uint32_t a_stack, std::uint64_t a_tick, std::uint32_t a_poisonIndex)
		{
			const auto address = reinterpret_cast<std::uintptr_t>(a_mem);

			if (Config::Get().ledgerEnabled) {
				AllocationInfo info;
				if (ShadowLedger::Get().Find(address, info)) {
					info.flags |= kFlagFreed | kFlagScaleform;
					if (a_poisonIndex != 0) {
						info.flags |= kFlagPoisoned;
					}
					info.freeSite = a_site;
					info.freeStack = a_stack;
					info.freeTick = a_tick;
					info.vtableAtFree = a_vtableAtFree;
					info.poisonIndex = a_poisonIndex;
					ShadowLedger::Get().Insert(address, info);
				} else {
					AllocationInfo fresh;
					fresh.ptr = address;
					fresh.size = a_size;
					fresh.threadId = ::GetCurrentThreadId();
					fresh.flags = kFlagFreed | kFlagScaleform;
					if (a_poisonIndex != 0) {
						fresh.flags |= kFlagPoisoned;
					}
					fresh.freeSite = a_site;
					fresh.freeStack = a_stack;
					fresh.freeTick = a_tick;
					fresh.vtableAtFree = a_vtableAtFree;
					fresh.poisonIndex = a_poisonIndex;
					ShadowLedger::Get().Insert(address, fresh);
				}
			}

			// Durable provenance, evict-oldest and separately budgeted.
			ScaleformFreeRecord record;
			record.ptr = address;
			record.vtableAtFree = a_vtableAtFree;
			record.size = a_size;
			record.freeSite = a_site;
			record.freeStack = a_stack;
			record.poisonIndex = a_poisonIndex;
			record.freeTick = a_tick;
			record.threadId = ::GetCurrentThreadId();
			ScaleformFreeRing::Get().Record(record);
		}

		// Really free one withheld block. The heap pointer is validated before we
		// call into it: a destroyed heap is refused (that block leaks) rather than
		// called. Residual risk remains: VirtualQuery only proves the page is
		// committed, and the module-map plausibility check only proves the first
		// qword looks like a vtable - neither proves it is the same GMemoryHeapPT.
		bool DrainOneQuarantined()
		{
			QuarantineRecord record;
			if (!PoisonQuarantine::Get().PopOldest(record)) {
				return false;
			}
			if (!record.heap) {
				return true;
			}

			const auto heap = reinterpret_cast<std::uintptr_t>(record.heap);
			if (!IsReadableRegion(record.heap) || !IsPlausibleVTable(SafeReadFirstQword(record.heap))) {
				logger::warn("poison quarantine: refusing to drain 0x{:X}: its heap 0x{:X} no longer looks like a live GMemoryHeapPT (leaking the block)",
					record.ptr, heap);
				return true;
			}

			o_SfFree(record.heap, reinterpret_cast<void*>(record.ptr));
			return true;
		}

		// Try to withhold this block's real free. Returns true when the block was
		// poisoned (poisonIndex set) and the caller must NOT call the original.
		bool TryPoisonOnFree(void* a_mem, void* a_heap, std::size_t a_size, void* a_site, std::uint32_t a_stack,
			std::uint64_t a_tick, std::uintptr_t a_vtableAtFree, std::uint32_t& a_poisonIndex)
		{
			a_poisonIndex = 0;
			auto& quarantine = PoisonQuarantine::Get();
			if (!Config::Get().scaleformPoisonEnabled || !quarantine.Ready()) {
				return false;
			}
			// The poison is one qword; never write past a block we know is smaller.
			if (a_size != 0 && a_size < sizeof(std::uintptr_t)) {
				return false;
			}
			if (!IsReadableRegion(a_mem)) {
				return false;  // a free of an unmapped block: let the engine report it
			}

			// Drain oldest-first until the budget admits this block. Bounded:
			// PopOldest empties the ring, so this loop terminates.
			std::size_t drains = 0;
			while (quarantine.OverBudget(a_size) && drains < (1u << 20)) {
				if (!DrainOneQuarantined()) {
					break;
				}
				++drains;
			}
			if (quarantine.OverBudget(a_size)) {
				return false;  // still over budget: fail open
			}

			const auto index = quarantine.Reserve();
			if (index == 0) {
				return false;
			}

			QuarantineRecord record;
			record.ptr = reinterpret_cast<std::uintptr_t>(a_mem);
			record.heap = a_heap;
			record.size = a_size;
			record.vtableAtFree = a_vtableAtFree;
			record.freeSite = a_site;
			record.freeStack = a_stack;
			record.index = index;
			record.freeTick = a_tick;

			// Poison first, publish second: a reader that finds the record must
			// already be able to trust the poison value in the block.
			*reinterpret_cast<volatile std::uintptr_t*>(a_mem) = quarantine.PoisonFor(index);
			quarantine.Publish(record);
			a_poisonIndex = index;
			return true;
		}

		void* hk_SfAlloc(void* a_self, std::size_t a_size, std::size_t a_align)
		{
			if (!ScaleformTrackingEnabled()) {
				return o_SfAlloc(a_self, a_size, a_align);
			}
			const auto site = _ReturnAddress();
			const auto stack = Config::Get().scaleformCaptureStacks ? CaptureStackIndex(1) : 0;
			auto*      result = o_SfAlloc(a_self, a_size, a_align);
			RecordScaleformAlloc(result, a_size, site, stack);
			return result;
		}

		void* hk_SfAlloc1(void* a_self, std::size_t a_size)
		{
			if (!ScaleformTrackingEnabled()) {
				return o_SfAlloc1(a_self, a_size);
			}
			const auto site = _ReturnAddress();
			const auto stack = Config::Get().scaleformCaptureStacks ? CaptureStackIndex(1) : 0;
			auto*      result = o_SfAlloc1(a_self, a_size);
			RecordScaleformAlloc(result, a_size, site, stack);
			return result;
		}

		void* hk_SfAllocAuto(void* a_self, const void* a_object, std::size_t a_size, std::size_t a_align)
		{
			if (!ScaleformTrackingEnabled()) {
				return o_SfAllocAuto(a_self, a_object, a_size, a_align);
			}
			const auto site = _ReturnAddress();
			const auto stack = Config::Get().scaleformCaptureStacks ? CaptureStackIndex(1) : 0;
			auto*      result = o_SfAllocAuto(a_self, a_object, a_size, a_align);
			RecordScaleformAlloc(result, a_size, site, stack);
			return result;
		}

		void* hk_SfAllocAuto1(void* a_self, const void* a_object, std::size_t a_size)
		{
			if (!ScaleformTrackingEnabled()) {
				return o_SfAllocAuto1(a_self, a_object, a_size);
			}
			const auto site = _ReturnAddress();
			const auto stack = Config::Get().scaleformCaptureStacks ? CaptureStackIndex(1) : 0;
			auto*      result = o_SfAllocAuto1(a_self, a_object, a_size);
			RecordScaleformAlloc(result, a_size, site, stack);
			return result;
		}

		void hk_SfFree(void* a_self, void* a_mem)
		{
			if (!a_mem || !ScaleformTrackingEnabled()) {
				o_SfFree(a_self, a_mem);
				return;
			}
			const auto site = _ReturnAddress();
			const auto stack = Config::Get().scaleformCaptureStacks ? CaptureStackIndex(1) : 0;
			const auto tick = NowTick();

			if (!RecordScaleformFreeBeforePoison(a_mem, site, stack)) {
				return;  // fail safe: double free
			}

			const auto vtableAtFree = SafeReadFirstQword(a_mem);
			const auto size = KnownScaleformSize(reinterpret_cast<std::uintptr_t>(a_mem));

			std::uint32_t poisonIndex = 0;
			if (TryPoisonOnFree(a_mem, a_self, size, site, stack, tick, vtableAtFree, poisonIndex)) {
				RecordScaleformFree(a_mem, size, vtableAtFree, site, stack, tick, poisonIndex);
				return;  // real free withheld; a later call through the block hits poison
			}

			RecordScaleformFree(a_mem, size, vtableAtFree, site, stack, tick, 0);
			o_SfFree(a_self, a_mem);
		}

		void* hk_SfRealloc(void* a_self, void* a_oldMem, std::size_t a_newSize)
		{
			if (!ScaleformTrackingEnabled()) {
				return o_SfRealloc(a_self, a_oldMem, a_newSize);
			}
			const auto site = _ReturnAddress();
			const auto stack = Config::Get().scaleformCaptureStacks ? CaptureStackIndex(1) : 0;
			auto*      result = o_SfRealloc(a_self, a_oldMem, a_newSize);
			if (result) {
				if (a_oldMem) {
					AllocationInfo old;
					ShadowLedger::Get().Erase(reinterpret_cast<std::uintptr_t>(a_oldMem), old);
				}
				RecordScaleformAlloc(result, a_newSize, site, stack);
			}
			return result;
		}

		// --- GFxResourceWeakLib context -----------------------------------
		//
		// Low-frequency (menu load/close), so recording is free relative to the
		// heap hooks. The event ring is bounded and evicts oldest-first.

		[[nodiscard]] bool WeakLibTrackingEnabled()
		{
			const auto& config = Config::Get();
			return config.enabled && config.weakLibHooksEnabled && config.ledgerEnabled;
		}

		void RecordWeakLibEvent(WeakLibEventKind a_kind, void* a_resource, void* a_site)
		{
			if (!a_resource) {
				return;
			}
			const auto resource = reinterpret_cast<std::uintptr_t>(a_resource);

			WeakLibEvents::Get().Record(a_kind, resource, a_site, NowTick(), ::GetCurrentThreadId());

			// Refresh the last vtable seen on this live resource, so the verdict
			// can tell "changed since we last saw it" from "always garbage".
			AllocationInfo info;
			if (ShadowLedger::Get().Find(resource, info) && !(info.flags & kFlagFreed)) {
				const auto seen = SafeReadFirstQword(a_resource);
				if (seen && IsPlausibleVTable(seen)) {
					info.lastKnownVtable = seen;
					if ((info.flags & kFlagScaleform) == 0) {
						info.flags |= kFlagScaleform;  // it is a Scaleform resource now
					}
					ShadowLedger::Get().Insert(resource, info);
				}
			}
		}

		std::uint32_t hk_WlAddRef(void* a_resource)
		{
			if (WeakLibTrackingEnabled()) {
				RecordWeakLibEvent(WeakLibEventKind::kAddRef, a_resource, _ReturnAddress());
			}
			return o_WlAddRef(a_resource);
		}

		void hk_WlPin(void* a_weakLib, void* a_resource)
		{
			if (WeakLibTrackingEnabled()) {
				RecordWeakLibEvent(WeakLibEventKind::kPin, a_resource, _ReturnAddress());
			}
			o_WlPin(a_weakLib, a_resource);
		}

		void hk_WlRemove(void* a_weakLib, void* a_resource)
		{
			if (WeakLibTrackingEnabled()) {
				RecordWeakLibEvent(WeakLibEventKind::kRemoveOnRelease, a_resource, _ReturnAddress());
			}
			o_WlRemove(a_weakLib, a_resource);
		}

		void hk_WlUnpin(void* a_weakLib, void* a_resource)
		{
			if (WeakLibTrackingEnabled()) {
				RecordWeakLibEvent(WeakLibEventKind::kUnpin, a_resource, _ReturnAddress());
			}
			o_WlUnpin(a_weakLib, a_resource);
		}

		// --- committed-table verification ---------------------------------
		//
		// Every hook target is named in Hooks/HookTargets.def, which is the only
		// place ids live. Before any detour is created we resolve each target
		// through the Address Library, check the vtable slot for virtual targets,
		// and hash the bytes at the target against the committed table for this
		// exact build. A mismatch REFUSES that hook and marks the plugin DEGRADED:
		// the game keeps running, but nothing unverifiable is ever patched.

		[[nodiscard]] std::uint64_t ModuleImageSize()
		{
			const auto  base = REL::Module::get().base();
			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
			const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
			return nt->OptionalHeader.SizeOfImage;
		}

		[[nodiscard]] ModuleIdentity ReadModuleIdentity()
		{
			ModuleIdentity identity;
			identity.sizeOfImage = ModuleImageSize();

			const auto  base = REL::Module::get().base();
			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
			const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
			identity.timeDateStamp = nt->FileHeader.TimeDateStamp;

			char path[MAX_PATH]{};
			if (::GetModuleFileNameA(nullptr, path, MAX_PATH) != 0) {
				WIN32_FILE_ATTRIBUTE_DATA data{};
				if (::GetFileAttributesExA(path, GetFileExInfoStandard, &data)) {
					identity.size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
				}
			}
			return identity;
		}

		// A bad pointer must never turn the verifier into the second fault.
		[[nodiscard]] bool SafeRead(const void* a_src, std::uint8_t* a_out, std::size_t a_size)
		{
			__try {
				std::memcpy(a_out, a_src, a_size);
				return true;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return false;
			}
		}

		class EngineResolver final : public TargetResolver
		{
		public:
			[[nodiscard]] std::uint64_t Base() const override { return REL::Module::get().base(); }

			[[nodiscard]] bool ResolveId(std::uint64_t a_id, std::uint64_t& a_rvaOut) const override
			{
				const auto address = REL::RelocationID(0, a_id).address();
				if (address == 0 || address < Base()) {
					return false;
				}
				a_rvaOut = address - Base();
				return true;
			}

			[[nodiscard]] bool ReadBytes(std::uint64_t a_rva, std::uint8_t* a_out, std::size_t a_size) const override
			{
				const auto imageSize = ModuleImageSize();
				if (a_size == 0 || a_rva >= imageSize || a_size > imageSize - a_rva) {
					return false;
				}
				return SafeRead(reinterpret_cast<const void*>(Base() + a_rva), a_out, a_size);
			}
		};

		struct TargetStatus
		{
			const HookTableRecord* record = nullptr;
			TargetCheck            check;
			std::uint64_t          address = 0;  // VA the detour will be created at
			bool                   installable = false;
		};

		std::array<TargetStatus, kHookTargetCount> g_targetStatus{};
		std::size_t                                g_installed = 0;

		// The tables travel inside the DLL (HookTableData.gen.h), so a DLL-only
		// install still has the verified bytes. There is deliberately no on-disk
		// table that could be missing or edited out from under the check; the
		// committed JSON stays the reviewable source of truth and CI proves the
		// embedded copy is byte-identical to it.
		[[nodiscard]] const HookTable* SelectHookTable(const ModuleIdentity& a_actual)
		{
			static std::vector<HookTable> tables;
			static bool                   populated = false;

			if (!populated) {
				populated = true;
				for (std::size_t i = 0; i < kEmbeddedHookTableCount; ++i) {
					HookTable   table;
					std::string error;
					if (!ParseHookTable(kEmbeddedHookTables[i].json, table, error)) {
						logger::error("hook table {}: {}", kEmbeddedHookTables[i].source, error);
						Health::Degrade(std::string("hook table ") + kEmbeddedHookTables[i].source +
										" failed to parse: " + error);
						continue;
					}
					table.source = kEmbeddedHookTables[i].source;
					tables.push_back(std::move(table));
				}
			}

			for (const auto& table : tables) {
				if (IdentityMatches(table.identity, a_actual)) {
					logger::info("hook table {}: {} {} (sha256 {}...) identity matches the running binary",
						table.source, table.identity.module, table.identity.version,
						table.identity.sha256.substr(0, 16));
					return &table;
				}
			}
			return nullptr;
		}

		void VerifyAllTargets(const HookTable* a_table, const TargetResolver& a_resolver)
		{
			for (std::size_t i = 0; i < kHookTargetCount; ++i) {
				const auto& target = kHookTargets[i];
				auto&       status = g_targetStatus[i];

				if (a_table == nullptr) {
					continue;  // no table matched: already reported and DEGRADED
				}

				const auto* record = a_table->Find(target.name);
				if (record == nullptr) {
					status.check.verdict = TargetVerdict::kNoRecord;
					logger::error("hook {}: no entry in {} - hook disabled", target.name, a_table->source);
					Health::Degrade(std::string("hook ") + target.name + " has no verification entry");
					continue;
				}

				status.record = record;
				status.check = VerifyHookTarget(*record, a_resolver);
				if (!status.check.Verified()) {
					logger::error("hook {}: REFUSED - {} (rva 0x{:X}; expected fnv1a64 0x{:016X}, got 0x{:016X}); hook disabled",
						target.name, TargetVerdictName(status.check.verdict), status.check.rva,
						status.check.expectedHash, status.check.actualHash);
					Health::Degrade(std::string("hook ") + target.name + " not verified: " +
									TargetVerdictName(status.check.verdict));
					continue;
				}

				status.address = a_resolver.Base() + status.check.rva;
				status.installable = true;
				if (record->kind == HookKind::kVtable) {
					logger::info("hook {}: target verified (vtable {} slot {:#x} -> rva 0x{:X}, {} bytes, fnv1a64 0x{:016X})",
						target.name, record->vtable.name, record->vtable.slot, status.check.rva,
						record->prologueLength, record->prologueHash);
				} else {
					logger::info("hook {}: target verified (rva 0x{:X}, {} bytes, fnv1a64 0x{:016X})",
						target.name, status.check.rva, record->prologueLength, record->prologueHash);
				}
			}
		}

		// Escape hatch: resolve every target but verify nothing. Loud, and it
		// leaves the sentinel DEGRADED, so a run with it off cannot look healthy.
		void ResolveAllTargetsUnverified(const TargetResolver& a_resolver)
		{
			logger::warn("hook target verification is DISABLED ([Hooks] bVerifyTargets=0): hooks are installed at "
						 "whatever address the Address Library resolves, with no check that it is the verified function");
			Health::Degrade("hook target verification disabled by [Hooks] bVerifyTargets=0");
			for (std::size_t i = 0; i < kHookTargetCount; ++i) {
				const auto&   target = kHookTargets[i];
				auto&         status = g_targetStatus[i];
				std::uint64_t rva = 0;
				if (!a_resolver.ResolveId(target.aeId, rva)) {
					logger::error("hook {}: address library returned null (AE id {})", target.name, target.aeId);
					Health::Degrade(std::string("hook ") + target.name + " unresolved (AE id " +
									std::to_string(target.aeId) + ")");
					continue;
				}
				status.address = a_resolver.Base() + rva;
				status.installable = true;
			}
		}

		template <class T>
		bool InstallOne(HookTargetId a_id, void* a_detour, T* a_original)
		{
			const auto& target = GetHookTarget(a_id);
			const auto& status = g_targetStatus[static_cast<std::size_t>(a_id)];
			if (!status.installable) {
				return false;  // the reason was already logged during verification
			}

			const auto hookStatus = MH_CreateHook(reinterpret_cast<LPVOID>(status.address), a_detour,
				reinterpret_cast<LPVOID*>(a_original));
			if (hookStatus != MH_OK) {
				logger::error("hook {}: MH_CreateHook failed ({})", target.name, MH_StatusToString(hookStatus));
				Health::Degrade(std::string("hook ") + target.name + " MH_CreateHook failed");
				return false;
			}

			++g_installed;
			return true;
		}
	}

	bool InstallHooks()
	{
		const auto status = MH_Initialize();
		if (status != MH_OK) {
			logger::error("MH_Initialize failed ({})", MH_StatusToString(status));
			Health::Degrade("MH_Initialize failed");
			return false;
		}

		const auto& config = Config::Get();

		// The committed table is AE-only, matching the existing convention: the SE
		// ids recorded in HookTargets.def are provenance, not a verified claim.
		if (REL::Module::GetRuntime() != REL::Module::Runtime::AE) {
			logger::error("hook target verification is AE-only (the committed table covers 1.7.104.0); the running "
						  "runtime is not AE - ALL hooks disabled");
			Health::Degrade("hook target verification is AE-only and this is not an AE runtime");
		} else {
			EngineResolver resolver;
			const auto     actual = ReadModuleIdentity();
			logger::info("module identity: size {} timestamp 0x{:X} sizeofimage 0x{:X}",
				actual.size, actual.timeDateStamp, actual.sizeOfImage);

			if (!config.verifyTargets) {
				ResolveAllTargetsUnverified(resolver);
			} else {
				const auto* table = SelectHookTable(actual);
				if (table == nullptr) {
					logger::error("hook target mismatch: this SkyrimSE.exe is not the build this revision was verified "
								  "against (running size {} timestamp 0x{:X} sizeofimage 0x{:X}); ALL hooks disabled. "
								  "Regenerate hooks/ with tools/gen-hooktable.py for this build.",
						actual.size, actual.timeDateStamp, actual.sizeOfImage);
					Health::Degrade("running SkyrimSE.exe is not the verified build - all hooks disabled");
				}
				VerifyAllTargets(table, resolver);
			}
		}

		// MemoryManager: the engine allocation facade (not virtual).
		InstallOne(HookTargetId::kMemoryManagerAllocate, reinterpret_cast<void*>(&hk_Allocate), &o_Allocate);
		InstallOne(HookTargetId::kMemoryManagerDeallocate, reinterpret_cast<void*>(&hk_Deallocate), &o_Deallocate);
		InstallOne(HookTargetId::kMemoryManagerReallocate, reinterpret_cast<void*>(&hk_Reallocate), &o_Reallocate);

		if (config.refCountGuardEnabled) {
			InstallOne(HookTargetId::kGRefCountImplRelease, reinterpret_cast<void*>(&hk_Release), &o_Release);
		}

		// Scaleform/GFx heap (GMemoryHeapPT), all six reached through the engine's
		// own ??_7GMemoryHeapPT vtable.
		if (config.scaleformHeapEnabled) {
			InstallOne(HookTargetId::kSfAlloc, reinterpret_cast<void*>(&hk_SfAlloc), &o_SfAlloc);
			InstallOne(HookTargetId::kSfAlloc1, reinterpret_cast<void*>(&hk_SfAlloc1), &o_SfAlloc1);
			InstallOne(HookTargetId::kSfAllocAuto, reinterpret_cast<void*>(&hk_SfAllocAuto), &o_SfAllocAuto);
			InstallOne(HookTargetId::kSfAllocAuto1, reinterpret_cast<void*>(&hk_SfAllocAuto1), &o_SfAllocAuto1);
			InstallOne(HookTargetId::kSfRealloc, reinterpret_cast<void*>(&hk_SfRealloc), &o_SfRealloc);
			InstallOne(HookTargetId::kSfFree, reinterpret_cast<void*>(&hk_SfFree), &o_SfFree);
		}

		// GFxResourceWeakLib context.
		if (config.weakLibHooksEnabled) {
			InstallOne(HookTargetId::kWlAddRef, reinterpret_cast<void*>(&hk_WlAddRef), &o_WlAddRef);
			InstallOne(HookTargetId::kWlPin, reinterpret_cast<void*>(&hk_WlPin), &o_WlPin);
			InstallOne(HookTargetId::kWlRemove, reinterpret_cast<void*>(&hk_WlRemove), &o_WlRemove);
			InstallOne(HookTargetId::kWlUnpin, reinterpret_cast<void*>(&hk_WlUnpin), &o_WlUnpin);
		}

		if (g_installed == 0) {
			logger::error("no hooks were installed - HeapSentinel is running, but blind");
			Health::Degrade("no hooks installed");
			return false;
		}

		const auto enable = MH_EnableHook(MH_ALL_HOOKS);
		if (enable != MH_OK) {
			logger::error("MH_EnableHook failed ({})", MH_StatusToString(enable));
			Health::Degrade("MH_EnableHook failed");
			return false;
		}

		logger::info("{} hooks installed and enabled of {} targets", g_installed, kHookTargetCount);
		// A run that degraded nothing is GREEN, not UNKNOWN: silence must never be
		// ambiguous, and "unknown" would be indistinguishable from "never set".
		if (Health::State() == ipc::HealthState::kUnknown) {
			Health::SetState(ipc::HealthState::kGreen, "all hook targets verified for this build");
		}
		logger::info("health: {}", Health::Line());
		return true;
	}

	void RemoveHooks()
	{
		MH_DisableHook(MH_ALL_HOOKS);
		MH_Uninitialize();
	}
}