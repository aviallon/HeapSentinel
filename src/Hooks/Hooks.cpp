#include "PCH.h"

#include "Hooks/Hooks.h"

#include "Core/GuardedPool.h"
#include "Core/ModuleMap.h"
#include "Core/Report.h"
#include "Core/ShadowLedger.h"
#include "Core/StackCapture.h"
#include "Config.h"

#include <MinHook.h>
#include <intrin.h>

#include <cstdio>

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
			ShadowLedger::Get().Insert(info.ptr, info);
		}

		// Returns false when the block is already known to have been freed; the
		// caller then refuses to call the original (fail safe). An untracked block
		// is recorded as a freed-only entry: that is the provenance the stale
		// GFxResource crash needs ("object X was freed by this stack"), and it is
		// the only way to attribute objects allocated before the hooks were live.
		[[nodiscard]] bool RecordScaleformFree(void* a_mem, void* a_site, std::uint32_t a_stack)
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
				info.flags |= kFlagFreed | kFlagScaleform;
				info.freeSite = a_site;
				info.freeStack = a_stack;
				ShadowLedger::Get().Insert(address, info);
			} else {
				AllocationInfo fresh;
				fresh.ptr = address;
				fresh.size = 0;
				fresh.threadId = ::GetCurrentThreadId();
				fresh.flags = kFlagFreed | kFlagScaleform;
				fresh.freeSite = a_site;
				fresh.freeStack = a_stack;
				ShadowLedger::Get().Insert(address, fresh);
			}
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
			if (!RecordScaleformFree(a_mem, site, stack)) {
				return;  // fail safe
			}
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

		template <class T>
		bool InstallOne(const char* a_name, std::uint64_t a_se, std::uint64_t a_ae, void* a_detour, T* a_original)
		{
			const REL::RelocationID id{ a_se, a_ae };
			const auto             address = id.address();
			if (!address) {
				logger::error("hook {}: address library returned null", a_name);
				return false;
			}

			const auto status = MH_CreateHook(reinterpret_cast<LPVOID>(address), a_detour, reinterpret_cast<LPVOID*>(a_original));
			if (status != MH_OK) {
				logger::error("hook {}: MH_CreateHook failed ({})", a_name, MH_StatusToString(status));
				return false;
			}

			logger::info("hook {}: 0x{:X}", a_name, address);
			return true;
		}
	}

	bool InstallHooks()
	{
		const auto status = MH_Initialize();
		if (status != MH_OK) {
			logger::error("MH_Initialize failed ({})", MH_StatusToString(status));
			return false;
		}

		const auto& config = Config::Get();

		// MemoryManager: 66859/68115 Allocate, 66861/68117 Deallocate, 66860/68116 Reallocate.
		InstallOne("MemoryManager::Allocate", 66859, 68115, reinterpret_cast<void*>(&hk_Allocate), &o_Allocate);
		InstallOne("MemoryManager::Deallocate", 66861, 68117, reinterpret_cast<void*>(&hk_Deallocate), &o_Deallocate);
		InstallOne("MemoryManager::Reallocate", 66860, 68116, reinterpret_cast<void*>(&hk_Reallocate), &o_Reallocate);

		// GRefCountImpl::Release (82197 on AE).
		if (config.refCountGuardEnabled) {
			InstallOne("GRefCountImpl::Release", 0, 82197, reinterpret_cast<void*>(&hk_Release), &o_Release);
		}

		// Scaleform/GFx heap (GMemoryHeapPT). AE Address Library ids only; the SE
		// ids are not verified here, so (like the Release hook above) this is
		// AE-only. ids 84498/84499/84501/84502/84520/84540, verified against
		// versionlib-1-7-104-0.bin and the engine's own ??_7GMemoryHeapPT vtable.
		if (config.scaleformHeapEnabled) {
			InstallOne("GMemoryHeapPT::Alloc(size,align)", 0, 84498, reinterpret_cast<void*>(&hk_SfAlloc), &o_SfAlloc);
			InstallOne("GMemoryHeapPT::Alloc(size)", 0, 84499, reinterpret_cast<void*>(&hk_SfAlloc1), &o_SfAlloc1);
			InstallOne("GMemoryHeapPT::AllocAutoHeap(size,align)", 0, 84501, reinterpret_cast<void*>(&hk_SfAllocAuto), &o_SfAllocAuto);
			InstallOne("GMemoryHeapPT::AllocAutoHeap(size)", 0, 84502, reinterpret_cast<void*>(&hk_SfAllocAuto1), &o_SfAllocAuto1);
			InstallOne("GMemoryHeapPT::Realloc", 0, 84540, reinterpret_cast<void*>(&hk_SfRealloc), &o_SfRealloc);
			InstallOne("GMemoryHeapPT::Free", 0, 84520, reinterpret_cast<void*>(&hk_SfFree), &o_SfFree);
		}

		const auto enable = MH_EnableHook(MH_ALL_HOOKS);
		if (enable != MH_OK) {
			logger::error("MH_EnableHook failed ({})", MH_StatusToString(enable));
			return false;
		}

		logger::info("hooks installed and enabled");
		return true;
	}

	void RemoveHooks()
	{
		MH_DisableHook(MH_ALL_HOOKS);
		MH_Uninitialize();
	}
}
