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

		AllocateFn   o_Allocate = nullptr;
		DeallocateFn o_Deallocate = nullptr;
		ReallocateFn o_Reallocate = nullptr;
		ReleaseFn    o_Release = nullptr;

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
