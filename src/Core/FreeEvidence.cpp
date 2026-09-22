#include "Core/FreeEvidence.h"

#include <cstdio>

namespace hs
{
	const char* FreeFamilyTag(FreeHookFamily a_family)
	{
		switch (a_family) {
		case FreeHookFamily::kMemoryManager:
			return "MM";
		case FreeHookFamily::kScaleform:
			return "SF";
		default:
			return "??";
		}
	}

	std::string DescribeAllocationFlags(std::uint32_t a_flags)
	{
		std::string names;
		const auto  add = [&](std::uint32_t a_bit, const char* a_name) {
			if ((a_flags & a_bit) != 0) {
				if (!names.empty()) {
					names += ',';
				}
				names += a_name;
			}
		};

		add(kFlagLive, "live");
		add(kFlagSampled, "sampled");
		add(kFlagFreed, "freed");
		add(kFlagScaleform, "scaleform");
		add(kFlagPoisoned, "poisoned");
		add(kFlagFreedByMM, "freed_by_mm");
		add(kFlagFreedBySF, "freed_by_sf");

		if (names.empty()) {
			names = "none";
		}

		char buffer[24]{};
		std::snprintf(buffer, sizeof(buffer), "0x%X", a_flags);
		return std::string(buffer) + "(" + names + ")";
	}

	FreeHookFamily FirstFreeFamily(const AllocationInfo& a_info)
	{
		if ((a_info.flags & kFlagFreedBySF) != 0) {
			return FreeHookFamily::kScaleform;
		}
		if ((a_info.flags & kFlagFreedByMM) != 0) {
			return FreeHookFamily::kMemoryManager;
		}
		return FreeHookFamily::kUnknown;
	}

	std::string FormatDoubleFreeEvidence(const AllocationInfo& a_info, FreeHookFamily a_secondFamily)
	{
		char buffer[640]{};
		// The temporary from DescribeAllocationFlags() lives until the end of the
		// snprintf full-expression, so its c_str() is valid here.
		std::snprintf(buffer, sizeof(buffer),
			"allocSite=0x%llX allocTick=%llu allocStack=%u flags=%s firstFreeBy=%s firstFreeSite=0x%llX firstFreeTick=%llu firstFreeStack=%u secondFreeBy=%s",
			static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a_info.allocSite)),
			static_cast<unsigned long long>(a_info.allocTick), a_info.allocStack,
			DescribeAllocationFlags(a_info.flags).c_str(),
			FreeFamilyTag(FirstFreeFamily(a_info)),
			static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a_info.freeSite)),
			static_cast<unsigned long long>(a_info.freeTick), a_info.freeStack,
			FreeFamilyTag(a_secondFamily));
		return buffer;
	}
}