#pragma once

#include "Core/ShadowLedger.h"

#include <cstdint>
#include <string>

// Alloc-side evidence for a suspected double free.
//
// The v0.3.0 report carried only the block size and the two free sites, which is
// exactly why 142 reports could not be classified: a genuine second free, a
// recycled address and a nested observation of one logical free all look the
// same. Every double-free report now carries the allocation's site, epoch, stack
// index, flag word (was it Scaleform?) and which hook family recorded the first
// free and which is seeing the second.

namespace hs
{
	enum class FreeHookFamily : std::uint8_t
	{
		kUnknown = 0,
		kMemoryManager = 1,
		kScaleform = 2,
	};

	[[nodiscard]] const char* FreeFamilyTag(FreeHookFamily a_family);

	[[nodiscard]] std::string DescribeAllocationFlags(std::uint32_t a_flags);

	// The family that recorded the first free, recovered from the record's flags.
	[[nodiscard]] FreeHookFamily FirstFreeFamily(const AllocationInfo& a_info);

	[[nodiscard]] std::string FormatDoubleFreeEvidence(const AllocationInfo& a_info, FreeHookFamily a_secondFamily);
}