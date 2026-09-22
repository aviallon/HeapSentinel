#pragma once

#include <cstdint>
#include <string>
#include <string_view>

// How much a double-free report may be trusted, given what we know about the
// allocation facade we hooked.
//
// Under EngineFixes' `bOverrideMemoryManager` the game's MemoryManager is
// replaced, so "the function at our hook target" is no longer the game's
// function. A `[double-free]` produced from a hook chain we do not understand is
// exactly the failure this branch fixes. While the facade is unverified or
// overridden, the report is emitted under a DISTINCT kind so no reader can
// mistake it for a confident claim.

namespace hs
{
	enum class AllocatorConfidence : std::uint8_t
	{
		kUnknown = 0,   // not decided yet (before InstallHooks runs)
		kVerified,      // every MemoryManager target matched the committed table
		kUnverified,    // verification disabled, no table, or target not checked
		kOverridden,    // bytes at the target are NOT the committed game function
	};

	[[nodiscard]] const char* ConfidenceName(AllocatorConfidence a_confidence);

	// Only kVerified earns the bare "double-free" kind.
	[[nodiscard]] bool DoubleFreeIsTrustworthy(AllocatorConfidence a_confidence) noexcept;

	[[nodiscard]] std::string_view DoubleFreeReportKind(AllocatorConfidence a_confidence);

	// Default one-line reason, used when no explicit detail was recorded.
	[[nodiscard]] std::string_view ConfidenceReason(AllocatorConfidence a_confidence);

	// Set once, before the hooks are enabled. A later read is a relaxed atomic
	// load; the detail string is written once behind a mutex.
	void SetAllocatorConfidence(AllocatorConfidence a_confidence, std::string a_detail);

	[[nodiscard]] AllocatorConfidence GetAllocatorConfidence() noexcept;
	[[nodiscard]] std::string         GetAllocatorConfidenceDetail();

	// Tests only.
	void ResetAllocatorConfidenceForTesting() noexcept;
}