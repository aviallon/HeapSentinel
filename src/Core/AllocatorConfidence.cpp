#include "Core/AllocatorConfidence.h"

#include <atomic>
#include <mutex>

namespace hs
{
	namespace
	{
		std::atomic<std::uint8_t> g_confidence{ static_cast<std::uint8_t>(AllocatorConfidence::kUnknown) };
		std::mutex                g_detailMutex;
		std::string               g_detail;
	}

	const char* ConfidenceName(AllocatorConfidence a_confidence)
	{
		switch (a_confidence) {
		case AllocatorConfidence::kVerified:
			return "verified";
		case AllocatorConfidence::kUnverified:
			return "unverified";
		case AllocatorConfidence::kOverridden:
			return "overridden";
		default:
			return "unknown";
		}
	}

	bool DoubleFreeIsTrustworthy(AllocatorConfidence a_confidence) noexcept
	{
		return a_confidence == AllocatorConfidence::kVerified;
	}

	std::string_view DoubleFreeReportKind(AllocatorConfidence a_confidence)
	{
		return DoubleFreeIsTrustworthy(a_confidence) ? std::string_view{ "double-free" }
													 : std::string_view{ "double-free-unverified" };
	}

	std::string_view ConfidenceReason(AllocatorConfidence a_confidence)
	{
		switch (a_confidence) {
		case AllocatorConfidence::kVerified:
			return "MemoryManager target matched the committed table for this build";
		case AllocatorConfidence::kOverridden:
			return "the bytes at the MemoryManager target are not the committed game function "
				   "(the allocator has been replaced, e.g. EngineFixes bOverrideMemoryManager)";
		case AllocatorConfidence::kUnverified:
			return "the MemoryManager target was not verified against the committed table";
		default:
			return "allocator confidence has not been established";
		}
	}

	void SetAllocatorConfidence(AllocatorConfidence a_confidence, std::string a_detail)
	{
		{
			const std::lock_guard lock(g_detailMutex);
			g_detail = std::move(a_detail);
		}
		g_confidence.store(static_cast<std::uint8_t>(a_confidence), std::memory_order_release);
	}

	AllocatorConfidence GetAllocatorConfidence() noexcept
	{
		return static_cast<AllocatorConfidence>(g_confidence.load(std::memory_order_acquire));
	}

	std::string GetAllocatorConfidenceDetail()
	{
		const std::lock_guard lock(g_detailMutex);
		return g_detail;
	}

	void ResetAllocatorConfidenceForTesting() noexcept
	{
		const std::lock_guard lock(g_detailMutex);
		g_detail.clear();
		g_confidence.store(static_cast<std::uint8_t>(AllocatorConfidence::kUnknown), std::memory_order_release);
	}
}