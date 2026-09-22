#include "Core/ReportLog.h"

#include <cstdio>

namespace hs
{
	std::string BuildSessionHeader(std::string_view a_version, std::string_view a_buildId, std::uint64_t a_timestampMs)
	{
		char buffer[320]{};
		std::snprintf(buffer, sizeof(buffer), "===== HeapSentinel v%.*s session start (build %.*s) t=%llu ms =====",
			static_cast<int>(a_version.size()), a_version.data(),
			static_cast<int>(a_buildId.size()), a_buildId.data(),
			static_cast<unsigned long long>(a_timestampMs));
		return buffer;
	}

	std::string BuildSessionContext(std::string_view a_configSummary, std::uint64_t a_modlistHash, std::size_t a_moduleCount)
	{
		char buffer[512]{};
		std::snprintf(buffer, sizeof(buffer), "[session] config: %.*s ; modules=%zu modlistHash=0x%016llX",
			static_cast<int>(a_configSummary.size()), a_configSummary.data(),
			a_moduleCount, static_cast<unsigned long long>(a_modlistHash));
		return buffer;
	}
}