#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Instrumentation stats. The v0.3.0 run's ~52 s session emitted NO stats line at
// all, so insert failures / writer drops / free-ring evictions were
// unmeasurable. The 60 s timer alone is not enough for short sessions: emit once
// at kDataLoaded and once on the first report as well.

namespace hs
{
	struct StatsSnapshot
	{
		std::size_t   ledgerEntries = 0;
		std::size_t   ledgerCapacity = 0;
		std::uint64_t insertFailures = 0;
		std::uint64_t writerDrops = 0;

		std::size_t   ringCount = 0;
		std::size_t   ringCapacity = 0;
		std::uint64_t ringEvictions = 0;
		bool          haveRetention = false;
		std::uint64_t retentionSeconds = 0;

		std::size_t   poisonCount = 0;
		std::size_t   poisonBlocks = 0;
		std::size_t   poisonKiB = 0;
		std::uint64_t poisonEvictions = 0;

		std::size_t   weaklibCount = 0;
		std::size_t   weaklibCapacity = 0;

		std::size_t   ledgerBloomKiB = 0;
		std::size_t   ringBloomKiB = 0;
		std::uint64_t bloomSwaps = 0;

		std::string health;
	};

	[[nodiscard]] std::vector<std::string> FormatStats(const StatsSnapshot& a_snapshot);
	[[nodiscard]] StatsSnapshot            GatherStats();

	// Gather + log, marked with why this emission happened.
	void LogStats(std::string_view a_reason);

	// One-shot schedule. Returns true exactly once per process for each event;
	// the 60 s timer is unconditional.
	[[nodiscard]] bool ShouldEmitOnDataLoaded() noexcept;
	[[nodiscard]] bool ShouldEmitOnFirstReport() noexcept;
	void               ResetStatsScheduleForTesting() noexcept;
}