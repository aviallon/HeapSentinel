#if defined(HS_NO_PCH)
#	include "Core/Stats.h"

#	include "Core/Health.h"
#	include "Core/PoisonQuarantine.h"
#	include "Core/ScaleformFreeRing.h"
#	include "Core/ShadowLedger.h"
#	include "Core/WatchpointReports.h"
#	include "Core/WatchpointSlots.h"
#	include "Core/WeakLibEvents.h"

#	include <atomic>
#else
#	include "PCH.h"

#	include "Core/Stats.h"

#	include "Core/Health.h"
#	include "Core/PoisonQuarantine.h"
#	include "Core/ScaleformFreeRing.h"
#	include "Core/ShadowLedger.h"
#	include "Core/WatchpointReports.h"
#	include "Core/WatchpointSlots.h"
#	include "Core/WeakLibEvents.h"
#endif

#include <cstdio>

namespace hs
{
	namespace
	{
		std::atomic<bool> g_emittedAtDataLoad{ false };
		std::atomic<bool> g_emittedAtFirstReport{ false };
	}

	std::vector<std::string> FormatStats(const StatsSnapshot& a_s)
	{
		std::vector<std::string> lines;
		lines.reserve(6);

		{
			char buffer[256]{};
			std::snprintf(buffer, sizeof(buffer), "stats: %zu ledger entries, %llu insert failures, %llu writer drops (capacity %zu)",
				a_s.ledgerEntries, static_cast<unsigned long long>(a_s.insertFailures),
				static_cast<unsigned long long>(a_s.writerDrops), a_s.ledgerCapacity);
			lines.emplace_back(buffer);
		}

		{
			char buffer[320]{};
			std::snprintf(buffer, sizeof(buffer), "stats: scaleform free ring %zu/%zu records, %llu evictions, retention %s",
				a_s.ringCount, a_s.ringCapacity, static_cast<unsigned long long>(a_s.ringEvictions),
				a_s.haveRetention ? (std::to_string(a_s.retentionSeconds) + " s").c_str() : "n/a");
			lines.emplace_back(buffer);
		}

		{
			char buffer[256]{};
			std::snprintf(buffer, sizeof(buffer), "stats: poison quarantine %zu/%zu blocks, %zu KiB retained, %llu evictions",
				a_s.poisonCount, a_s.poisonBlocks, a_s.poisonKiB,
				static_cast<unsigned long long>(a_s.poisonEvictions));
			lines.emplace_back(buffer);
		}

		{
			char buffer[256]{};
			std::snprintf(buffer, sizeof(buffer), "stats: weaklib events %zu (capacity %zu)",
				a_s.weaklibCount, a_s.weaklibCapacity);
			lines.emplace_back(buffer);
		}

		{
			char buffer[256]{};
			std::snprintf(buffer, sizeof(buffer), "stats: bloom filters %zu KiB (ledger) + %zu KiB (free ring), %llu swaps",
				a_s.ledgerBloomKiB, a_s.ringBloomKiB, static_cast<unsigned long long>(a_s.bloomSwaps));
			lines.emplace_back(buffer);
		}

		{
			char buffer[320]{};
			std::snprintf(buffer, sizeof(buffer),
				"stats: hardware watchpoints %zu/%zu slot(s), %llu claims, %llu claim drops, %llu releases, %llu trips, %llu report(s), %llu report drop(s)",
				a_s.watchSlotsOccupied, kWatchpointSlotCount, static_cast<unsigned long long>(a_s.watchClaims),
				static_cast<unsigned long long>(a_s.watchClaimDrops), static_cast<unsigned long long>(a_s.watchReleases),
				static_cast<unsigned long long>(a_s.watchTrips), static_cast<unsigned long long>(a_s.watchReports),
				static_cast<unsigned long long>(a_s.watchReportDrops));
			lines.emplace_back(buffer);
		}

		lines.push_back("stats: health " + a_s.health);
		return lines;
	}

	StatsSnapshot GatherStats()
	{
		StatsSnapshot snapshot;

		snapshot.ledgerEntries = ShadowLedger::Get().Count();
		snapshot.ledgerCapacity = ShadowLedger::Get().Capacity();
		snapshot.insertFailures = ShadowLedger::Get().InsertFailures();
		snapshot.writerDrops = ShadowLedger::Get().WriterDrops();
		snapshot.ledgerBloomKiB = ShadowLedger::Get().BloomBytes() / 1024u;
		snapshot.bloomSwaps = ShadowLedger::Get().BloomSwaps();

		snapshot.ringCount = ScaleformFreeRing::Get().Count();
		snapshot.ringCapacity = ScaleformFreeRing::Get().Capacity();
		snapshot.ringEvictions = ScaleformFreeRing::Get().Evictions();
		snapshot.ringBloomKiB = ScaleformFreeRing::Get().BloomBytes() / 1024u;
		snapshot.bloomSwaps += ScaleformFreeRing::Get().BloomSwaps();

		std::uint64_t oldest = 0;
		std::uint64_t newest = 0;
		if (ScaleformFreeRing::Get().RetentionTicks(oldest, newest)) {
			snapshot.haveRetention = true;
			snapshot.retentionSeconds = (newest - oldest) / 1000u;
		}

		snapshot.poisonCount = PoisonQuarantine::Get().Count();
		snapshot.poisonBlocks = PoisonQuarantine::Get().RegionSize() / 0x1000u;
		snapshot.poisonKiB = PoisonQuarantine::Get().Bytes() / 1024u;
		snapshot.poisonEvictions = PoisonQuarantine::Get().Evictions();

		snapshot.weaklibCount = WeakLibEvents::Get().Count();
		snapshot.weaklibCapacity = WeakLibEvents::Get().Capacity();

		snapshot.watchSlotsOccupied = WatchpointSlots::Get().OccupiedCount();
		snapshot.watchClaims = WatchpointSlots::Get().Claims();
		snapshot.watchClaimDrops = WatchpointSlots::Get().ClaimDrops();
		snapshot.watchReleases = WatchpointSlots::Get().Releases();
		snapshot.watchTrips = WatchpointSlots::Get().Trips();
		snapshot.watchReports = WatchpointReports::Get().Recorded();
		snapshot.watchReportDrops = WatchpointReports::Get().Dropped();

		snapshot.health = Health::Line();
		return snapshot;
	}

	void LogStats(std::string_view a_reason)
	{
#if !defined(HS_NO_PCH)
		logger::info("stats: emitting ({})", a_reason);
		for (const auto& line : FormatStats(GatherStats())) {
			logger::info("{}", line);
		}
#else
		(void)a_reason;
#endif
	}

	bool ShouldEmitOnDataLoaded() noexcept
	{
		return !g_emittedAtDataLoad.exchange(true, std::memory_order_acq_rel);
	}

	bool ShouldEmitOnFirstReport() noexcept
	{
		return !g_emittedAtFirstReport.exchange(true, std::memory_order_acq_rel);
	}

	void ResetStatsScheduleForTesting() noexcept
	{
		g_emittedAtDataLoad.store(false, std::memory_order_relaxed);
		g_emittedAtFirstReport.store(false, std::memory_order_relaxed);
	}
}