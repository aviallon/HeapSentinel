#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

// The reports log used to be opened with the spdlog truncate flag, so every
// launch destroyed the previous run's only evidence - which is why the v0.3.0
// flood could not be compared against an earlier run. It is now APPENDED to and
// rotated, and each session begins with a header so two runs can be told apart.

namespace hs
{
	// The reports log must never truncate. Pinned as a constant so a test (and a
	// reader) can see the intent rather than having to trust the sink call.
	inline constexpr bool kReportLogTruncates = false;

	// Rotation budget, and how the plugin decides. Kept pure so the decision is
	// testable off-game even though the actual rotation is done by spdlog's
	// rotating_file_sink.
	inline constexpr std::uint64_t kReportLogMaxBytes = 16ull << 20;  // 16 MiB
	inline constexpr int           kReportLogMaxFiles = 3;

	enum class ReportLogAction
	{
		kAppend,
		kRotate,
	};

	[[nodiscard]] constexpr ReportLogAction SelectReportLogAction(std::uint64_t a_currentBytes,
		std::uint64_t a_maxBytes) noexcept
	{
		return a_currentBytes >= a_maxBytes ? ReportLogAction::kRotate : ReportLogAction::kAppend;
	}

	// One line that starts a session: version + build id + timestamp, so two runs
	// in one appended file are distinguishable.
	[[nodiscard]] std::string BuildSessionHeader(std::string_view a_version, std::string_view a_buildId,
		std::uint64_t a_timestampMs);

	// The config + modlist part of the header, written once the config is loaded
	// and the module list is complete.
	[[nodiscard]] std::string BuildSessionContext(std::string_view a_configSummary, std::uint64_t a_modlistHash,
		std::size_t a_moduleCount);
}