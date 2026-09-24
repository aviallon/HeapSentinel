#if defined(HS_NO_PCH)
#	include "Core/WatchpointReports.h"

#	include <cstdio>
#else
#	include "PCH.h"

#	include "Core/WatchpointReports.h"

#	include <cstdio>
#endif

namespace hs
{
	WatchpointReports& WatchpointReports::Get()
	{
		static WatchpointReports reports;
		return reports;
	}

	std::uint64_t WatchpointReports::VersionFor(std::uint64_t a_seq, bool a_writing) noexcept
	{
		return (a_seq << 1) | (a_writing ? 1ull : 0ull);
	}

	std::uint64_t WatchpointReports::SeqOfVersion(std::uint64_t a_version) noexcept
	{
		return a_version >> 1;
	}

	bool WatchpointReports::VersionIsWriting(std::uint64_t a_version) noexcept
	{
		return (a_version & 1ull) != 0;
	}

	std::size_t WatchpointReports::NextPow2(std::size_t a_value) noexcept
	{
		std::size_t result = 1;
		while (result < a_value) {
			result <<= 1;
		}
		return result;
	}

	void WatchpointReports::Init(std::size_t a_capacity) noexcept
	{
		_capacity = NextPow2(a_capacity < 2 ? 2 : a_capacity);
		_slots = std::make_unique<Slot[]>(_capacity);
		for (std::size_t i = 0; i < _capacity; ++i) {
			_slots[i].version.store(0, std::memory_order_relaxed);
		}
		_writeCursor.store(0, std::memory_order_relaxed);
		_readCursor.store(0, std::memory_order_relaxed);
		_recorded.store(0, std::memory_order_relaxed);
		_dropped.store(0, std::memory_order_relaxed);
		_ready.store(true, std::memory_order_release);
	}

	void WatchpointReports::Shutdown() noexcept
	{
		_ready.store(false, std::memory_order_release);
		_slots.reset();
		_capacity = 0;
		_writeCursor.store(0, std::memory_order_relaxed);
		_readCursor.store(0, std::memory_order_relaxed);
	}

	void WatchpointReports::Record(const WatchpointReport& a_report) noexcept
	{
		if (!_ready.load(std::memory_order_acquire) || _capacity == 0) {
			return;
		}

		const auto seq = _writeCursor.fetch_add(1, std::memory_order_relaxed) + 1;
		auto&      slot = _slots[seq & (_capacity - 1)];

		slot.version.store(VersionFor(seq, true), std::memory_order_relaxed);
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.report = a_report;
		slot.report.seq = seq;
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.version.store(VersionFor(seq, false), std::memory_order_release);

		_recorded.fetch_add(1, std::memory_order_relaxed);

		// Overwrote a record the drainer had not taken yet.
		const auto read = _readCursor.load(std::memory_order_relaxed);
		if (seq > _capacity && (seq - _capacity) > read) {
			_dropped.fetch_add(1, std::memory_order_relaxed);
		}
	}

	std::size_t WatchpointReports::Drain(WatchpointReport* a_out, std::size_t a_max) noexcept
	{
		if (!_ready.load(std::memory_order_acquire) || _capacity == 0 || a_max == 0) {
			return 0;
		}

		const auto written = _writeCursor.load(std::memory_order_acquire);
		auto       read = _readCursor.load(std::memory_order_relaxed);

		// If the writer ran ahead of the reader, the records we missed are gone.
		// Advance the cursor and count the loss rather than returning stale data.
		const auto oldestLive = (written > _capacity) ? (written - _capacity + 1) : 1;
		if (oldestLive > read + 1) {
			_dropped.fetch_add(oldestLive - read - 1, std::memory_order_relaxed);
			read = oldestLive - 1;
			_readCursor.store(read, std::memory_order_relaxed);
		}

		std::size_t copied = 0;
		while (copied < a_max && read < written) {
			const auto seq = read + 1;
			const auto& slot = _slots[seq & (_capacity - 1)];

			const auto v1 = slot.version.load(std::memory_order_acquire);
			if (VersionIsWriting(v1) || SeqOfVersion(v1) != seq) {
				break;  // still being written, or overwritten
			}
			WatchpointReport copy = slot.report;
			std::atomic_signal_fence(std::memory_order_seq_cst);
			const auto v2 = slot.version.load(std::memory_order_acquire);
			if (v1 != v2) {
				break;  // torn
			}

			a_out[copied++] = copy;
			++read;
		}
		_readCursor.store(read, std::memory_order_relaxed);
		return copied;
	}

	void WatchpointReports::NoteUnattributedMeasured(DebugRegisterMeasurement a_measurement) noexcept
	{
		switch (a_measurement) {
		case DebugRegisterMeasurement::kReadFailed:
			_drReadFailed.fetch_add(1, std::memory_order_relaxed);
			break;
		case DebugRegisterMeasurement::kReadZero:
			_drReadZero.fetch_add(1, std::memory_order_relaxed);
			break;
		default:
			break;
		}
	}

	std::size_t WatchpointReports::Count() const noexcept
	{
		const auto written = _writeCursor.load(std::memory_order_acquire);
		const auto read = _readCursor.load(std::memory_order_acquire);
		const auto pending = written - read;
		return static_cast<std::size_t>(pending < _capacity ? pending : _capacity);
	}

	void WatchpointReports::ResetForTesting() noexcept
	{
		if (_capacity == 0) {
			Init(64);
			return;
		}
		for (std::size_t i = 0; i < _capacity; ++i) {
			_slots[i].version.store(0, std::memory_order_relaxed);
			_slots[i].report = WatchpointReport{};
		}
		_writeCursor.store(0, std::memory_order_relaxed);
		_readCursor.store(0, std::memory_order_relaxed);
		_recorded.store(0, std::memory_order_relaxed);
		_dropped.store(0, std::memory_order_relaxed);
		ResetSuppressionCountersForTesting();
	}

	std::size_t EncodeWatchpointReport(const WatchpointReport& a_report, char* a_buffer, std::size_t a_size) noexcept
	{
		if (a_buffer == nullptr || a_size == 0) {
			return 0;
		}
		const auto written = std::snprintf(a_buffer, a_size,
			"slot=%u watched=0x%llX before=0x%llX after=0x%llX%s writer_rip=0x%llX dr6=0x%X dr7=0x%X tid=%u armed_tick=%llu trap_tick=%llu stale_arm=%d table=0x%llX free_tick=%llu unattributed=%d ever_armed=0x%X any_dr=%d dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX",
			a_report.slotIndex,
			static_cast<unsigned long long>(a_report.watchedAddress),
			static_cast<unsigned long long>(a_report.valueAtArm),
			static_cast<unsigned long long>(a_report.valueAfterWrite),
			(a_report.flags & kWatchReportValueUnreadable) != 0 ? "(unreadable)" : "",
			static_cast<unsigned long long>(a_report.writerRip),
			a_report.dr6,
			a_report.dr7,
			a_report.threadId,
			static_cast<unsigned long long>(a_report.armedTick),
			static_cast<unsigned long long>(a_report.tick),
			(a_report.flags & kWatchReportStaleArm) != 0 ? 1 : 0,
			static_cast<unsigned long long>(a_report.tableAddress),
			static_cast<unsigned long long>(a_report.freeTick),
			(a_report.flags & kWatchReportUnattributed) != 0 ? 1 : 0,
			a_report.everArmedMask,
			a_report.anyDrProgrammed ? 1 : 0,
			static_cast<unsigned long long>(a_report.drAddress[0]),
			static_cast<unsigned long long>(a_report.drAddress[1]),
			static_cast<unsigned long long>(a_report.drAddress[2]),
			static_cast<unsigned long long>(a_report.drAddress[3]));

		if (written < 0) {
			return 0;
		}
		const auto haveDr = a_report.drReadSource != kDrSourceNone || a_report.drReadStatus != kDrReadNotAttempted;
		const auto haveFreeSource = a_report.freeTickSource != 0;  // FreeTickSource::kNone == 0
		if (!haveDr && !haveFreeSource) {
			return static_cast<std::size_t>(written);
		}

		// 0.6.4 FIX A/B, second line: HOW the DR fields above were obtained, and
		// WHICH free the classifier used. Kept on its own line so a record with no
		// provenance (or a reader grepping the 0.6.3 field order) is unchanged.
		const char* source = "none";
		switch (a_report.drReadSource) {
		case kDrSourceExceptionContext:
			source = "exception-record";
			break;
		case kDrSourceCurrentThread:
			source = "faulting-thread-read(no-suspend)";
			break;
		default:
			break;
		}
		const char* status = "not-attempted";
		switch (a_report.drReadStatus) {
		case kDrReadOk:
			status = "ok";
			break;
		case kDrReadFailed:
			status = "FAILED";
			break;
		default:
			break;
		}

		std::size_t offset = static_cast<std::size_t>(written);
		if (offset >= a_size) {
			offset = a_size - 1;
		}
		const auto appended = std::snprintf(a_buffer + offset, a_size - offset,
			"\n  dr_used=%s dr_read=%s dr_err=%u disagrees=%d trap_flag=%d free_from=%s\n"
			"    exception-record: dr6=0x%X dr7=0x%X dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX\n"
			"    faulting-thread-read: dr6=0x%X dr7=0x%X dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX eflags=0x%X",
			source, status, a_report.drReadError,
			(a_report.drReadFlags & kWatchReportDrContextDisagrees) != 0 ? 1 : 0,
			(a_report.flags & kWatchReportTrapFlagSet) != 0 ? 1 : 0,
			FreeTickSourceName(static_cast<FreeTickSource>(a_report.freeTickSource)),
			a_report.contextDr6, a_report.contextDr7,
			static_cast<unsigned long long>(a_report.contextDrAddress[0]),
			static_cast<unsigned long long>(a_report.contextDrAddress[1]),
			static_cast<unsigned long long>(a_report.contextDrAddress[2]),
			static_cast<unsigned long long>(a_report.contextDrAddress[3]),
			a_report.threadDr6, a_report.threadDr7,
			static_cast<unsigned long long>(a_report.threadDrAddress[0]),
			static_cast<unsigned long long>(a_report.threadDrAddress[1]),
			static_cast<unsigned long long>(a_report.threadDrAddress[2]),
			static_cast<unsigned long long>(a_report.threadDrAddress[3]),
			a_report.contextEFlags);
		if (appended < 0) {
			return static_cast<std::size_t>(written);
		}
		return static_cast<std::size_t>(written) + static_cast<std::size_t>(appended);
	}
}