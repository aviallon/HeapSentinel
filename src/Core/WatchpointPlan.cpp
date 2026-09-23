#if defined(HS_NO_PCH)
#	include "Core/WatchpointPlan.h"

#	include <algorithm>
#else
#	include "PCH.h"

#	include "Core/WatchpointPlan.h"
#endif

namespace hs
{
	namespace
	{
		[[nodiscard]] std::size_t NextPow2(std::size_t a_value) noexcept
		{
			std::size_t result = 1;
			while (result < a_value) {
				result <<= 1;
			}
			return result;
		}
	}

	void WatchpointPlan::Configure(WatchpointMode a_mode, std::uint32_t a_samplePrime, std::size_t a_maxPending) noexcept
	{
		_mode = a_mode;
		_prime = a_samplePrime == 0 ? kDefaultSamplePrime : a_samplePrime;
		_capacity = NextPow2(std::clamp<std::size_t>(a_maxPending, 1, kWatchpointMaxPending));
		_pending = std::make_unique<Candidate[]>(_capacity);
		_writeCursor.store(0, std::memory_order_relaxed);
		_readCursor.store(0, std::memory_order_relaxed);
		_considered.store(0, std::memory_order_relaxed);
		_selected.store(0, std::memory_order_relaxed);
		_filteredOut.store(0, std::memory_order_relaxed);
		_notSampled.store(0, std::memory_order_relaxed);
		_duplicates.store(0, std::memory_order_relaxed);
		_queueEvictions.store(0, std::memory_order_relaxed);
		_popped.store(0, std::memory_order_relaxed);
	}

	void WatchpointPlan::ResetForTesting() noexcept
	{
		if (_capacity == 0) {
			Configure(WatchpointMode::kSampleOnly, kDefaultSamplePrime, 16);
			return;
		}
		for (std::size_t i = 0; i < _capacity; ++i) {
			_pending[i].seq.store(0, std::memory_order_relaxed);
			_pending[i].ptr.store(0, std::memory_order_relaxed);
		}
		_writeCursor.store(0, std::memory_order_relaxed);
		_readCursor.store(0, std::memory_order_relaxed);
		_considered.store(0, std::memory_order_relaxed);
		_selected.store(0, std::memory_order_relaxed);
		_filteredOut.store(0, std::memory_order_relaxed);
		_notSampled.store(0, std::memory_order_relaxed);
		_duplicates.store(0, std::memory_order_relaxed);
		_queueEvictions.store(0, std::memory_order_relaxed);
		_popped.store(0, std::memory_order_relaxed);
	}

	bool WatchpointPlan::AlreadyQueued(std::uintptr_t a_ptr, std::uint64_t a_written) const noexcept
	{
		if (_capacity == 0) {
			return false;
		}
		// Bounded best-effort scan of the live window. A duplicate that slips
		// through under concurrency costs one slot, not correctness: the slot
		// table itself rejects the same address twice.
		constexpr std::size_t kMaxScan = 16;
		const auto            newest = a_written;
		const auto            oldest = (newest > _capacity) ? (newest - _capacity) : 0;
		std::size_t           scanned = 0;
		for (std::uint64_t seq = newest; seq > oldest && scanned < kMaxScan; --seq, ++scanned) {
			const auto& slot = _pending[seq & (_capacity - 1)];
			if (slot.seq.load(std::memory_order_acquire) != seq) {
				continue;  // overwritten; not a live candidate
			}
			if (slot.ptr.load(std::memory_order_relaxed) == a_ptr) {
				return true;
			}
		}
		return false;
	}

	WatchDecision WatchpointPlan::Consider(std::uintptr_t a_ptr, bool a_allocSiteMatch) noexcept
	{
		if (a_ptr == 0) {
			return WatchDecision::kFilteredOut;
		}
		_considered.fetch_add(1, std::memory_order_relaxed);

		bool selected = false;
		switch (_mode) {
		case WatchpointMode::kFilterOnly:
			selected = a_allocSiteMatch;
			if (!selected) {
				_filteredOut.fetch_add(1, std::memory_order_relaxed);
			}
			break;
		case WatchpointMode::kFilterPreferred:
			if (a_allocSiteMatch) {
				selected = true;
			} else if (ShouldWatchSample(a_ptr, _prime)) {
				selected = true;
			} else {
				_notSampled.fetch_add(1, std::memory_order_relaxed);
			}
			break;
		case WatchpointMode::kSampleOnly:
		default:
			selected = ShouldWatchSample(a_ptr, _prime);
			if (!selected) {
				_notSampled.fetch_add(1, std::memory_order_relaxed);
			}
			break;
		}

		if (!selected) {
			return _mode == WatchpointMode::kFilterOnly ? WatchDecision::kFilteredOut : WatchDecision::kNotSampled;
		}

		if (_capacity == 0) {
			return WatchDecision::kSelected;  // not configured; counted but not stored
		}

		const auto written = _writeCursor.load(std::memory_order_relaxed);
		if (AlreadyQueued(a_ptr, written)) {
			_duplicates.fetch_add(1, std::memory_order_relaxed);
			return WatchDecision::kDuplicate;
		}

		const auto seq = _writeCursor.fetch_add(1, std::memory_order_relaxed) + 1;

		// The ring overwrites its oldest unread entry. Count the loss rather than
		// pretending the queue absorbed it: the whole point of a bound is that it
		// is visible in the health line.
		const auto read = _readCursor.load(std::memory_order_relaxed);
		if (seq - read > _capacity) {
			_queueEvictions.fetch_add(1, std::memory_order_relaxed);
		}

		auto& slot = _pending[seq & (_capacity - 1)];
		slot.ptr.store(a_ptr, std::memory_order_relaxed);
		slot.seq.store(seq, std::memory_order_release);

		_selected.fetch_add(1, std::memory_order_relaxed);
		return WatchDecision::kSelected;
	}

	bool WatchpointPlan::PopCandidate(std::uintptr_t& a_out) noexcept
	{
		if (_capacity == 0) {
			return false;
		}

		const auto written = _writeCursor.load(std::memory_order_acquire);
		for (int attempt = 0; attempt < 4; ++attempt) {
			const auto read = _readCursor.load(std::memory_order_relaxed);
			if (read >= written) {
				return false;
			}

			const auto   seq = read + 1;
			const auto&  slot = _pending[seq & (_capacity - 1)];
			const auto   slotSeq = slot.seq.load(std::memory_order_acquire);
			if (slotSeq != seq) {
				// Overwritten before we consumed it. Skip to the oldest live entry
				// and count the skipped ones as evictions.
				const auto oldestLive = (written > _capacity) ? (written - _capacity + 1) : 1;
				if (oldestLive <= read) {
					return false;
				}
				_queueEvictions.fetch_add(oldestLive - read, std::memory_order_relaxed);
				_readCursor.store(oldestLive, std::memory_order_relaxed);
				continue;
			}

			const auto ptr = slot.ptr.load(std::memory_order_relaxed);
			_readCursor.store(seq, std::memory_order_relaxed);
			_popped.fetch_add(1, std::memory_order_relaxed);
			if (ptr != 0) {
				a_out = ptr;
				return true;
			}
		}
		return false;
	}

	std::size_t WatchpointPlan::PendingCount() const noexcept
	{
		const auto written = _writeCursor.load(std::memory_order_acquire);
		const auto read = _readCursor.load(std::memory_order_acquire);
		const auto pending = written - read;
		return static_cast<std::size_t>(pending < _capacity ? pending : _capacity);
	}

	WatchpointPlanStats WatchpointPlan::Stats() const noexcept
	{
		WatchpointPlanStats stats;
		stats.considered = _considered.load(std::memory_order_relaxed);
		stats.selected = _selected.load(std::memory_order_relaxed);
		stats.filteredOut = _filteredOut.load(std::memory_order_relaxed);
		stats.notSampled = _notSampled.load(std::memory_order_relaxed);
		stats.duplicates = _duplicates.load(std::memory_order_relaxed);
		stats.queueEvictions = _queueEvictions.load(std::memory_order_relaxed);
		stats.popped = _popped.load(std::memory_order_relaxed);
		return stats;
	}
}