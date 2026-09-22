#if defined(HS_NO_PCH)
#	include "Core/ScaleformFreeRing.h"

#	include <algorithm>
#	include <atomic>
#	include <cstring>
#else
#	include "PCH.h"

#	include "Core/ScaleformFreeRing.h"
#endif

namespace hs
{
	namespace
	{
		// Same seqlock encoding as src/Ipc/ShmLayout.h. Duplicated here rather
		// than included so the ledger cores stay free of the IPC header.
		[[nodiscard]] constexpr std::uint64_t VersionFor(std::uint64_t a_seq, bool a_writing) noexcept
		{
			return (a_seq << 1) | (a_writing ? 1u : 0u);
		}
		[[nodiscard]] constexpr std::uint64_t SeqOfVersion(std::uint64_t a_version) noexcept
		{
			return a_version >> 1;
		}
		[[nodiscard]] constexpr bool VersionIsWriting(std::uint64_t a_version) noexcept
		{
			return (a_version & 1u) != 0;
		}
	}

	ScaleformFreeRing& ScaleformFreeRing::Get()
	{
		static ScaleformFreeRing ring;
		return ring;
	}

	std::size_t ScaleformFreeRing::NextPow2(std::size_t a_value)
	{
		std::size_t result = 1;
		while (result < a_value) {
			result <<= 1;
		}
		return result;
	}

	bool ScaleformFreeRing::Init(std::size_t a_capacity)
	{
		if (_ready.load(std::memory_order_acquire)) {
			return true;
		}
		_capacity = NextPow2(std::max<std::size_t>(a_capacity, 2));
		_slots = std::make_unique<Slot[]>(_capacity);
		for (std::size_t i = 0; i < _capacity; ++i) {
			_slots[i].version.store(0, std::memory_order_relaxed);
		}
		_writeCursor.store(0, std::memory_order_relaxed);
		_evictions.store(0, std::memory_order_relaxed);
		_bloom.Init(_capacity, 10, false);
		_ready.store(true, std::memory_order_release);
#if !defined(HS_NO_PCH)
		logger::info("scaleform free ring: {} records (oldest evicted first)", _capacity);
#endif
		return true;
	}

	void ScaleformFreeRing::Shutdown()
	{
		_ready.store(false, std::memory_order_release);
		_slots.reset();
		_bloom.Shutdown();
		_capacity = 0;
		_writeCursor.store(0, std::memory_order_relaxed);
		_evictions.store(0, std::memory_order_relaxed);
	}

	void ScaleformFreeRing::Record(const ScaleformFreeRecord& a_record)
	{
		if (!Ready()) {
			return;
		}

		const std::uint64_t seq = _writeCursor.fetch_add(1, std::memory_order_relaxed) + 1;
		auto&               slot = _slots[seq & (_capacity - 1)];

		_bloom.Add(a_record.ptr);

		// Invalidate before touching the payload, publish after. A reader that
		// sees the odd version skips the slot.
		slot.version.store(VersionFor(seq, true), std::memory_order_relaxed);
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.record = a_record;
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.version.store(VersionFor(seq, false), std::memory_order_release);

		if (seq > _capacity) {
			_evictions.fetch_add(1, std::memory_order_relaxed);
		}
	}

	bool ScaleformFreeRing::Find(std::uintptr_t a_ptr, ScaleformFreeRecord& a_out) const
	{
		if (!Ready() || a_ptr <= 1) {
			return false;
		}

		// Bloom fast path: a pointer we never recorded costs one relaxed load.
		if (!_bloom.MightContain(a_ptr)) {
			return false;
		}

		const std::uint64_t newest = _writeCursor.load(std::memory_order_acquire);
		const std::uint64_t oldest = (newest > _capacity) ? (newest - _capacity) : 0;

		for (std::uint64_t seq = newest; seq > oldest; --seq) {
			const auto& slot = _slots[seq & (_capacity - 1)];

			const auto v1 = slot.version.load(std::memory_order_acquire);
			if (VersionIsWriting(v1) || SeqOfVersion(v1) != seq) {
				continue;  // overwritten or mid-write
			}
			ScaleformFreeRecord copy = slot.record;
			std::atomic_signal_fence(std::memory_order_seq_cst);
			const auto v2 = slot.version.load(std::memory_order_acquire);
			if (v1 != v2) {
				continue;  // torn
			}
			if (copy.ptr == a_ptr) {
				a_out = copy;
				return true;
			}
		}
		return false;
	}

	std::size_t ScaleformFreeRing::Count() const
	{
		const auto written = _writeCursor.load(std::memory_order_acquire);
		return static_cast<std::size_t>(written < _capacity ? written : _capacity);
	}

	bool ScaleformFreeRing::RetentionTicks(std::uint64_t& a_oldest, std::uint64_t& a_newest) const
	{
		if (!Ready()) {
			return false;
		}
		const auto written = _writeCursor.load(std::memory_order_acquire);
		if (written == 0) {
			return false;
		}
		const auto first = (written > _capacity) ? (written - _capacity + 1) : 1;
		for (std::uint64_t seq = first; seq <= written; ++seq) {
			const auto& slot = _slots[seq & (_capacity - 1)];
			const auto  v = slot.version.load(std::memory_order_acquire);
			if (!VersionIsWriting(v) && SeqOfVersion(v) == seq) {
				a_oldest = slot.record.freeTick;
				break;
			}
		}
		for (std::uint64_t seq = written; seq >= first; --seq) {
			const auto& slot = _slots[seq & (_capacity - 1)];
			const auto  v = slot.version.load(std::memory_order_acquire);
			if (!VersionIsWriting(v) && SeqOfVersion(v) == seq) {
				a_newest = slot.record.freeTick;
				break;
			}
			if (seq == 0) {
				break;
			}
		}
		return true;
	}
}