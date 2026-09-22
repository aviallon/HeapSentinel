#if defined(HS_NO_PCH)
#	include "Core/PoisonQuarantine.h"

#	include <algorithm>
#	include <atomic>
#else
#	include "PCH.h"

#	include "Core/PoisonQuarantine.h"
#endif

namespace hs
{
	namespace
	{
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

	PoisonQuarantine& PoisonQuarantine::Get()
	{
		static PoisonQuarantine quarantine;
		return quarantine;
	}

	std::size_t PoisonQuarantine::NextPow2(std::size_t a_value)
	{
		std::size_t result = 1;
		while (result < a_value) {
			result <<= 1;
		}
		return result;
	}

	std::size_t PoisonQuarantine::RoundUpCapacity(std::size_t a_value)
	{
		return NextPow2(std::max<std::size_t>(a_value, 2));
	}

	bool PoisonQuarantine::Init(std::size_t a_maxBlocks, std::size_t a_maxBytes, std::uintptr_t a_poisonBase, std::size_t a_stride)
	{
		if (_ready.load(std::memory_order_acquire)) {
			return true;
		}
		_capacity = NextPow2(std::max<std::size_t>(a_maxBlocks, 2));
		_stride = std::max<std::size_t>(a_stride, 8);
		_maxBytes = a_maxBytes;
		_poisonBase = a_poisonBase;

		_slots = std::make_unique<Slot[]>(_capacity);
		for (std::size_t i = 0; i < _capacity; ++i) {
			_slots[i].version.store(0, std::memory_order_relaxed);
		}
		_writeCursor.store(0, std::memory_order_relaxed);
		_readCursor.store(0, std::memory_order_relaxed);
		_publishSeq.store(0, std::memory_order_relaxed);
		_bytes.store(0, std::memory_order_relaxed);
		_evictions.store(0, std::memory_order_relaxed);
		_ready.store(true, std::memory_order_release);
		return true;
	}

	void PoisonQuarantine::Shutdown()
	{
		_ready.store(false, std::memory_order_release);
		_slots.reset();
		_capacity = 0;
	}

	std::uintptr_t PoisonQuarantine::PoisonFor(std::uint32_t a_index) const
	{
		return _poisonBase + (static_cast<std::uintptr_t>(a_index) - 1) * _stride;
	}

	bool PoisonQuarantine::OverBudget(std::size_t a_size) const
	{
		if (Count() >= _capacity) {
			return true;
		}
		return _maxBytes != 0 && (_bytes.load(std::memory_order_relaxed) + a_size > _maxBytes);
	}

	std::uint32_t PoisonQuarantine::Reserve()
	{
		if (!Ready()) {
			return 0;
		}
		// Bounded reservation (no unbounded spin). The caller drains when this
		// returns 0 or when OverBudget() is true.
		for (int attempt = 0; attempt < 64; ++attempt) {
			const auto w = _writeCursor.load(std::memory_order_relaxed);
			if (w - _readCursor.load(std::memory_order_acquire) >= _capacity) {
				return 0;
			}
			std::uint64_t expected = w;
			if (_writeCursor.compare_exchange_weak(expected, w + 1, std::memory_order_acq_rel, std::memory_order_relaxed)) {
				return static_cast<std::uint32_t>((w & (_capacity - 1)) + 1);
			}
		}
		return 0;
	}

	void PoisonQuarantine::Publish(const QuarantineRecord& a_record)
	{
		if (!Ready() || a_record.index == 0 || a_record.index > _capacity) {
			return;
		}
		auto&      slot = _slots[a_record.index - 1];
		const auto seq = _publishSeq.fetch_add(1, std::memory_order_relaxed) + 1;

		slot.version.store(VersionFor(seq, true), std::memory_order_relaxed);
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.record = a_record;
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.version.store(VersionFor(seq, false), std::memory_order_release);

		_bytes.fetch_add(a_record.size, std::memory_order_relaxed);
	}

	bool PoisonQuarantine::PopOldest(QuarantineRecord& a_out)
	{
		if (!Ready()) {
			return false;
		}
		for (;;) {
			const auto r = _readCursor.load(std::memory_order_relaxed);
			const auto w = _writeCursor.load(std::memory_order_acquire);
			if (r >= w) {
				return false;
			}

			const auto index = static_cast<std::uint32_t>((r & (_capacity - 1)) + 1);
			QuarantineRecord copy;
			bool             have = false;

			auto&      slot = _slots[index - 1];
			const auto v1 = slot.version.load(std::memory_order_acquire);
			if (!VersionIsWriting(v1) && SeqOfVersion(v1) != 0) {
				QuarantineRecord candidate = slot.record;
				std::atomic_signal_fence(std::memory_order_seq_cst);
				const auto v2 = slot.version.load(std::memory_order_acquire);
				if (v1 == v2 && candidate.index == index) {
					copy = candidate;
					have = true;
				}
			}

			std::uint64_t expected = r;
			if (!_readCursor.compare_exchange_strong(expected, r + 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
				continue;  // another drainer advanced it
			}
			if (have) {
				(void)_bytes.fetch_sub(std::min(copy.size, _bytes.load(std::memory_order_relaxed)), std::memory_order_relaxed);
				_evictions.fetch_add(1, std::memory_order_relaxed);
				a_out = copy;
				return true;
			}
			// Unpublished reservation (e.g. the process died mid-free): skip it.
		}
	}

	std::size_t PoisonQuarantine::Count() const
	{
		const auto w = _writeCursor.load(std::memory_order_acquire);
		const auto r = _readCursor.load(std::memory_order_acquire);
		return static_cast<std::size_t>(w > r ? w - r : 0);
	}

	bool PoisonQuarantine::DecodeFault(std::uintptr_t a_fault, std::uint32_t& a_index) const
	{
		if (!Ready() || a_fault < _poisonBase) {
			return false;
		}
		const auto offset = a_fault - _poisonBase;
		if (offset >= RegionSize()) {
			return false;
		}
		a_index = static_cast<std::uint32_t>(offset / _stride) + 1;
		return true;
	}

	bool PoisonQuarantine::GetSlot(std::uint32_t a_index, QuarantineRecord& a_out) const
	{
		if (!Ready() || a_index == 0 || a_index > _capacity) {
			return false;
		}
		const auto& slot = _slots[a_index - 1];

		const auto v1 = slot.version.load(std::memory_order_acquire);
		if (VersionIsWriting(v1) || SeqOfVersion(v1) == 0) {
			return false;
		}
		QuarantineRecord copy = slot.record;
		std::atomic_signal_fence(std::memory_order_seq_cst);
		const auto v2 = slot.version.load(std::memory_order_acquire);
		if (v1 != v2) {
			return false;
		}
		a_out = copy;
		return true;
	}
}