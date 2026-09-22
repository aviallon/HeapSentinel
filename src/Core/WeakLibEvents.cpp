#if defined(HS_NO_PCH)
#	include "Core/WeakLibEvents.h"

#	include <algorithm>
#	include <atomic>
#else
#	include "PCH.h"

#	include "Core/WeakLibEvents.h"
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

	WeakLibEvents& WeakLibEvents::Get()
	{
		static WeakLibEvents events;
		return events;
	}

	std::size_t WeakLibEvents::NextPow2(std::size_t a_value)
	{
		std::size_t result = 1;
		while (result < a_value) {
			result <<= 1;
		}
		return result;
	}

	bool WeakLibEvents::Init(std::size_t a_capacity)
	{
		if (_ready.load(std::memory_order_acquire)) {
			return true;
		}
		_capacity = NextPow2(std::max<std::size_t>(a_capacity, 16));
		_slots = std::make_unique<Slot[]>(_capacity);
		for (std::size_t i = 0; i < _capacity; ++i) {
			_slots[i].version.store(0, std::memory_order_relaxed);
		}
		_writeCursor.store(0, std::memory_order_relaxed);
		_ready.store(true, std::memory_order_release);
#if !defined(HS_NO_PCH)
		logger::info("weaKlib events: {} slots (pin/unpin/remove/addref context)", _capacity);
#endif
		return true;
	}

	void WeakLibEvents::Shutdown()
	{
		_ready.store(false, std::memory_order_release);
		_slots.reset();
		_capacity = 0;
		_writeCursor.store(0, std::memory_order_relaxed);
	}

	void WeakLibEvents::Record(WeakLibEventKind a_kind, std::uintptr_t a_ptr, void* a_site, std::uint64_t a_tick, std::uint32_t a_threadId)
	{
		if (!Ready() || a_ptr <= 1) {
			return;
		}

		const auto seq = _writeCursor.fetch_add(1, std::memory_order_relaxed) + 1;
		auto&      slot = _slots[seq & (_capacity - 1)];

		slot.version.store(VersionFor(seq, true), std::memory_order_relaxed);
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.event = WeakLibEvent{ a_ptr, a_site, a_tick, static_cast<std::uint32_t>(a_kind), a_threadId };
		std::atomic_signal_fence(std::memory_order_seq_cst);
		slot.version.store(VersionFor(seq, false), std::memory_order_release);
	}

	std::size_t WeakLibEvents::Find(std::uintptr_t a_ptr, WeakLibEvent* a_out, std::size_t a_max) const
	{
		if (!Ready() || a_ptr <= 1 || a_max == 0) {
			return 0;
		}

		const auto newest = _writeCursor.load(std::memory_order_acquire);
		const auto oldest = (newest > _capacity) ? (newest - _capacity) : 0;

		std::size_t found = 0;
		for (auto seq = newest; seq > oldest && found < a_max; --seq) {
			const auto& slot = _slots[seq & (_capacity - 1)];
			const auto  v1 = slot.version.load(std::memory_order_acquire);
			if (VersionIsWriting(v1) || SeqOfVersion(v1) != seq) {
				continue;
			}
			WeakLibEvent copy = slot.event;
			std::atomic_signal_fence(std::memory_order_seq_cst);
			const auto v2 = slot.version.load(std::memory_order_acquire);
			if (v1 != v2) {
				continue;
			}
			if (copy.ptr == a_ptr) {
				// Filled newest-first; reverse into chronological order.
				a_out[a_max - 1 - found] = copy;
				++found;
			}
		}

		if (found == 0) {
			return 0;
		}
		// Compact to the front (the caller reads [0, found)).
		const std::size_t first = a_max - found;
		for (std::size_t i = 0; i < found; ++i) {
			a_out[i] = a_out[first + i];
		}
		return found;
	}

	std::size_t WeakLibEvents::Count() const
	{
		const auto written = _writeCursor.load(std::memory_order_acquire);
		return static_cast<std::size_t>(written < _capacity ? written : _capacity);
	}
}