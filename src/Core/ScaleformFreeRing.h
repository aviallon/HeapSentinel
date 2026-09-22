#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace hs
{
	// One Scaleform free event. Kept separately from ShadowLedger because these
	// records are the durable attribution for a delayed use-after-free and must
	// not be evicted by the main table's normal bounded quarantine - but they
	// must still be bounded, or a long session fills memory and the instrument
	// goes silent. The ring evicts oldest-first when full, and the eviction
	// count plus the retention window are reported.
	struct ScaleformFreeRecord
	{
		std::uintptr_t ptr = 0;
		std::uintptr_t vtableAtFree = 0;
		std::size_t    size = 0;
		void*          freeSite = nullptr;
		std::uint32_t  freeStack = 0;
		std::uint32_t  poisonIndex = 0;  // 1-based quarantine slot, 0 = none
		std::uint64_t  freeTick = 0;
		std::uint32_t  threadId = 0;
		std::uint32_t  flags = 0;
	};

	// Fixed-capacity, lock-free, evict-oldest ring of Scaleform free records.
	// Same per-slot seqlock idiom as ShadowLedger / src/Ipc/ShmLayout.h: the
	// VEH can look a record up without taking a lock.
	class ScaleformFreeRing
	{
	public:
		static ScaleformFreeRing& Get();

		bool Init(std::size_t a_capacity);
		void Shutdown();
		[[nodiscard]] bool Ready() const { return _ready.load(std::memory_order_acquire); }

		void Record(const ScaleformFreeRecord& a_record);

		// Newest record for a_ptr. Lock-free; returns false when absent (e.g.
		// evicted) rather than blocking.
		[[nodiscard]] bool Find(std::uintptr_t a_ptr, ScaleformFreeRecord& a_out) const;

		[[nodiscard]] std::size_t Count() const;
		[[nodiscard]] std::size_t Capacity() const { return _capacity; }
		[[nodiscard]] std::uint64_t Evictions() const { return _evictions.load(std::memory_order_relaxed); }

		// Oldest/newest retained free tick, for a human-readable retention
		// window in milliseconds. Returns false when empty.
		bool RetentionTicks(std::uint64_t& a_oldest, std::uint64_t& a_newest) const;

	private:
		struct Slot
		{
			std::atomic<std::uint64_t> version{};
			ScaleformFreeRecord        record;
		};

		[[nodiscard]] static std::size_t NextPow2(std::size_t a_value);

		std::unique_ptr<Slot[]>    _slots;
		std::size_t                _capacity = 0;
		std::atomic<std::uint64_t> _writeCursor{ 0 };  // 1-based added count
		std::atomic<std::uint64_t> _evictions{ 0 };
		std::atomic<bool>          _ready{ false };
	};
}