#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace hs
{
	// A block whose real free is being withheld while its first qword is
	// poisoned. Kept in a bounded ring; the oldest is drained (really freed)
	// when the budget is reached.
	struct QuarantineRecord
	{
		std::uintptr_t ptr = 0;
		void*          heap = nullptr;  // GMemoryHeapPT `this`, needed to drain
		std::size_t    size = 0;
		std::uintptr_t vtableAtFree = 0;
		void*          freeSite = nullptr;
		std::uint32_t  freeStack = 0;
		std::uint32_t  index = 0;  // 1-based poison slot
		std::uint64_t  freeTick = 0;
	};

	// Poison-on-free quarantine for Scaleform blocks.
	//
	// The poison value is an address inside a dedicated region that is RESERVED
	// but never COMMITTED (PAGE_NOACCESS on Windows). Any read or call through
	// it faults, and because each slot has a page-sized stride the fault address
	// decodes back to the record that owns the block:
	//
	//   poison(index) = base + (index - 1) * stride
	//   index         = (fault - base) / stride + 1
	//
	// Any vtable-slot offset below `stride` (we use 0x1000) decodes to the same
	// record, so `call [rax]` and `call [rax+8]` alike land on the right block.
	// The region is pure address space (no committed memory), so reserving a
	// large budget costs no RAM until a block is actually withheld.
	//
	// BOUNDED and fail-open: Reserve() refuses at the block or byte budget, and
	// the caller then drains oldest-first (or, if it cannot, calls the original).
	class PoisonQuarantine
	{
	public:
		static PoisonQuarantine& Get();

		bool Init(std::size_t a_maxBlocks, std::size_t a_maxBytes, std::uintptr_t a_poisonBase, std::size_t a_stride);
		void Shutdown();
		[[nodiscard]] bool Ready() const { return _ready.load(std::memory_order_acquire); }

		[[nodiscard]] std::uintptr_t PoisonFor(std::uint32_t a_index) const;
		[[nodiscard]] std::uintptr_t PoisonBase() const { return _poisonBase; }
		[[nodiscard]] std::size_t    RegionSize() const { return _capacity * _stride; }
		[[nodiscard]] std::size_t    Stride() const { return _stride; }
		[[nodiscard]] std::size_t    MaxBytes() const { return _maxBytes; }
		[[nodiscard]] std::size_t    MaxBlocks() const { return _capacity; }

		// Rounds a requested block count up to the power of two the ring actually
		// uses, so the caller can size the reserved region before Init().
		[[nodiscard]] static std::size_t RoundUpCapacity(std::size_t a_value);

		// True when admitting a block of a_size would exceed the budget. The
		// caller drains (real-frees the oldest) until this is false.
		[[nodiscard]] bool OverBudget(std::size_t a_size) const;

		// Reserve the next poison slot. Returns 0 when the ring is at its block
		// capacity (the caller must drain first). The slot is not visible to
		// readers until Publish().
		[[nodiscard]] std::uint32_t Reserve();

		void Publish(const QuarantineRecord& a_record);

		// Oldest still-held block, advanced. Returns false when empty.
		bool PopOldest(QuarantineRecord& a_out);

		[[nodiscard]] std::size_t Count() const;
		[[nodiscard]] std::size_t Bytes() const { return _bytes.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t Evictions() const { return _evictions.load(std::memory_order_relaxed); }

		// fault -> poison slot index (0 = not a poison address).
		[[nodiscard]] bool DecodeFault(std::uintptr_t a_fault, std::uint32_t& a_index) const;
		// Read the record occupying a poison slot, lock-free. Returns false for
		// an empty/never-published slot.
		[[nodiscard]] bool GetSlot(std::uint32_t a_index, QuarantineRecord& a_out) const;

	private:
		[[nodiscard]] static std::size_t NextPow2(std::size_t a_value);
		struct Slot
		{
			std::atomic<std::uint64_t> version{};
			QuarantineRecord           record;
		};

		std::unique_ptr<Slot[]>    _slots;
		std::size_t                _capacity = 0;
		std::size_t                _stride = 0x1000;
		std::size_t                _maxBytes = 0;
		std::uintptr_t             _poisonBase = 0;
		std::atomic<std::uint64_t> _writeCursor{ 0 };  // reservations taken
		std::atomic<std::uint64_t> _readCursor{ 0 };   // reservations drained
		std::atomic<std::uint64_t> _publishSeq{ 0 };
		std::atomic<std::size_t>   _bytes{ 0 };
		std::atomic<std::uint64_t> _evictions{ 0 };
		std::atomic<bool>          _ready{ false };
	};
}