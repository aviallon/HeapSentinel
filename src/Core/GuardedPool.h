#pragma once

#include "Core/ShadowLedger.h"

namespace hs
{
	// GWP-ASan-style sampled guarded allocation pool.
	//
	// A small random fraction of allocations is served from our own region
	// instead of the engine's heap. Each sampled allocation gets one committed
	// data page flanked by PAGE_NOACCESS guard pages; on free the data page is
	// re-protected, so any later access faults and is caught by the VEH with
	// the allocation and free stacks on record.
	//
	// This is opt-in (Config::guardPoolEnabled, default off): a sampled block
	// was never returned by any engine heap, so the engine must never inspect it
	// with ContainsBlockImpl/Size. The allocator hooks route frees and reallocs
	// of our blocks back to us, but that is the whole safety argument.
	class GuardedPool
	{
	public:
		static GuardedPool& Get();

		bool Init(std::size_t a_slots, std::size_t a_maxSize, std::uint32_t a_sampleRate);
		void Shutdown();

		[[nodiscard]] bool Ready() const { return _ready; }
		[[nodiscard]] std::size_t SlotCount() const { return _slotCount; }
		[[nodiscard]] std::size_t MaxSize() const { return _maxSize; }

		// Cheap counter/PRNG check; only sampled sizes reach the pool.
		[[nodiscard]] bool ShouldSample(std::size_t a_size);

		// Returns nullptr when the pool is exhausted or the request does not
		// fit; the caller then falls back to the engine allocator.
		[[nodiscard]] void* Allocate(std::size_t a_size, std::size_t a_alignment, const AllocationInfo& a_info);

		[[nodiscard]] bool IsOurs(std::uintptr_t a_ptr) const;
		[[nodiscard]] bool Deallocate(std::uintptr_t a_ptr, void* a_freeSite, std::uint32_t a_freeStack);

		// VEH: is this fault address inside one of our slots? With a_fixUp the
		// data page is made accessible again so the game can continue.
		[[nodiscard]] bool OnFault(std::uintptr_t a_faultAddr, bool a_fixUp, AllocationInfo& a_out);

	private:
		enum SlotState : std::uint32_t
		{
			kFree = 0,
			kInUse = 1,
			kQuarantined = 2,
		};

		struct Slot
		{
			std::byte*    data = nullptr;  // start of the data page
			std::byte*    user = nullptr;  // returned pointer
			std::size_t   size = 0;
			std::atomic<std::uint32_t> state{ static_cast<std::uint32_t>(kFree) };
		};

		[[nodiscard]] Slot* SlotFor(std::uintptr_t a_ptr);
		void                ReleaseSlot(std::size_t a_index);

		std::byte*   _region = nullptr;
		std::size_t  _regionSize = 0;
		std::size_t  _slotStride = 0;
		std::size_t  _pageSize = 0;
		std::size_t  _slotCount = 0;
		std::size_t  _maxSize = 0;
		std::uint32_t _sampleRate = 1;

		std::unique_ptr<Slot[]> _slots;

		std::unique_ptr<std::uint32_t[]> _freeList;
		std::size_t                      _freeCount = 0;
		std::unique_ptr<std::uint32_t[]> _quarantine;
		std::size_t                      _quarantineCount = 0;
		std::size_t                      _quarantineCapacity = 0;
		std::size_t                      _quarantineHead = 0;

		std::atomic<std::uint64_t> _sampleCounter{ 0 };
		std::atomic<std::uint64_t> _rng{ 0x2545F4914F6CDD1Dull };
		// SRWLOCK, not a spinlock: under Wine it is futex-backed, so a preempted
		// holder parks its waiters instead of making them burn a scheduling
		// quantum. The hot engine path does not touch this pool (it is opt-in and
		// sampled 1/N); the lock-free per-thread-ring roadmap will remove it.
		SRWLOCK                    _lock = SRWLOCK_INIT;
		bool                       _ready = false;
	};
}
