#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace hs
{
	// Low-frequency GFxResourceWeakLib context. These fire on menu load/close
	// rather than per allocation, so they are essentially free, and they give
	// the one thing the heap stack cannot: whether the resource was pinned,
	// unpinned, or had RemoveResourceOnRelease called for it before it died.
	enum class WeakLibEventKind : std::uint32_t
	{
		kPin = 1,
		kRemoveOnRelease = 2,
		kUnpin = 3,
		kAddRef = 4,
	};

	struct WeakLibEvent
	{
		std::uintptr_t    ptr = 0;
		void*             site = nullptr;
		std::uint64_t     tick = 0;
		std::uint32_t     kind = 0;
		std::uint32_t     threadId = 0;
	};

	// Fixed, lock-free, evict-oldest event ring. The crash report scans it for
	// the tracked pointer; the VEH does so without taking a lock.
	class WeakLibEvents
	{
	public:
		static WeakLibEvents& Get();

		bool Init(std::size_t a_capacity);
		void Shutdown();
		[[nodiscard]] bool Ready() const { return _ready.load(std::memory_order_acquire); }

		void Record(WeakLibEventKind a_kind, std::uintptr_t a_ptr, void* a_site, std::uint64_t a_tick, std::uint32_t a_threadId);

		// Newest-first events for a_ptr, up to a_max, in chronological order
		// (oldest first) in the output. Returns the number written.
		[[nodiscard]] std::size_t Find(std::uintptr_t a_ptr, WeakLibEvent* a_out, std::size_t a_max) const;

		[[nodiscard]] std::size_t Count() const;
		[[nodiscard]] std::size_t Capacity() const { return _capacity; }

	private:
		struct Slot
		{
			std::atomic<std::uint64_t> version{};
			WeakLibEvent               event;
		};

		[[nodiscard]] static std::size_t NextPow2(std::size_t a_value);

		std::unique_ptr<Slot[]>    _slots;
		std::size_t                _capacity = 0;
		std::atomic<std::uint64_t> _writeCursor{ 0 };
		std::atomic<bool>          _ready{ false };
	};
}