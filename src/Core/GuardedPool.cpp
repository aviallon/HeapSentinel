#include "PCH.h"

#include "Core/GuardedPool.h"

namespace hs
{
	namespace
	{
		constexpr std::size_t kPageSize = 4096;
		constexpr std::size_t kMinSlots = 4;
		constexpr std::size_t kQuarantineDivisor = 4;
	}

	GuardedPool& GuardedPool::Get()
	{
		static GuardedPool pool;
		return pool;
	}

	bool GuardedPool::Init(std::size_t a_slots, std::size_t a_maxSize, std::uint32_t a_sampleRate)
	{
		if (_ready) {
			return true;
		}

		_pageSize = kPageSize;
		if (a_maxSize == 0 || a_maxSize > _pageSize - 32) {
			a_maxSize = _pageSize - 32;
		}
		_maxSize = a_maxSize;
		_sampleRate = a_sampleRate == 0 ? 1 : a_sampleRate;

		_slotCount = std::max<std::size_t>(a_slots, kMinSlots);
		// [guard][data][guard]
		_slotStride = _pageSize * 3;
		_regionSize = _slotCount * _slotStride;

		_region = static_cast<std::byte*>(::VirtualAlloc(nullptr, _regionSize, MEM_RESERVE, PAGE_NOACCESS));
		if (!_region) {
			logger::error("guarded pool: VirtualAlloc({} bytes) failed ({})", _regionSize, ::GetLastError());
			return false;
		}

		_slots = std::make_unique<Slot[]>(_slotCount);
		for (std::size_t i = 0; i < _slotCount; ++i) {
			_slots[i].data = _region + i * _slotStride + _pageSize;
			_slots[i].state.store(kFree, std::memory_order_relaxed);
		}

		_freeList = std::make_unique<std::uint32_t[]>(_slotCount);
		_freeCount = 0;

		_quarantineCapacity = std::max<std::size_t>(_slotCount / kQuarantineDivisor, 4);
		_quarantine = std::make_unique<std::uint32_t[]>(_quarantineCapacity);
		_quarantineCount = 0;
		_quarantineHead = 0;

		_ready = true;
		logger::info("guarded pool: {} slots, max size {}, sample 1/{} ({} KiB reserved)",
			_slotCount, _maxSize, _sampleRate, _regionSize / 1024);
		return true;
	}

	void GuardedPool::Shutdown()
	{
		_ready = false;
		if (_region) {
			::VirtualFree(_region, 0, MEM_RELEASE);
			_region = nullptr;
		}
		_slots.reset();
		_freeList.reset();
		_quarantine.reset();
		_slotCount = 0;
		_freeCount = 0;
		_quarantineCount = 0;
	}

	bool GuardedPool::ShouldSample(std::size_t a_size)
	{
		if (!_ready || a_size == 0 || a_size > _maxSize) {
			return false;
		}
		const auto counter = _sampleCounter.fetch_add(1, std::memory_order_relaxed);
		return (counter % _sampleRate) == 0;
	}

	bool GuardedPool::IsOurs(std::uintptr_t a_ptr) const
	{
		if (!_ready || !_region) {
			return false;
		}
		const auto start = reinterpret_cast<std::uintptr_t>(_region);
		return a_ptr >= start && a_ptr < start + _regionSize;
	}

	GuardedPool::Slot* GuardedPool::SlotFor(std::uintptr_t a_ptr)
	{
		if (!IsOurs(a_ptr)) {
			return nullptr;
		}
		const auto index = (a_ptr - reinterpret_cast<std::uintptr_t>(_region)) / _slotStride;
		if (index >= _slotCount) {
			return nullptr;
		}
		return &_slots[index];
	}

	void* GuardedPool::Allocate(std::size_t a_size, std::size_t a_alignment, const AllocationInfo& a_info)
	{
		if (!_ready || a_size == 0 || a_size > _maxSize) {
			return nullptr;
		}

		::AcquireSRWLockExclusive(&_lock);

		std::size_t index = static_cast<std::size_t>(-1);

		if (_freeCount > 0) {
			index = _freeList[--_freeCount];
		} else if (_quarantineCount > 0) {
			index = _quarantine[_quarantineHead];
			_quarantineHead = (_quarantineHead + 1) % _quarantineCapacity;
			--_quarantineCount;
			// Coming back out of quarantine: make it writable again.
			::VirtualProtect(_slots[index].data, _pageSize, PAGE_READWRITE, nullptr);
		}

		if (index == static_cast<std::size_t>(-1)) {
			::ReleaseSRWLockExclusive(&_lock);
			return nullptr;
		}

		auto& slot = _slots[index];
		if (slot.state.load(std::memory_order_relaxed) != kInUse) {
			::VirtualAlloc(slot.data, _pageSize, MEM_COMMIT, PAGE_READWRITE);
		}

		// Randomly left- or right-aligned so under- and overflows are equally
		// likely to touch a guard page.
		const auto bit = _rng.fetch_add(0x9E3779B97F4A7C15ull, std::memory_order_relaxed) >> 63;
		std::byte* user = nullptr;
		if (bit == 0) {
			user = slot.data;
		} else {
			const auto raw = reinterpret_cast<std::uintptr_t>(slot.data + _pageSize - a_size);
			const auto align = a_alignment == 0 ? 16 : a_alignment;
			user = reinterpret_cast<std::byte*>(raw & ~(static_cast<std::uintptr_t>(align) - 1));
		}

		slot.user = user;
		slot.size = a_size;
		slot.state.store(kInUse, std::memory_order_relaxed);

		::ReleaseSRWLockExclusive(&_lock);

		AllocationInfo info = a_info;
		info.ptr = reinterpret_cast<std::uintptr_t>(user);
		info.size = a_size;
		info.flags = kFlagLive | kFlagSampled;
		ShadowLedger::Get().Insert(reinterpret_cast<std::uintptr_t>(user), info);

		return user;
	}

	bool GuardedPool::Deallocate(std::uintptr_t a_ptr, void* a_freeSite, std::uint32_t a_freeStack)
	{
		auto* slot = SlotFor(a_ptr);
		if (!slot) {
			return false;
		}

		::AcquireSRWLockExclusive(&_lock);

		if (slot->state.load(std::memory_order_relaxed) == kQuarantined) {
			::ReleaseSRWLockExclusive(&_lock);
			return true;  // double free of a sampled block; the caller reports it
		}

		slot->state.store(kQuarantined, std::memory_order_relaxed);
		::VirtualProtect(slot->data, _pageSize, PAGE_NOACCESS, nullptr);

		const auto index = static_cast<std::uint32_t>(slot - _slots.get());

		if (_quarantineCount == _quarantineCapacity) {
			// Evict the oldest quarantined slot to the free list.
			const auto oldest = _quarantine[_quarantineHead];
			_quarantineHead = (_quarantineHead + 1) % _quarantineCapacity;
			--_quarantineCount;
			_slots[oldest].state.store(kFree, std::memory_order_relaxed);
			if (_freeCount < _slotCount) {
				_freeList[_freeCount++] = oldest;
			}
		}

		_quarantine[(_quarantineHead + _quarantineCount) % _quarantineCapacity] = index;
		++_quarantineCount;

		::ReleaseSRWLockExclusive(&_lock);

		AllocationInfo info;
		if (ShadowLedger::Get().Find(a_ptr, info)) {
			info.flags = kFlagFreed | kFlagSampled;
			info.freeSite = a_freeSite;
			info.freeStack = a_freeStack;
			ShadowLedger::Get().Insert(a_ptr, info);
		}
		return true;
	}

	bool GuardedPool::OnFault(std::uintptr_t a_faultAddr, bool a_fixUp, AllocationInfo& a_out)
	{
		auto* slot = SlotFor(a_faultAddr);
		if (!slot) {
			return false;
		}

		a_out = AllocationInfo{};
		(void)ShadowLedger::Get().Find(reinterpret_cast<std::uintptr_t>(slot->user), a_out);
		a_out.ptr = reinterpret_cast<std::uintptr_t>(slot->user);
		a_out.size = slot->size;

		if (a_fixUp) {
			// Fail-up is best-effort and must not take a lock: the VEH runs on the
			// faulting thread, which may hold the pool lock. A CAS keeps only one
			// fixer, and a lost race just means someone else already fixed it.
			std::uint32_t expected = kQuarantined;
			if (slot->state.compare_exchange_strong(expected, kInUse, std::memory_order_acq_rel)) {
				::VirtualProtect(slot->data, _pageSize, PAGE_READWRITE, nullptr);
			}
		}
		return true;
	}
}
