#include "PCH.h"

#include "Core/ShadowLedger.h"

namespace hs
{
	namespace
	{
		constexpr std::uintptr_t kEmpty = 0;
		constexpr std::uintptr_t kTombstone = 1;

		// Bounded linear probing. A full probe of a large shard is far too slow
		// for an allocation hook, and an unbounded table would grow until the
		// load-factor cap silently stopped recording. The window is long enough
		// to find a recently-freed entry to reuse (the ledger's quarantine).
		constexpr std::size_t kMaxProbe = 64;

		[[nodiscard]] constexpr std::uintptr_t Mix(std::uintptr_t a_value)
		{
			std::uintptr_t x = a_value >> 4;
			x *= 0x9E3779B97F4A7C15ull;
			x ^= x >> 29;
			x *= 0xBF58476D1CE4E5B9ull;
			x ^= x >> 32;
			return x;
		}

		[[nodiscard]] std::size_t NextPow2(std::size_t a_value)
		{
			std::size_t result = 1;
			while (result < a_value) {
				result <<= 1;
			}
			return result;
		}
	}

	ShadowLedger& ShadowLedger::Get()
	{
		static ShadowLedger ledger;
		return ledger;
	}

	bool ShadowLedger::Init(std::size_t a_capacity, std::size_t a_shards, std::size_t a_stackDepth)
	{
		if (_ready.load(std::memory_order_acquire)) {
			return true;
		}

		_shardCount = NextPow2(std::max<std::size_t>(a_shards, 1));
		_shardCapacity = NextPow2(std::max<std::size_t>(a_capacity / _shardCount, 16));

		_shards = std::make_unique<Shard[]>(_shardCount);
		for (std::size_t i = 0; i < _shardCount; ++i) {
			_shards[i].slots = std::make_unique<Entry[]>(_shardCapacity);
			_shards[i].capacity = _shardCapacity;
			_shards[i].count = 0;
		}

		if (a_stackDepth > 0) {
			_stackCount = 1u << 16;
			_stacks = std::make_unique<Stack[]>(_stackCount);
		}

		_ready.store(true, std::memory_order_release);
		logger::info("ledger: {} shards x {} slots ({} entries), stack ring {}",
			_shardCount, _shardCapacity, _shardCount * _shardCapacity, _stackCount);
		return true;
	}

	void ShadowLedger::Shutdown()
	{
		_ready.store(false, std::memory_order_release);
		_shards.reset();
		_stacks.reset();
		_shardCount = 0;
		_shardCapacity = 0;
		_stackCount = 0;
	}

	ShadowLedger::Shard& ShadowLedger::ShardFor(std::uintptr_t a_ptr)
	{
		return _shards[Mix(a_ptr) & (_shardCount - 1)];
	}

	const ShadowLedger::Shard& ShadowLedger::ShardFor(std::uintptr_t a_ptr) const
	{
		return _shards[Mix(a_ptr) & (_shardCount - 1)];
	}

	void ShadowLedger::Insert(std::uintptr_t a_ptr, const AllocationInfo& a_info)
	{
		if (!Ready() || a_ptr <= kTombstone) {
			return;
		}

		auto& shard = ShardFor(a_ptr);
		shard.Lock();

		const auto  mask = shard.capacity - 1;
		auto        index = Mix(a_ptr) & mask;
		std::size_t firstTombstone = static_cast<std::size_t>(-1);
		std::size_t firstFreed = static_cast<std::size_t>(-1);

		for (std::size_t probe = 0; probe < kMaxProbe; ++probe) {
			auto& slot = shard.slots[index];
			if (slot.key == a_ptr) {
				slot.info = a_info;
				shard.Unlock();
				return;
			}
			if (slot.key == kEmpty) {
				if (firstTombstone != static_cast<std::size_t>(-1)) {
					shard.slots[firstTombstone].key = a_ptr;
					shard.slots[firstTombstone].info = a_info;
				} else {
					slot.key = a_ptr;
					slot.info = a_info;
					++shard.count;
				}
				shard.Unlock();
				return;
			}
			if (slot.key == kTombstone && firstTombstone == static_cast<std::size_t>(-1)) {
				firstTombstone = index;
			} else if ((slot.info.flags & kFlagFreed) != 0 && firstFreed == static_cast<std::size_t>(-1)) {
				firstFreed = index;
			}
			index = (index + 1) & mask;
		}

		// Probe window exhausted. Reuse a tombstone, else evict the oldest freed
		// entry we saw (that is the ledger's bounded quarantine), else fail open.
		if (firstTombstone != static_cast<std::size_t>(-1)) {
			shard.slots[firstTombstone].key = a_ptr;
			shard.slots[firstTombstone].info = a_info;
		} else if (firstFreed != static_cast<std::size_t>(-1)) {
			shard.slots[firstFreed].key = a_ptr;
			shard.slots[firstFreed].info = a_info;
		} else {
			_insertFailures.fetch_add(1, std::memory_order_relaxed);
		}

		shard.Unlock();
	}

	bool ShadowLedger::Find(std::uintptr_t a_ptr, AllocationInfo& a_out) const
	{
		if (!Ready() || a_ptr <= kTombstone) {
			return false;
		}

		const auto& shard = ShardFor(a_ptr);
		shard.Lock();

		const auto mask = shard.capacity - 1;
		auto       index = Mix(a_ptr) & mask;
		bool       found = false;

		for (std::size_t probe = 0; probe < kMaxProbe; ++probe) {
			const auto& slot = shard.slots[index];
			if (slot.key == a_ptr) {
				a_out = slot.info;
				found = true;
				break;
			}
			if (slot.key == kEmpty) {
				break;
			}
			index = (index + 1) & mask;
		}

		shard.Unlock();
		return found;
	}

	bool ShadowLedger::Erase(std::uintptr_t a_ptr, AllocationInfo& a_out)
	{
		if (!Ready() || a_ptr <= kTombstone) {
			return false;
		}

		auto& shard = ShardFor(a_ptr);
		shard.Lock();

		const auto mask = shard.capacity - 1;
		auto       index = Mix(a_ptr) & mask;
		bool       found = false;

		for (std::size_t probe = 0; probe < kMaxProbe; ++probe) {
			auto& slot = shard.slots[index];
			if (slot.key == a_ptr) {
				a_out = slot.info;
				slot.key = kTombstone;
				found = true;
				break;
			}
			if (slot.key == kEmpty) {
				break;
			}
			index = (index + 1) & mask;
		}

		shard.Unlock();
		return found;
	}

	std::size_t ShadowLedger::Count() const
	{
		if (!Ready()) {
			return 0;
		}
		std::size_t total = 0;
		for (std::size_t i = 0; i < _shardCount; ++i) {
			const auto& shard = _shards[i];
			shard.Lock();
			total += shard.count;
			shard.Unlock();
		}
		return total;
	}

	std::uint32_t ShadowLedger::StoreStack(const Stack& a_stack)
	{
		if (!_stacks || a_stack.count == 0) {
			return 0;
		}
		const auto index = _stackCursor.fetch_add(1, std::memory_order_relaxed);
		if (index >= _stackCount) {
			return 0;
		}
		_stacks[index] = a_stack;
		return index;
	}

	const Stack* ShadowLedger::GetStack(std::uint32_t a_index) const
	{
		if (!_stacks || a_index == 0 || a_index >= _stackCount) {
			return nullptr;
		}
		return &_stacks[a_index];
	}
}
