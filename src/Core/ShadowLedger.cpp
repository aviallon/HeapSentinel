#if defined(HS_NO_PCH)
// Off-game test build: no Windows/CommonLib precompiled header, no logger. The
// ledger is plain C++ so it can be exercised on Linux and Windows by tests/.
#	include "Core/ShadowLedger.h"

#	include <algorithm>
#	include <cstdint>
#	include <memory>
#else
#	include "PCH.h"

#	include "Core/ShadowLedger.h"
#endif

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

		// Bounded writer claim: 16 pause-separated CAS attempts, then the record
		// is dropped and counted. Never an unbounded spin (see ShadowLedger.h).
		constexpr int kClaimAttempts = 16;

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

	bool ShadowLedger::Claim(Entry& a_entry, std::atomic<std::uint64_t>& a_drops)
	{
		for (int attempt = 0; attempt < kClaimAttempts; ++attempt) {
			const auto version = a_entry.version.load(std::memory_order_acquire);
			if ((version & 1u) != 0) {
				Relax();
				continue;
			}
			std::uint64_t expected = version;
			if (a_entry.version.compare_exchange_weak(expected, version | 1u, std::memory_order_acq_rel, std::memory_order_acquire)) {
				return true;
			}
			Relax();
		}
		a_drops.fetch_add(1, std::memory_order_relaxed);
		return false;
	}

	void ShadowLedger::Publish(Entry& a_entry, std::uint64_t a_claimedVersion)
	{
		// Barrier, then publish the next even sequence: readers that saw the odd
		// claim skip the entry; readers that see this version know the payload
		// write below is complete.
		std::atomic_signal_fence(std::memory_order_seq_cst);
		a_entry.version.store(a_claimedVersion + 2, std::memory_order_release);
	}

	bool ShadowLedger::Init(std::size_t a_capacity, std::size_t a_shards, std::size_t a_stackDepth)
	{
		if (_ready.load(std::memory_order_acquire)) {
			return true;
		}

		// Re-initialising (the off-game tests do this between cases) must reset
		// the counters as well, or a fresh table inherits stale failures.
		_insertFailures.store(0, std::memory_order_relaxed);
		_writerDrops.store(0, std::memory_order_relaxed);
		_stackCursor.store(1, std::memory_order_relaxed);

		_shardCount = NextPow2(std::max<std::size_t>(a_shards, 1));
		_shardCapacity = NextPow2(std::max<std::size_t>(a_capacity / _shardCount, 16));

		_shards = std::make_unique<Shard[]>(_shardCount);
		for (std::size_t i = 0; i < _shardCount; ++i) {
			_shards[i].slots = std::make_unique<Entry[]>(_shardCapacity);
			_shards[i].capacity = _shardCapacity;
			_shards[i].count.store(0, std::memory_order_relaxed);
			for (std::size_t j = 0; j < _shardCapacity; ++j) {
				_shards[i].slots[j].version.store(0, std::memory_order_relaxed);
				_shards[i].slots[j].key = kEmpty;
			}
		}

		if (a_stackDepth > 0) {
			_stackCount = 1u << 16;
			_stacks = std::make_unique<Stack[]>(_stackCount);
		}

		// ~10 bits/element gives ~1% false positives; sized to the table capacity
		// and non-aging so a miss never hides a record the table holds. If this
		// allocation fails, MightContain() fails open and Find() stays exact.
		_bloom.Init(_shardCount * _shardCapacity, 10, false);

		_ready.store(true, std::memory_order_release);
#if !defined(HS_NO_PCH)
		logger::info("ledger: {} shards x {} slots ({} entries), stack ring {} (lock-free seqlock, bounded {} attempt claim)",
			_shardCount, _shardCapacity, _shardCount * _shardCapacity, _stackCount, kClaimAttempts);
#endif
		return true;
	}

	void ShadowLedger::Shutdown()
	{
		_ready.store(false, std::memory_order_release);
		_shards.reset();
		_stacks.reset();
		_bloom.Shutdown();
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

	void ShadowLedger::InsertAtVictim(std::uintptr_t a_ptr, const AllocationInfo& a_info, std::size_t a_index, bool a_tombstone, bool a_mayEvictFreed)
	{
		auto& shard = ShardFor(a_ptr);
		auto& slot = shard.slots[a_index];

		const auto version = slot.version.load(std::memory_order_acquire);
		if ((version & 1u) != 0) {
			_insertFailures.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		if (!Claim(slot, _writerDrops)) {
			return;  // contended: drop and count rather than stall the allocator
		}

		const auto key = slot.key;
		bool       ok = false;
		if (key == kEmpty) {
			ok = true;
		} else if (key == kTombstone) {
			ok = a_tombstone;
		} else {
			// Evicting a freed entry is only legal when the caller chose it as the
			// bounded-quarantine victim, and only while it is still freed.
			ok = a_mayEvictFreed && ((slot.info.flags & kFlagFreed) != 0);
		}

		if (!ok) {
			// The victim changed underneath us (another writer reused it). Fail
			// open rather than clobber a slot that now holds a real record.
			Publish(slot, slot.version.load(std::memory_order_relaxed) & ~1ull);  // release our claim
			_insertFailures.fetch_add(1, std::memory_order_relaxed);
			return;
		}

		const bool wasEmpty = (key == kEmpty);
		slot.key = a_ptr;
		slot.info = a_info;
		Publish(slot, slot.version.load(std::memory_order_relaxed) & ~1ull);
		if (wasEmpty) {
			shard.count.fetch_add(1, std::memory_order_relaxed);
		}
	}

	void ShadowLedger::Insert(std::uintptr_t a_ptr, const AllocationInfo& a_info)
	{
		if (!Ready() || a_ptr <= kTombstone) {
			return;
		}

		_bloom.Add(a_ptr);

		auto& shard = ShardFor(a_ptr);

		const auto  mask = shard.capacity - 1;
		auto        index = Mix(a_ptr) & mask;
		std::size_t firstTombstone = static_cast<std::size_t>(-1);
		std::size_t firstFreed = static_cast<std::size_t>(-1);

		for (std::size_t probe = 0; probe < kMaxProbe; ++probe) {
			auto& slot = shard.slots[index];

			const auto version = slot.version.load(std::memory_order_acquire);
			if ((version & 1u) != 0) {
				// Being written. Skip it; the writer's record was new here and
				// we are looking for a different key.
				index = (index + 1) & mask;
				continue;
			}

			const auto key = slot.key;
			if (key == a_ptr) {
				if (!Claim(slot, _writerDrops)) {
					return;
				}
				slot.info = a_info;
				Publish(slot, version);
				return;
			}
			if (key == kEmpty) {
				const auto target = (firstTombstone != static_cast<std::size_t>(-1)) ? firstTombstone : index;
				InsertAtVictim(a_ptr, a_info, target, firstTombstone != static_cast<std::size_t>(-1), false);
				return;
			}
			if (key == kTombstone) {
				if (firstTombstone == static_cast<std::size_t>(-1)) {
					firstTombstone = index;
				}
			} else if ((slot.info.flags & kFlagFreed) != 0 && firstFreed == static_cast<std::size_t>(-1)) {
				// The main ledger evicts the oldest freed entry (bounded
				// quarantine) and keeps flowing. Durable Scaleform-free provenance
				// lives in the separately-budgeted ScaleformFreeRing, so it does
				// not depend on this table's eviction policy.
				firstFreed = index;
			}
			index = (index + 1) & mask;
		}

		// Probe window exhausted. Reuse a tombstone first, then evict the oldest
		// freed entry, else fail open. Durable Scaleform-free provenance is kept
		// in the separate free ring, not here.
		if (firstTombstone != static_cast<std::size_t>(-1)) {
			InsertAtVictim(a_ptr, a_info, firstTombstone, true, false);
		} else if (firstFreed != static_cast<std::size_t>(-1)) {
			InsertAtVictim(a_ptr, a_info, firstFreed, false, true);
		} else {
			_insertFailures.fetch_add(1, std::memory_order_relaxed);
		}
	}

	bool ShadowLedger::Find(std::uintptr_t a_ptr, AllocationInfo& a_out) const
	{
		if (!Ready() || a_ptr <= kTombstone) {
			return false;
		}

		// Bloom fast path: the common case (a register that is not ours) is one
		// relaxed atomic read, with no seqlock, no probing and no shard walk.
		if (!_bloom.MightContain(a_ptr)) {
			return false;
		}

		const auto& shard = ShardFor(a_ptr);

		const auto mask = shard.capacity - 1;
		auto       index = Mix(a_ptr) & mask;

		for (std::size_t probe = 0; probe < kMaxProbe; ++probe) {
			const auto& slot = shard.slots[index];

			const auto v1 = slot.version.load(std::memory_order_acquire);
			if ((v1 & 1u) != 0) {
				// Mid-write. Do not read the payload; keep probing. Reporting a
				// partial/unknown result is strictly better than blocking.
				index = (index + 1) & mask;
				continue;
			}

			const auto key = slot.key;
			if (key == kEmpty) {
				const auto v2 = slot.version.load(std::memory_order_acquire);
				if (v1 == v2) {
					return false;
				}
				index = (index + 1) & mask;
				continue;
			}
			if (key == a_ptr) {
				AllocationInfo copy = slot.info;
				std::atomic_signal_fence(std::memory_order_seq_cst);
				const auto v2 = slot.version.load(std::memory_order_acquire);
				if (v1 == v2) {
					a_out = copy;
					return true;
				}
				// Torn copy: this is a diagnostics path, so "unknown" is the
				// honest answer rather than a half-updated record.
				return false;
			}
			index = (index + 1) & mask;
		}
		return false;
	}

	bool ShadowLedger::Erase(std::uintptr_t a_ptr, AllocationInfo& a_out)
	{
		if (!Ready() || a_ptr <= kTombstone) {
			return false;
		}

		auto& shard = ShardFor(a_ptr);

		const auto mask = shard.capacity - 1;
		auto       index = Mix(a_ptr) & mask;

		for (std::size_t probe = 0; probe < kMaxProbe; ++probe) {
			auto& slot = shard.slots[index];

			const auto version = slot.version.load(std::memory_order_acquire);
			if ((version & 1u) != 0) {
				index = (index + 1) & mask;
				continue;
			}

			const auto key = slot.key;
			if (key == kEmpty) {
				return false;
			}
			if (key == a_ptr) {
				if (!Claim(slot, _writerDrops)) {
					return false;
				}
				a_out = slot.info;
				slot.key = kTombstone;
				Publish(slot, version);
				return true;
			}
			index = (index + 1) & mask;
		}
		return false;
	}

	std::size_t ShadowLedger::Count() const
	{
		if (!Ready()) {
			return 0;
		}
		std::size_t total = 0;
		for (std::size_t i = 0; i < _shardCount; ++i) {
			total += _shards[i].count.load(std::memory_order_relaxed);
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