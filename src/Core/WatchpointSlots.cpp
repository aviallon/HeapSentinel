#if defined(HS_NO_PCH)
#	include "Core/WatchpointSlots.h"
#else
#	include "PCH.h"

#	include "Core/WatchpointSlots.h"
#endif

namespace hs
{
	WatchpointSlots& WatchpointSlots::Get()
	{
		static WatchpointSlots slots;
		return slots;
	}

	std::uint64_t WatchpointSlots::VersionFor(std::uint64_t a_seq, bool a_writing) noexcept
	{
		return (a_seq << 1) | (a_writing ? 1ull : 0ull);
	}

	std::uint64_t WatchpointSlots::SeqOfVersion(std::uint64_t a_version) noexcept
	{
		return a_version >> 1;
	}

	bool WatchpointSlots::VersionIsWriting(std::uint64_t a_version) noexcept
	{
		return (a_version & 1ull) != 0;
	}

	bool WatchpointSlots::FreeSlot(const Slot& a_slot) noexcept
	{
		return a_slot.address == 0 || (a_slot.flags & kWatchSlotReleased) != 0;
	}

	bool WatchpointSlots::ClaimEntry(Slot& a_slot) noexcept
	{
		for (int attempt = 0; attempt < kClaimAttempts; ++attempt) {
			const auto version = a_slot.version.load(std::memory_order_acquire);
			if (VersionIsWriting(version)) {
				Relax();
				continue;
			}
			std::uint64_t expected = version;
			if (a_slot.version.compare_exchange_weak(expected, version | 1ull, std::memory_order_acq_rel, std::memory_order_acquire)) {
				return true;
			}
			Relax();
		}
		_claimDrops.fetch_add(1, std::memory_order_relaxed);
		return false;
	}

	void WatchpointSlots::Publish(Slot& a_slot, std::uint64_t a_claimedVersion) noexcept
	{
		// Barrier, then publish the next even sequence: a reader that saw the odd
		// claim skips the entry; a reader that sees this version knows the payload
		// write is complete.
		std::atomic_signal_fence(std::memory_order_seq_cst);
		a_slot.version.store(a_claimedVersion + 2, std::memory_order_release);
	}

	bool WatchpointSlots::Claim(std::uintptr_t a_address, std::uintptr_t a_valueAtArm, bool a_armedWasCode, std::uintptr_t a_allocSite,
		std::uint64_t a_tick, std::uint32_t a_generation, std::uint32_t a_threadId, std::size_t& a_outIndex) noexcept
	{
		if (a_address == 0) {
			return false;
		}

		// Bounded scan for a free slot. A busy (mid-write) entry is retried
		// within the whole-table attempt loop rather than spinning on one entry.
		for (int attempt = 0; attempt < kClaimAttempts; ++attempt) {
			bool anyFree = false;
			for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
				auto&      slot = _slots[i];
				const auto version = slot.version.load(std::memory_order_acquire);
				if (VersionIsWriting(version)) {
					continue;
				}
				if (!FreeSlot(slot)) {
					continue;
				}
				anyFree = true;

				std::uint64_t expected = version;
				if (!slot.version.compare_exchange_weak(expected, version | 1ull, std::memory_order_acq_rel, std::memory_order_acquire)) {
					Relax();
					break;  // re-scan from the top with fresh state
				}

				slot.address = a_address;
				slot.valueAtArm = a_valueAtArm;
				slot.armedWasCode = a_armedWasCode;
				slot.allocSite = a_allocSite;
				slot.armedTick = a_tick;
				slot.freeTick = 0;
				slot.generation = a_generation;
				slot.threadId = a_threadId;
				slot.flags = kWatchSlotOccupied;
				Publish(slot, version);

				_claims.fetch_add(1, std::memory_order_relaxed);
				a_outIndex = i;
				return true;
			}

			if (!anyFree) {
				// All four slots hold a live, un-released block. Drop and count:
				// the sample is full, and the rotation (free, hold timeout) is
				// what makes room.
				_claimDrops.fetch_add(1, std::memory_order_relaxed);
				return false;
			}
		}

		_claimDrops.fetch_add(1, std::memory_order_relaxed);
		return false;
	}

	bool WatchpointSlots::Release(std::uintptr_t a_address, std::uint64_t a_tick) noexcept
	{
		if (a_address == 0) {
			return false;
		}
		for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
			auto& slot = _slots[i];
			if (VersionIsWriting(slot.version.load(std::memory_order_acquire))) {
				continue;
			}
			if (slot.address != a_address || (slot.flags & kWatchSlotReleased) != 0) {
				continue;
			}
			if (!ClaimEntry(slot)) {
				return false;  // contended: the sweeper will retry on rotation
			}
			const auto claimed = slot.version.load(std::memory_order_relaxed) & ~1ull;
			slot.flags |= kWatchSlotReleased;
			slot.armedTick = a_tick;
			slot.freeTick = a_tick;
			Publish(slot, claimed);
			_releases.fetch_add(1, std::memory_order_relaxed);
			return true;
		}
		return false;
	}

	bool WatchpointSlots::MarkTripped(std::size_t a_index, std::uint64_t a_tick) noexcept
	{
		if (a_index >= kWatchpointSlotCount) {
			return false;
		}
		auto&      slot = _slots[a_index];
		const auto version = slot.version.load(std::memory_order_acquire);
		if (VersionIsWriting(version)) {
			return false;
		}
		if (!ClaimEntry(slot)) {
			return false;
		}
		const auto claimed = slot.version.load(std::memory_order_relaxed) & ~1ull;
		slot.flags |= kWatchSlotTripped;
		slot.armedTick = a_tick;
		Publish(slot, claimed);
		_trips.fetch_add(1, std::memory_order_relaxed);
		return true;
	}

	bool WatchpointSlots::RotateOldest(std::uint64_t a_nowTick, std::uint64_t a_maxHoldMs) noexcept
	{
		int    oldest = -1;
		std::uint64_t oldestTick = 0;
		for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
			const auto& slot = _slots[i];
			if (VersionIsWriting(slot.version.load(std::memory_order_acquire))) {
				continue;
			}
			if (slot.address == 0 || (slot.flags & kWatchSlotReleased) != 0) {
				continue;
			}
			if (oldest < 0 || slot.armedTick < oldestTick) {
				oldest = static_cast<int>(i);
				oldestTick = slot.armedTick;
			}
		}
		if (oldest < 0) {
			return false;
		}
		if (a_nowTick < oldestTick || (a_nowTick - oldestTick) < a_maxHoldMs) {
			return false;
		}
		if (Release(_slots[static_cast<std::size_t>(oldest)].address, a_nowTick)) {
			_rotations.fetch_add(1, std::memory_order_relaxed);
			return true;
		}
		return false;
	}

	std::size_t WatchpointSlots::Snapshot(WatchSlotSnapshot (&a_out)[kWatchpointSlotCount]) const noexcept
	{
		std::size_t count = 0;
		for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
			a_out[i] = WatchSlotSnapshot{};
			const auto& slot = _slots[i];

			const auto v1 = slot.version.load(std::memory_order_acquire);
			if (VersionIsWriting(v1)) {
				continue;
			}
			WatchSlotSnapshot copy;
			copy.address = slot.address;
			copy.valueAtArm = slot.valueAtArm;
			copy.allocSite = slot.allocSite;
			copy.armedTick = slot.armedTick;
			copy.freeTick = slot.freeTick;
			copy.generation = slot.generation;
			copy.flags = slot.flags;
			copy.threadId = slot.threadId;
			copy.armedWasCode = slot.armedWasCode;
			copy.valid = true;
			std::atomic_signal_fence(std::memory_order_seq_cst);
			const auto v2 = slot.version.load(std::memory_order_acquire);
			if (v1 != v2) {
				continue;  // torn: treat as free for this snapshot
			}
			if (copy.address == 0 || (copy.flags & (kWatchSlotReleased | kWatchSlotTripped)) != 0) {
				continue;  // free/released/tripped: BuildDr7 must disable it
			}
			a_out[i] = copy;
			++count;
		}
		return count;
	}

	bool WatchpointSlots::ReadSlot(std::size_t a_index, WatchSlotSnapshot& a_out) const noexcept
	{
		a_out = WatchSlotSnapshot{};
		if (a_index >= kWatchpointSlotCount) {
			return false;
		}
		const auto& slot = _slots[a_index];

		const auto v1 = slot.version.load(std::memory_order_acquire);
		if (VersionIsWriting(v1)) {
			return false;
		}
		WatchSlotSnapshot copy;
		copy.address = slot.address;
		copy.valueAtArm = slot.valueAtArm;
		copy.allocSite = slot.allocSite;
		copy.armedTick = slot.armedTick;
		copy.freeTick = slot.freeTick;
		copy.generation = slot.generation;
		copy.flags = slot.flags;
		copy.threadId = slot.threadId;
		copy.armedWasCode = slot.armedWasCode;
		copy.valid = true;
		std::atomic_signal_fence(std::memory_order_seq_cst);
		const auto v2 = slot.version.load(std::memory_order_acquire);
		if (v1 != v2) {
			return false;  // torn
		}
		if (copy.address == 0) {
			return false;
		}
		a_out = copy;
		return true;
	}

	std::size_t WatchpointSlots::ClearAll(std::uint64_t a_tick) noexcept
	{
		std::size_t cleared = 0;
		for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
			auto& slot = _slots[i];
			const auto version = slot.version.load(std::memory_order_acquire);
			if (VersionIsWriting(version)) {
				continue;
			}
			if ((slot.flags & kWatchSlotReleased) != 0) {
				continue;  // already free
			}
			if (!ClaimEntry(slot)) {
				continue;
			}
			const auto claimed = slot.version.load(std::memory_order_relaxed) & ~1ull;
			if (slot.address != 0) {
				++cleared;
			}
			slot.address = 0;
			slot.valueAtArm = 0;
			slot.armedWasCode = false;
			slot.allocSite = 0;
			slot.flags = kWatchSlotReleased;
			slot.armedTick = a_tick;
			slot.freeTick = a_tick;
			Publish(slot, claimed);
		}
		return cleared;
	}

	std::size_t WatchpointSlots::OccupiedCount() const noexcept
	{
		std::size_t count = 0;
		for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
			const auto& slot = _slots[i];
			if (VersionIsWriting(slot.version.load(std::memory_order_acquire))) {
				continue;
			}
			if (slot.address != 0 && (slot.flags & kWatchSlotReleased) == 0) {
				++count;
			}
		}
		return count;
	}

	void WatchpointSlots::ResetForTesting() noexcept
	{
		for (auto& slot : _slots) {
			slot.version.store(0, std::memory_order_relaxed);
			slot.address = 0;
			slot.valueAtArm = 0;
			slot.armedWasCode = false;
			slot.allocSite = 0;
			slot.armedTick = 0;
			slot.freeTick = 0;
			slot.generation = 0;
			slot.flags = 0;
			slot.threadId = 0;
		}
		_claims.store(0, std::memory_order_relaxed);
		_claimDrops.store(0, std::memory_order_relaxed);
		_releases.store(0, std::memory_order_relaxed);
		_trips.store(0, std::memory_order_relaxed);
		_rotations.store(0, std::memory_order_relaxed);
	}
}