#pragma once

#include "Core/WatchpointEncoding.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

#if defined(_MSC_VER)
#	include <intrin.h>  // _mm_pause for the bounded writer claim loop (matches ShadowLedger.h)
#endif

// The four DR slots, as a lock-free table.
//
// The table is the in-process model of "what DR0-DR3 currently watch". It uses
// the project's per-entry seqlock idiom (ShadowLedger / src/Ipc/ShmLayout.h):
// bit 0 of `version` is set while a writer owns an entry, the rest is a
// monotone sequence. A reader -- including the vectored exception handler on a
// faulting thread -- copies the payload, re-reads the version and rejects a
// torn copy. There is no lock and no allocation anywhere, so the trap path can
// read it safely.
//
// Writers use the same bounded claim as the ledger: 16 pause-separated CAS
// attempts, then the claim is DROPPED and counted. An unbounded spin on the
// allocation hot path could burn a scheduling quantum and stall the game, which
// is exactly the failure the shadow ledger already decided not to risk.
//
// Why a table and not a plain array: the slots are written by the allocation
// hook (any thread) and by the sweeper (promotion, rotation, release on free),
// and read by the trap handler (any thread). A seqlock gives the trap handler a
// consistent snapshot without ever blocking a game thread.

namespace hs
{
	enum WatchSlotFlags : std::uint32_t
	{
		kWatchSlotOccupied = 1u << 0,
		kWatchSlotTripped = 1u << 1,   // a write was caught; the watch is one-report-only
		kWatchSlotReleased = 1u << 2,  // the block was freed; the slot may be reused
	};

	struct WatchSlotSnapshot
	{
		std::uintptr_t address = 0;      // the watched block (its first 8 bytes)
		std::uintptr_t valueAtArm = 0;   // first qword when the watch was armed
		std::uintptr_t allocSite = 0;    // the Scaleform allocation site, when known
		std::uint64_t  armedTick = 0;
		std::uint64_t  freeTick = 0;     // the tick Release() recorded the block's free (0 = not released)
		// 0.6.5: allocation-instance matching (see WatchpointEncoding.h).
		// `allocInstance` is the allocation this watch armed (0 = unknown);
		// `freeInstance` is the allocation the Release free belonged to (0 = unknown).
		std::uint64_t  allocInstance = 0;
		std::uint64_t  freeInstance = 0;
		std::uint32_t  generation = 0;
		std::uint32_t  flags = 0;
		std::uint32_t  threadId = 0;
		// The module-map classification of `valueAtArm` taken once at arming: was
		// the first qword a code pointer then? This is the "WAS a code pointer"
		// half of the benign-vs-degradation rule (DESIGN §13.4) and is computed on
		// the sweeper, never in the trap path.
		bool armedWasCode = false;
		bool valid = false;
	};

	class WatchpointSlots
	{
	public:
		static constexpr int kClaimAttempts = 16;

		static WatchpointSlots& Get();

		// Claim a free (empty or released) slot for `a_address`. On success
		// `a_outIndex` is 0..3. On failure (no free slot, or every candidate
		// entry stayed contended for all 16 attempts) ClaimDrops is incremented
		// and false is returned -- never a stall. `a_armedWasCode` is the
		// module-map classification of `a_valueAtArm` at arming time, kept so the
		// trap path and the drainer can apply the benign-vs-degradation rule
		// without ever calling the locking module map themselves.
		bool Claim(std::uintptr_t a_address, std::uintptr_t a_valueAtArm, bool a_armedWasCode, std::uintptr_t a_allocSite,
			std::uint64_t a_tick, std::uint32_t a_generation, std::uint32_t a_threadId, std::size_t& a_outIndex,
			std::uint64_t a_allocInstance = 0) noexcept;

		// Mark the slot holding `a_address` released (the block was freed). The
		// watch can stay armed in already-armed threads until the next re-arm
		// cycle; a stale watch is harmless and may catch a re-use. Returns true
		// when a slot matched.
		bool Release(std::uintptr_t a_address, std::uint64_t a_tick, std::uint64_t a_freeInstance = 0) noexcept;

		// Mark the slot with this index tripped, so it is not re-armed.
		bool MarkTripped(std::size_t a_index, std::uint64_t a_tick) noexcept;

		// Release the slot that has been armed the longest when it is older than
		// `a_maxHoldMs`. Returns true when something was released. This is what
		// makes the sample rotate even when the watched blocks are immortal.
		bool RotateOldest(std::uint64_t a_nowTick, std::uint64_t a_maxHoldMs) noexcept;

		// Copy up to `kWatchpointSlotCount` occupied, non-released slots. The
		// caller (the arming sweep) uses this as the address[] it writes to DR0-DR3.
		// Returns the number of valid entries; `a_out[i].address` is 0 for a free
		// slot, so BuildDr7 disables it.
		std::size_t Snapshot(WatchSlotSnapshot (&a_out)[kWatchpointSlotCount]) const noexcept;

		// Lock-free read of one slot by index. Used by the trap path, which gets
		// the index from DR6. Returns false for an invalid/torn/empty slot.
		bool ReadSlot(std::size_t a_index, WatchSlotSnapshot& a_out) const noexcept;

		// Mark every slot free. Called on shutdown; the caller then asserts the
		// hardware registers are clear on every thread. Returns the number of
		// slots that were still occupied.
		std::size_t ClearAll(std::uint64_t a_tick) noexcept;

		[[nodiscard]] std::size_t OccupiedCount() const noexcept;
		[[nodiscard]] std::uint64_t Claims() const noexcept { return _claims.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t ClaimDrops() const noexcept { return _claimDrops.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t Releases() const noexcept { return _releases.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t Trips() const noexcept { return _trips.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t Rotations() const noexcept { return _rotations.load(std::memory_order_relaxed); }

		void ResetForTesting() noexcept;

	private:
		// Portable CPU relax for the bounded claim loop. The plugin is x64
		// Windows; the off-game tests also build on aarch64.
		static void Relax() noexcept
		{
#if defined(_MSC_VER)
			_mm_pause();
#elif defined(__i386__) || defined(__x86_64__)
			__builtin_ia32_pause();
#else
			std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
		}

		struct Slot
		{
			std::atomic<std::uint64_t> version{ 0 };
			std::uintptr_t             address = 0;
			std::uintptr_t             valueAtArm = 0;
			std::uintptr_t             allocSite = 0;
			std::uint64_t              armedTick = 0;
			std::uint64_t              freeTick = 0;
			std::uint64_t              allocInstance = 0;
			std::uint64_t              freeInstance = 0;
			std::uint32_t              generation = 0;
			std::uint32_t              flags = 0;
			std::uint32_t              threadId = 0;
			bool                       armedWasCode = false;
		};

		[[nodiscard]] static bool            FreeSlot(const Slot& a_slot) noexcept;
		[[nodiscard]] static std::uint64_t   VersionFor(std::uint64_t a_seq, bool a_writing) noexcept;
		[[nodiscard]] static std::uint64_t   SeqOfVersion(std::uint64_t a_version) noexcept;
		[[nodiscard]] static bool            VersionIsWriting(std::uint64_t a_version) noexcept;
		// Bounded claim of one entry. Returns false (and bumps ClaimDrops) when
		// the entry stays busy for the whole loop.
		bool                                 ClaimEntry(Slot& a_slot) noexcept;
		static void                          Publish(Slot& a_slot, std::uint64_t a_claimedVersion) noexcept;

		Slot                       _slots[kWatchpointSlotCount];
		std::atomic<std::uint64_t> _claims{ 0 };
		std::atomic<std::uint64_t> _claimDrops{ 0 };
		std::atomic<std::uint64_t> _releases{ 0 };
		std::atomic<std::uint64_t> _trips{ 0 };
		std::atomic<std::uint64_t> _rotations{ 0 };
	};
}