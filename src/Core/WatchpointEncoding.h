#pragma once

// x86-64 debug-register (DR0-DR3 / DR6 / DR7) encoding, kept dependency-free
// and header-only.
//
// This is deliberately separated from the privileged layer
// (Core/HwWatchpoint.h) so the bit layout is a claim about the ISA that the
// off-game test suite can check on EVERY platform, including Linux, where the
// Windows debug-register API does not exist. The privileged layer only has to
// be right about calling GetThreadContext/SetThreadContext; the arithmetic here
// is checked once, on both toolchains.
//
// DR7 layout (Intel SDM Vol 3B 17.2.2):
//   bit  2*i      : L_i   local enable for DRi
//   bit  2*i + 1  : G_i   global enable for DRi
//   bits 16+4*i   : RW_i  breakpoint condition (00 execute, 01 data write,
//                          11 data read/write)
//   bits 18+4*i   : LEN_i data length (00 = 1, 01 = 2, 11 = 4, 10 = 8 bytes)
//
// HeapSentinel wants the crash family this project keeps seeing: a 32-bit write
// landing in the low half of an 8-byte pointer field. So the watch is
// LEN=10b (8 bytes) and RW=01b (write only) on the first 8 bytes of the block,
// which is the object's vtable pointer. A read watch would trap on every
// ordinary dispatch through that vtable and drown the writer we are hunting.

#include <cstddef>
#include <cstdint>

namespace hs
{
	// DR0-DR3: four hardware slots, per thread, on every x86-64 CPU.
	inline constexpr std::size_t kWatchpointSlotCount = 4;

	// Byte length of a watch: the first qword of the block.
	inline constexpr std::size_t kWatchpointLength = 8;

	// RW=01b (data write), LEN=10b (8 bytes), for slot i.
	[[nodiscard]] constexpr std::uint64_t Dr7LocalEnableBit(std::size_t a_slot) noexcept
	{
		return 1ull << (2u * a_slot);
	}

	[[nodiscard]] constexpr std::uint64_t Dr7WriteBits(std::size_t a_slot) noexcept
	{
		const auto rw = 0b01ull << (16u + 4u * a_slot);   // data write
		const auto len = 0b10ull << (18u + 4u * a_slot);  // 8 bytes
		return rw | len;
	}

	// DR7 that enables a write watch on every non-zero entry of `a_addresses`.
	// Slots are assigned in order, so address i is watched by DRi.
	[[nodiscard]] constexpr std::uint64_t BuildDr7(const std::uintptr_t* a_addresses, std::size_t a_count) noexcept
	{
		std::uint64_t dr7 = 0;
		for (std::size_t i = 0; i < a_count && i < kWatchpointSlotCount; ++i) {
			if (a_addresses[i] != 0) {
				dr7 |= Dr7LocalEnableBit(i) | Dr7WriteBits(i);
			}
		}
		return dr7;
	}

	[[nodiscard]] constexpr bool Dr7SlotEnabled(std::uint64_t a_dr7, std::size_t a_slot) noexcept
	{
		return (a_dr7 & Dr7LocalEnableBit(a_slot)) != 0;
	}

	// Disable one slot and clear its condition/length. Used in the trap path:
	// once a writer has been caught, that watch is one-report-only, so a hot
	// loop cannot turn into a trap storm.
	[[nodiscard]] constexpr std::uint64_t Dr7ClearSlot(std::uint64_t a_dr7, std::size_t a_slot) noexcept
	{
		return a_dr7 & ~(Dr7LocalEnableBit(a_slot) | Dr7WriteBits(a_slot));
	}

	// Which DRi fired, per DR6 bits B0..B3. -1 when this was not one of ours
	// (e.g. a trap-flag single step), which must be handed to the next handler.
	[[nodiscard]] constexpr int Dr6TriggeredSlot(std::uint64_t a_dr6) noexcept
	{
		for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
			if ((a_dr6 & (1ull << i)) != 0) {
				return static_cast<int>(i);
			}
		}
		return -1;
	}

	// A data breakpoint must be aligned to its length on x86. Scaleform blocks
	// are 8-byte aligned, but the check is cheap and a misaligned watch is
	// undefined behaviour rather than a missed trap.
	[[nodiscard]] constexpr bool WatchableAddress(std::uintptr_t a_address) noexcept
	{
		return (a_address & (kWatchpointLength - 1u)) == 0;
	}

	[[nodiscard]] constexpr bool WatchableSize(std::size_t a_size) noexcept
	{
		return a_size >= kWatchpointLength;
	}

	// -----------------------------------------------------------------------
	// Trap ownership and write classification (0.6.2).
	//
	// Two pure decisions that used to live inside the VEH and the drainer, and
	// whose bugs killed a session. They are kept here -- dependency-free and
	// constexpr -- so the off-game suite checks them on EVERY toolchain, and the
	// Windows test drives them with a real hardware #DB.
	// -----------------------------------------------------------------------

	// Who a #DB belongs to. The narrow rule the 0.6.1 crash demanded: a DR slot
	// WE EVER ARMED on this thread is ours even when the table has moved on or
	// the entry is gone. Only a #DB on a slot we never touched is foreign, and
	// only that returns CONTINUE_SEARCH.
	enum class WatchpointTrapOwner : std::uint8_t
	{
		kForeign,         // not ours: hand it to the next handler (CONTINUE_SEARCH)
		kTableCurrent,    // ours; the live table slot still holds this address
		kTableReleased,   // ours; the table slot holds this address but it was released
		kStaleThreadArm,  // ours; the table moved on, this thread's DR is a leftover arm
		kStaleBareArm,    // ours; we armed this slot here, but have no address record left
	};

	[[nodiscard]] constexpr bool WatchpointOwnerIsOurs(WatchpointTrapOwner a_owner) noexcept
	{
		return a_owner != WatchpointTrapOwner::kForeign;
	}

	[[nodiscard]] constexpr bool WatchpointOwnerIsStale(WatchpointTrapOwner a_owner) noexcept
	{
		return a_owner == WatchpointTrapOwner::kStaleThreadArm || a_owner == WatchpointTrapOwner::kStaleBareArm;
	}

	// Decide who owns a trapped slot from the raw debug-register state plus the
	// two records we keep. Ordering matters: the live table is consulted first
	// (it is authoritative while the arm is current), then the per-thread arm
	// record (the safety net for a retired/re-armed address). A slot that is not
	// enabled in DR7 -- or whose DRi is zero -- is never a data watchpoint.
	[[nodiscard]] constexpr WatchpointTrapOwner ClassifyTrapOwner(
		bool a_dr7SlotEnabled, std::uintptr_t a_drAddress,
		bool a_everArmedThisSlot, bool a_threadArmValid, std::uintptr_t a_threadArmAddress,
		bool a_tableValid, std::uintptr_t a_tableAddress, bool a_tableReleased) noexcept
	{
		if (!a_dr7SlotEnabled || a_drAddress == 0) {
			return WatchpointTrapOwner::kForeign;
		}
		if (a_tableValid && a_tableAddress == a_drAddress) {
			return a_tableReleased ? WatchpointTrapOwner::kTableReleased : WatchpointTrapOwner::kTableCurrent;
		}
		if (a_everArmedThisSlot) {
			if (a_threadArmValid && a_threadArmAddress == a_drAddress) {
				return WatchpointTrapOwner::kStaleThreadArm;
			}
			return WatchpointTrapOwner::kStaleBareArm;
		}
		return WatchpointTrapOwner::kForeign;
	}

	// Is a write to a watched qword a real DEGRADATION (a code pointer turned
	// into something that is not code) or benign construction/rewriting?
	//
	// A hardware data breakpoint fires on ANY write, including the allocator's
	// or CRT's initialisation of a freshly allocated block -- the observed trip
	// was VCRUNTIME140 writing 0 into an already-zero qword. Reporting that is
	// noise, and releasing the slot on it loses the watch exactly when the
	// object is being constructed and about to receive its vtable. So the rule
	// is deliberately narrow:
	//
	//   * unreadable after the write               -> benign (never claim bytes we cannot read)
	//   * unchanged since arming                   -> benign (before == after by construction)
	//   * the armed value was not a code pointer    -> benign (nothing to clobber)
	//   * code -> different code                    -> benign (a legitimate vtable swap)
	//   * code -> non-code                          -> DEGRADATION (a clobbered vtable)
	enum class WatchpointWriteKind : std::uint8_t
	{
		kBenign,
		kDegradation,
	};

	[[nodiscard]] constexpr WatchpointWriteKind ClassifyWatchedWrite(
		std::uintptr_t a_valueAtArm, bool a_armedWasCode,
		std::uintptr_t a_valueAfter, bool a_afterReadable, bool a_afterIsCode) noexcept
	{
		if (!a_afterReadable) {
			return WatchpointWriteKind::kBenign;
		}
		if (a_valueAfter == a_valueAtArm) {
			return WatchpointWriteKind::kBenign;
		}
		if (!a_armedWasCode) {
			return WatchpointWriteKind::kBenign;
		}
		if (!a_afterIsCode) {
			return WatchpointWriteKind::kDegradation;
		}
		return WatchpointWriteKind::kBenign;
	}

	// -----------------------------------------------------------------------
	// 0.6.3: the structural survival rule and the allocator post-free window.
	// -----------------------------------------------------------------------

	// Once this process has EVER programmed a debug register, a #DB is ours as a
	// matter of STRUCTURE, not of classification. This is deliberately not a
	// smarter ClassifyTrapOwner: the 0.6.2 fix was a correct-looking classifier
	// with a mutation proof that reproduced the production exception class, and
	// the game still died because a #DB reached our handler that the classifier
	// called foreign. A camera cannot out-reason the exception it is trying to
	// survive, so the survival decision no longer depends on classifying at all.
	//
	// A foreign #DB is effectively nonexistent in this process -- nothing
	// requested one after we armed, and an escaping one kills the game anyway --
	// so consuming is strictly better than dying. Classification is still used
	// to decide what to RECORD and whether to release a slot, never whether the
	// process survives. Before we have ever programmed a DR (feature disabled,
	// or enabled but not yet past the trigger) nothing can be masked, and a #DB
	// is genuinely foreign and is passed on.
	[[nodiscard]] constexpr bool MustConsumeDebugException(bool a_everProgrammedAnyDr) noexcept
	{
		return a_everProgrammedAnyDr;
	}

	// How long after a block's recorded free a first-word write is still the
	// allocator's own bookkeeping rather than a use-after-free.
	//
	// 0.6.3 used 32 ms derived from ONE event (the 2026-09-23 21:37:41 link write,
	// one GetTickCount64 tick after the recorded free). The 2026-09-24 in-game trip
	// falsified that derivation: our free hook records the free tick BEFORE it
	// calls the original free, so the allocator's link write follows the record by
	// the duration of our own remaining hook work (a stack capture and ledger
	// lookups), and hk_SfRealloc records the free of the old block only AFTER
	// o_SfRealloc returns, so the write can precede the record by the same kind of
	// latency. The trip measures those gaps directly: 0-114 ms after the recorded
	// free and 1-165 ms before it. 250 ms is the next round bound above the
	// observed worst case, and the two genuine delayed writes in the same corpus
	// are 1858 ms and 12379 ms later -- an order of magnitude outside it.
	//
	// The window is applied on BOTH sides of the recorded free (see
	// ClassifyWriteAgainstFree), because both directions are the allocator's own
	// operation; only a write outside it is a genuine delayed write-after-free.
	// Residual risk, stated plainly: a genuine use-after-free write landing within
	// 250 ms of the free is treated as allocator bookkeeping and missed. That is
	// the price of not reporting every free-list insertion; the window is a
	// bounded silence, not a claim of completeness.
	inline constexpr std::uint64_t kAllocatorBookkeepingWindowMs = 250;

	// Which free the classifier used. The slot snapshot's Release tick and the
	// free ring's newest record for the same address are two different events in
	// general (the ring never invalidates a record when the address is recycled),
	// so which one won is part of the evidence, not an implementation detail.
	enum class FreeTickSource : std::uint8_t
	{
		kNone = 0,
		kSlotSnapshot = 1,
		kFreeRing = 2,
	};

	[[nodiscard]] constexpr const char* FreeTickSourceName(FreeTickSource a_source) noexcept
	{
		switch (a_source) {
		case FreeTickSource::kSlotSnapshot:
			return "slot-release";
		case FreeTickSource::kFreeRing:
			return "free-ring";
		default:
			return "none";
		}
	}

	// The free tick to classify against: the free ring's newest record for the
	// address WINS whenever it is NEWER than the slot's Release tick. The reverse
	// order was the 0.6.3 defect -- an already-released slot's stale Release tick
	// shadowed a newer free record, and a write that was the allocator linking the
	// just-freed block was reported as a clobber (the 17:56:56 case: slot tick
	// 261486289, ring 261487115, trap 261487115, i.e. a delta of 826 ms instead of
	// 0). When the ring's record is OLDER it is from a previous life of a recycled
	// address, so the slot's own Release (a later free of the same address) is the
	// better evidence and is kept.
	[[nodiscard]] constexpr std::uint64_t PreferNewestFreeTick(std::uint64_t a_slotFreeTick, std::uint64_t a_ringFreeTick) noexcept
	{
	// MUTATION M3 (temporary): the stale slot Release tick shadows the free
	// ring's newest record.
	(void)a_ringFreeTick;
	return a_slotFreeTick;
	}

	// What the recorded free says about a first-word write. The two allocator
	// cases are kept apart instead of being forced through one post-free window:
	// they are different orderings of the same operation, and a reader has to be
	// able to tell which one was seen.
	enum class WatchpointFreeContext : std::uint8_t
	{
		kLive,                   // no free recorded for this address: a free explains nothing
		kPostFreeLink,           // free <= trap, within the window: the allocator linking it
		kReallocInProgress,      // trap < free, within the window: the free lands after the write
		kFreePredatesArm,        // the free predates THIS arm: stale evidence about a recycled address
		kDelayedWriteAfterFree,  // free >= arm and outside the window: a genuine delayed UAF
	};

	[[nodiscard]] constexpr const char* WatchpointFreeContextName(WatchpointFreeContext a_context) noexcept
	{
		switch (a_context) {
		case WatchpointFreeContext::kPostFreeLink:
			return "allocator-post-free-link";
		case WatchpointFreeContext::kReallocInProgress:
			return "allocator-realloc-in-progress";
		case WatchpointFreeContext::kFreePredatesArm:
			return "free-predates-arm";
		case WatchpointFreeContext::kDelayedWriteAfterFree:
			return "delayed-write-after-free";
		default:
			return "live";
		}
	}

	// Only these two are the allocator's own bookkeeping. `kFreePredatesArm` is
	// deliberately NOT one of them: when the free ring's only record for the
	// address is older than the arm, the write is real and unclassified (the
	// address was recycled, or a watch was armed on an already-freed block), and
	// silencing it would hide a write to a freed block.
	[[nodiscard]] constexpr bool FreeContextIsAllocatorBookkeeping(WatchpointFreeContext a_context) noexcept
	{
		return a_context == WatchpointFreeContext::kPostFreeLink || a_context == WatchpointFreeContext::kReallocInProgress;
	}

	// The classifier, applied the same way in the trap path and in the drainer
	// (defence in depth for the race where the free record lands after the trap).
	// `a_armTick` is 0 when unknown; for a released slot the snapshot's armedTick
	// IS the release tick, so the predates-arm test is a no-op there by design.
	[[nodiscard]] constexpr WatchpointFreeContext ClassifyWriteAgainstFree(
		std::uint64_t a_freeTick, std::uint64_t a_armTick, std::uint64_t a_trapTick, std::uint64_t a_windowMs) noexcept
	{
		if (a_freeTick == 0) {
			return WatchpointFreeContext::kLive;
		}
		if (a_armTick != 0 && a_freeTick < a_armTick) {
			return WatchpointFreeContext::kFreePredatesArm;
		}
		if (a_trapTick >= a_freeTick) {
			return (a_trapTick - a_freeTick) <= a_windowMs ? WatchpointFreeContext::kPostFreeLink
													 : WatchpointFreeContext::kDelayedWriteAfterFree;
		}
		return (a_freeTick - a_trapTick) <= a_windowMs ? WatchpointFreeContext::kReallocInProgress
													: WatchpointFreeContext::kDelayedWriteAfterFree;
	}
}