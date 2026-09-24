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
	// allocator linking it into its free list rather than a use-after-free.
	//
	// The evidence (2026-09-23 21:37:41): the block was freed at tick
	// 188333102 and the first word rewritten at 188333103 -- one
	// GetTickCount64 tick later, microseconds in real time. GetTickCount64
	// advances in ~15.6 ms steps, so a free near a tick boundary and its link
	// just after it differ by one tick, and a slow free path can differ by two.
	// 32 ms (two ticks) covers the allocator's own bookkeeping. Residual risk,
	// stated plainly: a genuine use-after-free write landing within 32 ms of the
	// free is treated as a link and missed. That is the price of not reporting
	// every free-list insertion; the window is a bounded silence, not a claim of
	// completeness.
	inline constexpr std::uint64_t kAllocatorPostFreeLinkWindowMs = 32;

	[[nodiscard]] constexpr bool IsAllocatorPostFreeLink(
		std::uint64_t a_freeTick, std::uint64_t a_trapTick, std::uint64_t a_windowMs) noexcept
	{
		// MUTATION PROOF M3 (temporary): treat EVERY free as an allocator link, so
		// a delayed use-after-free is suppressed and test (d) must fail.
		(void)a_freeTick;
		(void)a_trapTick;
		(void)a_windowMs;
		return true;
	}
}