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
}