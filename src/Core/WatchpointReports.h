#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

// Preallocated report buffer for the hardware-watchpoint feature.
//
// The trap path runs inside the vectored exception handler, on the faulting
// thread, in a process that may already be corrupt. Microsoft's own guidance is
// that a vectored handler must not acquire synchronization objects or allocate,
// and the project already paid for that lesson once (Report() builds
// std::strings and writes through spdlog). So the handler does exactly one
// thing here: it copies a POD record into a preallocated slot. A watchdog
// thread drains the ring and only THERE is the record turned into a string,
// symbolised and logged.
//
// The ring is lock-free for both sides:
//   * writers (any trapping thread) take a slot with fetch_add and publish it
//     through the project's per-slot seqlock, so a reader never sees a torn
//     record;
//   * the drainer is a single consumer and never blocks a writer.
// Overwriting an undrained record is counted (Dropped()), so a trap storm is
// legible instead of silent.

namespace hs
{
	struct WatchpointReport
	{
		std::uint64_t  seq = 0;
		std::uint64_t  tick = 0;             // GetTickCount64 at the trap
		std::uintptr_t watchedAddress = 0;   // the block's first 8 bytes (the address that actually trapped)
		std::uintptr_t valueAtArm = 0;       // first qword when the watch was armed
		std::uintptr_t valueAfterWrite = 0;  // first qword read after the trap
		std::uintptr_t writerRip = 0;        // RIP at the #DB (see note below)
		std::uintptr_t allocSite = 0;        // Scaleform allocation site, when known
		std::uintptr_t tableAddress = 0;     // what the live table slot held at the trap (0 = none); differs from `watchedAddress` for a stale arm
		std::uint64_t  armedTick = 0;
		std::uint32_t  slotIndex = 0;        // which DR slot fired (0..3)
		std::uint32_t  threadId = 0;         // the writer's thread
		std::uint32_t  dr6 = 0;
		std::uint32_t  armGeneration = 0;    // generation of the arm that fired
		std::uint32_t  flags = 0;            // kWatchReport* bits below
		// The module-map classification of `valueAtArm` taken at arming time: was
		// the first qword a code pointer then? Stored so the drainer can apply the
		// benign-vs-degradation rule without re-classifying old bytes.
		bool armedWasCode = false;
	};

	inline constexpr std::uint32_t kWatchReportValueUnreadable = 1u << 0;
	// The block had already been freed when the write landed: the slot was
	// released by the Scaleform free hook but its watch had not yet been removed.
	// This is the write-after-free shape of the second observed crash.
	inline constexpr std::uint32_t kWatchReportBlockReleased = 1u << 2;
	// On x86 a data breakpoint is a TRAP: it is delivered after the store
	// completes, so the saved RIP points at the instruction after the writer.
	// The drainer can walk back to the store when the bytes decode, and sets
	// this flag when it did. The raw trap RIP is always kept.
	inline constexpr std::uint32_t kWatchReportWriterRipAdjusted = 1u << 1;
	// This trap came from a DR slot on the trapping thread that still held an
	// OLD address: the slot had since been released or re-armed for a different
	// block, but the sweep had not yet reached that thread. `watchedAddress` is
	// the address that actually trapped, and `tableAddress` (when non-zero) is
	// what the live table slot holds now. This is the 0.6.1 fatal case: it must
	// be consumed, and it is labelled so a reader can tell it apart from a
	// current arm.
	inline constexpr std::uint32_t kWatchReportStaleArm = 1u << 3;

	class WatchpointReports
	{
	public:
		static WatchpointReports& Get();

		void Init(std::size_t a_capacity) noexcept;
		void Shutdown() noexcept;
		[[nodiscard]] bool Ready() const noexcept { return _ready.load(std::memory_order_acquire); }

		// Allocation-free, lock-free. Safe from the VEH.
		void Record(const WatchpointReport& a_report) noexcept;

		// Single-consumer drain of up to `a_max` undrained records, oldest
		// first. Returns how many were copied.
		std::size_t Drain(WatchpointReport* a_out, std::size_t a_max) noexcept;

		[[nodiscard]] std::size_t Capacity() const noexcept { return _capacity; }
		[[nodiscard]] std::size_t Count() const noexcept;
		[[nodiscard]] std::uint64_t Recorded() const noexcept { return _recorded.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t Dropped() const noexcept { return _dropped.load(std::memory_order_relaxed); }

		void ResetForTesting() noexcept;

	private:
		struct Slot
		{
			std::atomic<std::uint64_t> version{ 0 };
			WatchpointReport           report;
		};

		[[nodiscard]] static std::uint64_t VersionFor(std::uint64_t a_seq, bool a_writing) noexcept;
		[[nodiscard]] static std::uint64_t SeqOfVersion(std::uint64_t a_version) noexcept;
		[[nodiscard]] static bool          VersionIsWriting(std::uint64_t a_version) noexcept;
		[[nodiscard]] static std::size_t   NextPow2(std::size_t a_value) noexcept;

		std::unique_ptr<Slot[]>    _slots;
		std::size_t                _capacity = 0;
		std::atomic<std::uint64_t> _writeCursor{ 0 };  // 1-based recorded count
		std::atomic<std::uint64_t> _readCursor{ 0 };   // 1-based drained count
		std::atomic<std::uint64_t> _recorded{ 0 };
		std::atomic<std::uint64_t> _dropped{ 0 };
		std::atomic<bool>          _ready{ false };
	};

	// Deterministic textual encoding of one record, into a caller-supplied
	// buffer. No allocation, no locale, no std::string -- the drainer uses it to
	// build the fixed part of the report before it adds symbolised names.
	// Returns the number of characters that would have been written (snprintf
	// semantics: the buffer is always NUL-terminated when a_size > 0).
	[[nodiscard]] std::size_t EncodeWatchpointReport(const WatchpointReport& a_report, char* a_buffer, std::size_t a_size) noexcept;
}