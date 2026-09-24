#pragma once

#include "Core/WatchpointEncoding.h"

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
		std::uint64_t  freeTick = 0;         // the block's recorded free tick, when known (0 = none)
		// 0.6.4 FIX B: which free the classifier used (slot Release tick, or the
		// free ring's newest record for the address). Two different events in
		// general, so which one won is evidence, not an implementation detail.
		std::uint32_t  freeTickSource = 0;   // FreeTickSource in WatchpointEncoding.h
		std::uint32_t  slotIndex = 0;        // which DR slot fired (0..3)
		std::uint32_t  threadId = 0;         // the writer's thread
		std::uint32_t  dr6 = 0;
		std::uint32_t  dr7 = 0;              // raw DR7 at the trap (0.6.3: diagnosable foreign #DBs)
		std::uint32_t  armGeneration = 0;    // generation of the arm that fired
		std::uint32_t  flags = 0;            // kWatchReport* bits below
		// 0.6.3: everything needed to diagnose a #DB the classifier did NOT
		// attribute. Recorded before the trap is dealt with, so a recurrence of
		// the 0.6.2 fatal case leaves data instead of another mystery.
		std::uint32_t  everArmedMask = 0;    // slots this thread was ever armed with
		std::uintptr_t drAddress[kWatchpointSlotCount] = {};  // raw DR0-DR3 at the trap
		bool           anyDrProgrammed = false;  // has this process ever written a DR?
		// The module-map classification of `valueAtArm` taken at arming time: was
		// the first qword a code pointer then? Stored so the drainer can apply the
		// benign-vs-degradation rule without re-classifying old bytes.
		bool armedWasCode = false;
		// ------------------------------------------------------------------
		// 0.6.4 FIX A: the DR fields above are a MEASUREMENT, and this says how
		// they were obtained. The 2026-09-24 trip produced 104/104 unattributed
		// records with dr6=dr7=dr0-3=0, which cannot be true of a delivered #DB
		// (a trap flag sets DR6.BS, a data breakpoint sets B0-B3). We could not
		// tell "the read failed" from "the read succeeded and returned zero", so
		// the trap path now takes its OWN read of the faulting thread.
		//
		// Which source supplies dr6/dr7/drAddress: the exception record is used
		// WHENEVER it carries anything, because on real Windows it does for a data
		// breakpoint (proven by the in-game attributed reports and by the Windows
		// hardware test, where the exception record's DR7 disagrees with
		// GetThreadContext's). The faulting-thread read is used only when the
		// exception record is empty -- which is exactly the case that has to be
		// legible. Both sets are always in the record, so `threadDr6 == 0` with
		// `drReadStatus == ok` says "an independent read also finds nothing" while
		// `drReadStatus == failed` says "nothing was measured at all".
		// ------------------------------------------------------------------
		std::uint32_t  drReadSource = 0;    // kDrSource* below: which set dr6/dr7/dr0-3 came from
		std::uint32_t  drReadStatus = 0;    // kDrRead* below: did the faulting-thread read succeed?
		std::uint32_t  drReadError = 0;     // GetLastError() when the read failed (0 otherwise)
		std::uint32_t  drReadFlags = 0;     // kWatchReportDr* below
		// The exception record's own DR state. 0.6.3 used only this, and on real
		// Windows it is populated for a data breakpoint (the in-game trip's
		// attributed reports read dr6=0xFFFF0FF2 dr7=0x99990055). It is the
		// authoritative source whenever it carries anything, which is why the
		// explicit read below does not override it.
		std::uint32_t  contextDr6 = 0;
		std::uint32_t  contextDr7 = 0;
		std::uint32_t  contextEFlags = 0;   // EFlags at the trap; TF (0x100) = a trap-flag single step
		std::uintptr_t contextDrAddress[kWatchpointSlotCount] = {};
		// The faulting thread's own DR state, read by GetThreadContext on the
		// faulting thread. Recorded whichever source won, so a reader can always
		// compare the two -- the comparison IS the answer FIX A needed: on the host
		// that produced 104 hollow records, does an independent read also return
		// zero, or does the read fail, or did only the exception record lose it?
		std::uintptr_t threadDrAddress[kWatchpointSlotCount] = {};
		std::uint32_t  threadDr6 = 0;
		std::uint32_t  threadDr7 = 0;
	};

	// Where dr6/dr7/drAddress in a record came from.
	inline constexpr std::uint32_t kDrSourceNone = 0;               // not a measurement at all
	inline constexpr std::uint32_t kDrSourceExceptionContext = 1;   // EXCEPTION_POINTERS::ContextRecord only
	inline constexpr std::uint32_t kDrSourceCurrentThread = 2;      // GetThreadContext on the faulting thread

	// The outcome of the chosen source read.
	inline constexpr std::uint32_t kDrReadNotAttempted = 0;
	inline constexpr std::uint32_t kDrReadOk = 1;
	inline constexpr std::uint32_t kDrReadFailed = 2;

	// The two DR sources disagree: the exception record's values differ from the
	// faulting-thread read's. Recorded because that disagreement is itself the
	// fact 0.6.3 could not see. (`threadDr6`/`threadDrAddress` carry the read's
	// values either way, so the disagreement can be inspected without this flag;
	// the flag makes it greppable.)
	inline constexpr std::uint32_t kWatchReportDrContextDisagrees = 1u << 5;
	// EFlags.TF was set at the trap: a trap-flag single step, not a data
	// breakpoint. When dr6 is genuinely zero this is the explanation to look for
	// first.
	inline constexpr std::uint32_t kWatchReportTrapFlagSet = 1u << 6;
	// The record carries a real debug-register measurement (drReadSource is not
	// kDrSourceNone). Set on every record the trap path writes in 0.6.4.
	inline constexpr std::uint32_t kWatchReportDrMeasured = 1u << 7;

	// The three outcomes the drainer must distinguish: the read failed (the
	// dr6/dr7/dr0-3 fields are NOT a measurement), the read succeeded and
	// genuinely returned zero debug state, or the read succeeded and found a
	// debug register set. Portable and constexpr so the off-game suite checks the
	// decision on every toolchain; the Windows test drives it with a real #DB.
	enum class DebugRegisterMeasurement : std::uint8_t
	{
		kNotAttempted,   // no measurement was taken (drReadSource == none)
		kReadFailed,     // GetThreadContext failed; the exception record is all we have
		kReadZero,       // the read succeeded and returned DR6 == 0 with DR0-DR3 all zero
		kReadNonZero,    // the read succeeded and found a debug register set
	};

	[[nodiscard]] constexpr DebugRegisterMeasurement ClassifyDebugRegisterMeasurement(
		std::uint32_t a_readSource, std::uint32_t a_readStatus, std::uint32_t a_dr6, const std::uintptr_t* a_drAddress,
		std::size_t a_count) noexcept
	{
	if (a_readSource == kDrSourceNone || a_readStatus == kDrReadNotAttempted) {
		return DebugRegisterMeasurement::kNotAttempted;
	}
	if (a_readStatus == kDrReadFailed) {
		return DebugRegisterMeasurement::kReadFailed;
	}
	// MUTATION M1 (temporary): never inspect the measured DR state, so a
	// successful read that found a breakpoint is reported as a zero read.
	(void)a_dr6;
	(void)a_drAddress;
	(void)a_count;
	return DebugRegisterMeasurement::kReadZero;
	}

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
	// 0.6.3: this #DB was NOT attributable to any slot we can name, yet it was
	// consumed structurally because this process has programmed a DR. The record
	// carries the raw DR6/DR7, the DR0-DR3 values, this thread's ever-armed mask
	// and the RIP, so the next occurrence is diagnosable rather than fatal. This
	// is measurement, not a verdict: an unattributed trap is reported as exactly
	// that, and never as a corruption.
	inline constexpr std::uint32_t kWatchReportUnattributed = 1u << 4;

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

		// ------------------------------------------------------------------
		// 0.6.4 accounting. These are counted HERE, in the portable record core,
		// rather than in the Windows-only watchpoint manager, because the periodic
		// stats line (Core/Stats.cpp) is compiled and linked by the off-game suite
		// too and must be able to read them without depending on a unit the Linux
		// build does not contain. Single writer set: the trap path and the drainer.
		// ------------------------------------------------------------------
		// A write silenced because it was the allocator linking a just-freed block,
		// or one written while a realloc of that block was still running (the two
		// are kept apart: they are different orderings of the same operation).
		void NotePostFreeSuppressed() noexcept { _postFreeSuppressed.fetch_add(1, std::memory_order_relaxed); }
		void NoteReallocSuppressed() noexcept { _reallocSuppressed.fetch_add(1, std::memory_order_relaxed); }
		// A report that could NOT be assigned to the allocator because the free
		// ring's only record for the address predates the arm.
		void NoteFreePredatesArm() noexcept { _freePredatesArm.fetch_add(1, std::memory_order_relaxed); }
		// How an unattributed #DB's debug-register state was measured. `kReadFailed`
		// means the fields in that record are NOT a measurement; `kReadZero` means a
		// successful read found no debug register set at all -- the question the
		// 0.6.3 log could not answer for 104/104 records.
		void NoteUnattributedMeasured(DebugRegisterMeasurement a_measurement) noexcept;

		[[nodiscard]] std::uint64_t PostFreeSuppressed() const noexcept { return _postFreeSuppressed.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t ReallocSuppressed() const noexcept { return _reallocSuppressed.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t FreePredatesArm() const noexcept { return _freePredatesArm.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t UnattributedDrReadFailed() const noexcept { return _drReadFailed.load(std::memory_order_relaxed); }
		[[nodiscard]] std::uint64_t UnattributedDrReadZero() const noexcept { return _drReadZero.load(std::memory_order_relaxed); }

		// Test helper: zero only the accounting above (the ring's data is reset by
		// ResetForTesting).
		void ResetSuppressionCountersForTesting() noexcept
		{
			_postFreeSuppressed.store(0, std::memory_order_relaxed);
			_reallocSuppressed.store(0, std::memory_order_relaxed);
			_freePredatesArm.store(0, std::memory_order_relaxed);
			_drReadFailed.store(0, std::memory_order_relaxed);
			_drReadZero.store(0, std::memory_order_relaxed);
		}

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
		std::atomic<std::uint64_t> _postFreeSuppressed{ 0 };
		std::atomic<std::uint64_t> _reallocSuppressed{ 0 };
		std::atomic<std::uint64_t> _freePredatesArm{ 0 };
		std::atomic<std::uint64_t> _drReadFailed{ 0 };
		std::atomic<std::uint64_t> _drReadZero{ 0 };
		std::atomic<bool>          _ready{ false };
	};

	// Deterministic textual encoding of one record, into a caller-supplied
	// buffer. No allocation, no locale, no std::string -- the drainer uses it to
	// build the fixed part of the report before it adds symbolised names.
	// Returns the number of characters that would have been written (snprintf
	// semantics: the buffer is always NUL-terminated when a_size > 0).
	[[nodiscard]] std::size_t EncodeWatchpointReport(const WatchpointReport& a_report, char* a_buffer, std::size_t a_size) noexcept;
}