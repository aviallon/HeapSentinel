#include "PCH.h"

#include "Core/Watchpoints.h"

#include "Config.h"
#include "Core/Health.h"
#include "Core/HwWatchpoint.h"
#include "Core/ModuleMap.h"
#include "Core/Report.h"
#include "Core/ScaleformFreeRing.h"
#include "Core/ShadowLedger.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace hs
{
	namespace
	{
		// Fault-safe read of the watched qword. No C++ objects in this frame, so
		// SEH is legal (the same rule as Veh.cpp's SafeReadQword).
		[[nodiscard]] bool SafeReadQword(std::uintptr_t a_addr, std::uintptr_t& a_out) noexcept
		{
			__try {
				a_out = *reinterpret_cast<const std::uintptr_t*>(a_addr);
				return true;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				a_out = 0;
				return false;
			}
		}

		// Hex RVA list ("DF49F7", "0xDF49F7, 0x1234"). Kept simple and bounded:
		// the caller's string is a startup-time input, not a hot path.
		[[nodiscard]] std::size_t ParseHexList(const std::string& a_text, std::uint64_t* a_out, std::size_t a_capacity) noexcept
		{
			std::size_t count = 0;
			const char* cursor = a_text.c_str();
			while (*cursor != '\0' && count < a_capacity) {
				while (*cursor == ',' || *cursor == ';' || *cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r') {
					++cursor;
				}
				if (*cursor == '\0') {
					break;
				}
				char* end = nullptr;
				errno = 0;
				const auto value = std::strtoull(cursor, &end, 16);
				if (end == cursor || errno != 0) {
					break;  // malformed: stop rather than guess
				}
				a_out[count++] = value;
				cursor = end;
			}
			return count;
		}
	}

	Watchpoints& Watchpoints::Get()
	{
		static Watchpoints watchpoints;
		return watchpoints;
	}

	bool Watchpoints::ResolveAllocSiteFilter()
	{
		_filterCount = 0;
		const auto& text = Config::Get().watchpointsAllocSiteRvas;
		if (text.empty()) {
			return true;
		}

		std::uint64_t rvas[kMaxAllocSiteFilters]{};
		const auto    count = ParseHexList(text, rvas, kMaxAllocSiteFilters);

		// The filters are RVAs relative to the game's main executable. The crash
		// sites in the observed reports are "SkyrimSE.exe+0xDF49F7" and the
		// GMemoryHeapPT free path, so the main module base is the right anchor.
		const auto base = reinterpret_cast<std::uintptr_t>(::GetModuleHandleA(nullptr));
		if (base == 0) {
			logger::warn("watchpoints: cannot resolve the main module base; alloc-site filter ignored");
			return false;
		}
		for (std::size_t i = 0; i < count; ++i) {
			_filter[i] = base + static_cast<std::uintptr_t>(rvas[i]);
			++_filterCount;
		}
		logger::info("watchpoints: {} alloc-site filter(s) resolved against main module 0x{:X}", _filterCount, base);
		return _filterCount > 0;
	}

	bool Watchpoints::AllocSiteMatches(std::uintptr_t a_site) const noexcept
	{
		if (_filterCount == 0) {
			return false;
		}
		for (std::size_t i = 0; i < _filterCount; ++i) {
			if (_filter[i] == a_site) {
				return true;
			}
		}
		return false;
	}

	void Watchpoints::Init()
	{
		if (_initialized.load(std::memory_order_acquire)) {
			return;
		}

		const auto& config = Config::Get();

		_sweepMs = config.watchpointsSweepMs == 0 ? 250 : config.watchpointsSweepMs;
		_rearmMs = config.watchpointsRearmMs == 0 ? 500 : config.watchpointsRearmMs;
		_holdMs = config.watchpointsHoldMs;
		_maxThreads = config.watchpointsMaxThreads == 0 ? kMaxTrackedThreads : config.watchpointsMaxThreads;
		if (_maxThreads > kMaxTrackedThreads) {
			_maxThreads = kMaxTrackedThreads;
		}
		_armAfterTrigger = config.watchpointsArmAfterTrigger;
		_armAfterReports = config.watchpointsArmAfterReports == 0 ? 1 : config.watchpointsArmAfterReports;
		_reportCapacity = config.watchpointsReportCapacity;
		// A stale arm is consumed unconditionally; this bound only decides for how
		// long it is still worth a report. Derive it from the hold budget so one
		// knob moves both, with a 10 s floor for very short holds.
		_staleGraceMs = _holdMs > 10000 ? static_cast<std::uint64_t>(_holdMs) : 10000ull;

		const bool haveFilter = ResolveAllocSiteFilter();

		WatchpointMode mode = WatchpointMode::kSampleOnly;
		if (haveFilter) {
			mode = config.watchpointsAllocSiteOnly ? WatchpointMode::kFilterOnly : WatchpointMode::kFilterPreferred;
		}
		_plan.Configure(mode, config.watchpointsSamplePrime, config.watchpointsMaxPending);
		WatchpointReports::Get().Init(_reportCapacity);

		_reportEvents.store(0, std::memory_order_relaxed);
		_generation.store(1, std::memory_order_relaxed);
		_lastRearmTick.store(0, std::memory_order_relaxed);
		_forceRearm.store(false, std::memory_order_relaxed);
		_stop.store(false, std::memory_order_relaxed);
		_dirty.store(false, std::memory_order_relaxed);
		_armRequested.store(!_armAfterTrigger, std::memory_order_relaxed);
		_active.store(false, std::memory_order_relaxed);
		_trackedCount.store(0, std::memory_order_relaxed);
		_everProgrammedAnyDr.store(false, std::memory_order_relaxed);
		_unattributed.store(0, std::memory_order_relaxed);
		WatchpointReports::Get().ResetSuppressionCountersForTesting();

		_initialized.store(true, std::memory_order_release);

		logger::info("watchpoints: enabled (mode={}, sample=1/{} prime, pending {}, reports {}, sweep {} ms, re-arm {} ms, hold {} ms, max threads {}, armAfterTrigger={} after {} report(s))",
			mode == WatchpointMode::kFilterOnly ? "alloc-site-only" : (mode == WatchpointMode::kFilterPreferred ? "alloc-site-preferred" : "sample-only"),
			config.watchpointsSamplePrime, config.watchpointsMaxPending, _reportCapacity, _sweepMs, _rearmMs, _holdMs,
			_maxThreads, _armAfterTrigger, _armAfterReports);

		_sweeper = std::thread(&Watchpoints::SweeperLoop, this);
	}

	void Watchpoints::OnScaleformAlloc(void* a_ptr, std::size_t a_size, void* a_site) noexcept
	{
		if (!_active.load(std::memory_order_relaxed)) {
			return;
		}
		const auto address = reinterpret_cast<std::uintptr_t>(a_ptr);
		if (!WatchableSize(a_size) || !WatchableAddress(address)) {
			_unwatchable.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		_plan.Consider(address, AllocSiteMatches(reinterpret_cast<std::uintptr_t>(a_site)));
	}

	void Watchpoints::OnScaleformFree(void* a_ptr) noexcept
	{
		if (!_active.load(std::memory_order_relaxed)) {
			return;
		}
		const auto address = reinterpret_cast<std::uintptr_t>(a_ptr);
		if (address == 0) {
			return;
		}
		// 0.6.5 (CHANGE 1): the allocation instance of the block being freed. The
		// ledger still holds its live record here -- RecordScaleformFree has not run
		// and, for a realloc, Erase has not run either -- so the free can be paired
		// with the allocation it actually frees. Unknown (0) falls back to ticks.
		std::uint64_t freeInstance = 0;
		{
			AllocationInfo info;
			if (ShadowLedger::Get().Find(address, info)) {
				freeInstance = info.allocInstance;
			}
		}
		if (WatchpointSlots::Get().Release(address, ::GetTickCount64(), freeInstance)) {
			// FIX 2: ask the next sweep to clear the released slot on EVERY thread,
			// not just this one. The free hook must not do the OS work itself, so
			// this is a flag + a generation bump, bounded to one sweep.
			_dirty.store(true, std::memory_order_relaxed);
			RequestDisarm();
		}
	}

	void Watchpoints::NotifyReportEvent() noexcept
	{
		if (!_initialized.load(std::memory_order_acquire)) {
			return;
		}
		const auto events = _reportEvents.fetch_add(1, std::memory_order_relaxed) + 1;
		if (_armAfterTrigger && events >= _armAfterReports) {
			_armRequested.store(true, std::memory_order_release);
		}
	}

	void Watchpoints::SweeperLoop() noexcept
	{
		while (!_stop.load(std::memory_order_acquire)) {
			std::this_thread::sleep_for(std::chrono::milliseconds(_sweepMs));
			if (_stop.load(std::memory_order_acquire)) {
				break;
			}
			SweepOnce();
		}
	}

	void Watchpoints::SweepOnce() noexcept
	{
		const auto now = ::GetTickCount64();

		if (!_active.load(std::memory_order_acquire) && _armRequested.load(std::memory_order_acquire)) {
			ArmRequested();
		}
		if (!_active.load(std::memory_order_acquire)) {
			return;
		}

		PromoteCandidates(now);
		RotateHeld(now);
		// A release (free hook or a drained degradation) sets this so its slot is
		// cleared on every thread at the next sweep, bypassing the re-arm throttle
		// for exactly one pass. Bounded: one forced sweep per sweep period.
		const bool forceRearm = _forceRearm.exchange(false, std::memory_order_acq_rel);
		SweepThreads(now, forceRearm);
		DrainReports();
	}

	void Watchpoints::ArmRequested() noexcept
	{
		_active.store(true, std::memory_order_release);
		logger::warn("watchpoints: ARMING - the report trigger fired ({} report event(s)); arming DR0-DR3 on every thread of the process. "
					 "This is an opt-in diagnostic: brief thread suspensions at the {} ms re-arm cadence.",
			_reportEvents.load(std::memory_order_relaxed), _rearmMs);
		// Arm immediately, not on the next sweep: the object that just produced a
		// report is the one worth watching.
		SweepThreads(::GetTickCount64(), true);
	}

	void Watchpoints::PromoteCandidates(std::uint64_t a_now) noexcept
	{
		auto& slots = WatchpointSlots::Get();
		for (int i = 0; i < static_cast<int>(kWatchpointSlotCount); ++i) {
			if (slots.OccupiedCount() >= kWatchpointSlotCount) {
				break;
			}
			std::uintptr_t candidate = 0;
			if (!_plan.PopCandidate(candidate)) {
				break;
			}
			std::uintptr_t valueAtArm = 0;
			const bool     readable = SafeReadQword(candidate, valueAtArm);
			// FIX 3: snapshot, at arming, whether the first qword is a code pointer.
			// This is the ONLY classification the trap path and the drainer need;
			// the locking module map is never consulted from the VEH.
			const bool armedWasCode = readable && IsPlausibleVTable(valueAtArm);
			// 0.6.5 (CHANGE 1): the instance of the allocation we are arming. The
			// ledger holds it for a live Scaleform block; when the record is absent or
			// already freed the instance stays 0 (unknown) and the classifier falls
			// back to the tick evidence rather than claiming a match.
			std::uint64_t allocInstance = 0;
			{
				AllocationInfo info;
				if (ShadowLedger::Get().Find(candidate, info) && (info.flags & kFlagFreed) == 0) {
					allocInstance = info.allocInstance;
				}
			}

			std::size_t index = 0;
			if (slots.Claim(candidate, readable ? valueAtArm : 0, armedWasCode, 0, a_now, _generation.load(std::memory_order_relaxed),
					::GetCurrentThreadId(), index, allocInstance)) {
				BumpGeneration();
				_dirty.store(true, std::memory_order_relaxed);
				logger::info("watchpoints: slot {} armed for block 0x{:X} (first qword 0x{:X}, {} copied from a sampled Scaleform allocation)",
					index, candidate, valueAtArm, armedWasCode ? "a code pointer" : "not a code pointer");
			}
		}
	}

	void Watchpoints::RotateHeld(std::uint64_t a_now) noexcept
	{
		if (_holdMs == 0) {
			return;
		}
		if (WatchpointSlots::Get().RotateOldest(a_now, _holdMs)) {
			_dirty.store(true, std::memory_order_relaxed);
			RequestDisarm();
		}
	}

	Watchpoints::ThreadEntry* Watchpoints::FindThread(std::uint32_t a_tid) noexcept
	{
		const auto count = _trackedCount.load(std::memory_order_acquire);
		for (std::uint32_t i = 0; i < count; ++i) {
			if (_threads[i].tid.load(std::memory_order_acquire) == a_tid) {
				return &_threads[i];
			}
		}
		return nullptr;
	}

	void Watchpoints::SweepThreads(std::uint64_t a_now, bool a_force) noexcept
	{
		std::uint32_t tids[kMaxTrackedThreads]{};
		std::size_t   total = 0;
		const auto    copied = hw::EnumerateProcessThreads(tids, kMaxTrackedThreads, ::GetCurrentThreadId(), &total);
		_lastCheckedThreads = total;

		const auto generation = _generation.load(std::memory_order_relaxed);
		const auto lastRearm = _lastRearmTick.load(std::memory_order_relaxed);
		const bool throttleOpen = a_force || lastRearm == 0 || (a_now - lastRearm) >= _rearmMs;

		// Read the current address set once. Snapshot excludes released/tripped
		// slots, so BuildDr7 disables them.
		WatchSlotSnapshot snap[kWatchpointSlotCount];
		WatchpointSlots::Get().Snapshot(snap);
		std::uintptr_t addresses[kWatchpointSlotCount]{};
		for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
			addresses[i] = snap[i].valid ? snap[i].address : 0;
		}

		std::size_t armedNow = 0;
		bool        rearmedAny = false;

		// 0.6.3 structural rule: the moment we are about to write ANY debug
		// register, this process must treat every later #DB as ours. Set BEFORE
		// ArmThread so a trap on the new watch cannot race the flag: an
		// over-claim only means we consume a foreign #DB, which is the safe
		// direction. It is monotonic and only reset by Init.
		bool haveAddress = false;
		for (std::size_t slot = 0; slot < kWatchpointSlotCount; ++slot) {
			haveAddress = haveAddress || addresses[slot] != 0;
		}
		if (haveAddress) {
			_everProgrammedAnyDr.store(true, std::memory_order_release);
		}

		for (std::size_t i = 0; i < copied; ++i) {
			auto* entry = FindThread(tids[i]);
			if (entry == nullptr) {
				const auto used = _trackedCount.load(std::memory_order_relaxed);
				if (used >= _maxThreads) {
					_threadTableOverflow.fetch_add(1, std::memory_order_relaxed);
					continue;
				}
				entry = &_threads[used];
				// Reset the per-thread arm record before the tid is published: a
				// reused tid must not inherit "we ever armed slot i here" from a
				// thread that has exited.
				entry->everArmedMask.store(0, std::memory_order_relaxed);
				for (auto& arm : entry->arms) {
					arm.address.store(0, std::memory_order_relaxed);
					arm.valueAtArm.store(0, std::memory_order_relaxed);
					arm.allocSite.store(0, std::memory_order_relaxed);
					arm.armedAt.store(0, std::memory_order_relaxed);
					arm.allocInstance.store(0, std::memory_order_relaxed);
					arm.generation.store(0, std::memory_order_relaxed);
					arm.armedWasCode.store(false, std::memory_order_relaxed);
				}
				entry->generation.store(0, std::memory_order_relaxed);
				entry->armedAt.store(0, std::memory_order_relaxed);
				entry->tid.store(tids[i], std::memory_order_release);
				_trackedCount.store(static_cast<std::uint32_t>(used + 1), std::memory_order_release);
			}

			const bool isNew = entry->generation.load(std::memory_order_relaxed) == 0;
			if (!isNew && entry->generation.load(std::memory_order_relaxed) == generation) {
				continue;  // already armed with the current set
			}
			if (!isNew && !throttleOpen) {
				continue;  // defer the re-arm; this entry stays stale until the cadence opens
			}

			const auto thread = ::OpenThread(
				THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tids[i]);
			if (!thread) {
				// The thread is exiting (OpenThread with these rights fails for a live
				// thread only in practice). Do NOT drop the per-thread arm record: a
				// watch we set on this tid earlier may still be physically present
				// until the OS clears it, and FIX 1 requires that trap to be consumed.
				// Mark the generation stale so the next sweep re-arms the tid (fresh,
				// via isNew) if it is still alive; a reused tid then overwrites the
				// record when it is armed. The over-claim direction is the safe one.
				entry->generation.store(0, std::memory_order_relaxed);
				continue;
			}
			std::uint64_t dr7 = 0;
			// Record the arm BEFORE writing the hardware: close the window in which
			// DRi is set on the thread but the per-thread safety-net bit is not yet
			// visible. If ArmThread then fails the record is a harmless over-claim
			// (a trap on that slot is consumed rather than handed to the crash
			// handler), which is the safe direction.
			for (std::size_t slot = 0; slot < kWatchpointSlotCount; ++slot) {
				if (addresses[slot] == 0) {
					continue;
				}
				auto& arm = entry->arms[slot];
				arm.address.store(addresses[slot], std::memory_order_relaxed);
				arm.valueAtArm.store(snap[slot].valueAtArm, std::memory_order_relaxed);
				arm.allocSite.store(snap[slot].allocSite, std::memory_order_relaxed);
				arm.armedWasCode.store(snap[slot].armedWasCode, std::memory_order_relaxed);
				arm.armedAt.store(a_now, std::memory_order_relaxed);
				arm.allocInstance.store(snap[slot].allocInstance, std::memory_order_relaxed);
				arm.generation.store(generation, std::memory_order_relaxed);
				entry->everArmedMask.fetch_or(1u << slot, std::memory_order_release);
			}
			if (hw::ArmThread(thread, addresses, kWatchpointSlotCount, dr7)) {
				entry->generation.store(generation, std::memory_order_release);
				entry->armedAt.store(a_now, std::memory_order_relaxed);
				++armedNow;
				if (!isNew) {
					rearmedAny = true;
				}
			}
			::CloseHandle(thread);
		}

		if (rearmedAny || a_force) {
			_lastRearmTick.store(a_now, std::memory_order_relaxed);
		}
		_lastArmedThreads = armedNow;
	}

	std::uint64_t Watchpoints::ResolveFreeEvidence(std::uint64_t a_slotFreeTick, std::uint64_t a_slotFreeInstance,
		std::uintptr_t a_address, std::uint64_t* a_outInstance, std::uint32_t* a_outSource) noexcept
	{
		// 0.6.4 FIX B + 0.6.5 CHANGE 1. The free ring is consulted UNCONDITIONALLY,
		// and the tick it returns is paired with ITS OWN allocation instance. 0.6.3
		// only looked the ring up when the slot had no Release tick, so for an
		// already-released slot the stale Release tick shadowed the ring's newest
		// record (free_tick=261486289, ring 261487115, trap 261487115: a delta of
		// 826 ms was reported where the true delta was 0). PreferNewestFreeTick
		// picks the newer tick; the instance that wins with it is the one the
		// classifier must use, because a tick without its instance cannot say
		// whether the free belongs to this allocation or to a previous incarnation
		// of a recycled address.
		std::uint64_t tick = a_slotFreeTick;
		std::uint64_t instance = a_slotFreeInstance;
		auto          source = a_slotFreeTick != 0 ? FreeTickSource::kSlotSnapshot : FreeTickSource::kNone;

		ScaleformFreeRecord record;
		if (ScaleformFreeRing::Get().Find(a_address, record) && record.freeTick != 0) {
			const auto preferred = PreferNewestFreeTick(a_slotFreeTick, record.freeTick);
			if (preferred != tick || source == FreeTickSource::kNone) {
				tick = preferred;
				instance = record.allocInstance;
				source = FreeTickSource::kFreeRing;
			}
		}

		if (a_outInstance != nullptr) {
			*a_outInstance = instance;
		}
		if (a_outSource != nullptr) {
			*a_outSource = static_cast<std::uint32_t>(source);
		}
		return tick;
	}

	void Watchpoints::DrainReports() noexcept
	{
		WatchpointReport reports[16];
		const auto      count = WatchpointReports::Get().Drain(reports, 16);

		for (std::size_t i = 0; i < count; ++i) {
			const auto& report = reports[i];
			_drained.fetch_add(1, std::memory_order_relaxed);

			// 0.6.3: a #DB the classifier could not attribute. This is a
			// diagnosis record, not a verdict about corruption: if the 0.6.2
			// fatal case recurs, it leaves data instead of another mystery.
			if ((report.flags & kWatchReportUnattributed) != 0) {
				// NOTE: `_unattributed` and its two breakdown counters are incremented
				// where the record is WRITTEN (the trap path), not here: a record the
				// ring overwrites before the drainer sees it is still a #DB that was
				// consumed, and 0.6.3 counted it in both places (doubling the stat).
				char encoded[2048]{};
				EncodeWatchpointReport(report, encoded, sizeof(encoded));
				// 0.6.4 FIX A: the single most important question about this record --
				// is the DR state a measurement? -- is answered here, in words, so a
				// reader does not have to know that dr6 == 0 is impossible for a
				// delivered #DB.
				const auto measurement = ClassifyDebugRegisterMeasurement(report.drReadSource, report.drReadStatus, report.dr6,
					report.drAddress, kWatchpointSlotCount);
				std::string detail = "HARDWARE WATCHPOINT: a #DB was consumed structurally but could not be attributed to a watch we can name\n  ";
				detail += encoded;
				detail += "\n  ";
				detail += report.drReadSource == kDrSourceCurrentThread ?
					"dr_used=faulting-thread-read (the exception record carried nothing, so the explicit read supplies the fields); " :
					(report.drReadSource == kDrSourceExceptionContext ?
							"dr_used=exception-record; " :
							"");
				if (measurement == DebugRegisterMeasurement::kReadFailed) {
					detail += "DEBUG REGISTER MEASUREMENT: the read FAILED (GetThreadContext on the faulting thread returned error ";
					detail += std::to_string(report.drReadError);
					detail += "). The dr6/dr7/dr0-3 fields in this record are the exception record's, NOT a measurement of "
							  "the faulting thread: nothing can be concluded from them.";
				} else if (measurement == DebugRegisterMeasurement::kReadZero) {
					detail += "DEBUG REGISTER MEASUREMENT: the faulting thread's OWN debug state was read successfully "
							  "(GetThreadContext on the faulting thread, no suspension) and returned DR6 == 0 with DR0-DR3 all "
							  "zero: this host delivered a single step with NO debug register set at all (trap flag, int1/icebp, or "
							  "host/kernel behaviour). That is a finding to chase, not a hole in the record; the trap flag bit of "
							  "EFlags is shown above.";
				} else if (measurement == DebugRegisterMeasurement::kReadNonZero) {
					detail += "DEBUG REGISTER MEASUREMENT: the faulting thread's own debug state was read successfully, so "
							  "the dr6/dr7/dr0-3 fields above are a real measurement that the classifier could not attribute.";
				} else {
					detail += "DEBUG REGISTER MEASUREMENT: none was taken; the dr6/dr7/dr0-3 fields above are not a "
							  "measurement.";
				}
				detail += "\n  writer: ";
				detail += ModuleMap::Get().Describe(report.writerRip);
				detail += "\n  (consumed because this process has programmed a debug register: see DESIGN.md 13.4. "
						  "A foreign #DB is effectively nonexistent and an escaping one kills the game, so survival no "
						  "longer depends on classifying correctly. The raw DR6/DR7/DRi, HOW they were read, and the "
						  "ever-armed mask are above.)";
				Report("watchpoint-unattributed", detail);
				continue;
			}

			// 0.6.4 FIX B + 0.6.5 CHANGE 1: resolve the free EVIDENCE the same way the
			// trap path does -- ALWAYS consult the free ring, prefer its newest record
			// over the slot's Release tick, and take the allocation instance paired with
			// the tick that won. This is the drainer's own lookup (defence in depth for
			// the race where the free record lands after the trap), and it is what makes
			// the 17:56:56 case silent instead of a 826 ms delta.
			const auto    freeFromSnap = report.freeTick;
			std::uint32_t freeSource = report.freeTickSource;
			std::uint64_t freeInstance = report.freeInstance;
			const auto    freeTick = ResolveFreeEvidence(report.freeTick, report.freeInstance, report.watchedAddress,
				&freeInstance, &freeSource);
			const auto    instanceMatch = MatchFreeInstance(report.armedInstance, freeInstance);
			const auto freeContext = ClassifyWriteAgainstFreeInstance(instanceMatch, freeTick, report.armedTick, report.tick,
				kAllocatorBookkeepingWindowMs);
			if (FreeContextIsAllocatorBookkeeping(freeContext)) {
				if (freeContext == WatchpointFreeContext::kReallocInProgress) {
					WatchpointReports::Get().NoteReallocSuppressed();
				} else {
					WatchpointReports::Get().NotePostFreeSuppressed();
				}
				continue;
			}
			if (freeContext == WatchpointFreeContext::kFreePredatesArm ||
				freeContext == WatchpointFreeContext::kFreePredatesAllocation) {
				// A real write we cannot attribute to the allocator: the free evidence is
				// older than the arm, or belongs to a DIFFERENT allocation of a recycled
				// address. Reported below, labelled -- silencing it would hide a write to
				// a freed block.
				WatchpointReports::Get().NoteFreePredatesArm();
			}

			// FIX 3: the trap path records only writes that could be a
			// degradation (a code pointer was armed and the value changed). The
			// drainer is allowed to call the locking module map, so it makes the
			// final call here. A code -> different-code write is a legitimate
			// vtable swap and is discarded silently; only code -> non-code is a
			// clobbered vtable. A discarded write leaves the slot armed.
			const bool     afterReadable = (report.flags & kWatchReportValueUnreadable) == 0;
			const bool     afterIsCode = afterReadable && IsPlausibleVTable(report.valueAfterWrite);
			const auto     kind = ClassifyWatchedWrite(report.valueAtArm, report.armedWasCode,
				report.valueAfterWrite, afterReadable, afterIsCode);
			if (kind != WatchpointWriteKind::kDegradation) {
				continue;
			}

			// A real clobbered vtable: stop watching this block. Release is by
			// address (the table slot may have rotated since the trap), and the
			// generation bump + force flag make the next sweep clear it on every
			// thread, not just the trapping one (FIX 2).
			if (WatchpointSlots::Get().Release(report.watchedAddress, report.tick)) {
				// Mark the slot tripped only if it STILL holds the trapped address: the
				// slot may have rotated and been re-used for a different block since
				// the trap, and marking the wrong index would disarm that block.
				WatchSlotSnapshot current{};
				if (WatchpointSlots::Get().ReadSlot(report.slotIndex, current) &&
					current.address == report.watchedAddress) {
					WatchpointSlots::Get().MarkTripped(report.slotIndex, report.tick);
				}
				_dirty.store(true, std::memory_order_relaxed);
				RequestDisarm();
			}

			char encoded[2048]{};
			EncodeWatchpointReport(report, encoded, sizeof(encoded));

			std::string detail = "HARDWARE WATCHPOINT: a code pointer was clobbered on the first 8 bytes of a watched block\n  ";
			detail += encoded;

			// FIX 4: never print a bare "unmapped / unknown" for a block WE armed.
			// The address was walked by our own watcher, so the honest statement is
			// that the ledger no longer classifies it, not that it is a mystery.
			const auto classified = ClassifyAddress(report.watchedAddress);
			detail += "\n  watched block: ";
			detail += classified;
			if (classified == "unmapped / unknown") {
				detail += " (we armed this block ourselves; the ledger no longer classifies it: evicted, "
						  "allocated before the hooks were live, or freed and decommitted)";
			}

			AllocationInfo info;
			if (ShadowLedger::Get().Find(report.watchedAddress, info)) {
				if (info.allocSite) {
					detail += "\n  allocSite=";
					detail += ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(info.allocSite));
				}
				detail += "\n  ledger: ";
				detail += (info.flags & kFlagFreed) != 0 ? "freed" : "live";
				if ((info.flags & kFlagScaleform) != 0) {
					// The Scaleform ledger records the allocator REQUEST, which for a
					// segment/heap allocation is a capacity, not the object's size.
					// Reporting it as a block size was the 0.6.1 contradiction.
					detail += "; block size unknown (allocator request";
					if (info.size != 0) {
						detail += " " + std::to_string(info.size);
					}
					detail += " is a heap capacity for segment allocations, not the object size)";
				} else if (info.size != 0) {
					detail += " size=" + std::to_string(info.size);
				}
			}

			ScaleformFreeRecord freeRecord;
			if (ScaleformFreeRing::Get().Find(report.watchedAddress, freeRecord)) {
				detail += "\n  Scaleform free record: freed at tick " + std::to_string(freeRecord.freeTick);
				if (freeRecord.allocInstance != 0) {
					detail += " (allocation instance " + std::to_string(freeRecord.allocInstance) + ")";
				}
				if (freeRecord.freeSite) {
					detail += " by ";
					detail += ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(freeRecord.freeSite));
				}
			}

			// 0.6.4 FIX B: say which free the classifier used and what it decided,
			// and when the slot's own Release tick was overruled, say by how much.
			// That shadowed tick is exactly the number that made the 17:56:56 case a
			// false report (826 instead of 0).
			detail += "\n  free evidence: ";
			detail += FreeTickSourceName(static_cast<FreeTickSource>(freeSource));
			detail += " tick " + std::to_string(freeTick) + "; context ";
			detail += WatchpointFreeContextName(freeContext);
			// 0.6.5 CHANGE 1: WHICH allocation the free belonged to, and whether that
			// is the allocation we armed. This is the difference between "the free ring
			// has a record for this address" and "the free IS this block's own free".
			detail += "; armed_alloc_instance=" + std::to_string(report.armedInstance) + " free_alloc_instance=" +
				std::to_string(freeInstance) + " (" + FreeInstanceMatchName(instanceMatch) + ")";
			if (freeTick != 0) {
				detail += " (trap - free = ";
				detail += std::to_string(report.tick >= freeTick ? static_cast<long long>(report.tick - freeTick)
																		: -static_cast<long long>(freeTick - report.tick));
				detail += " ms)";
			}
			if (freeFromSnap != 0 && freeFromSnap != freeTick) {
				detail += "; the slot's own Release tick " + std::to_string(freeFromSnap) +
						  " was overruled by the free ring's newer record (0.6.3 used it and reported a false delta of " +
						  std::to_string(static_cast<long long>(report.tick >= freeFromSnap ? report.tick - freeFromSnap
																									: freeFromSnap - report.tick)) +
						  " ms)";
			}
			if (freeContext == WatchpointFreeContext::kFreePredatesArm) {
				detail += "\n  FREE EVIDENCE PREDATES THIS ARM: the free ring's newest record for this address (tick " +
						  std::to_string(freeTick) +
						  ") is older than the arm (tick " + std::to_string(report.armedTick) +
						  "), so it is not evidence about this write: either the address was recycled and the ring record is "
						  "stale (the ring never invalidates a record on re-allocation), or a watch was armed on an "
						  "already-freed block. The write is real and is reported rather than assigned to the allocator.";
			}
			if (freeContext == WatchpointFreeContext::kFreePredatesAllocation) {
				detail += "\n  FREE EVIDENCE BELONGS TO ANOTHER ALLOCATION: the free record for this address was of "
						  "allocation instance " + std::to_string(freeInstance) + ", but this watch armed instance " +
						  std::to_string(report.armedInstance) +
						  ". The free ring never invalidates a record when an address is recycled, so this free is a "
						  "previous incarnation's, NOT this block's own free: it is not evidence about this write and the "
						  "write is real. Reported and labelled rather than silently matched to this allocation.";
			}

			// FIX 4: the stale-arm case is a first-class outcome of the 0.6.1
			// failure, not an omission.
			if ((report.flags & kWatchReportStaleArm) != 0) {
				detail += "\n  ARM WAS STALE: the DR slot still held 0x" + std::to_string(report.watchedAddress) +
						  " from an earlier arm on this thread; the live table slot ";
				detail += std::to_string(report.slotIndex);
				if (report.tableAddress != 0) {
					detail += " had since been re-armed for 0x" + std::to_string(report.tableAddress);
				} else {
					detail += " is now empty";
				}
				detail += ". The write is real; the trap was consumed rather than handed to the crash handler, "
						  "which is what kept the process alive (see DESIGN.md §13.4).";
			}

			detail += "\n  writer: ";
			detail += ModuleMap::Get().Describe(report.writerRip);
			detail += "\n  (x86 data breakpoints are TRAPS: the saved RIP is the instruction AFTER the store, so the "
					  "writer is at or shortly before that address; the value shown is the qword read immediately after "
					  "the write, and a racing writer could change it again)";

			Report("watchpoint-write", detail);
		}
	}

	long Watchpoints::HandleDebugException(void* a_exceptionPointers) noexcept
	{
		auto* info = static_cast<EXCEPTION_POINTERS*>(a_exceptionPointers);
		if (!info || !info->ExceptionRecord || !info->ContextRecord) {
			return EXCEPTION_CONTINUE_SEARCH;
		}
		if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// 0.6.3 STRUCTURAL RULE. Survival no longer depends on classifying a
		// #DB correctly. Once this process has programmed ANY debug register, a
		// single-step is ours by construction: consume it and record it,
		// attributed or not. The 0.6.2 fix was a correct-looking classifier with
		// a real mutation proof that still let the game die, because a #DB
		// reached this handler that the classifier called foreign. Before any DR
		// has ever been programmed (feature disabled, or enabled but not yet
		// armed) nothing can be masked, and a foreign #DB is passed on -- which
		// is what lets a debugger keep working on a run where we never armed.
		const bool everProgrammed = _everProgrammedAnyDr.load(std::memory_order_acquire);
		if (!MustConsumeDebugException(everProgrammed)) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		auto*      context = info->ContextRecord;

		// 0.6.4 FIX A. The debug-register fields are a MEASUREMENT, and the 0.6.3
		// records made that unanswerable: all 104 unattributed traps carried
		// dr6=dr7=dr0-3=0, which cannot be true of a delivered #DB (a trap flag sets
		// DR6.BS = 0x4000, a data breakpoint sets one of B0-B3), yet the fields were
		// printed as if they had been read. We cannot tell "the host left the VEH's
		// ContextRecord zeroed" from "the read failed" unless we take our own read,
		// so we do: GetThreadContext on the FAULTING thread with
		// CONTEXT_DEBUG_REGISTERS. No suspension is needed (it is our own thread)
		// and it cannot deadlock, which is why it is legal here at all. The result,
		// its GetLastError() and the exception record's own DR values are all kept,
		// so "read failed" and "read succeeded and genuinely returned zero" are two
		// different records instead of the same 0x0.
		hw::ThreadDebugState drState;
		std::uint32_t        drReadError = 0;
		const bool           drReadOk = hw::ReadCurrentThread(drState, &drReadError);

		const auto contextDr6 = static_cast<std::uint64_t>(context->Dr6);
		const auto contextDr7 = static_cast<std::uint64_t>(context->Dr7);
		const std::uint64_t contextDrAddress[kWatchpointSlotCount] = {
			static_cast<std::uint64_t>(context->Dr0),
			static_cast<std::uint64_t>(context->Dr1),
			static_cast<std::uint64_t>(context->Dr2),
			static_cast<std::uint64_t>(context->Dr3),
		};

		// The explicit read is authoritative ONLY when the exception record carries
		// nothing. On real Windows the exception record does carry DR6/DR7/DR0-3 for
		// a data breakpoint (the in-game attributed reports and the Windows hardware
		// test both show it), and it is the state the CPU trapped on; the
		// faulting-thread read is what makes the empty case legible, which is the
		// case the 104 hollow records were. Preferring the read unconditionally would
		// have replaced a working measurement with a different one -- the Windows
		// test caught exactly that.
		const bool contextHasDr = contextDr6 != 0 || contextDr7 != 0 || contextDrAddress[0] != 0 ||
			contextDrAddress[1] != 0 || contextDrAddress[2] != 0 || contextDrAddress[3] != 0;
		const bool useThreadRead = drReadOk && !contextHasDr;

		const auto dr6 = useThreadRead ? drState.dr6 : contextDr6;
		const auto dr7 = useThreadRead ? drState.dr7 : contextDr7;
		const std::uint64_t threadDrAddress[kWatchpointSlotCount] = {
			static_cast<std::uint64_t>(drState.dr0),
			static_cast<std::uint64_t>(drState.dr1),
			static_cast<std::uint64_t>(drState.dr2),
			static_cast<std::uint64_t>(drState.dr3),
		};
		std::uint64_t drAddress[kWatchpointSlotCount] = {};
		for (std::size_t slot = 0; slot < kWatchpointSlotCount; ++slot) {
			drAddress[slot] = useThreadRead ? threadDrAddress[slot] : contextDrAddress[slot];
		}

		const auto drReadSource = useThreadRead ? kDrSourceCurrentThread : kDrSourceExceptionContext;
		const auto drReadStatus = drReadOk ? kDrReadOk : kDrReadFailed;
		const auto drContextDisagrees = drReadOk &&
			(drState.dr6 != contextDr6 || drState.dr7 != contextDr7 || drState.dr0 != contextDrAddress[0] ||
				drState.dr1 != contextDrAddress[1] || drState.dr2 != contextDrAddress[2] || drState.dr3 != contextDrAddress[3]);
		const auto contextEFlags = static_cast<std::uint32_t>(context->EFlags);

		// Apply the provenance to a record. Used by both the attributed and the
		// unattributed paths so no record ever prints an unset DR field as a
		// measurement again. BOTH sets are filled: the exception record's and the
		// faulting-thread read's.
		const auto fillDrProvenance = [&](WatchpointReport& a_target) noexcept {
			a_target.drReadSource = drReadSource;
			a_target.drReadStatus = drReadStatus;
			a_target.drReadError = drReadError;
			a_target.drReadFlags = drContextDisagrees ? kWatchReportDrContextDisagrees : 0u;
			a_target.contextDr6 = static_cast<std::uint32_t>(contextDr6);
			a_target.contextDr7 = static_cast<std::uint32_t>(contextDr7);
			a_target.contextEFlags = contextEFlags;
			a_target.threadDr6 = drReadOk ? static_cast<std::uint32_t>(drState.dr6) : 0u;
			a_target.threadDr7 = drReadOk ? static_cast<std::uint32_t>(drState.dr7) : 0u;
			a_target.flags |= kWatchReportDrMeasured;
			if ((contextEFlags & 0x100u) != 0) {
				a_target.flags |= kWatchReportTrapFlagSet;
			}
			for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
				a_target.contextDrAddress[i] = static_cast<std::uintptr_t>(contextDrAddress[i]);
				a_target.threadDrAddress[i] = drReadOk ? static_cast<std::uintptr_t>(threadDrAddress[i]) : 0u;
			}
		};

		// FIX 1: the per-thread record is the safety net. A DR slot this thread
		// was EVER armed with is OURS, and its #DB must be consumed even when the
		// table entry is gone or has been re-armed for a different block. This is
		// the exact 0.6.1 fatal case: thread 844 still held the old address after
		// the slot had moved on, the table could not match it, and returning
		// CONTINUE_SEARCH let the game die of our own stale watchpoint.
		const auto selfTid = ::GetCurrentThreadId();
		ThreadEntry* entry = FindThread(selfTid);
		const auto   everMask = entry != nullptr ? entry->everArmedMask.load(std::memory_order_acquire) : 0u;

		bool          handled = false;
		std::uint64_t clearedDr7 = dr7;
		const auto    now = ::GetTickCount64();

		for (std::size_t slot = 0; slot < kWatchpointSlotCount; ++slot) {
			if ((dr6 & (1ull << slot)) == 0) {
				continue;
			}
			const bool enabled = Dr7SlotEnabled(dr7, slot);
			const auto drAddr = static_cast<std::uintptr_t>(drAddress[slot]);

			WatchSlotSnapshot snap{};
			const bool tableValid = WatchpointSlots::Get().ReadSlot(slot, snap);
			const bool tableReleased = tableValid && (snap.flags & kWatchSlotReleased) != 0;

			const bool hasArmRecord = (everMask & (1u << slot)) != 0u;
			const auto armAddress = hasArmRecord ? entry->arms[slot].address.load(std::memory_order_acquire)
											 : static_cast<std::uintptr_t>(0);
			const bool armValid = hasArmRecord && armAddress != 0;

			const auto owner = ClassifyTrapOwner(enabled, drAddr, hasArmRecord, armValid, armAddress,
				tableValid, snap.address, tableReleased);
			if (!WatchpointOwnerIsOurs(owner)) {
				continue;  // cannot be attributed to a slot we named; recorded below
			}
			handled = true;

			WatchpointReport report;
			report.tick = now;
			report.writerRip = static_cast<std::uintptr_t>(context->Rip);
			report.slotIndex = static_cast<std::uint32_t>(slot);
			report.threadId = selfTid;
			report.dr6 = static_cast<std::uint32_t>(dr6);
			report.dr7 = static_cast<std::uint32_t>(dr7);
			// 0.6.4: an attributed record carries the same evidence an unattributed
			// one does. 0.6.3 left these unset, so the write reports printed
			// ever_armed=0x0 any_dr=0 dr0-3=0x0 -- indistinguishable from a failed
			// read, which is exactly the ambiguity FIX A exists to remove.
			report.everArmedMask = everMask;
			report.anyDrProgrammed = everProgrammed;
			for (std::size_t i = 0; i < kWatchpointSlotCount; ++i) {
				report.drAddress[i] = static_cast<std::uintptr_t>(drAddress[i]);
			}
			fillDrProvenance(report);

			if (owner == WatchpointTrapOwner::kTableCurrent || owner == WatchpointTrapOwner::kTableReleased) {
				report.watchedAddress = snap.address;
				report.valueAtArm = snap.valueAtArm;
				report.allocSite = snap.allocSite;
				report.armedTick = snap.armedTick;
				report.freeTick = snap.freeTick;
				report.armedInstance = snap.allocInstance;
				report.freeInstance = snap.freeInstance;
				report.armGeneration = snap.generation;
				report.armedWasCode = snap.armedWasCode;
				if (owner == WatchpointTrapOwner::kTableReleased) {
					report.flags |= kWatchReportBlockReleased;
				}
			} else {
				// Stale: report the address that actually trapped, and keep the
				// current table address so the reader can see the re-arm.
				report.watchedAddress = drAddr;
				report.tableAddress = tableValid ? snap.address : 0;
				report.flags |= kWatchReportStaleArm;
				if (armValid) {
					report.valueAtArm = entry->arms[slot].valueAtArm.load(std::memory_order_relaxed);
					report.allocSite = entry->arms[slot].allocSite.load(std::memory_order_relaxed);
					report.armedTick = entry->arms[slot].armedAt.load(std::memory_order_relaxed);
					report.armedInstance = entry->arms[slot].allocInstance.load(std::memory_order_relaxed);
					report.armGeneration = entry->arms[slot].generation.load(std::memory_order_relaxed);
					report.armedWasCode = entry->arms[slot].armedWasCode.load(std::memory_order_relaxed);
				}
			}

			// 0.6.4 FIX B: resolve the free tick ALWAYS, preferring the free ring's
			// newest record for the address over the slot's Release tick, and record
			// which source won. 0.6.3 only looked the ring up when the slot's tick was
			// zero, so a stale Release tick shadowed the newest free record.
			report.freeTick = ResolveFreeEvidence(report.freeTick, report.freeInstance, report.watchedAddress,
				&report.freeInstance, &report.freeTickSource);
			report.freeInstanceMatch =
				static_cast<std::uint32_t>(MatchFreeInstance(report.armedInstance, report.freeInstance));

			std::uintptr_t valueAfter = 0;
			const bool     readable = SafeReadQword(report.watchedAddress, valueAfter);
			report.valueAfterWrite = valueAfter;
			if (!readable) {
				report.flags |= kWatchReportValueUnreadable;
			}

			// Consume silently unless this could be a degradation. The trap path may
			// NOT call the locking module map, so "could be" means: a code pointer
			// was armed at snapshot time, the value changed, and the new value is
			// readable. The drainer makes the final code/non-code call.
			bool record = report.armedWasCode && readable && valueAfter != report.valueAtArm;

			// 0.6.4 FIX B: suppress the allocator's own bookkeeping, on both sides of
			// the recorded free and with the two sides kept apart. A post-free link is
			// the free-list next pointer written just after the free; a realloc-time
			// write is the link written while o_SfRealloc is still running, i.e. before
			// the free record lands. Neither is a use-after-free. Do NOT record either
			// and do NOT clear this thread's DR: keep watching, stay silent.
			if (record) {
				const auto freeContext = ClassifyWriteAgainstFreeInstance(
					static_cast<FreeInstanceMatch>(report.freeInstanceMatch), report.freeTick, report.armedTick, now,
					kAllocatorBookkeepingWindowMs);
				if (FreeContextIsAllocatorBookkeeping(freeContext)) {
					record = false;
					if (freeContext == WatchpointFreeContext::kReallocInProgress) {
						WatchpointReports::Get().NoteReallocSuppressed();
					} else {
						WatchpointReports::Get().NotePostFreeSuppressed();
					}
				}
			}

			if (record && WatchpointOwnerIsStale(owner)) {
				// A recently-retired arm is worth a report for a bounded grace
				// period; older stale arms are still consumed, just not reported.
				const bool fresh = report.armedTick != 0 && now >= report.armedTick &&
					(now - report.armedTick) <= _staleGraceMs;
				record = fresh;
			}
			if (record) {
				WatchpointReports::Get().Record(report);
			}

			// Traps that stop watching this thread's slot: a degradation candidate
			// (the drainer will release it) and a stale arm (the address is gone).
			// A BENIGN write keeps the slot armed -- that is the point of FIX 3, and
			// a data breakpoint is a trap, so the store itself cannot re-fire. A
			// post-free link is benign in exactly this sense and keeps the watch.
			if (WatchpointOwnerIsStale(owner) || record) {
				clearedDr7 = Dr7ClearSlot(clearedDr7, slot);
			}
			if (WatchpointOwnerIsStale(owner) || (owner == WatchpointTrapOwner::kTableReleased)) {
				// Some thread was left behind (or the block was freed): re-arm every
				// thread with the current set at the next sweep, so a retired arm is
				// cleared on EVERY thread, not only this one (FIX 2).
				_forceRearm.store(true, std::memory_order_release);
			}
		}

		if (!handled) {
			// 0.6.3 DELIVERABLE 1. The classifier could not attribute this #DB,
			// but the structural rule says consume it anyway. Record the raw
			// evidence into the preallocated ring BEFORE dealing with it: no
			// allocation, no lock, no std::string, no spdlog. If the 0.6.2 fatal
			// case recurs, this is the data that was missing.
			WatchpointReport report;
			report.tick = now;
			report.writerRip = static_cast<std::uintptr_t>(context->Rip);
			report.threadId = selfTid;
			report.dr6 = static_cast<std::uint32_t>(dr6);
			report.dr7 = static_cast<std::uint32_t>(dr7);
			report.everArmedMask = everMask;
			report.anyDrProgrammed = everProgrammed;
			report.flags = kWatchReportUnattributed;
			for (std::size_t slot = 0; slot < kWatchpointSlotCount; ++slot) {
				report.drAddress[slot] = static_cast<std::uintptr_t>(drAddress[slot]);
			}
			fillDrProvenance(report);
			WatchpointReports::Get().Record(report);
			_unattributed.fetch_add(1, std::memory_order_relaxed);

			// 0.6.4 FIX A: count the two cases the 0.6.3 records could not tell
			// apart, so the next trip's summary says which one it was without reading
			// every record. `kReadFailed` means the dr6/dr7/dr0-3 fields above are not
			// a measurement; `kReadZero` means the read succeeded and this host
			// genuinely delivered a #DB with no debug register set (trap flag, int1,
			// or host behaviour) -- which is a finding, not a hole.
			const auto measurement = ClassifyDebugRegisterMeasurement(report.drReadSource, report.drReadStatus, report.dr6,
				report.drAddress, kWatchpointSlotCount);
			WatchpointReports::Get().NoteUnattributedMeasured(measurement);

			// We do not know which (if any) DR fired, so we cannot clear a slot.
			// Clear DR6 and the trap flag: an unattributed #DB must not re-fire on
			// the next instruction and turn one swallowed exception into a storm.
			context->Dr6 = 0;
			context->EFlags &= ~0x100u;  // clear TF so a trap-flag single step cannot re-fire
			BumpGeneration();
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		// The trap is a trap: the store has already completed. Resume at the next
		// instruction and clear DR6 so the same breakpoint can fire again.
		context->Dr7 = clearedDr7;
		context->Dr6 = 0;
		BumpGeneration();
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	void Watchpoints::Shutdown()
	{
		if (!_initialized.load(std::memory_order_acquire)) {
			return;
		}
		_initialized.store(false, std::memory_order_release);
		_active.store(false, std::memory_order_release);
		_stop.store(true, std::memory_order_release);
		if (_sweeper.joinable()) {
			_sweeper.join();
		}

		// Disarm every thread we can open, then assert. The assertion is the
		// point: "we think we cleared the DRs" is not a claim, and a stale
		// watchpoint left armed would silently change what the game does.
		constexpr std::size_t kMax = 4096;
		static std::uint32_t  tids[kMax];
		const auto            count = hw::EnumerateProcessThreads(tids, kMax, 0, nullptr);
		std::size_t           disarmed = 0;
		for (std::size_t i = 0; i < count; ++i) {
			const auto thread = ::OpenThread(
				THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tids[i]);
			if (!thread) {
				continue;
			}
			if (hw::DisarmThread(thread)) {
				++disarmed;
			}
			::CloseHandle(thread);
		}
		hw::DisarmCurrentThread();

		std::size_t checked = 0;
		std::size_t stillArmed = 0;
		const bool  clear = hw::VerifyAllThreadsDisarmed(&checked, &stillArmed);
		logger::info("watchpoints: shutdown - disarmed {} thread(s), verified {} thread(s), {} still armed", disarmed, checked, stillArmed);
		if (!clear) {
			// Not fatal (the process is going away), but never silent: an armed
			// DR modifies the game's behaviour.
			logger::error("watchpoints: ASSERTION FAILED - {} thread(s) still have DR7 set after shutdown", stillArmed);
			Health::Degrade("watchpoints: debug registers were still armed after shutdown");
		}

		WatchpointSlots::Get().ClearAll(::GetTickCount64());
		WatchpointReports::Get().Shutdown();
		logger::info("watchpoints: final state: {} slot(s) occupied, {} claims, {} claim drops, {} releases, {} trips, {} unattributed #DB(s) consumed, {} post-free link(s) suppressed, {} realloc-in-progress write(s) suppressed, {} free-predates-arm report(s)",
			WatchpointSlots::Get().OccupiedCount(), WatchpointSlots::Get().Claims(), WatchpointSlots::Get().ClaimDrops(),
			WatchpointSlots::Get().Releases(), WatchpointSlots::Get().Trips(),
			_unattributed.load(std::memory_order_relaxed),
			WatchpointReports::Get().PostFreeSuppressed(), WatchpointReports::Get().ReallocSuppressed(),
			WatchpointReports::Get().FreePredatesArm());
		logger::info("watchpoints: debug-register measurement: {} unattributed #DB(s) carried a FAILED read (fields are not a measurement), {} carried a successful read that genuinely returned no debug register",
			WatchpointReports::Get().UnattributedDrReadFailed(),
			WatchpointReports::Get().UnattributedDrReadZero());
	}

	WatchpointStats Watchpoints::Stats() const noexcept
	{
		const auto& slots = WatchpointSlots::Get();
		const auto& reports = WatchpointReports::Get();
		const auto  plan = _plan.Stats();

		WatchpointStats stats;
		stats.initialized = _initialized.load(std::memory_order_relaxed);
		stats.active = _active.load(std::memory_order_relaxed);
		stats.armed = _lastArmedThreads > 0;
		stats.occupied = slots.OccupiedCount();
		stats.trackedThreads = _trackedCount.load(std::memory_order_relaxed);
		stats.lastCheckedThreads = _lastCheckedThreads;
		stats.lastArmedThreads = _lastArmedThreads;
		stats.claims = slots.Claims();
		stats.claimDrops = slots.ClaimDrops();
		stats.releases = slots.Releases();
		stats.rotations = slots.Rotations();
		stats.trips = slots.Trips();
		stats.reportsRecorded = reports.Recorded();
		stats.reportsDropped = reports.Dropped();
		stats.reportsDrained = _drained.load(std::memory_order_relaxed);
		stats.unattributedTraps = _unattributed.load(std::memory_order_relaxed);
		stats.postFreeLinksSuppressed = reports.PostFreeSuppressed();
		stats.reallocInProgressSuppressed = reports.ReallocSuppressed();
		stats.unattributedDrReadFailed = reports.UnattributedDrReadFailed();
		stats.unattributedDrReadZero = reports.UnattributedDrReadZero();
		stats.freePredatesArmReports = reports.FreePredatesArm();
		stats.considerCount = plan.considered;
		stats.selectedCount = plan.selected;
		stats.queueEvictions = plan.queueEvictions;
		stats.unwatchable = _unwatchable.load(std::memory_order_relaxed);
		stats.threadTableOverflow = _threadTableOverflow.load(std::memory_order_relaxed);
		return stats;
	}
}