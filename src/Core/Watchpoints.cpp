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
		_postFreeSuppressed.store(0, std::memory_order_relaxed);

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
		if (WatchpointSlots::Get().Release(address, ::GetTickCount64())) {
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

			std::size_t index = 0;
			if (slots.Claim(candidate, readable ? valueAtArm : 0, armedWasCode, 0, a_now, _generation.load(std::memory_order_relaxed),
					::GetCurrentThreadId(), index)) {
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
				_unattributed.fetch_add(1, std::memory_order_relaxed);
				char encoded[1024]{};
				EncodeWatchpointReport(report, encoded, sizeof(encoded));
				std::string detail = "HARDWARE WATCHPOINT: a #DB was consumed structurally but could not be attributed to a watch we can name\n  ";
				detail += encoded;
				detail += "\n  writer: ";
				detail += ModuleMap::Get().Describe(report.writerRip);
				detail += "\n  (consumed because this process has programmed a debug register: see DESIGN.md 13.4. "
						  "A foreign #DB is effectively nonexistent and an escaping one kills the game, so survival no "
						  "longer depends on classifying correctly. The raw DR6/DR7/DRi and the ever-armed mask are above.)";
				Report("watchpoint-unattributed", detail);
				continue;
			}

			// 0.6.3: the allocator's own post-free link. A write that lands within
			// the bounded window after the block's recorded free is the free-list
			// next pointer, not corruption. Stay silent and keep the watch: only a
			// write to a block freed EARLIER than the window is a genuine
			// use-after-free. (Defence in depth: the trap path already suppresses
			// these; this catches the race where the free record landed after the
			// trap.)
			std::uint64_t freeTick = report.freeTick;
			if (freeTick == 0) {
				ScaleformFreeRecord lookedUp;
				if (ScaleformFreeRing::Get().Find(report.watchedAddress, lookedUp)) {
					freeTick = lookedUp.freeTick;
				}
			}
			if (IsAllocatorPostFreeLink(freeTick, report.tick, kAllocatorPostFreeLinkWindowMs)) {
				_postFreeSuppressed.fetch_add(1, std::memory_order_relaxed);
				continue;
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

			char encoded[512]{};
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
				if (freeRecord.freeSite) {
					detail += " by ";
					detail += ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(freeRecord.freeSite));
				}
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
		const auto dr6 = static_cast<std::uint64_t>(context->Dr6);
		const auto dr7 = static_cast<std::uint64_t>(context->Dr7);

		const std::uint64_t drAddress[kWatchpointSlotCount] = {
			static_cast<std::uint64_t>(context->Dr0),
			static_cast<std::uint64_t>(context->Dr1),
			static_cast<std::uint64_t>(context->Dr2),
			static_cast<std::uint64_t>(context->Dr3),
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

			if (owner == WatchpointTrapOwner::kTableCurrent || owner == WatchpointTrapOwner::kTableReleased) {
				report.watchedAddress = snap.address;
				report.valueAtArm = snap.valueAtArm;
				report.allocSite = snap.allocSite;
				report.armedTick = snap.armedTick;
				report.freeTick = snap.freeTick;
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
					report.armGeneration = entry->arms[slot].generation.load(std::memory_order_relaxed);
					report.armedWasCode = entry->arms[slot].armedWasCode.load(std::memory_order_relaxed);
				}
			}

			// A stale arm may still name a block the free ring remembers; the slot's
			// own free tick is authoritative for a released current slot.
			if (report.freeTick == 0) {
				ScaleformFreeRecord freeRecord;
				if (ScaleformFreeRing::Get().Find(report.watchedAddress, freeRecord)) {
					report.freeTick = freeRecord.freeTick;
				}
			}

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

			// 0.6.3: suppress the allocator's own post-free link. A write inside
			// the bounded window after the block's recorded free is the free-list
			// next pointer, not a use-after-free. Do NOT record it and do NOT
			// clear this thread's DR: keep watching, stay silent. Only a write to
			// a block freed earlier than the window is reported.
			if (record && IsAllocatorPostFreeLink(report.freeTick, now, kAllocatorPostFreeLinkWindowMs)) {
				record = false;
				_postFreeSuppressed.fetch_add(1, std::memory_order_relaxed);
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
			WatchpointReports::Get().Record(report);
			_unattributed.fetch_add(1, std::memory_order_relaxed);

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
		logger::info("watchpoints: final state: {} slot(s) occupied, {} claims, {} claim drops, {} releases, {} trips, {} unattributed #DB(s) consumed, {} post-free link(s) suppressed",
			WatchpointSlots::Get().OccupiedCount(), WatchpointSlots::Get().Claims(), WatchpointSlots::Get().ClaimDrops(),
			WatchpointSlots::Get().Releases(), WatchpointSlots::Get().Trips(),
			_unattributed.load(std::memory_order_relaxed), _postFreeSuppressed.load(std::memory_order_relaxed));
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
		stats.postFreeLinksSuppressed = _postFreeSuppressed.load(std::memory_order_relaxed);
		stats.considerCount = plan.considered;
		stats.selectedCount = plan.selected;
		stats.queueEvictions = plan.queueEvictions;
		stats.unwatchable = _unwatchable.load(std::memory_order_relaxed);
		stats.threadTableOverflow = _threadTableOverflow.load(std::memory_order_relaxed);
		return stats;
	}
}