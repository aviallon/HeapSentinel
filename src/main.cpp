#include "PCH.h"

#include "Config.h"
#include "Core/BuildInfo.h"
#include "Core/GuardedPool.h"
#include "Core/Health.h"
#include "Core/ModuleMap.h"
#include "Core/PoisonQuarantine.h"
#include "Core/Report.h"
#include "Core/ScaleformFreeRing.h"
#include "Core/ShadowLedger.h"
#include "Core/StackCapture.h"
#include "Core/Stats.h"
#include "Core/WeakLibEvents.h"
#include "Hooks/Hooks.h"
#include "Veh.h"

namespace
{
	// The module list must be refreshed after every SKSE plugin has been loaded.
	// HeapSentinel loads early (SKSE loads plugins alphabetically), so a snapshot
	// taken in SKSEPlugin_Load is missing plugins that load after it - and every
	// vtable inside one of those looks unmapped to the refcount guard.
	void OnMessage(SKSE::MessagingInterface::Message* a_msg)
	{
		if (!a_msg) {
			return;
		}
		switch (a_msg->type) {
		case SKSE::MessagingInterface::kPostLoad:
			hs::ModuleMap::Get().Refresh();
			hs::ModuleMap::Get().SetComplete();
			logger::info("module map complete: {} modules", hs::ModuleMap::Get().Size());
			break;
		case SKSE::MessagingInterface::kDataLoaded:
			hs::ModuleMap::Get().Refresh();
			hs::ModuleMap::Get().SetComplete();
			logger::info("module map complete: {} modules", hs::ModuleMap::Get().Size());
			// Proof that the MemoryManager thunks actually ran: the ledger is only
			// written by the Allocate/Deallocate hooks.
			logger::info("ledger after data load: {} tracked blocks", hs::ShadowLedger::Get().Count());
			// Module list is now complete: record it (session header) and emit the
			// first stats line. A short session never reaches the 60 s timer, which
			// is why the v0.3.0 run produced no stats at all.
			hs::ReportSessionContext(hs::Config::Get().Summary(), hs::ModuleMap::Get().ModlistHash(),
				hs::ModuleMap::Get().Size());
			if (hs::ShouldEmitOnDataLoaded()) {
				hs::LogStats("data-load");
			}
			break;
		default:
			break;
		}
	}
}

SKSE_PLUGIN_LOAD(const SKSE::LoadInterface* a_skse)
{
	SKSE::Init(a_skse);
	hs::SetupLog();

	logger::info("HeapSentinel v" HS_VERSION " (Skyrim SE/AE, Address Library + CommonLibSSE-NG, build " HS_BUILD_ID ") loading");

	if (auto* messaging = SKSE::GetMessagingInterface()) {
		messaging->RegisterListener("SKSE", OnMessage);
	}

	hs::Config::Get().Load();
	if (!hs::Config::Get().enabled) {
		logger::info("disabled in HeapSentinel.ini - installing nothing");
		hs::Health::Off("disabled in HeapSentinel.ini");
		logger::info("health: {}", hs::Health::Line());
		return true;
	}

	// Order matters: the module map and stack capture are needed by every
	// report, and the ledger must exist before the hooks that write to it.
	hs::InitStackCapture();
	hs::ModuleMap::Get().Refresh();
	logger::info("config summary: {}", hs::Config::Get().Summary());
	// Write the session context (config + module set) into the appended reports
	// log now, and again at kDataLoaded once the module list is complete.
	hs::ReportSessionContext(hs::Config::Get().Summary(), hs::ModuleMap::Get().ModlistHash(),
		hs::ModuleMap::Get().Size());

	const auto& config = hs::Config::Get();

	if (config.ledgerEnabled) {
		hs::ShadowLedger::Get().Init(config.ledgerCapacity, config.ledgerShards, config.ledgerStackDepth);
	}

	if (config.guardPoolEnabled) {
		hs::GuardedPool::Get().Init(config.guardPoolSlots, config.guardPoolMaxSize, config.guardPoolSampleRate);
	}

	// The Scaleform free ring is the DURABLE provenance store: separate from the
	// main ledger so engine allocations keep flowing, evict-oldest when full, and
	// its occupancy/evictions are logged so a lossy run is legible.
	if (config.scaleformHeapEnabled) {
		hs::ScaleformFreeRing::Get().Init(config.scaleformFreeCapacity);
	}

	// Poison-on-free needs a reserved, never-committed region so every poison
	// address faults. Address space only; no RAM until a block is withheld.
	if (config.scaleformHeapEnabled && config.scaleformPoisonEnabled) {
		const auto blocks = hs::PoisonQuarantine::RoundUpCapacity(config.scaleformPoisonMaxBlocks);
		const auto bytes = blocks * 0x1000u;
		if (auto* base = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, bytes, MEM_RESERVE, PAGE_NOACCESS))) {
			hs::PoisonQuarantine::Get().Init(config.scaleformPoisonMaxBlocks, config.scaleformPoisonMaxBytes,
				reinterpret_cast<std::uintptr_t>(base), 0x1000);
			logger::info("poison region: {} blocks x 0x1000 reserved at 0x{:X}, {} MiB address space (never committed)",
				blocks, reinterpret_cast<std::uintptr_t>(base), bytes / (1u << 20));
		} else {
			logger::warn("poison region reserve failed ({}); poison-on-free will fail open", ::GetLastError());
			hs::Health::Degrade("poison region reserve failed: poison-on-free is off, the verdict is not deterministic");
		}
	}

	if (config.weakLibHooksEnabled) {
		hs::WeakLibEvents::Get().Init(config.weakLibEventCapacity);
	}

	if (config.vehEnabled) {
		hs::InstallVeh();
	}

	hs::InstallHooks();

	// Periodic stats so a soak test is observable: if the ledger stays bounded
	// (and keeps changing) the hooks are live and the bounded-probe eviction is
	// working; if it is stuck, recording has stopped. A one-shot warning the
	// first time insert failures appear makes a saturated ledger loud instead of
	// silently dropping the allocations the crash hunt depends on.
	std::thread([] {
		bool warnedSaturated = false;
		for (;;) {
			std::this_thread::sleep_for(std::chrono::seconds(60));
			const auto failures = hs::ShadowLedger::Get().InsertFailures();
			const auto drops = hs::ShadowLedger::Get().WriterDrops();

			hs::LogStats("timer");

			if (!warnedSaturated && (failures > 0 || drops > 0)) {
				logger::warn("ledger lossy: {} insert failures, {} writer drops; raise [Ledger] uCapacity or accept the gap", failures, drops);
				warnedSaturated = true;
			}
		}
	}).detach();

	logger::info("health: {}", hs::Health::Line());
	logger::info("...ready");
	return true;
}
