#include "PCH.h"

#include "Config.h"
#include "Core/GuardedPool.h"
#include "Core/ModuleMap.h"
#include "Core/Report.h"
#include "Core/ShadowLedger.h"
#include "Core/StackCapture.h"
#include "Hooks/Hooks.h"
#include "Veh.h"

SKSE_PLUGIN_LOAD(const SKSE::LoadInterface* a_skse)
{
	SKSE::Init(a_skse);
	SetupLog();

	logger::info("HeapSentinel v0.1.0 (Skyrim SE/AE, Address Library + CommonLibSSE-NG) loading");

	Config::Get().Load();
	if (!Config::Get().enabled) {
		logger::info("disabled in HeapSentinel.ini - installing nothing");
		return true;
	}

	// Order matters: the module map and stack capture are needed by every
	// report, and the ledger must exist before the hooks that write to it.
	InitStackCapture();
	ModuleMap::Get().Refresh();

	const auto& config = Config::Get();

	if (config.ledgerEnabled) {
		ShadowLedger::Get().Init(config.ledgerCapacity, config.ledgerShards, config.ledgerStackDepth);
	}

	if (config.guardPoolEnabled) {
		GuardedPool::Get().Init(config.guardPoolSlots, config.guardPoolMaxSize, config.guardPoolSampleRate);
	}

	if (config.vehEnabled) {
		InstallVeh();
	}

	InstallHooks();

	logger::info("...ready");
	return true;
}
