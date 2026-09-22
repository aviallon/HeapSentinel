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
	hs::SetupLog();

	logger::info("HeapSentinel v0.1.0 (Skyrim SE/AE, Address Library + CommonLibSSE-NG) loading");

	hs::Config::Get().Load();
	if (!hs::Config::Get().enabled) {
		logger::info("disabled in HeapSentinel.ini - installing nothing");
		return true;
	}

	// Order matters: the module map and stack capture are needed by every
	// report, and the ledger must exist before the hooks that write to it.
	hs::InitStackCapture();
	hs::ModuleMap::Get().Refresh();

	const auto& config = hs::Config::Get();

	if (config.ledgerEnabled) {
		hs::ShadowLedger::Get().Init(config.ledgerCapacity, config.ledgerShards, config.ledgerStackDepth);
	}

	if (config.guardPoolEnabled) {
		hs::GuardedPool::Get().Init(config.guardPoolSlots, config.guardPoolMaxSize, config.guardPoolSampleRate);
	}

	if (config.vehEnabled) {
		hs::InstallVeh();
	}

	hs::InstallHooks();

	logger::info("...ready");
	return true;
}
