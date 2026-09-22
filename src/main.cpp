#include "PCH.h"

#include "Config.h"
#include "Core/GuardedPool.h"
#include "Core/ModuleMap.h"
#include "Core/Report.h"
#include "Core/ShadowLedger.h"
#include "Core/StackCapture.h"
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
		case SKSE::MessagingInterface::kDataLoaded:
			hs::ModuleMap::Get().Refresh();
			hs::ModuleMap::Get().SetComplete();
			logger::info("module map complete: {} modules", hs::ModuleMap::Get().Size());
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

	logger::info("HeapSentinel v0.1.1 (Skyrim SE/AE, Address Library + CommonLibSSE-NG) loading");

	if (auto* messaging = SKSE::GetMessagingInterface()) {
		messaging->RegisterListener("SKSE", OnMessage);
	}

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
