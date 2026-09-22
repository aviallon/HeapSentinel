#include "PCH.h"

#include "Config.h"

#include <filesystem>

namespace hs
{
	namespace
	{
		std::filesystem::path g_pluginDir;

		[[nodiscard]] std::uint32_t ReadUInt(const char* a_section, const char* a_key, std::uint32_t a_default, const std::filesystem::path& a_ini)
		{
			return static_cast<std::uint32_t>(::GetPrivateProfileIntA(a_section, a_key, static_cast<INT>(a_default), a_ini.string().c_str()));
		}

		[[nodiscard]] bool ReadBool(const char* a_section, const char* a_key, bool a_default, const std::filesystem::path& a_ini)
		{
			return ReadUInt(a_section, a_key, a_default ? 1u : 0u, a_ini) != 0;
		}

		void ResolvePluginDir()
		{
			HMODULE self = nullptr;
			if (!::GetModuleHandleExA(
					GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
					reinterpret_cast<LPCSTR>(&ResolvePluginDir),
					&self)) {
				return;
			}

			char buffer[MAX_PATH]{};
			const auto len = ::GetModuleFileNameA(self, buffer, MAX_PATH);
			if (len == 0) {
				return;
			}

			g_pluginDir = std::filesystem::path(std::string(buffer, len)).parent_path();
		}
	}

	const std::filesystem::path& PluginDir()
	{
		if (g_pluginDir.empty()) {
			ResolvePluginDir();
		}
		return g_pluginDir;
	}

	Config& Config::Get()
	{
		static Config config;
		return config;
	}

	void Config::Load()
	{
		const auto ini = PluginDir() / "HeapSentinel.ini";
		if (!std::filesystem::exists(ini)) {
			logger::info("no {} - using defaults", ini.string());
			return;
		}

		enabled = ReadBool("General", "bEnabled", enabled, ini);

		verifyTargets = ReadBool("Hooks", "bVerifyTargets", verifyTargets, ini);

		ledgerEnabled = ReadBool("Ledger", "bEnabled", ledgerEnabled, ini);
		ledgerCapacity = ReadUInt("Ledger", "uCapacity", static_cast<std::uint32_t>(ledgerCapacity), ini);
		ledgerShards = ReadUInt("Ledger", "uShards", static_cast<std::uint32_t>(ledgerShards), ini);
		ledgerStackDepth = ReadUInt("Ledger", "uStackDepth", static_cast<std::uint32_t>(ledgerStackDepth), ini);

		guardPoolEnabled = ReadBool("GuardPool", "bEnabled", guardPoolEnabled, ini);
		guardPoolSampleRate = ReadUInt("GuardPool", "uSampleRate", guardPoolSampleRate, ini);
		guardPoolSlots = ReadUInt("GuardPool", "uSlots", static_cast<std::uint32_t>(guardPoolSlots), ini);
		guardPoolMaxSize = ReadUInt("GuardPool", "uMaxSize", static_cast<std::uint32_t>(guardPoolMaxSize), ini);
		guardPoolFixUp = ReadBool("GuardPool", "bFixUp", guardPoolFixUp, ini);

		refCountGuardEnabled = ReadBool("RefCountGuard", "bEnabled", refCountGuardEnabled, ini);
		refCountGuardFailSafe = ReadBool("RefCountGuard", "bFailSafe", refCountGuardFailSafe, ini);

		scaleformHeapEnabled = ReadBool("ScaleformHeap", "bEnabled", scaleformHeapEnabled, ini);
		scaleformCaptureStacks = ReadBool("ScaleformHeap", "bCaptureStacks", scaleformCaptureStacks, ini);
		scaleformPoisonEnabled = ReadBool("ScaleformHeap", "bPoisonOnFree", scaleformPoisonEnabled, ini);
		scaleformPoisonMaxBlocks = ReadUInt("ScaleformHeap", "uPoisonMaxBlocks", static_cast<std::uint32_t>(scaleformPoisonMaxBlocks), ini);
		scaleformPoisonMaxBytes = ReadUInt("ScaleformHeap", "uPoisonMaxBytes", static_cast<std::uint32_t>(scaleformPoisonMaxBytes), ini);
		scaleformFreeCapacity = ReadUInt("ScaleformHeap", "uFreeRingCapacity", static_cast<std::uint32_t>(scaleformFreeCapacity), ini);

		weakLibHooksEnabled = ReadBool("WeakLib", "bEnabled", weakLibHooksEnabled, ini);
		weakLibEventCapacity = ReadUInt("WeakLib", "uEventCapacity", static_cast<std::uint32_t>(weakLibEventCapacity), ini);

		reportScreenshot = ReadBool("Reporting", "bScreenshot", reportScreenshot, ini);
		reportFreeze = ReadBool("Reporting", "bFreeze", reportFreeze, ini);
		vehEnabled = ReadBool("Reporting", "bVeh", vehEnabled, ini);
		reportUntrackedFree = ReadBool("Reporting", "bReportUntrackedFree", reportUntrackedFree, ini);
		preventDoubleFree = ReadBool("Reporting", "bPreventDoubleFree", preventDoubleFree, ini);
		reportSymbolHint = ReadBool("Reporting", "bSymbolHint", reportSymbolHint, ini);
		maxReportsPerSecond = ReadUInt("Reporting", "uMaxReportsPerSecond", static_cast<std::uint32_t>(maxReportsPerSecond), ini);

		logger::info("config: enabled={} verifyTargets={} ledger={} guardPool={} (1/{}) refCountGuard={} (failSafe={}) scaleformHeap={} (stacks={}, poison={}, {} blocks/{} bytes) weaklib={}",
			enabled, verifyTargets, ledgerEnabled, guardPoolEnabled, guardPoolSampleRate, refCountGuardEnabled, refCountGuardFailSafe,
			scaleformHeapEnabled, scaleformCaptureStacks, scaleformPoisonEnabled, scaleformPoisonMaxBlocks,
			scaleformPoisonMaxBytes, weakLibHooksEnabled);
	}

	std::string Config::Summary() const
	{
		std::string behaviourChanging;
		if (preventDoubleFree) {
			behaviourChanging += "preventDoubleFree (suspected double free skipped -> leak)";
		}
		if (scaleformPoisonEnabled) {
			if (!behaviourChanging.empty()) {
				behaviourChanging += ", ";
			}
			behaviourChanging += "scaleformPoison (real free withheld + poison qword written)";
		}
		if (guardPoolEnabled) {
			if (!behaviourChanging.empty()) {
				behaviourChanging += ", ";
			}
			behaviourChanging += "guardPool (sampled blocks served from our region)";
		}
		if (refCountGuardFailSafe) {
			if (!behaviourChanging.empty()) {
				behaviourChanging += ", ";
			}
			behaviourChanging += "refCountGuardFailSafe (bad-vtable release skipped -> leak)";
		}
		if (behaviourChanging.empty()) {
			behaviourChanging = "none (semantics-preserving)";
		}

		return "verifyTargets=" + std::to_string(verifyTargets ? 1 : 0) +
			" ledger=" + std::to_string(ledgerEnabled ? 1 : 0) +
			" scaleformHeap=" + std::to_string(scaleformHeapEnabled ? 1 : 0) +
			" weaklib=" + std::to_string(weakLibHooksEnabled ? 1 : 0) +
			" refCountGuard=" + std::to_string(refCountGuardEnabled ? 1 : 0) +
			" behaviourChanging=" + behaviourChanging;
	}
}
