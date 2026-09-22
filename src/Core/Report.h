#pragma once

#include <string>

namespace hs
{
	// Sets up spdlog: the main log plus a dedicated reports log, both next to
	// the plugin DLL.
	void SetupLog();

	// The product. Classifies the address, writes a multi-line report to both
	// logs, and optionally takes a screenshot and/or freezes the game.
	void Report(std::string_view a_kind, std::string_view a_detail);

	// "SkyrimSE.exe+0xCF326C" / "guarded slot (freed, size 96)" /
	// "ledger-known freed block" / "unmapped".
	[[nodiscard]] std::string ClassifyAddress(std::uintptr_t a_addr);

	// GDI capture of the game window to a BMP next to the reports log. May be
	// black for a DXGI flip-model window; the swapchain hook is the follow-up.
	void Screenshot(std::string_view a_tag);
}
