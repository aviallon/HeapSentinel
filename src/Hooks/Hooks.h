#pragma once

namespace hs
{
	// Installs the MinHook detours and enables them. Returns false (and installs
	// nothing) if MinHook cannot initialise, so the game is never left with a
	// half-installed hook set.
	bool InstallHooks();
	void RemoveHooks();
}
