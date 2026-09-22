#pragma once

#include <string>
#include <string_view>

#include "Ipc/ShmLayout.h"

// The plugin's own health, as opposed to the game's. The point of a health
// state is that silence is never ambiguous: when a safety feature has to switch
// itself off (a hook target that could not be verified, a region that could not
// be reserved), the sentinel says DEGRADED and names the reason instead of
// quietly running with less protection than the user believes.
//
// It reuses hs::ipc::HealthState from the shared-memory layout so the in-process
// plugin and the out-of-process helper speak the same vocabulary.

namespace hs
{
	namespace Health
	{
		// Replace the state and start a fresh reason list.
		void SetState(ipc::HealthState a_state, std::string_view a_reason);
		// Set DEGRADED (never downgrading OFF) and append a reason.
		void Degrade(std::string_view a_reason);
		// The plugin is intentionally running with a feature disabled.
		void Off(std::string_view a_reason);

		[[nodiscard]] ipc::HealthState State();
		[[nodiscard]] const char* StateName();
		// "a; b; c", with a trailing " (+N more)" when the bound was hit.
		[[nodiscard]] std::string Reasons();
		// "GREEN: ..." / "DEGRADED: a; b" - one line for the log.
		[[nodiscard]] std::string Line();

		void Reset();
	}
}
