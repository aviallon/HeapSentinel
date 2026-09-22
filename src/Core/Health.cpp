#include "Core/Health.h"

#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

namespace hs
{
	namespace Health
	{
		namespace
		{
			// Startup and shutdown only; never on a hook path, so a plain mutex is
			// the right tool (no lock-free contortion needed).
			constexpr std::size_t kMaxReasons = 32;

			std::mutex           g_mutex;
			ipc::HealthState      g_state = ipc::HealthState::kUnknown;
			std::vector<std::string> g_reasons;
			std::size_t          g_dropped = 0;
		}

		void SetState(ipc::HealthState a_state, std::string_view a_reason)
		{
			std::lock_guard lock(g_mutex);
			g_state = a_state;
			g_reasons.clear();
			g_dropped = 0;
			if (!a_reason.empty()) {
				g_reasons.emplace_back(a_reason);
			}
		}

		void Degrade(std::string_view a_reason)
		{
			std::lock_guard lock(g_mutex);
			// OFF is a deliberate, configured state; a failure must not overwrite
			// it with a less specific one, but any failure does set DEGRADED.
			if (g_state != ipc::HealthState::kOff) {
				g_state = ipc::HealthState::kDegraded;
			}
			if (a_reason.empty()) {
				return;
			}
			if (g_reasons.size() < kMaxReasons) {
				g_reasons.emplace_back(a_reason);
			} else {
				++g_dropped;
			}
		}

		void Off(std::string_view a_reason)
		{
			std::lock_guard lock(g_mutex);
			g_state = ipc::HealthState::kOff;
			g_reasons.clear();
			g_dropped = 0;
			if (!a_reason.empty()) {
				g_reasons.emplace_back(a_reason);
			}
		}

		ipc::HealthState State()
		{
			std::lock_guard lock(g_mutex);
			return g_state;
		}

		const char* StateName()
		{
			switch (State()) {
			case ipc::HealthState::kGreen: return "GREEN";
			case ipc::HealthState::kDegraded: return "DEGRADED";
			case ipc::HealthState::kOff: return "OFF";
			default: return "UNKNOWN";
			}
		}

		std::string Line()
		{
			std::string reasons;
			{
				std::lock_guard lock(g_mutex);
				for (const auto& reason : g_reasons) {
					if (!reasons.empty()) {
						reasons += "; ";
					}
					reasons += reason;
				}
				if (g_dropped != 0) {
					reasons += " (+" + std::to_string(g_dropped) + " more)";
				}
			}
			std::string out = StateName();
			if (!reasons.empty()) {
				out += ": ";
				out += reasons;
			}
			return out;
		}

		void Reset()
		{
			std::lock_guard lock(g_mutex);
			g_state = ipc::HealthState::kUnknown;
			g_reasons.clear();
			g_dropped = 0;
		}
	}
}
