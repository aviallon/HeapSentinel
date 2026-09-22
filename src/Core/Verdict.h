#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace hs
{
	// What the provenance says happened to a pointer that the faulting code was
	// using. Deliberately portable so the decision is exercised off-game; the
	// Windows side only gathers the facts.
	enum class VerdictKind : std::uint32_t
	{
		kUnknown = 0,
		kUseAfterFreePoison,        // freed, poison still present: deterministic UAF
		kUseAfterFree,              // freed, object was healthy when freed
		kUseAfterFreeAlreadyCorrupt,// freed, but already corrupt before the free
		kStrayWriteLive,            // live, first qword no longer code: a write bug
		kLiveFirstQwordChanged,     // live, first qword changed since we last saw it
		kLiveHealthy,               // live and plausible: not explained by a free
	};

	struct VerdictFacts
	{
		const char*    regName = "?";
		std::uintptr_t value = 0;

		bool known = false;   // found in the ledger, free ring or quarantine
		bool freed = false;
		bool poisoned = false;
		std::size_t size = 0;

		// alloc-time qword is pre-construction and often garbage; recorded, but
		// the verdict never rests on it alone.
		std::uintptr_t firstQwordAtAlloc = 0;
		bool           firstQwordAtAllocPlausible = false;

		std::uintptr_t vtableAtFree = 0;
		bool           vtableAtFreePlausible = false;

		std::uintptr_t lastKnownVtable = 0;
		bool           lastKnownVtablePlausible = false;

		std::uintptr_t currentFirstQword = 0;
		bool           currentReadable = false;
		bool           currentPlausible = false;

		bool poisonMatch = false;

		bool        hasAllocSite = false;
		bool        hasFreeSite = false;
		std::string allocSiteName;
		std::string freeSiteName;
	};

	struct VerdictResult
	{
		VerdictKind kind = VerdictKind::kUnknown;
		std::string reason;
	};

	[[nodiscard]] VerdictResult BuildVerdict(const VerdictFacts& a_facts);
}