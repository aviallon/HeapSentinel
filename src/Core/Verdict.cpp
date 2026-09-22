#if defined(HS_NO_PCH)
#	include "Core/Verdict.h"

#	include <sstream>
#else
#	include "PCH.h"

#	include "Core/Verdict.h"
#endif

namespace hs
{
	namespace
	{
		[[nodiscard]] std::string Hex(std::uintptr_t a_value)
		{
			std::ostringstream out;
			out << "0x" << std::hex << a_value;
			return out.str();
		}

		[[nodiscard]] std::string Site(const std::string& a_name, bool a_present)
		{
			return a_present && !a_name.empty() ? a_name : std::string("(unknown)");
		}
	}

	VerdictResult BuildVerdict(const VerdictFacts& a_facts)
	{
		VerdictResult result;
		const auto    value = Hex(a_facts.value);

		if (!a_facts.known) {
			result.kind = VerdictKind::kUnknown;
			result.reason = a_facts.regName + std::string(" ") + value +
				" is unknown to the ledger: allocated before the hooks were live, "
				"allocated through an unhooked entry point (AllocSysDirect), or its "
				"record has been evicted - a negative result, not a clean bill of health";
			return result;
		}

		const std::string sizeText = a_facts.size != 0 ? (" size " + std::to_string(a_facts.size)) : std::string();
		const std::string freeBy = Site(a_facts.freeSiteName, a_facts.hasFreeSite);

		if (a_facts.freed) {
			if (a_facts.poisonMatch || a_facts.poisoned) {
				result.kind = VerdictKind::kUseAfterFreePoison;
				result.reason = "use-after-free; freed by " + freeBy +
					" and its real free is withheld - the object still holds the poison" + sizeText;
			} else if (a_facts.vtableAtFreePlausible) {
				result.kind = VerdictKind::kUseAfterFree;
				result.reason = "use-after-free; freed by " + freeBy + " (first qword was code when freed)" + sizeText;
			} else {
				result.kind = VerdictKind::kUseAfterFreeAlreadyCorrupt;
				result.reason = "use-after-free; freed by " + freeBy +
					", but its first qword was already not code at free time (" + Hex(a_facts.vtableAtFree) +
					") - it was corrupted before the free" + sizeText;
			}
			return result;
		}

		// Live according to the ledger.
		if (a_facts.currentReadable && !a_facts.currentPlausible) {
			result.kind = VerdictKind::kStrayWriteLive;
			result.reason = "stray WRITE / corruption of a LIVE object " + value +
				": it is still allocated, but its first qword is " + Hex(a_facts.currentFirstQword) +
				", which is not code - this is not a use-after-free" + sizeText;
			return result;
		}

		if (a_facts.lastKnownVtablePlausible && a_facts.currentFirstQword != a_facts.lastKnownVtable) {
			result.kind = VerdictKind::kLiveFirstQwordChanged;
			result.reason = "live object " + value + " whose first qword changed from the last vtable observed at a "
				"GFxResourceWeakLib hook (" + Hex(a_facts.lastKnownVtable) + " -> " +
				Hex(a_facts.currentFirstQword) + ")" + sizeText;
			return result;
		}

		result.kind = VerdictKind::kLiveHealthy;
		result.reason = "object " + value + " is live with a plausible first qword; the fault is NOT explained by a free of it "
			"(the register may not be the object, or the table entry is corrupt)" + sizeText;
		return result;
	}
}