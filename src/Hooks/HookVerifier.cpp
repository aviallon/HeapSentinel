#include "Hooks/HookVerifier.h"

namespace hs
{
	std::uint64_t Fnv1a64(const std::uint8_t* a_data, std::size_t a_size)
	{
		std::uint64_t hash = kFnv1a64OffsetBasis;
		for (std::size_t i = 0; i < a_size; ++i) {
			hash ^= a_data[i];
			hash *= kFnv1a64Prime;
		}
		return hash;
	}

	bool IdentityMatches(const HookTableIdentity& a_expected, const ModuleIdentity& a_actual)
	{
		return a_expected.size == a_actual.size &&
			a_expected.timeDateStamp == a_actual.timeDateStamp &&
			a_expected.sizeOfImage == a_actual.sizeOfImage;
	}

	const char* TargetVerdictName(TargetVerdict a_verdict)
	{
		switch (a_verdict) {
		case TargetVerdict::kVerified: return "verified";
		case TargetVerdict::kNoRecord: return "no table entry";
		case TargetVerdict::kIdUnresolved: return "address library id unresolved";
		case TargetVerdict::kAddressLibraryMismatch: return "address library disagrees with the table";
		case TargetVerdict::kVtableMismatch: return "vtable slot does not hold the expected function";
		case TargetVerdict::kPrologueMismatch: return "prologue mismatch";
		case TargetVerdict::kUnreadable: return "target bytes unreadable";
		}
		return "unknown";
	}

	TargetCheck VerifyHookTarget(const HookTableRecord& a_record, const TargetResolver& a_resolver)
	{
		TargetCheck check;
		check.expectedHash = a_record.prologueHash;

		std::uint64_t functionRva = 0;
		if (!a_resolver.ResolveId(a_record.aeId, functionRva)) {
			check.verdict = TargetVerdict::kIdUnresolved;
			return check;
		}
		if (functionRva != a_record.rva) {
			check.verdict = TargetVerdict::kAddressLibraryMismatch;
			check.rva = functionRva;
			return check;
		}

		if (a_record.kind == HookKind::kVtable) {
			std::uint64_t vtableRva = 0;
			if (!a_resolver.ResolveId(a_record.vtable.id, vtableRva)) {
				check.verdict = TargetVerdict::kIdUnresolved;
				return check;
			}
			if (vtableRva != a_record.vtable.rva) {
				check.verdict = TargetVerdict::kAddressLibraryMismatch;
				check.vtableRva = vtableRva;
				return check;
			}

			std::uint8_t slotBytes[sizeof(std::uint64_t)]{};
			if (!a_resolver.ReadBytes(vtableRva + a_record.vtable.slot * sizeof(std::uint64_t),
					slotBytes, sizeof(slotBytes))) {
				check.verdict = TargetVerdict::kUnreadable;
				check.vtableRva = vtableRva;
				return check;
			}
			std::uint64_t slotTarget = 0;
			for (std::size_t i = 0; i < sizeof(slotBytes); ++i) {
				slotTarget |= static_cast<std::uint64_t>(slotBytes[i]) << (8 * i);
			}

			check.vtableRva = vtableRva;
			check.expectedTargetVa = a_resolver.Base() + functionRva;
			check.actualTargetVa = slotTarget;
			if (slotTarget != check.expectedTargetVa) {
				check.verdict = TargetVerdict::kVtableMismatch;
				return check;
			}
		}

		check.rva = functionRva;

		std::uint8_t prologue[64]{};
		if (a_record.prologueLength == 0 || a_record.prologueLength > sizeof(prologue)) {
			check.verdict = TargetVerdict::kUnreadable;
			return check;
		}
		if (!a_resolver.ReadBytes(functionRva, prologue, static_cast<std::size_t>(a_record.prologueLength))) {
			check.verdict = TargetVerdict::kUnreadable;
			return check;
		}
		check.actualHash = Fnv1a64(prologue, static_cast<std::size_t>(a_record.prologueLength));
		if (check.actualHash != a_record.prologueHash) {
			check.verdict = TargetVerdict::kPrologueMismatch;
			return check;
		}

		check.verdict = TargetVerdict::kVerified;
		return check;
	}
}
