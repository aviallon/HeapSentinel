#pragma once

#include <cstddef>
#include <cstdint>

#include "Hooks/HookTable.h"

// Runtime verification of a hook target against the committed table.
//
// Everything here is deliberately platform-neutral and expressed against a
// TargetResolver, so the whole verifier is exercised off-game on Linux and
// Windows by feeding it synthetic bytes (match, single-byte mismatch, truncated
// read, unresolvable id, missing entry). The Windows build supplies a resolver
// backed by REL::RelocationID + the mapped image; the tests supply a fake.
//
// What it proves: the running SkyrimSE.exe is the build this revision was
// verified against, and the function about to be hooked is still the function
// the table describes - and, for a virtual target, that the vtable slot still
// points at it.
//
// What it does NOT prove: semantics. A hook can sit at the right address with
// the right prologue and still be wrong for our purpose (the GMemoryHeapPT
// argument count had to come from disassembly precisely because the header
// comment order was wrong, and no signature check would have caught that).

namespace hs
{
	// 64-bit FNV-1a over the first N bytes of a function. The same constants are
	// implemented in tools/gen-hooktable.py; the tests pin the value for a known
	// vector so the two cannot silently diverge.
	inline constexpr std::uint64_t kFnv1a64OffsetBasis = 0xCBF29CE484222325ull;
	inline constexpr std::uint64_t kFnv1a64Prime = 0x100000001B3ull;

	[[nodiscard]] std::uint64_t Fnv1a64(const std::uint8_t* a_data, std::size_t a_size);

	// The cheap identity of the running module: all three fields come out of the
	// PE headers / file system, so no 38 MB hash is computed at load time. The
	// full SHA-256 is recorded in the table and checked by the generator/CI.
	struct ModuleIdentity
	{
		std::uint64_t size = 0;
		std::uint64_t timeDateStamp = 0;
		std::uint64_t sizeOfImage = 0;
	};

	[[nodiscard]] bool IdentityMatches(const HookTableIdentity& a_expected, const ModuleIdentity& a_actual);

	// The process as the verifier sees it. RVAs are image-base relative.
	class TargetResolver
	{
	public:
		virtual ~TargetResolver() = default;

		// The module's load address (what a vtable entry points at).
		[[nodiscard]] virtual std::uint64_t Base() const = 0;
		// Address Library id -> RVA. False when the id is absent for this build.
		[[nodiscard]] virtual bool ResolveId(std::uint64_t a_id, std::uint64_t& a_rvaOut) const = 0;
		// Read exactly a_size bytes at an RVA. False when the range is not
		// readable (unmapped, guard page, past SizeOfImage).
		[[nodiscard]] virtual bool ReadBytes(std::uint64_t a_rva, std::uint8_t* a_out, std::size_t a_size) const = 0;
	};

	enum class TargetVerdict
	{
		kVerified,                 // identity + id + (vtable slot) + prologue all agree
		kNoRecord,                 // no table entry for this target
		kIdUnresolved,             // the Address Library has no such id in this build
		kAddressLibraryMismatch,   // the id resolves somewhere else than the table says
		kVtableMismatch,           // the vtable slot does not hold the expected function
		kPrologueMismatch,         // the bytes at the target are not the verified ones
		kUnreadable,               // the target's bytes could not be read
	};

	[[nodiscard]] const char* TargetVerdictName(TargetVerdict a_verdict);

	struct TargetCheck
	{
		TargetVerdict verdict = TargetVerdict::kNoRecord;
		std::uint64_t rva = 0;             // resolved function RVA
		std::uint64_t vtableRva = 0;       // resolved vtable RVA (vtable targets)
		std::uint64_t expectedTargetVa = 0;
		std::uint64_t actualTargetVa = 0;
		std::uint64_t expectedHash = 0;
		std::uint64_t actualHash = 0;

		[[nodiscard]] bool Verified() const { return verdict == TargetVerdict::kVerified; }
	};

	[[nodiscard]] TargetCheck VerifyHookTarget(const HookTableRecord& a_record, const TargetResolver& a_resolver);
}
