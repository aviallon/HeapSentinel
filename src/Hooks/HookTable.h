#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "Hooks/HookTargets.h"

// The committed hook-target verification table (hooks/*.json), as parsed at
// runtime and in the off-game tests.
//
// The table is committed once per exact game build and embeds the build's
// identity (size, PE TimeDateStamp, SizeOfImage, SHA-256) plus, per hook target,
// the Address Library id, the name and its provenance, the RVA, the .pdata
// extent, and a 64-bit hash of the first N bytes of the function. For virtual
// targets it also carries {vtable id, vtable name, vtable RVA, slot}.
//
// No byte of SkyrimSE.exe is committed: a hash verifies identity just as well as
// a verbatim prologue, and a prologue is Bethesda's copyrighted code.
//
// The parser is STRICT on purpose: an unknown key, a missing field or a
// malformed number is an error, so a typo in a field name can never silently
// produce a record whose verification is skipped.

namespace hs
{
	struct HookTableIdentity
	{
		std::string   module;
		std::string   version;
		std::uint64_t size = 0;
		std::uint64_t timeDateStamp = 0;
		std::uint64_t sizeOfImage = 0;
		std::string   sha256;
	};

	struct HookTableVtable
	{
		std::uint64_t id = 0;
		std::string   name;
		std::uint64_t rva = 0;
		std::uint64_t slot = 0;
	};

	struct HookTableRecord
	{
		std::string    target;
		HookKind       kind = HookKind::kRva;
		std::uint64_t  seId = 0;
		std::uint64_t  aeId = 0;
		std::string    name;
		std::uint64_t  rva = 0;
		std::uint64_t  pdataExtent = 0;
		bool           hasPdataExtent = false;
		std::uint64_t  slotLength = 0;
		bool           hasSlotLength = false;
		std::uint64_t  prologueLength = 0;
		std::uint64_t  prologueHash = 0;
		HookTableVtable vtable;
		bool           hasVtable = false;
	};

	struct HookTable
	{
		std::string                  schema;
		std::string                  source;  // repository-relative path, for logs
		HookTableIdentity            identity;
		std::vector<HookTableRecord> records;

		[[nodiscard]] const HookTableRecord* Find(std::string_view a_target) const;
	};

	// Parses one committed table. Returns false and fills a_error (with the
	// byte offset) on any schema violation.
	[[nodiscard]] bool ParseHookTable(std::string_view a_json, HookTable& a_out, std::string& a_error);
}
