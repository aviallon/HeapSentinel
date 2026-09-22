// Off-game tests for the committed hook-target verification table: the parser,
// the verifier, and the invariant that every hook target named in the source has
// a verified entry.
//
// Everything here runs without a game binary. The verifier is fed synthetic
// bytes through a fake TargetResolver, which is exactly what makes the
// match / single-byte-mismatch / truncated / unknown-id / missing-entry cases
// testable at all: in-game there is no second SkyrimSE.exe to compare against.

#include "harness.h"

#include "Core/Health.h"
#include "Hooks/HookTable.h"
#include "Hooks/HookTableData.gen.h"
#include "Hooks/HookTargets.h"
#include "Hooks/HookVerifier.h"

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

using namespace hs;

namespace
{
	// A synthetic process: an id -> RVA map plus a byte buffer indexed by RVA.
	class FakeResolver final : public TargetResolver
	{
	public:
		std::uint64_t                         base = 0x140000000;
		std::unordered_map<std::uint64_t, std::uint64_t> ids;
		std::vector<std::uint8_t>             bytes = std::vector<std::uint8_t>(0x2000, 0);
		bool                                  readFails = false;

		[[nodiscard]] std::uint64_t Base() const override { return base; }

		[[nodiscard]] bool ResolveId(std::uint64_t a_id, std::uint64_t& a_rvaOut) const override
		{
			const auto it = ids.find(a_id);
			if (it == ids.end()) {
				return false;
			}
			a_rvaOut = it->second;
			return true;
		}

		[[nodiscard]] bool ReadBytes(std::uint64_t a_rva, std::uint8_t* a_out, std::size_t a_size) const override
		{
			if (readFails || a_rva + a_size > bytes.size()) {
				return false;
			}
			std::memcpy(a_out, bytes.data() + a_rva, a_size);
			return true;
		}
	};

	// A synthetic table record whose recorded hash is derived from the bytes the
	// resolver will return, i.e. the "pristine build" case.
	HookTableRecord MakeRvaRecord(const FakeResolver& a_resolver, std::uint64_t a_aeId, std::uint64_t a_rva,
		std::uint64_t a_length = 32)
	{
		HookTableRecord record;
		record.target = "Synthetic::Target";
		record.kind = HookKind::kRva;
		record.aeId = a_aeId;
		record.rva = a_rva;
		record.prologueLength = a_length;
		record.prologueHash = Fnv1a64(a_resolver.bytes.data() + a_rva, static_cast<std::size_t>(a_length));
		return record;
	}

	HookTableRecord MakeVtableRecord(const FakeResolver& a_resolver, std::uint64_t a_vtableId,
		std::uint64_t a_vtableRva, std::uint64_t a_slot, std::uint64_t a_aeId, std::uint64_t a_rva,
		std::uint64_t a_length = 32)
	{
		auto record = MakeRvaRecord(a_resolver, a_aeId, a_rva, a_length);
		record.kind = HookKind::kVtable;
		record.vtable.id = a_vtableId;
		record.vtable.name = "??_7Synthetic@@6B@";
		record.vtable.rva = a_vtableRva;
		record.vtable.slot = a_slot;
		record.hasVtable = true;
		return record;
	}

	void WriteQword(FakeResolver& a_resolver, std::uint64_t a_rva, std::uint64_t a_value)
	{
		for (std::size_t i = 0; i < 8; ++i) {
			a_resolver.bytes[a_rva + i] = static_cast<std::uint8_t>((a_value >> (8 * i)) & 0xFF);
		}
	}

	constexpr const char* kMinimalTable = R"JSON({
  "schema": "heapsentinel.hooktable/1",
  "identity": {
    "module": "SkyrimSE.exe",
    "version": "1.2.3.4",
    "size": 4096,
    "timeDateStamp": 4660,
    "sizeOfImage": 8192,
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "targets": [
    {
      "target": "Synthetic::Target",
      "kind": "rva",
      "seId": 0,
      "aeId": 7,
      "name": "Synthetic::Target_*",
      "rva": 4096,
      "pdataExtent": 64,
      "slotLength": 64,
      "prologueLength": 32,
      "prologueHash": 1234567
    }
  ]
})JSON";
}

// --- the committed table -----------------------------------------------------

HS_TEST(hooktable_committed_table_parses_and_covers_every_source_target)
{
	static_assert(kEmbeddedHookTableCount >= 1, "the committed table must be embedded");
	HS_CHECK_EQ(kEmbeddedHookTableCount, static_cast<std::size_t>(1));

	HookTable   table;
	std::string error;
	HS_CHECK(ParseHookTable(kEmbeddedHookTables[0].json, table, error));
	if (!error.empty()) {
		hstest::Note(error);
	}
	HS_CHECK_EQ(table.schema, std::string("heapsentinel.hooktable/1"));
	HS_CHECK_EQ(table.identity.version, std::string("1.7.104.0"));
	HS_CHECK_EQ(table.identity.module, std::string("SkyrimSE.exe"));
	HS_CHECK_EQ(table.identity.size, 37910440u);
	HS_CHECK_EQ(table.identity.sha256.size(), std::size_t(64));

	// The invariant that replaces the untestable hook wiring, asserted here too:
	// every target named in the source has exactly one entry.
	HS_CHECK_EQ(table.records.size(), kHookTargetCount);
	for (std::size_t i = 0; i < kHookTargetCount; ++i) {
		const auto& target = kHookTargets[i];
		const auto* record = table.Find(target.name);
		HS_CHECK(record != nullptr);
		if (record != nullptr) {
			HS_CHECK(record->aeId == target.aeId);
			HS_CHECK(record->seId == target.seId);
			HS_CHECK_EQ(static_cast<int>(record->kind), static_cast<int>(target.kind));
			if (target.kind == HookKind::kVtable) {
				HS_CHECK(record->hasVtable);
				HS_CHECK(record->vtable.id == target.vtableId);
				HS_CHECK(record->vtable.slot == target.vtableSlot);
			} else {
				HS_CHECK(!record->hasVtable);
			}
			HS_CHECK(record->prologueLength >= 8);
			HS_CHECK(record->prologueLength <= 64);
			HS_CHECK(record->prologueHash != 0);
			HS_CHECK(record->rva != 0);
		}
	}

	// Spot-check the two shapes, so a future reformat cannot silently turn a
	// vtable record into an rva one.
	const auto* allocate = table.Find("MemoryManager::Allocate");
	HS_CHECK(allocate != nullptr);
	if (allocate != nullptr) {
		HS_CHECK(allocate->kind == HookKind::kRva);
		HS_CHECK_EQ(allocate->rva, 0xCDE250u);
		HS_CHECK_EQ(allocate->prologueLength, 32u);
	}
	const auto* free = table.Find("GMemoryHeapPT::Free");
	HS_CHECK(free != nullptr);
	if (free != nullptr) {
		HS_CHECK(free->kind == HookKind::kVtable);
		HS_CHECK_EQ(free->vtable.id, 242891u);
		HS_CHECK_EQ(free->vtable.slot, 12u);
		HS_CHECK_EQ(free->rva, 0x117CF90u);
	}
}

HS_TEST(hooktargets_registry_is_well_formed)
{
	HS_CHECK(kHookTargetCount > 0);
	for (std::size_t i = 0; i < kHookTargetCount; ++i) {
		const auto& target = kHookTargets[i];
		HS_CHECK(target.name != nullptr);
		HS_CHECK(target.name[0] != '\0');
		HS_CHECK(target.aeId != 0);
		HS_CHECK(static_cast<std::size_t>(target.id) == i);
		if (target.kind == HookKind::kVtable) {
			HS_CHECK(target.vtableId != 0);
			HS_CHECK(target.vtableSlot != 0);
		} else {
			HS_CHECK(target.vtableId == 0);
			HS_CHECK(target.vtableSlot == 0);
		}
		for (std::size_t j = i + 1; j < kHookTargetCount; ++j) {
			HS_CHECK(std::strcmp(target.name, kHookTargets[j].name) != 0);
		}
	}
}

// --- the parser --------------------------------------------------------------

HS_TEST(hooktable_parser_accepts_a_minimal_table)
{
	HookTable   table;
	std::string error;
	HS_CHECK(ParseHookTable(kMinimalTable, table, error));
	HS_CHECK_EQ(table.records.size(), std::size_t(1));
	HS_CHECK_EQ(table.records[0].target, std::string("Synthetic::Target"));
	HS_CHECK_EQ(table.records[0].rva, 4096u);
	HS_CHECK_EQ(table.records[0].prologueHash, 1234567u);
	HS_CHECK(table.records[0].hasPdataExtent);
	HS_CHECK_EQ(table.records[0].pdataExtent, 64u);
	HS_CHECK(table.Find("Synthetic::Target") != nullptr);
	HS_CHECK(table.Find("Synthetic::Other") == nullptr);
}

HS_TEST(hooktable_parser_rejects_malformed_json)
{
	HookTable   table;
	std::string error;
	HS_CHECK(!ParseHookTable("{\"schema\": ", table, error));
	HS_CHECK(!error.empty());

	HS_CHECK(!ParseHookTable("[]", table, error));
	HS_CHECK(!error.empty());

	HS_CHECK(!ParseHookTable("", table, error));
	HS_CHECK(!error.empty());

	// Trailing garbage after a complete document must not be ignored.
	HS_CHECK(!ParseHookTable(std::string(kMinimalTable) + "{}", table, error));
	HS_CHECK(!error.empty());
}

HS_TEST(hooktable_parser_rejects_an_unknown_key)
{
	// The typo trap: "prologuHash" must be an error, not a record whose hash is
	// silently 0 and whose verification is silently skipped.
	auto broken = std::string(kMinimalTable);
	const auto pos = broken.find("\"prologueHash\"");
	HS_CHECK(pos != std::string::npos);
	broken.replace(pos, std::strlen("\"prologueHash\""), "\"prologuHash\"");

	HookTable   table;
	std::string error;
	HS_CHECK(!ParseHookTable(broken, table, error));
	HS_CHECK(error.find("unknown key") != std::string::npos);
	HS_CHECK(error.find("prologuHash") != std::string::npos);
}

HS_TEST(hooktable_parser_rejects_a_missing_field)
{
	auto broken = std::string(kMinimalTable);
	const auto pos = broken.find("\"prologueLength\": 32,");
	HS_CHECK(pos != std::string::npos);
	broken.erase(pos, std::strlen("\"prologueLength\": 32,"));

	HookTable   table;
	std::string error;
	HS_CHECK(!ParseHookTable(broken, table, error));
	HS_CHECK(error.find("prologueLength") != std::string::npos);
}

HS_TEST(hooktable_parser_rejects_a_bad_schema)
{
	auto        broken = std::string(kMinimalTable);
	const auto  pos = broken.find("heapsentinel.hooktable/1");
	broken.replace(pos, std::strlen("heapsentinel.hooktable/1"), "heapsentinel.hooktable/99");

	HookTable   table;
	std::string error;
	HS_CHECK(!ParseHookTable(broken, table, error));
	HS_CHECK(error.find("schema") != std::string::npos);
}

HS_TEST(hooktable_parser_rejects_a_duplicate_target)
{
	auto        broken = std::string(kMinimalTable);
	const auto  targets = broken.find("\"targets\"");
	HS_CHECK(targets != std::string::npos);
	const auto  recordBegin = broken.find('{', targets);
	HS_CHECK(recordBegin != std::string::npos);
	const auto  recordEnd = broken.find('}', recordBegin);
	HS_CHECK(recordEnd != std::string::npos);
	const auto  record = broken.substr(recordBegin, recordEnd - recordBegin + 1);
	broken.insert(recordBegin, record + ",\n    ");

	HookTable   table;
	std::string error;
	HS_CHECK(!ParseHookTable(broken, table, error));
	HS_CHECK(error.find("duplicate target") != std::string::npos);
}

HS_TEST(hooktable_parser_rejects_a_vtable_record_without_a_vtable_block)
{
	auto broken = std::string(kMinimalTable);
	const auto pos = broken.find("\"kind\": \"rva\"");
	HS_CHECK(pos != std::string::npos);
	broken.replace(pos, std::strlen("\"kind\": \"rva\""), "\"kind\": \"vtable\"");

	HookTable   table;
	std::string error;
	HS_CHECK(!ParseHookTable(broken, table, error));
	HS_CHECK(error.find("vtable") != std::string::npos);
}

HS_TEST(hooktable_parser_rejects_an_out_of_range_prologue_length)
{
	auto broken = std::string(kMinimalTable);
	const auto pos = broken.find("\"prologueLength\": 32");
	HS_CHECK(pos != std::string::npos);
	broken.replace(pos, std::strlen("\"prologueLength\": 32"), "\"prologueLength\": 0");

	HookTable   table;
	std::string error;
	HS_CHECK(!ParseHookTable(broken, table, error));
	HS_CHECK(error.find("prologueLength") != std::string::npos);
}

// --- the verifier ------------------------------------------------------------

HS_TEST(fnv1a64_matches_the_generator)
{
	// Pinned against tools/gen-hooktable.py's fnv1a64() for the same input, so
	// the C++ and Python implementations cannot silently diverge.
	const std::string text = "HeapSentinel hook table";
	const auto        hash = Fnv1a64(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
	HS_CHECK_EQ(hash, 0x679D1C8E58EF54BEull);

	// Empty input is the offset basis.
	HS_CHECK_EQ(Fnv1a64(nullptr, 0), kFnv1a64OffsetBasis);
}

HS_TEST(verifier_accepts_a_matching_rva_target)
{
	FakeResolver resolver;
	const std::uint64_t rva = 0x1000;
	resolver.ids[7] = rva;
	for (std::size_t i = 0; i < 32; ++i) {
		resolver.bytes[rva + i] = static_cast<std::uint8_t>(i * 3 + 1);
	}

	const auto record = MakeRvaRecord(resolver, 7, rva);
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kVerified);
	HS_CHECK(check.Verified());
	HS_CHECK_EQ(check.rva, rva);
	HS_CHECK_EQ(check.actualHash, check.expectedHash);
}

HS_TEST(verifier_rejects_a_single_byte_mismatch)
{
	FakeResolver resolver;
	const std::uint64_t rva = 0x1000;
	resolver.ids[7] = rva;
	for (std::size_t i = 0; i < 32; ++i) {
		resolver.bytes[rva + i] = static_cast<std::uint8_t>(i * 3 + 1);
	}

	const auto record = MakeRvaRecord(resolver, 7, rva);
	// One byte differs from the verified build.
	resolver.bytes[rva + 17] ^= 0x40;

	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kPrologueMismatch);
	HS_CHECK(!check.Verified());
	HS_CHECK_NE(check.actualHash, check.expectedHash);
	HS_CHECK_EQ(check.expectedHash, record.prologueHash);
}

HS_TEST(verifier_rejects_a_corrupted_recorded_hash)
{
	// MUTATION CHECK (a), unit level: corrupt one bit of the table's recorded
	// hash and confirm the verifier refuses the target instead of installing it.
	FakeResolver resolver;
	const std::uint64_t rva = 0x1000;
	resolver.ids[7] = rva;
	for (std::size_t i = 0; i < 32; ++i) {
		resolver.bytes[rva + i] = static_cast<std::uint8_t>(0xA5 ^ i);
	}

	auto record = MakeRvaRecord(resolver, 7, rva);
	HS_CHECK(VerifyHookTarget(record, resolver).verdict == TargetVerdict::kVerified);

	record.prologueHash ^= 0x1;  // one bit, one hex digit of the recorded hash
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kPrologueMismatch);
	HS_CHECK_EQ(check.expectedHash, record.prologueHash);
	HS_CHECK_EQ(check.actualHash, Fnv1a64(resolver.bytes.data() + rva, 32));
}

HS_TEST(verifier_rejects_a_truncated_function)
{
	FakeResolver resolver;
	const std::uint64_t rva = 0x1000;
	resolver.ids[7] = rva;
	for (std::size_t i = 0; i < 32; ++i) {
		resolver.bytes[rva + i] = static_cast<std::uint8_t>(i + 1);
	}

	const auto record = MakeRvaRecord(resolver, 7, rva);
	resolver.readFails = true;  // the range is not readable in this process
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kUnreadable);
	HS_CHECK(!check.Verified());

	// And a genuine truncation: the prologue runs past the readable buffer.
	resolver.readFails = false;
	const auto longRecord = MakeRvaRecord(resolver, 7, rva, 32);
	FakeResolver small;
	small.ids[7] = rva;
	small.bytes.resize(rva + 16);
	const auto truncated = VerifyHookTarget(longRecord, small);
	HS_CHECK(truncated.verdict == TargetVerdict::kUnreadable);
}

HS_TEST(verifier_rejects_an_unknown_id)
{
	FakeResolver resolver;  // no ids at all
	const auto record = MakeRvaRecord(resolver, 7, 0x1000);
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kIdUnresolved);
}

HS_TEST(verifier_rejects_an_address_library_mismatch)
{
	FakeResolver resolver;
	resolver.ids[7] = 0x2000;  // the id resolves somewhere else than the table says
	const auto record = MakeRvaRecord(resolver, 7, 0x1000);
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kAddressLibraryMismatch);
	HS_CHECK_EQ(check.rva, 0x2000u);
}

HS_TEST(verifier_rejects_a_missing_entry)
{
	// A target with no table entry never reaches VerifyHookTarget: the lookup
	// fails first, and the caller refuses the hook. Assert both halves.
	HookTable   table;
	std::string error;
	HS_CHECK(ParseHookTable(kMinimalTable, table, error));
	HS_CHECK(table.Find("Synthetic::NotInTheTable") == nullptr);
}

HS_TEST(verifier_accepts_a_vtable_target_whose_slot_matches)
{
	FakeResolver resolver;
	const std::uint64_t vtableRva = 0x1800;
	const std::uint64_t slot = 9;
	const std::uint64_t functionRva = 0x1000;
	resolver.ids[242891] = vtableRva;
	resolver.ids[84498] = functionRva;
	WriteQword(resolver, vtableRva + slot * 8, resolver.base + functionRva);
	for (std::size_t i = 0; i < 32; ++i) {
		resolver.bytes[functionRva + i] = static_cast<std::uint8_t>(0x90 + i);
	}

	const auto record = MakeVtableRecord(resolver, 242891, vtableRva, slot, 84498, functionRva);
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kVerified);
	HS_CHECK_EQ(check.vtableRva, vtableRva);
	HS_CHECK_EQ(check.actualTargetVa, resolver.base + functionRva);
}

HS_TEST(verifier_rejects_a_vtable_target_whose_slot_moved)
{
	// This is the check that caught CommonLibSSE-NG's header comment order not
	// matching the engine's real vtable order.
	FakeResolver resolver;
	const std::uint64_t vtableRva = 0x1800;
	const std::uint64_t slot = 9;
	const std::uint64_t functionRva = 0x1000;
	resolver.ids[242891] = vtableRva;
	resolver.ids[84498] = functionRva;
	// The slot now holds a different function.
	WriteQword(resolver, vtableRva + slot * 8, resolver.base + 0x1200);
	for (std::size_t i = 0; i < 32; ++i) {
		resolver.bytes[functionRva + i] = static_cast<std::uint8_t>(0x90 + i);
	}

	const auto record = MakeVtableRecord(resolver, 242891, vtableRva, slot, 84498, functionRva);
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kVtableMismatch);
	HS_CHECK_EQ(check.actualTargetVa, resolver.base + 0x1200);
	HS_CHECK_EQ(check.expectedTargetVa, resolver.base + functionRva);
}

HS_TEST(verifier_rejects_an_unresolvable_vtable_id)
{
	FakeResolver resolver;
	const std::uint64_t functionRva = 0x1000;
	resolver.ids[84498] = functionRva;  // the vtable id is absent
	const auto record = MakeVtableRecord(resolver, 242891, 0x1800, 9, 84498, functionRva);
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kIdUnresolved);
}

HS_TEST(verifier_rejects_a_vtable_whose_rva_disagrees_with_the_table)
{
	FakeResolver resolver;
	const std::uint64_t functionRva = 0x1000;
	resolver.ids[242891] = 0x1900;  // resolves elsewhere
	resolver.ids[84498] = functionRva;
	WriteQword(resolver, 0x1900 + 9 * 8, resolver.base + functionRva);
	const auto record = MakeVtableRecord(resolver, 242891, 0x1800, 9, 84498, functionRva);
	const auto check = VerifyHookTarget(record, resolver);
	HS_CHECK(check.verdict == TargetVerdict::kAddressLibraryMismatch);
}

HS_TEST(identity_matches_only_on_all_three_cheap_fields)
{
	HookTableIdentity expected;
	expected.size = 37910440;
	expected.timeDateStamp = 1787588678;
	expected.sizeOfImage = 59936768;

	ModuleIdentity actual;
	actual.size = expected.size;
	actual.timeDateStamp = expected.timeDateStamp;
	actual.sizeOfImage = expected.sizeOfImage;
	HS_CHECK(IdentityMatches(expected, actual));

	actual.sizeOfImage += 1;
	HS_CHECK(!IdentityMatches(expected, actual));
	actual = {};
	HS_CHECK(!IdentityMatches(expected, actual));
	actual.size = expected.size;
	HS_CHECK(!IdentityMatches(expected, actual));
}

// --- health ------------------------------------------------------------------

HS_TEST(health_degrades_and_never_downgrades_a_deliberate_off)
{
	Health::Reset();
	HS_CHECK(Health::State() == ipc::HealthState::kUnknown);

	Health::SetState(ipc::HealthState::kGreen, "all hooks verified");
	HS_CHECK_EQ(std::string(Health::StateName()), std::string("GREEN"));

	Health::Degrade("hook X not verified");
	HS_CHECK(Health::State() == ipc::HealthState::kDegraded);
	HS_CHECK(Health::Line().find("DEGRADED") != std::string::npos);
	HS_CHECK(Health::Line().find("hook X not verified") != std::string::npos);

	Health::Off("all tiers disabled in the ini");
	HS_CHECK(Health::State() == ipc::HealthState::kOff);
	// A later failure must not overwrite a deliberate OFF with DEGRADED...
	Health::Degrade("hook Y not verified");
	HS_CHECK(Health::State() == ipc::HealthState::kOff);
	// ...but the reason is still recorded, so it is not silently lost.
	HS_CHECK(Health::Line().find("hook Y not verified") != std::string::npos);

	Health::Reset();
	HS_CHECK(Health::State() == ipc::HealthState::kUnknown);
}
