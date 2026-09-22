#pragma once

#include <cstddef>
#include <cstdint>

// The hook target registry, expanded from the X-macro list in
// Hooks/HookTargets.def. That file is the single source of truth: it builds the
// enum below, the metadata table used by the installer, AND is parsed by
// tools/check-hooktable.py, which fails CI when a target has no entry in the
// committed verification table. Adding a hook without adding a verified
// signature is therefore a build error, not an act of faith.

namespace hs
{
	enum class HookKind : std::uint8_t
	{
		kRva,     // a plain (non-virtual) function, reached by its AE id
		kVtable,  // a virtual function; AE id -> function, vtable id + slot -> must match
	};

	enum class HookTargetId : std::size_t
	{
#define HOOK_TARGET(id, name, kind, se, ae, vt, slot) id,
#include "Hooks/HookTargets.def"
#undef HOOK_TARGET
		kCount,
	};

	struct HookTarget
	{
		HookTargetId  id;
		const char*   name;
		HookKind      kind;
		std::uint64_t seId;
		std::uint64_t aeId;
		std::uint64_t vtableId;
		std::uint64_t vtableSlot;
	};

	inline constexpr HookTarget kHookTargets[] = {
#define HOOK_TARGET(id, name, kind, se, ae, vt, slot) \
	{ HookTargetId::id, name, HookKind::kind, se, ae, vt, slot },
#include "Hooks/HookTargets.def"
#undef HOOK_TARGET
	};

	inline constexpr std::size_t kHookTargetCount =
		sizeof(kHookTargets) / sizeof(kHookTargets[0]);

	static_assert(kHookTargetCount == static_cast<std::size_t>(HookTargetId::kCount),
		"the HOOK_TARGET list must not have a trailing comma or a hidden entry");

	[[nodiscard]] constexpr const HookTarget& GetHookTarget(HookTargetId a_id)
	{
		return kHookTargets[static_cast<std::size_t>(a_id)];
	}
}
