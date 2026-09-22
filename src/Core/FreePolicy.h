#pragma once

namespace hs
{
	// What a free hook does when a free is suspected to be a second free.
	//
	// SAFETY-FIRST DEFAULT. A diagnostic must never alter the thing it observes.
	// The v0.3.0 double-free path reported and then returned WITHOUT calling the
	// original, which turns a false positive into a leak and changes the game's
	// allocator behaviour. `callOriginal` is therefore true by default.
	//
	// `a_prevent` is the explicit opt-in (Config::preventDoubleFree, default
	// false): skip the original so a suspected second free cannot reach the
	// allocator at all. A user who prefers "leak rather than risk a corrupting
	// real double free" can set it, but it is documented as a behaviour change.
	struct DoubleFreeAction
	{
		bool report = true;
		bool callOriginal = true;
	};

	[[nodiscard]] constexpr DoubleFreeAction DecideDoubleFree(bool a_prevent) noexcept
	{
		return DoubleFreeAction{ true, !a_prevent };
	}

	// The poison-on-free path deliberately WITHHOLDS the original free (that is
	// the mechanism: the block is kept pointed at a poison address so a later
	// use-after-free faults deterministically). It is a behaviour change, so it
	// is opt-in (Config::scaleformPoisonEnabled default false). This constant
	// exists so the intent is one place and a test can pin it.
	inline constexpr bool kPoisonWithholdsOriginalFree = true;
}