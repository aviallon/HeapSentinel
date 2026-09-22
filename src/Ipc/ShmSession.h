#pragma once

// The shared-memory session: one region per game launch, created by the plugin
// and attached by the detached helper. This header is deliberately free of
// Windows types (the mapping handle is an opaque void*) so that tests/ can
// include it on Linux; only ShmSession.cpp knows about HANDLEs.

#include "Ipc/ShmLayout.h"
#include "Ipc/ShmRing.h"

#include <cstdint>
#include <string>

namespace hs::ipc
{
	// Geometry. 64 Ki records per ring at 72 bytes per slot is ~4.5 MiB per
	// ring, so the full 64-ring registry is ~288 MiB of hot window - which is
	// the number the health line has to keep visible, because the *time* window
	// it buys depends entirely on how fast the game allocates.
	inline constexpr std::uint64_t kDefaultSlotCountPerRing = 65536;
	inline constexpr std::uint64_t kDefaultMemcacheBytes = 0;  // reserved; Phase C sizes it

	// Guards against a corrupted or hostile header before any size arithmetic.
	inline constexpr std::uint64_t kMaxSlotCountPerRing = 1ull << 24;
	inline constexpr std::uint64_t kMaxMemcacheBytes = 1ull << 40;
	inline constexpr std::uint64_t kMaxTotalBytes = 1ull << 36;  // 64 GiB

	// Monotonic tick, machine-wide (QPC on Windows) so that both processes
	// compare the same clock without any IPC.
	[[nodiscard]] std::uint64_t NowTick() noexcept;
	[[nodiscard]] std::uint64_t TickFrequency() noexcept;

	// A session name is unique per game process *and* per launch, so a mapping
	// left behind by an earlier run can never be mistaken for this one.
	[[nodiscard]] std::string SessionName(std::uint32_t a_gamePid, std::uint64_t a_sessionId);
	[[nodiscard]] std::uint64_t NewSessionId() noexcept;

	// Converts a duration to ticks, for the staleness and heartbeat timeouts.
	[[nodiscard]] inline std::uint64_t MillisecondsToTicks(std::uint64_t a_millis) noexcept
	{
		const std::uint64_t frequency = TickFrequency();
		return frequency == 0 ? 0 : (frequency * a_millis) / 1000u;
	}

	class Session
	{
	public:
		Session() = default;
		~Session();
		Session(const Session&) = delete;
		Session& operator=(const Session&) = delete;

		// Creates a fresh, zero-filled region and initialises the header. If the
		// name is already taken (a stale session, or a reused pid) it retries
		// with a new session id instead of attaching to a stranger's region.
		[[nodiscard]] bool Create(const ShmLayout& a_layout, std::uint32_t a_gamePid, std::uint32_t a_samplePrime);

		// Attaches to an existing region and validates it. On failure `Error()`
		// explains why, and the caller must refuse to run rather than guess:
		// a helper built against a different layout would misread every field.
		[[nodiscard]] bool Attach(const std::string& a_name);

		void Close();

		[[nodiscard]] bool              IsOpen() const noexcept { return _base != nullptr; }
		[[nodiscard]] void*             Base() const noexcept { return _base; }
		[[nodiscard]] ShmHeader&        Header() const noexcept { return HeaderAt(_base); }
		[[nodiscard]] const ShmLayout&  Layout() const noexcept { return _layout; }
		[[nodiscard]] const std::string& Name() const noexcept { return _name; }
		[[nodiscard]] const std::string& Error() const noexcept { return _error; }
		[[nodiscard]] std::uint32_t     GamePid() const noexcept;

		// Game side: refreshes the heartbeat and publishes the run state.
		void Beat(GameState a_state) noexcept;

		// Either side: publishes the run state without claiming liveness.
		void SetGameState(GameState a_state) noexcept;

		// Helper side: true when the game beat recently enough to be alive. A
		// hang (still running, no beats) and a crash (gone) are distinguished by
		// the caller, which also holds the process handle.
		[[nodiscard]] bool HeartbeatFresh(std::uint64_t a_timeoutTicks) const noexcept;

		// Helper side: marks itself present and beating, so the game's own log
		// can say whether anyone is actually consuming its records.
		void BeatAsHelper() noexcept;

	private:
		void*       _base = nullptr;     // mapped view (opaque HANDLE in the .cpp)
		void*       _mapping = nullptr;  // mapping handle
		ShmLayout   _layout{};
		std::string _name;
		std::string _error;
	};
}
