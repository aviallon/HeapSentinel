#include "harness.h"

#include "Ipc/Sampling.h"
#include "Ipc/ShmRing.h"
#include "Ipc/ShmSession.h"

#include <string>
#include <vector>

#if defined(_WIN32)
#	ifndef WIN32_LEAN_AND_MEAN
#		define WIN32_LEAN_AND_MEAN
#	endif
#	ifndef NOMINMAX
#		define NOMINMAX
#	endif
#	include <Windows.h>
#endif

using namespace hs::ipc;

#if defined(_WIN32)

namespace
{
	constexpr std::uint64_t kTestSlotsPerRing = 256;

	[[nodiscard]] ShmLayout TestLayout()
	{
		return ShmLayout::Compute(kTestSlotsPerRing, 0);
	}

	[[nodiscard]] std::string SelfPath()
	{
		char        buffer[MAX_PATH] = {};
		const DWORD length = ::GetModuleFileNameA(nullptr, buffer, MAX_PATH);
		return std::string(buffer, length);
	}

	struct CollectState
	{
		std::vector<ShmEvent> events;
	};

	void Collect(void* a_context, std::uint32_t, const ShmEvent& a_event)
	{
		static_cast<CollectState*>(a_context)->events.push_back(a_event);
	}
}

HS_TEST(session_create_initialises_and_never_adopts_a_stale_region)
{
	Session session;
	HS_CHECK(session.Create(TestLayout(), /*gamePid*/ 12345, hs::kDefaultSamplePrime));
	HS_CHECK(session.IsOpen());
	HS_CHECK(!session.Name().empty());
	HS_CHECK_EQ(session.GamePid(), 12345u);
	HS_CHECK(session.Error().empty());

	// A freshly created region must already validate: this is the check the
	// helper performs, run here against the creator's own output.
	HS_CHECK(Validate(session.Header(), session.Layout(), session.Layout().totalBytes).empty());
	HS_CHECK_EQ(session.Header().hostPid, 0u);
	HS_CHECK_EQ(session.Header().helperAttached, 0ull);

	// A second session with the same game pid must get a different name rather
	// than silently adopting the first one's contents.
	Session other;
	HS_CHECK(other.Create(TestLayout(), /*gamePid*/ 12345, hs::kDefaultSamplePrime));
	HS_CHECK_NE(other.Name(), session.Name());
}

HS_TEST(session_attach_sees_the_same_region_in_both_directions)
{
	Session creator;
	HS_CHECK(creator.Create(TestLayout(), /*gamePid*/ 777, hs::kDefaultSamplePrime));

	Session attacher;
	HS_CHECK(attacher.Attach(creator.Name()));
	HS_CHECK(attacher.IsOpen());
	HS_CHECK_EQ(attacher.GamePid(), 777u);
	HS_CHECK_EQ(attacher.Layout().totalBytes, creator.Layout().totalBytes);

	// Game -> helper.
	creator.Beat(GameState::kRunning);
	HS_CHECK_EQ(LoadAcquire(attacher.Header().gameState), static_cast<std::uint64_t>(GameState::kRunning));
	HS_CHECK(attacher.HeartbeatFresh(MillisecondsToTicks(5000)));

	// Helper -> game.
	attacher.BeatAsHelper();
	HS_CHECK_EQ(LoadAcquire(creator.Header().helperAttached), 1ull);
	HS_CHECK_EQ(LoadAcquire(creator.Header().hostPid), static_cast<std::uint32_t>(::GetCurrentProcessId()));
}

HS_TEST(session_attach_refuses_a_mismatched_layout_version)
{
	Session creator;
	HS_CHECK(creator.Create(TestLayout(), 778, hs::kDefaultSamplePrime));

	// This is the failure that matters most: a helper built from a different
	// revision would misread every field, so it must be refused loudly.
	const std::uint32_t realVersion = creator.Header().layoutVersion;
	creator.Header().layoutVersion = realVersion + 1;

	Session attacher;
	HS_CHECK(!attacher.Attach(creator.Name()));
	HS_CHECK(attacher.Error().find("layout version") != std::string::npos);

	creator.Header().layoutVersion = realVersion;
	Session recovered;
	HS_CHECK(recovered.Attach(creator.Name()));
}

HS_TEST(session_attach_refuses_a_bad_magic_and_an_implausible_size)
{
	Session creator;
	HS_CHECK(creator.Create(TestLayout(), 779, hs::kDefaultSamplePrime));

	const std::uint64_t realMagic = creator.Header().magic;
	creator.Header().magic = 0x1234;
	{
		Session attacher;
		HS_CHECK(!attacher.Attach(creator.Name()));
		HS_CHECK(attacher.Error().find("magic") != std::string::npos);
	}
	creator.Header().magic = realMagic;

	// A corrupt size field must be rejected BEFORE any size arithmetic, so that
	// a bad header cannot decide how much address space we reserve.
	const std::uint64_t realSlots = creator.Header().slotCountPerRing;
	creator.Header().slotCountPerRing = kMaxSlotCountPerRing + 1;
	{
		Session attacher;
		HS_CHECK(!attacher.Attach(creator.Name()));
		HS_CHECK(!attacher.Error().empty());
	}
	creator.Header().slotCountPerRing = realSlots;

	// And the region must still be usable afterwards.
	Session recovered;
	HS_CHECK(recovered.Attach(creator.Name()));
}

HS_TEST(session_heartbeat_freshness_tracks_the_game)
{
	Session session;
	HS_CHECK(session.Create(TestLayout(), 780, hs::kDefaultSamplePrime));

	HS_CHECK(session.HeartbeatFresh(MillisecondsToTicks(60000)));

	// Push the recorded beat beyond the timeout: a dead or hung game must read
	// as not-fresh, which is what the helper's watchdog keys off.
	StoreRelaxed(session.Header().heartbeatTick, NowTick() - MillisecondsToTicks(60000));
	HS_CHECK(!session.HeartbeatFresh(MillisecondsToTicks(1000)));
}

// The real cross-process test: this binary re-invokes itself as the helper, so
// the mapping, the ring and the heartbeat are all exercised across a genuine
// process boundary. Nothing here is satisfied by an in-process shortcut.
HS_TEST(session_cross_process_child_produces_and_beats)
{
	Session session;
	HS_CHECK(session.Create(TestLayout(), /*gamePid*/ 4242, hs::kDefaultSamplePrime));

	const std::string commandLine = "\"" + SelfPath() + "\" --child \"" + session.Name() + "\"";
	std::vector<char> mutableCommand(commandLine.begin(), commandLine.end());
	mutableCommand.push_back('\0');

	STARTUPINFOA        startup{};
	startup.cb = sizeof(startup);
	PROCESS_INFORMATION info{};

	const BOOL created = ::CreateProcessA(
		nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info);
	HS_CHECK(created != FALSE);
	if (created == FALSE) {
		return;
	}

	::WaitForSingleObject(info.hProcess, 30000);
	DWORD exitCode = 0xFFFFFFFF;
	::GetExitCodeProcess(info.hProcess, &exitCode);
	::CloseHandle(info.hThread);
	::CloseHandle(info.hProcess);

	HS_CHECK_EQ(exitCode, 0u);

	// The child's records must be readable from this process...
	CollectState state;
	const auto   stats = DrainAll(session.Base(), session.Layout(), Collect, &state);
	HS_CHECK_EQ(stats.consumed, 100ull);
	HS_CHECK_EQ(stats.dropped, 0ull);
	HS_CHECK_EQ(state.events.size(), 100u);
	if (state.events.size() == 100u) {
		HS_CHECK_EQ(state.events.front().ptr, 0xC0FFEE0000ull);
		HS_CHECK_EQ(state.events.back().ptr, 0xC0FFEE0000ull + 99ull);
	}

	// ... and the child's liveness marker must have landed.
	HS_CHECK_EQ(LoadRelaxed(session.Header().helperAttached), 1ull);
	HS_CHECK_NE(LoadRelaxed(session.Header().hostPid), 0u);
	HS_CHECK(LoadRelaxed(session.Header().helperHeartbeat) > 0ull);
}

#endif  // _WIN32

namespace hstest
{
	int RunChild(int a_argc, char** a_argv)
	{
#if defined(_WIN32)
		if (a_argc < 3) {
			std::fprintf(stderr, "child: expected --child <session-name>\n");
			return 2;
		}

		const std::string name = a_argv[2];

		Session session;
		if (!session.Attach(name)) {
			std::fprintf(stderr, "child: attach failed: %s\n", session.Error().c_str());
			return 3;
		}

		RingProducer producer;
		if (!producer.Claim(session.Base(), session.Layout(), static_cast<std::uint64_t>(::GetCurrentThreadId()), NowTick(), 0)) {
			std::fprintf(stderr, "child: could not claim a ring\n");
			return 4;
		}

		for (std::uint64_t i = 0; i < 100; ++i) {
			ShmEvent event{};
			event.kind = static_cast<std::uint32_t>(EventKind::kAlloc);
			event.ptr = 0xC0FFEE0000ull + i;
			event.tick = NowTick();
			producer.Publish(session.Base(), session.Layout(), event);
		}

		session.BeatAsHelper();

		if (LoadRelaxed(session.Header().eventsConsumed) != 0ull) {
			// The parent must not have drained before we finished.
			std::fprintf(stderr, "child: unexpected consumer activity\n");
			return 5;
		}
		return 0;
#else
		(void)a_argc;
		(void)a_argv;
		std::fprintf(stderr, "child: cross-process sessions are Windows-only\n");
		return 2;
#endif
	}
}
