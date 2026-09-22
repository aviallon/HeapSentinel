// Deliberately does not include PCH.h: tests/ compiles this file on Linux too
// (where it becomes an empty translation unit apart from the portable clock and
// name helpers), so that the off-game harness links against the same code the
// plugin does.
#ifndef HS_NO_PCH
#	include "PCH.h"
#endif

#include "Ipc/ShmSession.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <random>

#if defined(_WIN32)
#	ifndef WIN32_LEAN_AND_MEAN
#		define WIN32_LEAN_AND_MEAN
#	endif
#	ifndef NOMINMAX
#		define NOMINMAX
#	endif
#	include <Windows.h>
#endif

namespace hs::ipc
{
#if defined(_WIN32)

	std::uint64_t NowTick() noexcept
	{
		LARGE_INTEGER counter{};
		::QueryPerformanceCounter(&counter);
		return static_cast<std::uint64_t>(counter.QuadPart);
	}

	std::uint64_t TickFrequency() noexcept
	{
		static const std::uint64_t frequency = [] {
			LARGE_INTEGER value{};
			::QueryPerformanceFrequency(&value);
			return static_cast<std::uint64_t>(value.QuadPart);
		}();
		return frequency;
	}

#else

	// The off-game harness only needs a monotonic tick. Nothing in the ring
	// protocol depends on the unit, only on both sides agreeing on the scale,
	// and here both sides are threads of one process.
	std::uint64_t NowTick() noexcept
	{
		return static_cast<std::uint64_t>(
			std::chrono::duration_cast<std::chrono::nanoseconds>(
				std::chrono::steady_clock::now().time_since_epoch())
				.count());
	}

	std::uint64_t TickFrequency() noexcept
	{
		return 1000000000ull;
	}

#endif

	std::uint64_t NewSessionId() noexcept
	{
		std::random_device device;
		std::uint64_t      id = (static_cast<std::uint64_t>(device()) << 32) ^ static_cast<std::uint64_t>(device());
		id ^= NowTick();
		return id | 1ull;  // never 0, so "unset" stays distinguishable
	}

	std::string SessionName(std::uint32_t a_gamePid, std::uint64_t a_sessionId)
	{
		char buffer[80];
		std::snprintf(buffer, sizeof(buffer), "Local\\HeapSentinel-%u-%016llx",
			static_cast<unsigned>(a_gamePid),
			static_cast<unsigned long long>(a_sessionId));
		return buffer;
	}

#if defined(_WIN32)

	namespace
	{
		std::string Win32Error(const char* a_what)
		{
			return std::string(a_what) + " failed with Win32 error " + std::to_string(::GetLastError());
		}
	}

	Session::~Session()
	{
		Close();
	}

	void Session::Close()
	{
		if (_base != nullptr) {
			::UnmapViewOfFile(_base);
			_base = nullptr;
		}
		if (_mapping != nullptr) {
			::CloseHandle(static_cast<HANDLE>(_mapping));
			_mapping = nullptr;
		}
		_name.clear();
	}

	bool Session::Create(const ShmLayout& a_layout, std::uint32_t a_gamePid, std::uint32_t a_samplePrime)
	{
		Close();
		_error.clear();
		_layout = a_layout;

		for (int attempt = 0; attempt < 8; ++attempt) {
			const std::uint64_t sessionId = NewSessionId();
			const std::string   name = SessionName(a_gamePid, sessionId);

			HANDLE mapping = ::CreateFileMappingA(
				INVALID_HANDLE_VALUE,
				nullptr,
				PAGE_READWRITE,
				static_cast<DWORD>(a_layout.totalBytes >> 32),
				static_cast<DWORD>(a_layout.totalBytes & 0xFFFFFFFFull),
				name.c_str());

			if (mapping == nullptr) {
				_error = Win32Error("CreateFileMappingA");
				return false;
			}

			// Read the error immediately: MapViewOfFile would overwrite it.
			const DWORD lastError = ::GetLastError();
			if (lastError == ERROR_ALREADY_EXISTS) {
				// A stale session, or a recycled pid. Take a different id rather
				// than adopt somebody else's region, which would also mean
				// adopting their contents.
				::CloseHandle(mapping);
				continue;
			}

			auto* base = static_cast<std::uint8_t*>(::MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0));
			if (base == nullptr) {
				_error = Win32Error("MapViewOfFile");
				::CloseHandle(mapping);
				return false;
			}

			_mapping = mapping;
			_base = base;
			_name = name;

			// A page-file-backed mapping is guaranteed to be zero-filled, so
			// there is no memset of the whole region here - which matters,
			// because that region can be hundreds of megabytes.
			InitialiseSession(
				_base,
				_layout,
				sessionId,
				a_gamePid,
				static_cast<std::uint64_t>(std::time(nullptr)),
				NowTick(),
				TickFrequency(),
				a_samplePrime);
			return true;
		}

		_error = "could not create a uniquely named session after 8 attempts";
		return false;
	}

	bool Session::Attach(const std::string& a_name)
	{
		Close();
		_error.clear();

		HANDLE mapping = ::OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, a_name.c_str());
		if (mapping == nullptr) {
			_error = Win32Error("OpenFileMappingA") + " (is the game running, and was it started after the helper?)";
			return false;
		}

		// Read the header through a header-sized view first. Mapping the whole
		// region on the word of a possibly corrupt size field would let a bad
		// header decide how much address space we reserve.
		auto* probe = static_cast<std::uint8_t*>(::MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ShmHeader)));
		if (probe == nullptr) {
			_error = Win32Error("MapViewOfFile (header probe)");
			::CloseHandle(mapping);
			return false;
		}

		const auto* probeHeader = reinterpret_cast<const ShmHeader*>(probe);
		if (probeHeader->magic != kShmMagic) {
			_error = "refusing to attach: bad magic (this mapping is not a HeapSentinel session)";
			::UnmapViewOfFile(probe);
			::CloseHandle(mapping);
			return false;
		}
		if (probeHeader->layoutVersion != kShmLayoutVersion) {
			_error = "refusing to attach: layout version " + std::to_string(probeHeader->layoutVersion) +
			         ", this build speaks " + std::to_string(kShmLayoutVersion) +
			         " (plugin and helper were built from different revisions)";
			::UnmapViewOfFile(probe);
			::CloseHandle(mapping);
			return false;
		}

		const std::uint64_t slotCount = probeHeader->slotCountPerRing;
		const std::uint64_t memcacheBytes = probeHeader->memcacheBytes;
		const std::uint64_t totalBytes = probeHeader->totalSize;
		::UnmapViewOfFile(probe);

		if (slotCount == 0 || slotCount > kMaxSlotCountPerRing ||
			memcacheBytes > kMaxMemcacheBytes ||
			totalBytes < sizeof(ShmHeader) || totalBytes > kMaxTotalBytes) {
			_error = "refusing to attach: implausible geometry in the header";
			::CloseHandle(mapping);
			return false;
		}

		const ShmLayout layout = ShmLayout::Compute(slotCount, memcacheBytes);

		auto* base = static_cast<std::uint8_t*>(
			::MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, static_cast<SIZE_T>(totalBytes)));
		if (base == nullptr) {
			_error = Win32Error("MapViewOfFile");
			::CloseHandle(mapping);
			return false;
		}

		const std::string_view reason = Validate(*reinterpret_cast<const ShmHeader*>(base), layout, totalBytes);
		if (!reason.empty()) {
			_error = "refusing to attach: " + std::string(reason);
			::UnmapViewOfFile(base);
			::CloseHandle(mapping);
			return false;
		}

		_mapping = mapping;
		_base = base;
		_name = a_name;
		_layout = layout;
		return true;
	}

	std::uint32_t Session::GamePid() const noexcept
	{
		if (_base == nullptr) {
			return 0;
		}
		return HeaderAt(_base).gamePid;
	}

	void Session::SetGameState(GameState a_state) noexcept
	{
		if (_base == nullptr) {
			return;
		}
		StoreRelaxed(HeaderAt(_base).gameState, static_cast<std::uint64_t>(a_state));
	}

	void Session::Beat(GameState a_state) noexcept
	{
		if (_base == nullptr) {
			return;
		}
		auto& header = HeaderAt(_base);
		StoreRelaxed(header.gameState, static_cast<std::uint64_t>(a_state));
		StoreRelaxed(header.heartbeatTick, NowTick());
		// The sequence bump is the release that publishes the tick and state.
		StoreRelease(header.heartbeatSeq, LoadRelaxed(header.heartbeatSeq) + 1);
	}

	bool Session::HeartbeatFresh(std::uint64_t a_timeoutTicks) const noexcept
	{
		if (_base == nullptr) {
			return false;
		}
		const auto&         header = HeaderAt(_base);
		const std::uint64_t last = LoadAcquire(header.heartbeatTick);
		const std::uint64_t now = NowTick();
		if (now <= last) {
			// The clock did not advance (or the header was written by a process
			// with a different epoch). Treat as fresh rather than declare a
			// living game dead and dump a bogus post-mortem.
			return true;
		}
		return (now - last) <= a_timeoutTicks;
	}

	void Session::BeatAsHelper() noexcept
	{
		if (_base == nullptr) {
			return;
		}
		auto& header = HeaderAt(_base);
		// hostPid is a 32-bit field, so it needs the 32-bit accessor. This is
		// exactly the line GCC never compiles (the whole method is inside
		// #if defined(_WIN32)), which is why the CI matrix builds and runs the
		// suite on Windows as well as Linux.
		StoreRelaxed32(header.hostPid, static_cast<std::uint32_t>(::GetCurrentProcessId()));
		StoreRelaxed(header.helperHeartbeat, NowTick());
		StoreRelease(header.helperAttached, 1);
	}

#endif  // _WIN32
}
