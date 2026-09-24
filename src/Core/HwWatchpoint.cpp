#if defined(HS_NO_PCH)
#	include "Core/HwWatchpoint.h"

#	include <TlHelp32.h>
#else
#	include "PCH.h"

#	include "Core/HwWatchpoint.h"
#endif

namespace hs::hw
{
	namespace
	{
		[[nodiscard]] bool ApplyDebugState(HANDLE a_thread, const ThreadDebugState& a_state)
		{
			CONTEXT context{};
			context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (!::GetThreadContext(a_thread, &context)) {
				return false;
			}
			context.Dr0 = a_state.dr0;
			context.Dr1 = a_state.dr1;
			context.Dr2 = a_state.dr2;
			context.Dr3 = a_state.dr3;
			context.Dr6 = a_state.dr6;
			context.Dr7 = a_state.dr7;
			return ::SetThreadContext(a_thread, &context) != FALSE;
		}

		[[nodiscard]] ThreadDebugState StateFor(const std::uintptr_t a_addresses[kWatchpointSlotCount], std::size_t a_count,
			std::uint64_t& a_outDr7)
		{
			std::uintptr_t padded[kWatchpointSlotCount]{};
			for (std::size_t i = 0; i < a_count && i < kWatchpointSlotCount; ++i) {
				padded[i] = a_addresses[i];
			}

			ThreadDebugState state;
			state.dr0 = padded[0];
			state.dr1 = padded[1];
			state.dr2 = padded[2];
			state.dr3 = padded[3];
			state.dr6 = 0;
			state.dr7 = BuildDr7(padded, kWatchpointSlotCount);
			a_outDr7 = state.dr7;
			return state;
		}
	}

	bool ArmCurrentThread(const std::uintptr_t a_addresses[kWatchpointSlotCount], std::size_t a_count,
		std::uint64_t& a_outDr7, ThreadDebugState* a_outState)
	{
		const auto state = StateFor(a_addresses, a_count, a_outDr7);
		if (!ApplyDebugState(::GetCurrentThread(), state)) {
			return false;
		}
		if (a_outState) {
			*a_outState = state;
		}
		return true;
	}

	bool DisarmCurrentThread()
	{
		ThreadDebugState state;  // all zero
		return ApplyDebugState(::GetCurrentThread(), state);
	}

	bool ReadCurrentThread(ThreadDebugState& a_out, std::uint32_t* a_outError)
	{
	// MUTATION M6 (temporary): the explicit read never succeeds, so the trap
	// path falls back to the exception context only -- the 0.6.3 state.
	(void)a_out;
	if (a_outError) {
		*a_outError = 87u;
	}
	return false;
	}

	bool ReadThread(HANDLE a_thread, ThreadDebugState& a_out)
	{
		CONTEXT context{};
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!::GetThreadContext(a_thread, &context)) {
			return false;
		}
		a_out.dr0 = context.Dr0;
		a_out.dr1 = context.Dr1;
		a_out.dr2 = context.Dr2;
		a_out.dr3 = context.Dr3;
		a_out.dr6 = context.Dr6;
		a_out.dr7 = context.Dr7;
		return true;
	}

	bool ArmThread(HANDLE a_thread, const std::uintptr_t a_addresses[kWatchpointSlotCount], std::size_t a_count,
		std::uint64_t& a_outDr7, ThreadDebugState* a_outState)
	{
		const auto state = StateFor(a_addresses, a_count, a_outDr7);

		// Suspend so the write is not racing the thread's own context switches.
		const DWORD previousSuspend = ::SuspendThread(a_thread);
		if (previousSuspend == static_cast<DWORD>(-1)) {
			return false;
		}

		const bool ok = ApplyDebugState(a_thread, state);

		::ResumeThread(a_thread);
		if (ok && a_outState) {
			*a_outState = state;
		}
		return ok;
	}

	bool DisarmThread(HANDLE a_thread)
	{
		const DWORD previousSuspend = ::SuspendThread(a_thread);
		if (previousSuspend == static_cast<DWORD>(-1)) {
			return false;
		}
		ThreadDebugState state;  // all zero
		const bool     ok = ApplyDebugState(a_thread, state);
		::ResumeThread(a_thread);
		return ok;
	}

	std::size_t EnumerateProcessThreads(std::uint32_t* a_out, std::size_t a_capacity, std::uint32_t a_skipTid,
		std::size_t* a_outTotal)
	{
		if (a_outTotal) {
			*a_outTotal = 0;
		}

		const auto snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return 0;
		}

		const auto selfPid = ::GetCurrentProcessId();
		THREADENTRY32 entry{};
		entry.dwSize = sizeof(entry);

		std::size_t copied = 0;
		std::size_t total = 0;
		if (::Thread32First(snapshot, &entry)) {
			do {
				if (entry.dwSize < FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(entry.th32OwnerProcessID)) {
					continue;
				}
				if (entry.th32OwnerProcessID != selfPid) {
					continue;
				}
				++total;
				if (entry.th32ThreadID == a_skipTid) {
					continue;
				}
				if (copied >= a_capacity) {
					continue;  // bounded: keep counting, stop copying
				}
				a_out[copied++] = entry.th32ThreadID;
			} while (::Thread32Next(snapshot, &entry));
		}
		::CloseHandle(snapshot);

		if (a_outTotal) {
			*a_outTotal = total;
		}
		return copied;
	}

	bool VerifyAllThreadsDisarmed(std::size_t* a_outChecked, std::size_t* a_outStillArmed)
	{
		constexpr std::size_t kMaxThreads = 4096;
		static std::uint32_t  tids[kMaxThreads];

		const auto selfTid = ::GetCurrentThreadId();
		const auto count = EnumerateProcessThreads(tids, kMaxThreads, 0, nullptr);

		std::size_t checked = 1;  // this thread is always checked directly
		std::size_t armed = 0;

		ThreadDebugState selfState;
		if (ReadThread(::GetCurrentThread(), selfState) && selfState.dr7 != 0) {
			++armed;
		}

		for (std::size_t i = 0; i < count; ++i) {
			if (tids[i] == selfTid) {
				continue;
			}
			const auto thread = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tids[i]);
			if (!thread) {
				continue;
			}
			ThreadDebugState state;
			// A thread that exits between enumeration and here is simply skipped:
			// the claim is "no thread we could inspect is armed".
			if (ReadThread(thread, state)) {
				++checked;
				if (state.dr7 != 0) {
					++armed;
				}
			}
			::CloseHandle(thread);
		}

		if (a_outChecked) {
			*a_outChecked = checked;
		}
		if (a_outStillArmed) {
			*a_outStillArmed = armed;
		}
		return armed == 0;
	}
}