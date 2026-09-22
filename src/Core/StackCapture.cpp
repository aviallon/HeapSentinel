#include "PCH.h"

#include "Core/StackCapture.h"
#include "Core/ModuleMap.h"

namespace hs
{
	namespace
	{
		using CaptureFn = USHORT(WINAPI*)(ULONG, ULONG, PVOID*, PULONG);

		CaptureFn g_capture = nullptr;

		[[nodiscard]] CaptureFn ResolveCapture()
		{
			const auto ntdll = ::GetModuleHandleA("ntdll.dll");
			if (!ntdll) {
				return nullptr;
			}
			return reinterpret_cast<CaptureFn>(::GetProcAddress(ntdll, "RtlCaptureStackBackTrace"));
		}
	}

	void InitStackCapture()
	{
		g_capture = ResolveCapture();
		if (!g_capture) {
			logger::warn("RtlCaptureStackBackTrace not found - stack capture disabled");
		}
	}

	void CaptureStack(Stack& a_out, std::uint32_t a_skip, std::uint32_t a_depth)
	{
		a_out.count = 0;
		if (!g_capture || a_depth == 0) {
			return;
		}
		if (a_depth > kMaxFrames) {
			a_depth = kMaxFrames;
		}

		ULONG hash = 0;
		const auto n = g_capture(a_skip + 1, a_depth, a_out.frames, &hash);
		a_out.count = n;
	}

	std::string FormatStack(const Stack& a_stack)
	{
		std::string result;
		for (std::uint32_t i = 0; i < a_stack.count; ++i) {
			if (i != 0) {
				result += " <- ";
			}
			result += ModuleMap::Get().Describe(reinterpret_cast<std::uintptr_t>(a_stack.frames[i]));
		}
		return result;
	}
}
