#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace hs
{
	inline constexpr std::size_t kMaxFrames = 24;

	struct Stack
	{
		std::uint32_t count = 0;
		void*         frames[kMaxFrames]{};
	};

	// Resolve RtlCaptureStackBackTrace once (ntdll, dynamically, so we do not
	// depend on a particular import library).
	void InitStackCapture();

	// Capture up to a_depth frames, skipping a_skip + 1 of our own.
	void CaptureStack(Stack& a_out, std::uint32_t a_skip = 0, std::uint32_t a_depth = kMaxFrames);

	// "SkyrimSE.exe+0xCF326C <- TrueHUD.dll+0x3F4E5 <- ..."
	[[nodiscard]] std::string FormatStack(const Stack& a_stack);
}
