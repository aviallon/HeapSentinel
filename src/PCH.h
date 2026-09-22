#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#	define NOMINMAX
#endif

// CommonLibSSE-NG first. REX/W32/BASE.h detects an already-included
// <Windows.h> and refuses to build ("Please move any Windows API includes
// after CommonLib"), so the Windows headers below come after it.
#include <RE/Skyrim.h>
#include <SKSE/SKSE.h>

#include <Windows.h>
#include <TlHelp32.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace logger = SKSE::log;
