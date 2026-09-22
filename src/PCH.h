#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#	define NOMINMAX
#endif

#include <Windows.h>
#include <TlHelp32.h>

#include <RE/Skyrim.h>
#include <SKSE/SKSE.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace logger = SKSE::log;
