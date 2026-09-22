-- HeapSentinel - sampled guard-page + shadow-ledger memory sentinel for Skyrim.
--
-- Build system: xmake + CommonLibSSE-NG (git submodule) + MinHook (git
-- submodule), the same shape as the other local SKSE ports (CrosshairRefEventsFix,
-- SexLabpp). CommonLibSSE-NG is pinned to the revision whose include/REL/IDDB.h
-- defines Format::SSEv5, i.e. the one that can read the 1.7.104 Address Library
-- (versionlib-1-7-104-0.bin, format 5). CI asserts that before compiling.

set_xmakever("3.0.0")

includes("lib/CommonLibSSE-NG/xmake.lua")

set_project("HeapSentinel")
set_version("0.3.0")
set_languages("c++23")
set_license("MIT")

set_allowedplats("windows")
set_allowedarchs("x64")
set_defaultplat("windows")
set_defaultarchs("x64")

add_rules("mode.debug", "mode.release")
set_runtimes("MD")
set_warnings("allextra")

if is_mode("debug") then
    add_defines("DEBUG")
    set_optimize("none")
elseif is_mode("release") then
    add_defines("NDEBUG")
    set_optimize("fastest")
    set_symbols("debug")
end

target("HeapSentinel")
    add_deps("commonlibsse-ng")
    add_rules("commonlibsse-ng.plugin", {
        name = "HeapSentinel",
        author = "aviallon",
        description = "Sampled guard-page + shadow-ledger memory sentinel: detects dangling pointers, double frees and use-after-free, and fails safe instead of crashing.",
    })

    set_pcxxheader("src/PCH.h")
    add_files("src/**.cpp")
    add_headerfiles("src/**.h")
    add_includedirs("src")

    -- MinHook: function-entry detours (the SKSE trampoline only redirects an
    -- existing branch and cannot install a prologue hook with an original-call
    -- trampoline).
    add_files("lib/minhook/src/hook.c", "lib/minhook/src/buffer.c", "lib/minhook/src/trampoline.c", "lib/minhook/src/hde/hde64.c")
    add_includedirs("lib/minhook/include", "lib/minhook/src", "lib/minhook/src/hde")
    add_defines("WIN32_LEAN_AND_MEAN", "NOMINMAX")

    -- GDI/user32 for the optional report screenshot (CreateDIBSection, BitBlt,
    -- PrintWindow, GetDC/ReleaseDC, GetForegroundWindow).
    add_syslinks("gdi32", "user32")
target_end()
