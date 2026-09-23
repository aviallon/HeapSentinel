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
set_version("0.6.1")
set_languages("c++23")
set_license("MIT")

-- Build identity stamped into the DLL and printed in the reports-log session
-- header. xmake's script sandbox exposes only a small os API (os.iorunv is not
-- available), so this uses the environment rather than shelling out to git:
-- CI sets GITHUB_SHA, a developer can set HS_BUILD_ID, and a plain local build
-- honestly reports "unknown".
local build_id = os.getenv("HS_BUILD_ID")
if not build_id or build_id == "" then
    build_id = os.getenv("GITHUB_SHA")
end
if not build_id or build_id == "" then
    build_id = "unknown"
end
build_id = build_id:sub(1, 12)
add_defines("HS_BUILD_ID=\"" .. build_id .. "\"")

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

    -- Symbols are a shipped FEATURE, not debug clutter. Crash Logger resolves a
    -- frame only when HeapSentinel.pdb sits in the DLL's own directory; without
    -- it our frames appear as "HeapSentinel.dll+0x39C1B" and nobody can resolve
    -- them. set_symbols("debug") above already enables /Zi + /DEBUG; /DEBUG:FULL
    -- forces the full private symbols (not a stripped PDB), which is what lets
    -- the DIA session map an RVA to a function name and a source line. CI
    -- asserts the PDB exists, is non-empty and carries the MSF signature, and
    -- the release/FOMOD packaging places it next to the DLL.
    if is_plat("windows") then
        add_ldflags("/DEBUG:FULL", { force = true })
    end

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
