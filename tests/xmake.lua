-- Off-game test harness for HeapSentinel's shared-memory IPC layer.
--
-- Deliberately a standalone xmake project rather than part of the plugin build:
-- the plugin is Windows-only, but everything under src/Ipc is plain C++ with no
-- Windows dependency, so building and RUNNING these tests on Linux as well as
-- Windows is what turns the layout static_asserts into a cross-compiler claim
-- instead of a claim about one compiler. HS_NO_PCH keeps the shared sources from
-- pulling in the plugin's precompiled header (Windows.h + CommonLibSSE-NG).

set_project("HeapSentinelTests")
set_version("0.5.0")
set_languages("c++23")
set_license("MIT")

set_allowedplats("windows", "linux", "macosx")
-- No set_allowedarchs: xmake maps x64 to x86_64 on Linux and rejects it when the
-- allowed list names the Windows spelling. The arch is irrelevant here anyway -
-- the tests only care about a 64-bit target.

add_rules("mode.debug", "mode.release")

if is_mode("debug") then
    set_optimize("none")
    set_symbols("debug")
else
    set_optimize("fastest")
    set_symbols("debug")
end

target("heapsentinel-tests")
    set_kind("binary")
    set_warnings("allextra")

    add_defines("HS_NO_PCH")

    add_files("main.cpp", "test_*.cpp")
    add_files("../src/Ipc/ShmRing.cpp", "../src/Ipc/ShmSession.cpp")
    -- The shadow ledger and the new Scaleform attribution cores are plain C++
    -- (HS_NO_PCH keeps them off Windows.h and the CommonLib precompiled header),
    -- so the poison encoding, the free-ring bound, the verdict and the
    -- non-eviction rules are exercised off-game on both platforms.
    add_files("../src/Core/ShadowLedger.cpp")
    add_files("../src/Core/BloomFilter.cpp")
    add_files("../src/Core/ScaleformFreeRing.cpp")
    add_files("../src/Core/PoisonQuarantine.cpp")
    add_files("../src/Core/WeakLibEvents.cpp")
    add_files("../src/Core/Verdict.cpp")
    -- The 0.5.0 double-free fixes: the per-thread re-entrancy guard, the
    -- alloc-side evidence formatter, the report-kind gating on allocator
    -- confidence, the stats formatter/schedule and the reports-log header build
    -- are all plain C++, so they are exercised off-game on both platforms.
    add_files("../src/Core/FreeReentrancy.cpp")
    add_files("../src/Core/FreeEvidence.cpp")
    add_files("../src/Core/AllocatorConfidence.cpp")
    add_files("../src/Core/Stats.cpp")
    add_files("../src/Core/ReportLog.cpp")
    -- The hook-target verification table parser + verifier and the plugin health
    -- state are plain C++ too, so the committed table is parsed and the verifier
    -- is exercised with synthetic bytes off-game on both platforms (and under
    -- ASan/UBSan). No game binary is involved.
    add_files("../src/Hooks/HookTable.cpp")
    add_files("../src/Hooks/HookVerifier.cpp")
    add_files("../src/Core/Health.cpp")
    -- Hardware watchpoints: the selection policy, the four-slot DR table with its
    -- bounded-claim/drop counter, and the preallocated trap report ring are plain
    -- C++ with no Windows dependency, so they run off-game on Linux AND Windows.
    -- The DR7 bit layout is header-only for the same reason.
    add_files("../src/Core/WatchpointPlan.cpp")
    add_files("../src/Core/WatchpointSlots.cpp")
    add_files("../src/Core/WatchpointReports.cpp")
    add_includedirs("..", "../src", ".")

    if is_plat("linux") or is_plat("macosx") then
        add_syslinks("pthread")
    end
    if is_plat("windows") then
        -- The one Windows-only piece: GetThreadContext/SetThreadContext. The
        -- Windows test arms a real watchpoint, writes to the watched address
        -- and asserts the trap fired with the writer's RIP.
        add_files("../src/Core/HwWatchpoint.cpp")
        add_defines("WIN32_LEAN_AND_MEAN", "NOMINMAX")
    end
target_end()
