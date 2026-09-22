# HeapSentinel

An SKSE plugin that **retrofits a memory sentinel onto a running Skyrim SE/AE
process**. It watches the allocators the engine and Scaleform actually use,
detects the classes of dangling-reference bug that crash modded installs, fails
safe where it can instead of dying, and writes a report a human can act on
without a debugger.

It exists because of a real bug: a one-line ActionScript mistake in TrueHUD
(`var iconLoader = …` shadowing the member, plus never unloading the Skyrim UI
icon SWF) produced a Scaleform use-after-free that surfaced 50 minutes later as

```
SkyrimSE.exe+0CF326C  jmp [rax]        ; GRefCountImpl::Release
Access Violation: read at 0xFFFFFFFFFFFFFFFF
```

with a stack-scan pile and no allocator provenance. HeapSentinel is the tool
that should have turned that into a one-line report naming the freed movie
definition and both stacks.

**Read [`RESEARCH.md`](RESEARCH.md) for the state of the art and what actually
transfers to a closed binary, and [`DESIGN.md`](DESIGN.md) for the
architecture.** The short version: you cannot build AddressSanitizer for a game
you cannot recompile, but you *can* build a shadow allocation ledger, a
GWP-ASan-style sampled guarded pool, and a refcount/vtable guard — and the last
one alone catches the crash above.

## What it does

| Tier | Mechanism | Detects | Default |
|---|---|---|---|
| A | Shadow ledger on `MemoryManager::Allocate/Deallocate/Reallocate` | double free, invalid free, sized-dealloc mismatch, provenance | on |
| A | Vtable guard on `GRefCountImpl::Release` | release through a dead/corrupt vtable — **with optional fail-safe** | on |
| B | GWP-ASan-style sampled guarded pool | use-after-free and buffer overflow, deterministically, for sampled allocations | **off** (opt-in) |
| — | Vectored exception handler | classifies any access violation; fixes up only faults in our own guarded pool | on |

Reports include the kind, the faulting/object address classified
(module+offset / guarded slot / ledger-known-freed / poison / unmapped), the
pre-crash stack, the alloc and free stacks, the object bytes, and optionally a
screenshot and a freeze.

## Status

**v0.5 — double-free reporting is honest and non-perturbing.** A suspected
double free is reported and the original free is still called (the old
behaviour skipped it and turned false positives into leaks); a per-thread,
allocation-free re-entrancy guard stops one logical free being counted twice
when two of our hooks observe it; every double-free report carries the
allocation site/epoch/stack/flags and which hook family saw each free; and a
report is emitted as `double-free-unverified` rather than `double-free` when the
MemoryManager target is not the verified game function (e.g. replaced by
EngineFixes). Poison-on-free now defaults off. Stats are emitted at data-load
and on the first report, and the reports log is appended and rotated instead of
truncated. Hooking the tbbmalloc choke point is designed but deferred (it is a
mod-DLL target; see `DESIGN.md` §3.4).

**v0.4 — committed hook-target verification.** Before installing each hook the
plugin checks the running binary's identity, the Address Library id, the vtable
slot for virtual targets and a hash of the function's first bytes against a
table committed per exact game build (`hooks/`); a mismatch refuses that hook and
reports `DEGRADED` instead of patching an address it cannot name. The
verification logic and the committed table are unit-tested off-game and checked
in CI; the plugin itself is still **not** verified in game. See `DESIGN.md` §3.3
and §11 for the roadmap.

## Build

```
git clone --recursive https://github.com/aviallon/HeapSentinel
cd HeapSentinel
xmake f -p windows -a x64 -m release -y
xmake build HeapSentinel
```

Dependencies are pinned as git submodules:

- **CommonLibSSE-NG** (`alandtse/CommonLibVR`, branch `ng`) pinned to the
  revision whose `include/REL/IDDB.h` defines `Format::SSEv5`, i.e. the one
  that can read the 1.7.104 Address Library (`versionlib-1-7-104-0.bin`,
  format 5). CI asserts that before compiling.
- **MinHook** v1.3.4 — function-entry detours. The SKSE trampoline cannot
  install a prologue hook with a call-the-original trampoline.

Portability comes from CommonLibSSE-NG: every engine target is a
`REL::RelocationID(se, ae)` pair, so SE/AE/VR selection is the library's job and
there are no hard-coded offsets. Which targets exist, and the ids, live in one
place: `src/Hooks/HookTargets.def` (an X-macro list that also drives the
committed-table completeness check in CI).

## Install

Copy `HeapSentinel.dll` to `Data/SKSE/Plugins/` and the config to
`Data/SKSE/Plugins/HeapSentinel.ini` (or install the release archive with
Amethyst / MO2 / Vortex). Logs go next to the other SKSE logs:
`HeapSentinel.log` and `HeapSentinel-reports.log`.

Start with the defaults. Turn on `[GuardPool] bEnabled=1` only when you are
hunting a specific UAF and can tolerate the opt-in risk described in
`DESIGN.md` §5.

## Layout

```
src/
  Config.{h,cpp}          INI config, plugin directory
  main.cpp                SKSE entry point
  Veh.{h,cpp}             vectored exception handler: classify + fix up
  Core/
    ModuleMap.{h,cpp}     loaded modules, executable ranges, vtable plausibility
    StackCapture.{h,cpp}  RtlCaptureStackBackTrace, module+offset formatting
    ShadowLedger.{h,cpp}  sharded lock-free ptr -> metadata table
    GuardedPool.{h,cpp}   GWP-ASan-style sampled guard-page pool
    Report.{h,cpp}        classification, loud logging, screenshot, freeze
  Hooks/
    Hooks.{h,cpp}         MinHook install + MemoryManager / GRefCountImpl thunks
    HookTargets.def       THE canonical list of hook targets (ids, kind, vtable slot)
    HookTargets.h         X-macro expansion -> enum + metadata
    HookTable.{h,cpp}     strict parser for the committed table
    HookVerifier.{h,cpp}  identity + id + vtable slot + prologue-hash check
    HookTableData.gen.h   GENERATED: the committed table embedded in the DLL
  Core/Health.{h,cpp}     GREEN / DEGRADED / OFF, with reasons
hooks/                    committed per-build verification tables (see hooks/README.md)
tools/                    gen-hooktable.py, check-hooktable.py (CI gate)
config/HeapSentinel.ini   documented defaults
```

## Licence

MIT. MinHook is BSD-2-Clause; CommonLibSSE-NG is GPL-3.0-or-later with the
Modding Exception (linked, not modified).
