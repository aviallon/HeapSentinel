# HeapSentinel — design

An SKSE plugin that retrofits a memory sentinel onto a running Skyrim SE/AE
process: it watches the allocators the engine and Scaleform actually use,
detects the classes of dangling-reference bug that crash this install, fails
safe instead of dying, and writes a loud, precise report.

Read [`RESEARCH.md`](RESEARCH.md) first — this document assumes its conclusions
(especially §7 the allocator landscape and §8 the transfer matrix).

## 1. Goals and non-goals

**Goals**

1. Detect, *before* the fault, the operations that are provably wrong:
   double free, invalid free, sized-dealloc mismatch, release of a refcounted
   object whose vtable is not a plausible vtable.
2. Detect, deterministically for a sampled subset, use-after-free and
   buffer overflow, via guard pages (GWP-ASan).
3. Fail safe where a specific operation can be refused (skip a destructor
   dispatch, refuse a double free) instead of letting the engine crash.
4. Produce a report a human can act on without a debugger: kind, address
   classification, alloc stack, free stack, fault stack, object bytes,
   optional screenshot, optional freeze.
5. Stay portable: every target is `REL::RelocationID` / `RELOCATION_ID` plus
   `RE::` types, so SE/AE/VR selection is CommonLibSSE-NG's job.

**Non-goals**

- Repairing corrupted object graphs. We can refuse an operation or leak; we
  cannot rewrite every pointer (see RESEARCH §6).
- Detecting every use-after-free. Without shadow memory or hardware tagging,
  a UAF *read* of a live-looking address is undetectable. We make it
  *probable* (sampling), *visible* (poison), or *impossible for one class*
  (refcount guard).
- Zero overhead. The dial is explicit: Tier A is cheap, Tier B is opt-in.

## 2. Architecture

```
                       ┌──────────────────────────────┐
   MinHook detours ──▶ │ Hooks/MemoryHooks            │  MemoryManager::Allocate/Deallocate/Reallocate
                       │                              │  ScrapHeap::Allocate/Deallocate
                       └──────────┬───────────────────┘
                                  │ record / look up / route
                       ┌──────────▼───────────────────┐
                       │ Core/ShadowLedger            │  ptr → {size, thread, allocSite, freeSite, flags}
                       │  sharded, lock-free, fixed   │
                       └──────────┬───────────────────┘
                                  │
              ┌───────────────────┼────────────────────┐
              ▼                   ▼                    ▼
   ┌──────────────────┐ ┌────────────────────┐ ┌────────────────────┐
   │ Core/GuardedPool │ │ Hooks/RefCountGuard│ │ Core/Report        │
   │  sampled slots,  │ │  GRefCountImpl::   │ │  classify + stacks │
   │  guard pages,    │ │  Release vtable    │ │  + screenshot +    │
   │  quarantine      │ │  validation        │ │  freeze            │
   └────────┬─────────┘ └────────────────────┘ └────────────────────┘
            │ fault
   ┌────────▼─────────┐
   │ Veh              │  AddVectoredExceptionHandler: classify any AV,
   │                  │  fix up guarded-slot faults, rate-limit reports
   └──────────────────┘
```

Everything is off/on through `HeapSentinel.ini` (see §8).

## 3. Hooks

Installed with **MinHook** (function-entry detours). The SKSE trampoline is
*not* usable here: `Trampoline::write_branch<5>` redirects an existing branch
and returns the original branch target, so it cannot install a prologue hook
with a call-the-original trampoline. MinHook handles prologue length decoding.

| Target | CommonLibSSE-NG id (SE/AE) | Purpose |
|---|---|---|
| `MemoryManager::Allocate` | 66859 / 68115 | record allocation; maybe sample into the guarded pool |
| `MemoryManager::Deallocate` | 66861 / 68117 | double/invalid-free check; route guarded blocks; poison payload |
| `MemoryManager::Reallocate` | 66860 / 68116 | route guarded blocks; update ledger |
| `ScrapHeap::Allocate` | 68144 | (optional) finer-grained coverage of the per-thread heap |
| `ScrapHeap::Deallocate` | 68146 | (optional) |
| `GRefCountImpl::Release` | 82197 | vtable validation + optional fail-safe |
| `GMemoryHeapPT::Alloc(size, align)` | AE 84498 | Scaleform/GFx allocation coverage (vtable slot 9) |
| `GMemoryHeapPT::Alloc(size)` | AE 84499 | Scaleform/GFx allocation coverage (vtable slot 0xA) |
| `GMemoryHeapPT::AllocAutoHeap(size, align)` | AE 84501 | Scaleform/GFx allocation coverage (vtable slot 0xD) |
| `GMemoryHeapPT::AllocAutoHeap(size)` | AE 84502 | Scaleform/GFx allocation coverage (vtable slot 0xE) |
| `GMemoryHeapPT::Realloc` | AE 84540 | Scaleform/GFx realloc coverage (vtable slot 0xB) |
| `GMemoryHeapPT::Free` | AE 84520 | Scaleform/GFx free coverage (vtable slot 0xC) + poison-on-free |
| `GFxResource::AddRef` | AE 82783 | WeakLib context: AddRef observed on a live resource |
| `GFxResourceWeakLib::PinResource` | AE 82796 | WeakLib context: resource pinned |
| `GFxResourceWeakLib::RemoveResourceOnRelease` | AE 82798 | WeakLib context: deregistered from the weak lib |
| `GFxResourceWeakLib::UnpinResource` | AE 82802 | WeakLib context: resource unpinned |

`GRefCountImpl::AddRef` (82195) is included only as an optional counter if it
turns out not to be inlined at the call sites we care about; most AddRefs are
inlined and cannot be intercepted without patching every site.

MinHook is the v0.1 choice because it is the lightest dependency, but it is the
weakest link: its HDE64 disassembler is **length-only** and it does not
advertise general RIP-relative relocation of the prologue bytes it copies into
the trampoline (RESEARCH §5). The upgrade path is **SafetyHook**, which
suspends the other threads, fixes their IPs, relocates RIP-relative
displacements and widens short branches. Until then, each target's prologue
should be verified before installing rather than trusting the Address Library
blindly. The SKSE trampoline is deliberately not used: it is a branch writer,
not a prologue relocator.

These ids are not guesses. EngineFixes has shipped hooks on exactly these
functions for years (`MemoryManager` 66859/68115 etc., `ScrapHeap`
66882–66885, the Scaleform heap-init call site 80300/82323 + 0xED/0x16C), which
is independent evidence that the chokepoints are real and hookable
(RESEARCH §10).

### 3.1 Why `MemoryManager` is the primary chokepoint

It is the facade every engine allocation goes through, and its prologue reads
`gs:0x58` (the TEB TLS array), so the per-thread scrap-heap path is largely
lock-free. Hooking it gives near-complete coverage of *engine* objects.
Coverage gaps (Scaleform, plugin CRTs, Havok, direct `VirtualAlloc`) are
documented in RESEARCH §7.3 and addressed by the Scaleform hooks.

### 3.2 `GRefCountImpl::Release` guard

```asm
140cf3250  mov eax,-1
140cf3255  lock xadd [rcx+8],eax     ; refcount--
140cf325a  cmp eax,1
140cf325f  test rcx,rcx
140cf3264  mov rax,[rcx]             ; vtable
140cf326c  jmp [rax]                 ; <-- the TrueHUD crash
```

The thunk runs *before* the decrement and validates:

1. `rcx` is non-null and plausibly a heap pointer;
2. `[rcx]` is 8-byte aligned and inside a loaded image (`ModuleMap::Contains`);
3. `[[rcx]]` (the first vtable slot) is inside an **executable** section.

If all hold → call the original. If not:
- log a full report (object address, "vtable", first slot, module+offset,
  the caller's stack);
- with `bFailSafe=1`, **return without calling the original**. The refcount is
  not decremented, the object leaks, and the crash does not happen.

The check is exactly `IsPlausibleVTable()` in `Core/ModuleMap.h`. For the
observed crash it fails at step 2 (`0x141A2E20C` is not 8-byte aligned).

## 4. Shadow ledger

The ledger maps `ptr → AllocationInfo` and is **lock-free by construction**
(0.3.0). Every entry carries a seqlock word — the same
`VersionFor`/`SeqOfVersion`/`VersionIsWriting` encoding used by
`src/Ipc/ShmLayout.h` and `src/Ipc/ShmRing.cpp`: bit 0 set while a writer owns
the entry, the rest a monotone sequence. A writer CASes an even version to odd,
mutates the payload, then release-publishes version + 2. A reader loads the
version, skips an odd entry, copies the payload, re-loads the version and
rejects the copy if it changed. A torn read therefore yields *unknown*, never a
wrong record. There is **no spinlock** anywhere on the read path, so the VEH can
read provenance from inside the exception handler without any risk of
deadlocking on a lock the faulting thread holds.

Writers are bounded and fail open: a 16-attempt pause-separated CAS claim, then
the record is *dropped and counted* (`WriterDrops`, surfaced as `writer drops`
in the 60 s stats line). Userspace has no preemption-disabled guarantee, so an
unbounded spin here could burn a whole scheduling quantum — worse under Wine,
where `sched_yield` does not reliably let the holder run, and across the two
NUMA nodes of a 5950X. The per-thread lock-free ring design in
`plans/heapsentinel-long-session-architecture-2026-09-22` deletes the shared
table entirely; until then, dropping a record is honest and stalling the game is
not.

The one exclusive lock left in the plugin is `GuardedPool`'s, now an `SRWLOCK`
(futex-backed under Wine, so a preempted holder parks its waiters).
`GuardedPool::OnFault` takes no lock at all.

```cpp
struct AllocationInfo {
    std::uintptr_t ptr;             // key
    std::size_t    size;
    std::uint32_t  threadId;
    std::uint32_t  flags;           // live | sampled | freed | scaleform | poisoned
    void*          allocSite;       // return address of the hook
    void*          freeSite;
    std::uint32_t  allocStack;      // index into the stack ring (0 = none)
    std::uint32_t  freeStack;
    // 0.3.0 attribution fields
    std::uintptr_t vtableAtAlloc;   // first qword the instant alloc returned
    std::uintptr_t vtableAtFree;    // first qword just before poison/free (the real one)
    std::uintptr_t lastKnownVtable; // last plausible vtable seen on a LIVE resource
    std::uint64_t  allocTick;
    std::uint64_t  freeTick;
    std::uint32_t  poisonIndex;     // 1-based quarantine slot, 0 = none
};
```

`vtableAtAlloc` is read at hook time, but the block is **pre-construction** then
(a constructor sets the vtable afterwards), so it is often garbage and the
verdict never rests on it alone. `vtableAtFree` is the meaningful "was the
object healthy when it died" value, and `lastKnownVtable` is a bonus signal
refreshed by the WeakLib hooks.

- **Sharded open addressing**, `uShards` independent tables, linear probing,
  empty key `0`, tombstone `1`, bounded probe window 64. No allocation after
  `Init()`. Effective memory is ~112 bytes per entry plus the stack ring; at the
  shipped 4 M capacity that is ~460 MiB, at the deployed 1 M it is ~115 MiB.
- **Fail open**: if the table is full or uninitialised, the hook passes
  through untouched. A sentinel that breaks the game is worse than no sentinel.
- **Stack ring**: a fixed ring of captured stacks (`Core/StackCapture`), indexed
  by `allocStack`/`freeStack`. Depth is configurable (default 12 frames);
  `0` disables stack capture and keeps only the immediate return address.
- **Eviction**: the oldest *freed* entry is reused when the probe window is full
  (bounded quarantine); when there is no freed entry the insert fails open and
  `InsertFailures` rises.

### 4.1 Durable Scaleform free records (`Core/ScaleformFreeRing`)

A delayed use-after-free can outlive the main table's eviction. Scaleform free
provenance therefore lives in a **dedicated** fixed ring, separate from the
ledger so engine allocations keep flowing: `uFreeRingCapacity` records
(default 1 M, ~64 MiB), evict-oldest-when-full, lock-free lookup by pointer.
Evictions and the effective retention window (oldest→newest free tick, in
seconds) are logged every 60 s, so attribution degrades *legibly* rather than
saturating the main table.

### 4.2 Poison-on-free quarantine (`Core/PoisonQuarantine`)

On `GMemoryHeapPT::Free(p)` of a tracked block the plugin:

1. records the free (stacks, tick, vtable-at-free) in the free ring;
2. claims a quarantine slot and overwrites `p[0]` (the vtable pointer) with a
   **poison address**;
3. **withholds the real free** until the budget is reached.

Any later virtual call through the dead object reads the poison and faults.
The poison is an address in a dedicated region reserved with
`VirtualAlloc(MEM_RESERVE, PAGE_NOACCESS)` and never committed, one page per
slot:

```
poison(i) = base + (i - 1) * 0x1000
index     = (fault - base) / 0x1000 + 1
```

Any vtable-slot offset below 4 KiB decodes to the same record, and the region is
pure address space (no RAM until a block is withheld). The VEH decodes the
fault, reads the quarantined record, and reports the alloc stack **and** the
free stack deterministically. Bounds: `uPoisonMaxBlocks` (default 65536) and
`uPoisonMaxBytes` (default 64 MiB retained); at the budget the oldest block is
really freed. Fail-open everywhere: not ready, poison disabled, or over budget
calls the original immediately. Poison is the deterministic **fast path** for
recent frees; the free ring is the general attribution for older ones.

Residual hazard, stated plainly: the deferred free stores the heap
(`GMemoryHeapPT this`) pointer and validates it with `VirtualQuery` plus a
first-qword plausibility check before calling back into it. That proves the page
is committed and the first qword looks like a vtable, **not** that it is the
same heap object; a heap destroyed inside the retention window would be refused
(block leaked) rather than called.

Ledger operations used by the hooks:

| Event | Check | Action |
|---|---|---|
| Allocate | — | insert `{size, live}` |
| Deallocate, not tracked | not in ledger, not in any heap | report **invalid free** |
| Deallocate, tracked, already freed | flags has `freed` | report **double free**, do not call original (fail safe) |
| Deallocate, tracked, live | size mismatch vs `a_size` (if provided) | report **sized-dealloc mismatch**, continue |
| Deallocate, tracked, live | — | mark freed, record `freeSite`, call original |
| Reallocate, guarded | in guarded region | allocate new slot, copy, free old |

## 5. Guarded pool (GWP-ASan, Tier B)

`Core/GuardedPool` implements the sampled detector directly, because no
existing implementation can be dropped into a running game.

- Reserve one region with `VirtualAlloc(MEM_RESERVE, PAGE_NOACCESS)`, carved
  into `uSlots` slots. Each slot is `[guard page][data pages][guard page]`.
- `ShouldSample()` is a fast counter/PRNG check against `uSampleRate` (default
  1 in 2000) and a size filter (`uMaxSize`, default 3 KiB — one data page
  handles it).
- `Allocate(size, alignment)` picks a free slot, commits the data pages
  `PAGE_READWRITE`, chooses the user pointer **left- or right-aligned at
  random**, and records the slot metadata plus the alloc stack in the ledger.
- `IsOurs(ptr)` is a cheap range test, so the `Deallocate`/`Reallocate` hooks
  can route our blocks away from the engine's allocator.
- `Deallocate(ptr)` `VirtualProtect`s the data pages to `PAGE_NOACCESS`, records
  the free stack, and moves the slot to a small FIFO quarantine. Any later
  access faults — that is the detection.
- The **VEH** recognises a fault inside the region, reports the access plus the
  alloc and free stacks, and (with `bFixUp=1`) re-protects the page and returns
  `EXCEPTION_CONTINUE_EXECUTION`, so the game survives the bug it just made.

The risk that makes this opt-in is explicit: a sampled block was never
returned by any of the engine's heaps, so the engine must never call
`ContainsBlockImpl`/`Size` on it. We intercept the free/realloc path, but any
engine code that inspects a heap directly would be surprised. Hence default
`bEnabled=0`, a low sample rate, and a size cap.

Sizing follows Chromium's production numbers (RESEARCH §3.1): ~400 bytes of
metadata per slot against 4 KB per allocation; 1/1000 sampling with 16 slots
exhausts on long-lived allocations while 1/8000 with 64 slots samples a whole
process lifetime; and up to a 5 % regression from the instrumentation alone,
however low the rate. The defaults above (64 slots, 1/2000, one data page)
sit inside that envelope. Like Chromium, the region should be reserved at a
high address so a wild pointer is unlikely to land in it by accident, and
left/right alignment is randomized so under- and overflows are equally likely
to hit a guard page.

## 6. Reporting

`Core/Report` is the product. A report contains:

- **kind**: double free / invalid free / sized-dealloc mismatch / bad vtable
  release / guarded-slot UAF / guarded-slot overflow / unclassified AV;
- **address classification** of the faulting or object address:
  `module+offset`, `guarded slot N (freed at T, allocated at T)`,
  `ledger-known (freed at T)`, `poison pattern`, `unknown/unmapped`;
- **ledger provenance** of the fault address and the `rcx`/`rax`/`rdx`/`rbx`
  registers (the object behind an indirect call is usually in `rcx`): whether
  the block is live or freed, which allocator produced it (engine / Scaleform /
  guarded pool), the alloc and free sites (as `module+0xOFFSET`, with a hint to
  resolve against the module's shipped PDB), the vtable at alloc vs at free vs
  current, whether the current first qword is our poison, the pin/remove/AddRef
  history from the WeakLib hooks, and the alloc and free stacks; then a single
  `VERDICT:` line. This is what names the mod that freed a stale `GFxResource`
  when the fault itself cannot. The verdict distinguishes a **use-after-free**
  (freed; poison intact = deterministic; or healthy-at-free) from a **stray
  WRITE into a LIVE object** (still allocated, but its first qword is no longer
  code) — two different investigations. If no tracked object is among the
  registers, the verdict says so explicitly rather than printing nothing.
- the **pre-crash stack** captured at the hook (the culprit's stack, not the
  victim's);
- **alloc stack** and **free stack** from the ledger/guard pool;
- **object bytes** (the first N bytes, so a garbage vtable is visible);
- the **register state** if the report came from the VEH;
- optional **screenshot**: hook the D3D11 swapchain `Present`, keep the last
  frame in a staging texture, WIC-encode a PNG. GDI `PrintWindow`/`BitBlt` is
  the fallback and is often black for a DXGI flip-model window.
- optional **freeze**: a modal dialog instead of continuing, so the user can
  attach a debugger or take their own screenshot.

Reports go to `HeapSentinel.log` (spdlog, next to the other SKSE logs) and to a
dedicated `HeapSentinel-reports.log`. Rate limiting (`uMaxReportsPerSecond`,
default 20) prevents a fault storm from hanging the game.

Known hazard, on the roadmap: the VEH runs on the faulting thread inside a
corrupt process, and Microsoft's guidance is that a vectored handler "should
not call functions that acquire synchronization objects or allocate memory".
**The ledger, free-ring, quarantine and WeakLib-event reads are now fully
lock-free (seqlocks), so the handler no longer takes a ledger lock.** The one
reader-side lock still taken while building a report is `ModuleMap`'s
futex-backed `std::shared_mutex`, needed only to turn an address into
`module+offset`; it is pre-existing and not a spinlock. `Report` still builds
`std::string`s and writes through spdlog, i.e. it allocates. The fix is a
preallocated report ring buffer that the handler fills and a watchdog thread
drains (RESEARCH §8).

## 7. Exception handling

`Veh` installs an `AddVectoredExceptionHandler(1, …)` (first handler, so it
runs before Crash Logger SSE) that:

- ignores everything except `EXCEPTION_ACCESS_VIOLATION` and
  `EXCEPTION_IN_PAGE_ERROR`;
- classifies the fault address;
- if it is a guarded slot → report + optional fix-up + continue;
- otherwise → report (if `bVeh`) and return `EXCEPTION_CONTINUE_SEARCH`, so
  Crash Logger SSE still produces its own log and the game still dies the way
  it always did. **We never swallow an unknown crash.**

## 8. Configuration (`Data/SKSE/Plugins/HeapSentinel.ini`)

```ini
[General]
bEnabled=1

[Ledger]
bEnabled=1
uCapacity=4194304      ; 4M entries (~112 bytes each, plus the stack ring)
uShards=64
uStackDepth=12

[GuardPool]
bEnabled=0            ; opt-in: sampled blocks are foreign to the engine
uSampleRate=2000
uSlots=64
uMaxSize=3072
bFixUp=1

[RefCountGuard]
bEnabled=1
bFailSafe=0           ; 1 = skip the dispatch and leak instead of crashing

[ScaleformHeap]
bEnabled=1
bCaptureStacks=1      ; free stacks are what name the culprit
bPoisonOnFree=1       ; poison the first qword + withhold the real free briefly
uPoisonMaxBlocks=65536
uPoisonMaxBytes=67108864   ; 64 MiB retained
uFreeRingCapacity=1048576  ; durable free records, evict-oldest

[WeakLib]
bEnabled=1            ; PinResource / RemoveResourceOnRelease / Unpin / AddRef
uEventCapacity=16384

[Reporting]
bScreenshot=0
bFreeze=0
bVeh=1
bReportUntrackedFree=0
bSymbolHint=1
uMaxReportsPerSecond=20
```

## 9. Performance budget

The constraint is **latency on the main/render thread**, not total CPU.

| Tier | Hot-path work | Budget |
|---|---|---|
| Ledger insert/lookup | lock-free seqlock entry, a few probes, optional stack capture | tens of ns; stack capture is the expensive part, hence configurable depth |
| Scaleform free | poison write + quarantine bookkeeping; free ring record; one drain per free at steady state | ~1-2 µs, dominated by `VirtualQuery`/stack capture; no lock, no allocation, no logging |
| Guarded pool sample | `VirtualAlloc`/`VirtualProtect` only on the sampled 1-in-N | negligible amortised |
| RefCount guard | one vtable validation per non-inlined release | tens of ns |
| WeakLib context | one event record + one ledger update per Pin/Unpin/Remove/AddRef | ~100 ns at menu-load frequency |
| VEH | only on a fault | n/a |

Rules: no allocation inside a hook; no logging inside a hook (the quarantine
logs only when it refuses to drain a dead heap, one line per such record); no
global lock; writers bounded-spin then drop; defer symbolization and file I/O to
a watchdog thread; fail open when the ledger or quarantine is unavailable.

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| The sentinel itself crashes the game | fail-open ledger; no allocation/locks/logging in hooks; MinHook only, no hand-rolled trampolines; every hook wrapped so an exception disables it and passes through |
| Hooking hot functions costs frames | per-thread/sharded tables; stack capture sampled or off; guard pool opt-in |
| MinHook copies prologue bytes with a length-only disassembler | verify each target's prologue before installing; upgrade to SafetyHook (IP fix-up + RIP-relative relocation) |
| The VEH allocates while reporting | preallocated report ring + watchdog drain (roadmap) |
| Inlined `Release`/`AddRef` are not intercepted | documented limitation; the standalone `Release` is the one on the observed crash stack |
| The engine does not know our sampled region | guard pool off by default, size-capped, and frees/reallocs intercepted |
| Poisoning corrupts the allocator | poison only offset 0 of the block the allocator *returned* (the object's vtable pointer); never the allocator's private header before it; the real free is only delayed, never skipped |
| Swallowing a real crash | VEH only fixes up faults in our own region; everything else is `CONTINUE_SEARCH` |
| Wrong Address Library resolution | `REL::RelocationID` with SE/AE pairs; verify each target's prologue before installing and log a refusal if it does not match |

## 11. Roadmap

- **v0.1 (this scaffold)**: build system, CI, config, logging, module map,
  stack capture, shadow ledger, report, VEH, `MemoryManager` ledger hooks,
  `GRefCountImpl::Release` guard. Guarded pool present but off.
- **v0.2**: guarded pool hardened (quarantine, fix-up tested in game),
  `ScrapHeap` hooks, Scaleform `GMemoryHeapPT` ledger hooks (done: Alloc ×2,
  AllocAutoHeap ×2, Realloc, Free, AE-only ids verified against the 1.7.104
  Address Library and the engine vtable), screenshot via swapchain.
- **v0.3**: reliable stale-`GFxResource` attribution. Lock-free seqlock ledger
  (no spinlock anywhere on the read path; bounded-spin-then-drop writers);
  vtable-at-alloc / vtable-at-free / last-known-vtable discriminator and a
  one-line `VERDICT:`; durable dedicted Scaleform free ring; bounded
  poison-on-free quarantine (64 MiB default); GFxResourceWeakLib context hooks;
  freed-vs-stray-write verdict. `AllocSysDirect`/`FreeSysDirect` remain
  unhooked (unmeasured share).
- **v0.4**: read the engine's own `HeapBlock::Used` stack-trace/checkpoint bits
  (RESEARCH §7.1) instead of maintaining a parallel stack table where possible;
  payload poison + write-after-free check on `ScrapHeap` blocks.
- **v0.5**: a "bisect" mode that narrows sampling to one size range or one
  allocation site, for reproducing a specific bug.
