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

### 3.3 Hook target verification (committed, per exact game build)

Installing a detour at "whatever the Address Library resolves" is an act of
faith. v0.4 replaces it with a committed, content-verified table plus a runtime
check, so the claim becomes "we hooked a function whose bytes we verified for
this exact binary".

- **The table** is `hooks/skyrimse-<version>-<sha256-prefix>.json`, one file per
exact game build. Per target it records the AE Address Library id, the
`meh321/AddressLibraryDatabase` name (provenance recorded, not vendored), the
RVA, the `.pdata` extent and slot length, and a 64-bit **FNV-1a hash of the
first N bytes** (N = 32, shortened only when the `.pdata`/slot bound requires
it). **No byte of `SkyrimSE.exe` is committed**: a hash verifies identity
exactly as well as a verbatim prologue would, and a prologue is Bethesda's
copyrighted code. `hooks/README.md` records the licensing decision and the name
database's provenance.
- **Virtual targets are first-class**: `{vtable id, vtable name, vtable RVA,
slot, expected target id}`. This is not hypothetical - reading the engine's own
`??_7GMemoryHeapPT@@6B@` (AE id 242891) is what caught that CommonLibSSE-NG's
header comment order for `GMemoryHeap` does not match the engine's real vtable
order. `MemoryManager` and `GRefCountImpl` are **not** polymorphic in this build
(verified: no vtable in the image contains their function addresses), so they
are plain RVA targets.
- **The source of truth for the target list** is `src/Hooks/HookTargets.def`, an
X-macro list included by `src/Hooks/HookTargets.h` (the enum + metadata the
installer uses) and parsed by `tools/check-hooktable.py`, which fails CI when a
target has no verified entry. Adding a hook without adding a signature is a
build error, not an act of faith.
- **The table is embedded in the DLL** (`HookTableData.gen.h`, generated from the
committed JSON and checked byte-for-byte in CI), so a DLL-only install still has
the verified bytes. There is deliberately no on-disk table that could be missing
or edited out from under the check.
- **Runtime check, before installing each hook**: the cheap identity (exe size,
PE `TimeDateStamp`, `SizeOfImage`) must match the table's; then the id must
resolve to the recorded RVA; for a virtual target the vtable slot must hold the
expected function; then the N-byte prologue hash must match. On any mismatch
that hook is **refused** and the sentinel reports **DEGRADED**, naming the target
and the reason. The game keeps running; nothing is patched that we cannot name.
- **Generation** is `tools/gen-hooktable.py <SkyrimSE.exe> <versionlib.bin>
<skyrimae.rename>`. It also writes the id->offset slice
(`hooks/addresslibrary-<version>.json`) that CI cross-checks every record's RVA
against, so a hand edit to an RVA is caught without the third-party Address
Library file. It **refuses to generate** when a vtable slot does not hold the
target, so a layout change must be investigated rather than rubber-stamped.

**What it does not do.** It verifies *identity*, not *semantics*: a hook can sit
at the right address with the right prologue and still be wrong for our purpose
(the `GMemoryHeapPT` argument count had to come from disassembly for exactly
this reason, and no signature check would have caught it). It is AE-only,
matching the existing `RelocationID(0, ae)` convention; the SE ids in
`HookTargets.def` are recorded, not verified. It says nothing about mod DLLs.

### 3.4 Double-free reporting: do not lie, do not perturb (v0.5)

v0.3.0 produced 142 `[double-free]` reports in one ~52 s session. A read-only
investigation found the overwhelming cause was our own instrumentation, not a
game bug: under EngineFixes' allocator replacement (`bOverrideMemoryManager`)
one logical Scaleform free is observed TWICE - first by `hk_SfFree`, then by
`hk_Deallocate` re-entered from the call to the original - and an address
recycled by an allocator path we do not hook leaves a stale `kFlagFreed` record.
Neither is a second free. The v0.5 rules below are the fix.

1. **Report-only by default; always call the original.** A suspected double free
   is reported and then `o_Deallocate` / `o_SfFree` is still called. The old
   `return` turned a false positive into a *leak* and changed the game's
   allocator behaviour. `[Reporting] bPreventDoubleFree=0` is the default;
   setting it to 1 skips the original and is documented as a behaviour change.
   `Core/FreePolicy.h` holds the decision so it is one place and one test.
2. **Poison-on-free defaults off** (`[ScaleformHeap] bPoisonOnFree=0`). It is the
   one path that *withholds* the real free and writes a poison qword into freed
   memory - the strongest deterministic UAF attribution, but also the largest
   perturbation. It becomes an explicit opt-in for a UAF hunt. The budget stays
   bounded and fail-open (`uPoisonMaxBlocks` / `uPoisonMaxBytes`), and the
   startup config summary names every setting that changes allocator behaviour.
3. **Re-entrancy guard.** `Core/FreeReentrancy` is a per-thread, allocation-free
   stack of the pointers currently being freed by a hook. A nested free hook for
   a pointer already on the stack is the same logical free, not a second one: it
   is neither recorded nor reported, and the original is called exactly once.
   It fails open when the 32-entry stack is full, never blocks a free, and holds
   no lock (the project's no-spinlock rule). This removes mechanism M1 directly.
4. **Alloc-side evidence on every report.** The report now carries
   `allocSite`, `allocTick`, `allocStack`, the decoded `flags` (was it
   `kFlagScaleform`?) and the hook family that recorded the first free and the
   one seeing the second (`MM` vs `SF`). Without this a genuine second free and
   a recycled address are indistinguishable - which is exactly why the v0.3.0
   reports could not be classified.
5. **Refuse to claim unverified.** `Core/AllocatorConfidence` is set at install
   time from the same per-target checks as §3.3. If the bytes at a
   `MemoryManager` target are not the committed game function (the allocator has
   been replaced), or verification was disabled or had no table, reports are
   emitted under the distinct kind `double-free-unverified` instead of a
   confident `double-free`, and the sentinel is `DEGRADED`. A bare `double-free`
   is only ever emitted from a hook chain we verified for this exact build.
6. **Stats are emitted at `kDataLoaded` and on the first report**, in addition
   to the 60 s timer. A ~52 s session must not be able to produce no stats line
   at all; insert failures, writer drops and free-ring evictions have to be
   visible for a run to be diagnosable.
7. **The reports log is appended to and rotated, never truncated**
   (`rotating_file_sink_mt`, 16 MiB x 3), with a session header carrying the
   version, build id, config summary and a hash of the loaded-module set. Two
   runs must be comparable; the v0.3.0 truncate flag destroyed the previous
   run's only evidence.

**Still blind: the allocator, not the facades (deferred to a later version).**
HeapSentinel hooks `MemoryManager` and `GMemoryHeapPT`, but EngineFixes routes
`ScrapHeap`, Havok, RenderPassCache, the shadowmap allocator, `AllocSysDirect` /
`FreeSysDirect` and the replaced CRT imports through the same tbbmalloc pool.
An allocation from any of those is invisible, so a recycled address can still
produce a stale-freed report. The real fix is to hook the tbbmalloc choke point
(`scalable_malloc` / `scalable_free` / `scalable_aligned_*`). That is
**deliberately not bolted on in v0.5** because it is a mod-DLL target and the
committed table is a *SkyrimSE.exe* table:

- `EngineFixes.dll` 7.0.21 exports only `SKSEPlugin_Load/Preload/Version`; its
tbbmalloc is statically linked (vcpkg `tbbmalloc.lib`, PDB module
`src\tbbmalloc\...\frontend.cpp.obj`), so `scalable_malloc`/`scalable_free` are
**not exported** and there is no Address Library id for them. In 7.0.21 the
PDB resolves `scalable_malloc` to RVA `0x966B0` and `scalable_free` /
`scalable_aligned_free` to `0x963D0` (ICF-folded into one body), but those RVAs
are per-EngineFixes-build and cannot be resolved generically.
- A mod-DLL target therefore needs its **own identity and verification**: a
  second table keyed by `{module name, size, TimeDateStamp, SizeOfImage,
  sha256}` (the same cheap-identity + full-hash scheme as the exe table, but for
  a mod DLL), plus per-target prologue signatures resolved by signature scan
  (since there are no exported symbols). `tools/gen-hooktable.py` would grow a
  mod-DLL mode and `HookTargets.def` a target kind that names the owning module.
  Installing any tbbmalloc hook without that verification would violate the
  §3.3 rule and is not done.
- Until then: **M2 remains possible** and `AllocSysDirect` stays blind. The
  v0.5 mitigations are that the reports no longer alter allocator behaviour, are
  labelled unverified when the facade is not the game's, and carry the
  alloc-side evidence needed to tell an unhooked re-use from a real free.

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

### 4.3 Bloom pre-filter (read path only)

A crash lands on an address that is almost never one of our blocks, so the
common case on the read side is a MISS. Both the ledger and the free ring
therefore sit behind a lock-free `BloomFilter`:

- **Read-only in the VEH:** `MightContain` is a handful of relaxed atomic
  loads. No lock, no seqlock, no probing, no allocation. A miss short-circuits
  the lookup, so the dangerous surface inside the exception handler shrinks to
  one read for the overwhelmingly common case.
- **Never a positive decision.** A set bit may be a false positive; only the
  exact store confirms. A miss maps to *unknown*, never to a bug.
- **Off the alloc/dealloc write path.** There the common case is a HIT, which a
  bloom filter cannot confirm, so it would be pure added cost.
- **Sized to the store capacity, ~10 bits/element (~1% FP), non-aging** in
  production. An aging two-half filter is implemented and tested (clear the
  older half at a fill threshold and swap; `Swaps()` is reported), but if the
  filter window is shorter than the store's own retention, a false negative
  would silently drop attribution for a record the store still holds. So the
  production filters are sized to the ledger/free-ring capacity and never
  cleared; a key inserted since `Init` always has its bits set. Bytes: ~5 MiB
  for a 4 M ledger (~1.25 MiB at the deployed 1 M) and ~1.25 MiB for a 1 M
  free ring.

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

[Hooks]
bVerifyTargets=1      ; refuse a hook whose bytes are not the verified ones

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

[Watchpoints]
; Hardware DATA WATCHPOINTS (DR0-DR3): who WROTE the corruption. Opt-in, off.
bEnabled=0
bArmAfterTrigger=1        ; arm only after a report event, so normal play is untouched
uArmAfterReports=1
uSweepMs=250              ; sweeper cadence (candidate promotion, new-thread arming)
uRearmMs=500             ; floor on the suspend+SetThreadContext re-arm period
uHoldMs=30000           ; give up a block never freed, so 4 immortals cannot own the sample
uMaxThreads=256
uSamplePrime=61          ; prime only; a non-prime is refused
uAllocSiteRvas=          ; hex RVAs vs SkyrimSE.exe, e.g. DF49F7 (the observed stray-write site)
bAllocSiteOnly=0         ; 0 = preferred (sampled too), 1 = only matching sites
uMaxPending=16           ; bounded selected-but-unarmed queue
uReportCapacity=256      ; preallocated trap report slots (the VEH allocates nothing)

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
- **v0.4**: committed, per-exact-build hook target verification. A table
  (`hooks/skyrimse-<version>-<hash>.json`) recording each target's Address
  Library id, RVA, `.pdata` extent and a hash of its first bytes - plus
  `{vtable id, slot, expected target}` for virtual targets - verified at load
  time before each hook is installed; a mismatch refuses that hook and reports
  DEGRADED. `tools/gen-hooktable.py` regenerates it; `tools/check-hooktable.py`
  makes "a hook with no verified signature" a CI failure. (Semantics - argument
  counts, which vtable slot means what - still comes from disassembly.)
- **v0.5**: double-free reporting made honest and non-perturbing. Report-only
  by default (the original free is always called); poison-on-free opt-in
  (default off); a per-thread allocation-free re-entrancy guard that removes the
  double observation of one logical free; alloc-side evidence
  (allocSite/tick/stack/flags + hook family) on every double-free report; an
  allocator-confidence gate that emits `double-free-unverified` when the
  MemoryManager target is not the verified game function; stats at data-load
  and on the first report; and an appended, rotated reports log with a session
  header. Hooking the tbbmalloc choke point (a mod-DLL target) is designed but
  deferred - see §3.4.
- **v0.6**: read the engine's own `HeapBlock::Used` stack-trace/checkpoint bits
  (RESEARCH §7.1) instead of maintaining a parallel stack table where possible;
  payload poison + write-after-free check on `ScrapHeap` blocks.
- **v0.6**: hardware data watchpoints (DESIGN §13) - the writer's RIP for a
  corrupted block, not merely the fact of corruption - and a shipped
  `HeapSentinel.pdb` next to the DLL so Crash Logger resolves our own frames
  (DESIGN §14).
- **v0.7**: a "bisect" mode that narrows sampling to one size range or one
  allocation site, for reproducing a specific bug.

## 12. Testing and sanitizers

The off-game suite is a separate xmake project (`tests/`) that builds and RUNS
on Linux and Windows, so the layout/`static_assert`s and the new attribution
cores are a claim about two toolchains, not one. The suite counts failures and
asserts a non-trivial check count, so a runner that executes nothing cannot look
like success.

**Harness: keep the dependency-free one (decision).** Its zero-dependency
nature is exactly why `tests/` builds and runs with nothing but a compiler.
GoogleTest's value-add (fixtures, matchers, mocks, death tests) only starts
paying off when the surface is large and mock-heavy - i.e. Phase B with libmdbx.
When that happens, vendor it **as a submodule** like MinHook and
CommonLibSSE-NG, never as a network fetch, so CI stays hermetic.

**ASan + UBSan** run as a separate `sanitize` CI job on the off-game suite,
configured with `-fsanitize=address,undefined -fno-omit-frame-pointer`, with
`ASAN_OPTIONS`/`UBSAN_OPTIONS` `halt_on_error=1`. Leak detection is off on
purpose: the harness and the single-instance cores keep state alive for the
whole process by design, so LSAN would report those as leaks and drown the
signal. A sanitizer job that has never been observed to fail is not evidence,
so it was proven able to fail with a temporary deliberate out-of-bounds access
(see the report).

**TSan is deliberately not enabled.** It does not understand seqlocks, and the
per-entry seqlock and the lock-free rings read/write payload fields
non-atomically by design, so TSan would flag every one as a race and drown the
real signal. Enabling it later needs suppressions/annotations and is a separate
deliberate decision - do not "helpfully" turn it on.

**Hook target verification is checked without the game.** CI's `hook-table` job
needs no game binary and no third-party Address Library file: it checks the
committed table against the canonical target list in the source (completeness
both ways), against the committed id->offset slice (consistency), for internal
invariants (no duplicate RVAs, unique vtable slots per vtable id, distinct
prologue signatures, no overlapping prologue windows, every field present), and
against the embedded header the DLL ships (byte-for-byte regeneration). The C++
parser and verifier are unit-tested off-game on both platforms and under
ASan/UBSan with synthetic bytes: match, single-byte mismatch, corrupted recorded
hash, truncated read, unknown id, missing entry, moved vtable slot. The
completeness check was proven able to fail with a temporary target added to the
source and no table entry (see the report).

**Reach of the tests, stated honestly.** The ledger, bloom, quarantine,
free-ring, verdict and hook-table logic are unit-tested off-game. The Scaleform
**hook wiring**, the poison path and the **runtime** (Windows)
`REL::RelocationID`-backed resolver are NOT unit-testable here: there is no game
to hook. The committed table itself was verified against the real
`SkyrimSE.exe` bytes off-game with the real verifier (14/14 targets), but the
plugin's own load-time path has only been compiled and string-checked. In-game
behaviour is unobserved.

The hardware-watchpoint cores are held to the same bar and then some. The
selection policy, the four-slot DR table (its bounded claim and drop counter),
the preallocated trap report ring and the DR7/DR6 encoding are plain C++ and run
in `tests/` on Linux AND Windows. The one Windows-only claim - that arming DR0
actually traps a write and reports the writer - is a test that arms a real
watchpoint, writes to the watched address, and asserts the trap fired with the
writer's RIP; it is deliberately able to fail (break the DR7 write and the trap
never arrives). See §13.

## 13. Hardware data watchpoints (who wrote it)

**Why.** Two real crashes showed the same shape: a 32-bit write landing in the
low half of an 8-byte pointer field. In the QuickLootRE crash a LIVE 72-byte
Scaleform object's vtable went `0x6FFFFB89DDB8` to `0x6FFFFB89DDB4` (high half
unchanged, low half decremented by 4). A later crash had a freed Scaleform block
whose first qword was already garbage at free time, split exactly like the
residue of a 32-bit write of `3` into the low half. HeapSentinel's ledger can
say the object WAS corrupted; it cannot say who wrote. x86-64 debug registers
can, at the moment of the write.

### 13.1 What is armed and what a trap reports

`Core/HwWatchpoint` arms DR0-DR3 with a **write** watchpoint (`RW=01b`, `LEN=10b`,
i.e. 8 bytes) on the first 8 bytes of a block - the object's vtable pointer. A
read watch would trap on every ordinary dispatch through that vtable and drown
the signal. Only 8-byte-aligned blocks at least 8 bytes long are watchable.

On the `#DB` (`EXCEPTION_SINGLE_STEP`) trap the VEH reports, at minimum:

- the writer's RIP as `module+0xRVA`;
- the watched address (the address that actually trapped), the first qword at
  arming time and the first qword read immediately after the write;
- which DR slot fired and the raw DR6;
- **how the debug registers were measured** (0.6.4): the source of the DR6/DR7/
  DR0-DR3 fields, whether that read succeeded and its `GetLastError()`, the
  exception record's own DR values next to it, and EFlags (whose TF bit
  explains a trap-flag single step). See 13.4;
- **which free the classifier used** (0.6.4): the slot's Release tick or the
  free ring's newest record for the address, plus the resulting context (a
  post-free link, a realloc-in-progress write, a free that predates the arm, or
  a genuine delayed write-after-free). See 13.4;
- whether the arm was **stale** (the table had moved on) and, when it was, the
  address the live table slot holds now - so `watched=` is never contradicted by
  the table (0.6.2; see 13.4).

`Core/WatchpointEncoding.h` owns the bit layout and is header-only, so the
arithmetic is checked on both toolchains even where `SetThreadContext` does not
exist.

**One caveat, stated plainly.** On x86 a data breakpoint is a *trap*: it is
delivered **after** the store completes, so the saved RIP is the instruction
after the writer. The report keeps that raw RIP and says so; it is the writer's
function, and it is one instruction off the store. Reading the value after the
trap is the same kind of approximation - a racing writer could change it again.
The report labels the unreadable case rather than showing a zero.

### 13.2 The four-slot, per-thread problem (the arming strategy)

Hardware limits, not design taste:

- **Four slots per thread.** 4 M live blocks exist; four can be watched.
- **Per-thread.** A DR set on the main thread does not see a write by a worker.
- **A context write is real work**: `SuspendThread` + `SetThreadContext` on every
  thread. Doing that per allocation is impossible.

So the strategy is a **moving sample**, in four bounded stages:

1. **Selection (hot path, no OS calls).** `Core/WatchpointPlan` judges each
   Scaleform allocation. Two modes, both selectable:
   - *alloc-site filter*: hex RVAs relative to `SkyrimSE.exe`
     (`sAllocSiteRvas`, e.g. the observed allocation site `0xDF49F7`).
     `bAllocSiteOnly=1` considers only matching sites; `=0` lets a match bypass
     the sample while every other block is still sampled.
   - *rotating sample*: `Mix64(ptr) % prime == 0`, with `prime` a PRIME from the
     project ladder (default 61). Mix first because heap pointers are 16-byte
     aligned, so a raw `ptr % prime` would reach only a slice of the buckets.

   A selected pointer goes into a bounded pending queue (default 16,
   overwrite-oldest); every loss is counted. The hook does **no** allocation, no
   lock, no OS call: a few atomics and one relaxed `_active` load when disabled.
2. **Promotion (sweeper).** The sweeper claims a free DR slot from
   `Core/WatchpointSlots` (the lock-free four-entry seqlock table: 16
   pause-separated CAS attempts, then drop and count - no spinlock) and reads
   the block's first qword for the before-value.
3. **Arming (sweeper, throttled).** The sweeper enumerates the process's threads
   and writes the current DR set into each thread's context. Newly created
   threads are picked up on the next sweep (bounded by `uSweepMs`, default
   250 ms); a changed watched set is re-applied to already-armed threads at most
   once per `uRearmMs` (default 500 ms) because suspending threads is the
   expensive part. Threads whose `OpenThread` fails are dropped from the table,
   so a reused tid is armed afresh rather than assumed armed.
4. **Release / rotation.** A watched block that is freed releases its slot on
   the free hook (atomically, again no OS call) and the slot is reused. A block
   that is never freed is given up after `uHoldMs` (default 30 s), so four
   immortal allocations cannot own the sample forever. Releasing a slot is a
   *logical* release: it bumps the generation and sets a force flag, and the
   next sweep re-arms **every** thread with the new set, clearing the released
   slot on threads that had not yet seen the change (FIX 2). That forced sweep
   is bounded to once per sweep period; there is no spin and no lock. Because a
   released slot's watch can still be physically present on a thread the sweep
   has not reached, a trap from that address inside the grace window is still
   recognised as ours (FIX 1) rather than treated as foreign. A
   write-after-free inside that window is still caught and labelled as one.

### 13.3 Trigger: a diagnostic must not alter what it observes

The feature is `bEnabled=0` by default. Even enabled, it does not arm at load:
`bArmAfterTrigger=1` makes it wait for `uArmAfterReports` report events (default
one), so ordinary play with a healthy install pays only one relaxed atomic load
per Scaleform allocation. `Core/Report` increments the trigger; the watchdog
thread does the arming.

Once armed, the perturbation is real and bounded: repeated `SuspendThread`/
`SetThreadContext` at the `uRearmMs` cadence, plus one extra `#DB` on the write
that is caught (which the VEH handles and immediately resumes). It does not
change allocator semantics, memory contents or control flow.

### 13.4 The trap path: no allocation, no locks, no strings

The VEH runs on the faulting thread in a process that may already be corrupt.
The trap path therefore does exactly one thing: it copies a POD
(`Core/WatchpointReports`, a preallocated seqlock ring, default 256 slots) and
then clears the firing slot in the faulting context. It never takes a lock,
never allocates, never builds a `std::string` and never calls spdlog. A
watchdog thread drains the ring, symbolises the RIP, looks up the ledger and the
Scaleform free ring, applies the final benign-vs-degradation call (which needs
the locking module map) and only then calls `Report`. Overwritten, undrained
traps are counted (`Dropped`), not lost silently.

**Which `#DB`s are ours: the structural rule (0.6.3).** 0.6.2 decided
"ours" by classification (`ClassifyTrapOwner`) and returned
`EXCEPTION_CONTINUE_SEARCH` for anything it could not name. The 2026-09-24
17:12:44 crash falsified that: an `EXCEPTION_SINGLE_STEP` arrived through our
own `GMemoryHeapPT::Realloc` hook (`Hooks.cpp:626`) while the feature was armed,
the classifier called it foreign, it was handed on, and the game died. The
session's counters read `0 trips, 0 reports` -- our own handler had judged our
own trap foreign. The lesson is not "classify better"; it is that a survival
decision must not depend on classification at all.

So the survival rule is structural and lives in `MustConsumeDebugException`:

* **before this process has ever programmed a debug register** (feature
disabled, or enabled but not yet past the trigger) nothing can have been
masked, so a `#DB` is genuinely foreign and is passed on -- a debugger keeps
working on a run where we never armed;
* **once any DR has been programmed**, ANY `#DB` is ours. It is consumed and,
if the classifier cannot name it, *recorded as unattributed* (Deliverable 1
below). A foreign `#DB` is effectively nonexistent in this process -- nothing
requested one after we armed -- and an escaping one kills the game, so
consuming is strictly better than dying. The old "unknown exceptions return
`EXCEPTION_CONTINUE_SEARCH`" rule still applies to every other exception code.

The flag is monotonic and set before the first `SetThreadContext` (an
over-claim only means we consume a foreign `#DB`, which is the safe direction).
**Residual risk, stated plainly:** once armed, a legitimate trap-flag
single-step or a debugger's own hardware breakpoint is consumed rather than
forwarded. That is a bounded, deliberate masking of a diagnostic that is not
part of a shipping game, traded for not dying on our own watchpoint. When
`bEnabled=0` nothing is ever armed, so nothing is masked; the off-game tests
assert that (`BuildDr7(all-zero) == 0` and
`MustConsumeDebugException(false) == false`), and the Windows test drives the
real rule with a real `#DB`.

Classification is still used, but only to decide what to RECORD and whether to
release a slot: `ClassifyTrapOwner` names a current arm, a released block
(write-after-free), or a stale per-thread arm, and the per-thread record remains
the safety net for an arm the table has moved on from. A classification bug can
now lose a report; it can no longer kill the process.

**Unattributed traps are recorded (0.6.3, Deliverable 1).** When the classifier
cannot attribute a `#DB`, the handler writes a record into the preallocated ring
BEFORE dealing with it: raw DR6 and DR7, the raw DR0-DR3, the faulting thread
id, the RIP, this thread's ever-armed slot mask, and whether any DR was ever
programmed. No allocation, no lock, no `std::string`, no spdlog -- the same POD
record path as every other trap. If the fatal case recurs, it leaves data
instead of another mystery.

**The debug-register fields are a measurement (0.6.4, FIX A).** The 0.6.3 trip
produced 104 unattributed records and every one of them read
`dr6=0x0 dr7=0x0 dr0-3=0`. That cannot be a valid reading of a delivered `#DB`:
a trap-flag single-step sets `DR6.BS` (0x4000) and a data breakpoint sets one of
`B0-B3`. So the fields were either a failed read or an uninitialised struct -- and
nothing in the record said which. The most important question about this feature
was unanswerable.

0.6.4 makes the measurement explicit. The trap path takes its **own** read of
the faulting thread, `GetThreadContext(GetCurrentThread(),
CONTEXT_DEBUG_REGISTERS)`: it is our own thread, so no suspension is needed and it
cannot deadlock, which is why it is legal in the VEH at all. Which set of values
the classifier then uses is a rule, not a preference: the **exception record wins
whenever it carries anything**, because on real Windows it does for a data
breakpoint -- the in-game attributed reports read `dr6=0xFFFF0FF2
dr7=0x99990055`, and the Windows hardware test falsified the opposite choice
(there `GetThreadContext`'s DR7 does not match the trap's DR7, so preferring the
read unconditionally replaced a working classification with a different one). The
faulting-thread read supplies the fields only when the exception record is empty,
which is precisely the case the 104 hollow records were.

Both sets are in the record either way, plus the read's outcome and its
`GetLastError()`, plus EFlags, whose TF bit identifies a trap-flag single step.
That makes the two questions answerable from the log alone: if the exception
record was empty *and* the read failed, the record says `dr_read=FAILED` and the
fields are **not a measurement**; if the exception record was empty but the read
succeeded and also returned zero, the record says `dr_read=ok` and this host
delivered a single step with no debug register set at all -- a finding to chase.
The three outcomes are a portable `constexpr` decision
(`ClassifyDebugRegisterMeasurement`) checked on Linux and driven by a real `#DB`
in the Windows test, and the drainer says the outcome in words and counts them
separately in the periodic stats line. "Read failed" and "read succeeded and
genuinely found no debug register" are now different records instead of the same
`0x0`.

The attributed write reports carry the same provenance (0.6.3 left those fields
unset, so they too printed `ever_armed=0x0 any_dr=0 dr0-3=0x0`, indistinguishable
from a failed read).

**Benign writes vs a clobbered vtable (0.6.2).** A data breakpoint fires on
*any* write, including the allocator's or CRT's initialisation of a freshly
allocated block. The one real trip was `VCRUNTIME140` writing `0` into an
already-zero qword - construction, not corruption - and 0.6.1 reported it and
released the slot, losing the watch exactly while the object was being
constructed. At arming, 0.6.2 snapshots the first qword and whether it is a code
pointer (the existing module-map classification, taken on the sweeper, never in
the VEH). A trap is a **degradation** only when a value that *was* a code
pointer has become a non-code value. Everything else is benign:

* `before == after` is benign by construction (the observed case);
* a value that was not a code pointer at arming is benign whatever is written;
* code -> different code is a legitimate vtable swap, not a clobber;
* an unreadable value is never claimed to be a degradation.

A benign trap is consumed silently and **the slot stays armed**; a data
breakpoint is a trap, so the store itself cannot re-fire. Only a degradation is
reported, and only then is the slot released. The rule is `ClassifyWatchedWrite`
in `Core/WatchpointEncoding.h` and is unit-tested off-game.

**The allocator's own writes around a free (0.6.3 Deliverable 3, corrected in
0.6.4 -- FIX B).** The 2026-09-23 21:37:41 event was a valid vtable replaced by a
heap address one `GetTickCount64` tick after the block's own recorded free
(`freed at tick 188333102`, written at `188333103`). That is the allocator
linking the just-freed block into its free list: normal reuse, safe by itself,
not corruption. 0.6.3 therefore suppressed a write within 32 ms after the
block's recorded free.

The 2026-09-24 trip falsified that in two ways, both structural:

1. **The free ring was consulted only when the slot had no Release tick.**
   `Watchpoints` reads the free ring only if `report.freeTick == 0`, so for an
   already-released slot the stale slot `Release` tick SHADOWED the free ring's
   newest record. Concrete case: slot tick 261486289, free-ring record 261487115,
   trap 261487115 -- a delta of 0 where 0.6.3 computed 826 ms and reported a
   clobber. The resolution is now unconditional and recorded:
   `PreferNewestFreeTick` takes the free ring's newest record for the address
   whenever it is NEWER than the slot's Release tick (when it is older it is from a
   previous life of a recycled address, so the slot's own later Release is kept),
   and the record says which source won.
2. **The two orderings were conflated.** `hk_SfFree` records the free BEFORE it
   calls the original, so the allocator's link write FOLLOWS the record
   (`free <= trap`); `hk_SfRealloc` calls `o_SfRealloc` first and records the free
   of the old block only AFTER it returns, so the link write PRECEDES the record
   (`trap < free`). The 0.6.3 post-free window could only ever see the first. The
   classification is now `ClassifyWriteAgainstFree`, which names the two
   separately -- `allocator-post-free-link` and `allocator-realloc-in-progress` --
   and reports a third, `free-predates-arm`, when the free ring's only record is
   OLDER than the arm (a recycled address whose ring record is stale, or a watch
   armed on an already-freed block). That third case is NOT silenced: it is a
   real write we cannot assign to the allocator.

The window is also derived from the trip rather than from one event. Our free hook
takes its tick before the original free call, so the link write can follow the
record by the duration of our own remaining work (a stack capture and ledger
lookups), and `hk_SfRealloc` can precede its record by the same kind of latency.
The trip measures those gaps directly: 0-114 ms after the recorded free and
1-165 ms before it. `kAllocatorBookkeepingWindowMs` is 250 ms, the next round
bound above the observed worst case, and applied on BOTH sides through that one
function, which the trap path and the drainer call identically (defence in depth
for the race where the free record lands after the trap).

**Residual risk, stated plainly:** a genuine use-after-free write landing within
250 ms of the free is treated as allocator bookkeeping and missed. The two
genuine delayed writes in the same corpus are 1858 ms and 12379 ms after their
free, an order of magnitude outside the window, and they are still reported. The
window is a bounded silence, not a claim of completeness.

**Why the window is this wide, and the structural fix that would shrink it.** The
width is entirely our own instrumentation latency: `hk_SfFree` takes its tick
before `RecordScaleformFree` and before `o_SfFree`, so the free we record is
older than the free the allocator performs, by however long our stack capture and
ledger lookups take. Recording the tick AFTER the original free returns (and
rejecting a promotion candidate the free ring already records as freed, which is
the likely shape of the two `free-predates-arm` rows) would let the window shrink
back to a couple of ticks. Both change free-record semantics that the double-free
path depends on, so neither belongs in a narrow correctness release; they are
candidates for 0.6.5.

**What the 2026-09-24 corpus says under the corrected rules.** Replaying the
trip's 21 write reports through the shipped classifier (a permanent off-game
test, `watchpoint_live_corpus_2026_09_24_write_reports_are_classified_as_designed`)
gives: 18 are allocator bookkeeping and go silent (7 post-free links and 11
realloc-in-progress writes), 2 report because their free record predates the arm
(0xA34DF900, written by `VCRUNTIME140.dll`; 0xA33C04B0, written by
`SkyrimSE.exe+0x11922AB`), and 1 (`0xA36190E0`) is a genuine delayed write whose
`after` value is still a code pointer, so the drainer's benign shape rule drops
it. Of the 18 shape-conforming, non-stale reports named as the trip's noise, 16
go silent and 2 remain, labelled. The expectation before the replay was that all
18 would go silent; 16 + 2 labelled is what the evidence supports, and the two
survivors are a new question (why were we watching an address whose only free
record predates the arm?) rather than a regression.

**The headline, stated honestly.** After the trip: the instrument survives a real
in-game session and produces records, and the writers it names are overwhelmingly
the engine's own allocator code and the game's CRT -- **but a third-party module
has now been observed as the writer.** The v0.6.3 session's log kept growing
after the 18:02:36 window the first analysis covered, and the five later write
reports include two written by `QuickLootIE.dll+0x9ADB9` (the AE port of the very
mod whose vtable corruption started this feature at 0.6.0) and others by
`SkyrimSE.exe+0xD0500C` and `+0xD5A843`, all over the first qword of a block
whose free record PREDATES the arm. Four of those five are still reported under
0.6.4's rules, labelled `free-predates-arm`; the fifth -- a `QuickLootIE` write
whose block's free record is 174 ms earlier and whose arm tick equals that free
tick -- would be silenced as an allocator post-free link. That is a concrete
instance of the window's residual risk, on the one writer that matters, and it is
recorded here rather than smoothed over. The corruptor question is open in the
sense that this is a correlation, not a proof of an owning bug: the free ring
never invalidates a record when an address is recycled, so `free-predates-arm`
means "the free evidence is older than this arm" and not "this module corrupted
a live object".

### 13.5 Shutdown and the final-state assertion

`Shutdown` stops the sweeper, disarms every thread it can open, disarms the
calling thread, and then **asserts** the final state with
`VerifyAllThreadsDisarmed`: it reads DR7 on every thread and reports how many
were checked and how many were still armed, degrading health if any were. "We
think we cleared them" is not a claim. SKSE has no plugin-unload callback, so
the clean path is registered with `atexit` as a best effort; a hard process exit
clears the per-thread debug registers by definition. Within a session, a stale
DR is now handled by three independent mechanisms rather than one: the trap-time
per-thread record (a stale trap is consumed, not fatal - 13.4), the release on
free plus the forced all-thread re-arm (FIX 2), and the hold rotation.

### 13.6 Coverage, honestly

**Partial by construction.** Four addresses at a time, applied per thread. The
sample is 1-in-`uSamplePrime` of the blocks that reach the Scaleform alloc
hooks, plus every block from a filtered allocation site. A block allocated
before the feature armed, allocated through an unhooked path, or simply not in
the sample is invisible to the watchpoints (the ledger may still attribute its
corruption after the fact). The health line reports slot occupancy, claims,
claim drops, trips, rotations and report drops so a lossy run is legible. This
is a detector for a sampled subset, not a shadow heap, and it is not presented
as one. **It has now been run in the game three times.** The 0.6.1 trip exposed
four defects: a stale arm whose `#DB` was handed to the crash handler and killed
the session, a release that only disarmed the trapping thread, a benign
construction write reported and released as if it were corruption, and a report
whose `watched=` address disagreed with the table. 0.6.2 fixed those four,
proved them off-game on Linux and on real hardware watchpoints in the Windows
test -- and then **still killed the session on 2026-09-24**, because a `#DB`
reached the handler through our own `Realloc` hook that the classifier called
foreign and handed on. That is the precedent for not claiming more than the
evidence shows: a green suite with a real mutation proof did not cover the case
the game hit.

The 0.6.3 changes are structural rather than another classifier -- survival is
`MustConsumeDebugException` and no longer depends on classification -- and the
2026-09-24 trip (build `4f409330007c`) confirmed the structural rule in the real
process: 104 `EXCEPTION_SINGLE_STEP`s that the classifier could not attribute
were consumed and recorded, and **the session survived**. That trip falsified two
things in the *measurement*, not in the survival: the unattributed record's
debug-register fields were hollow (104/104 read `dr6=0x0 dr7=0x0 dr0-3=0`, which
no delivered `#DB` can be), and the post-free suppression was falsified by live
evidence (the stale slot `Release` tick shadowed the free ring, and
`hk_SfRealloc`'s free record lands after the trap). 0.6.4 fixes both -- see 13.4 --
and the 0.6.3 corpus is now a permanent off-game regression test rather than a
one-off analysis.

**What is proven and what is not.** PROVEN off-game on Linux (without ASan/UBSan
errors) and, for the trap-path decisions, on real hardware `#DB`s in the Windows
test: the debug-register measurement classification (failed vs
genuinely-zero vs armed), the free-tick preference, the two allocator orderings
kept apart, the `free-predates-arm` case reported rather than silenced, the
record encoding, and the 21-row 2026-09-24 corpus replay. Each of those tests was
broken once and seen to fail (the mutation run ids are in the v0.6.4 release
notes). **UNPROVEN: the in-game correctness of the corrected path.** 0.6.2 is the
precedent for not claiming otherwise -- a green suite with a real mutation proof
did not cover the case the game hit. Only a fresh trip can show that the
corrected record is populated, that the 16 allocator rows stay silent in the real
process, and what the two `free-predates-arm` rows really are. The counters in
the periodic stats line exist so that a fresh trip answers it from the log
without a second analysis pass: `suppressed N post-free link(s) + M
realloc-in-progress write(s), K free-predates-arm report(s); unattributed #DB
debug-register reads: F failed (no measurement), Z succeeded and found no debug
register`.

## 14. Publishing symbols (making our own frames legible)

Our frames appeared in crash logs as `HeapSentinel.dll+0x39C1B` and **nobody
could resolve them** - not CrashLogger, not us. QuickLootRE ships a `.pdb` next
to its DLL and CrashLogger resolved its entire call path *with source lines*. A
sentinel whose own frames are opaque is a sentinel that hides its own bugs.

So the build produces `HeapSentinel.pdb` (MSVC `/Zi` + a forced `/DEBUG:FULL`,
so the PDB is the full private-symbol one, not a stripped stub) and it is
shipped in the same directory as the DLL, which is where CrashLogger looks:

- the flat release archive puts both at `SKSE/Plugins/HeapSentinel.{dll,pdb}`;
- the FOMOD lists the PDB as a `requiredInstallFiles` entry, so the wizard
  installs it to `SKSE/Plugins/HeapSentinel.pdb`;
- CI uploads it as an artifact and attaches it to a tagged release, and asserts
  it exists, is non-empty and carries the Windows PDB (`MSF`) signature.

**Cost:** 17,788,928 bytes (17.0 MiB) on disk for the 1.7.104 build, next to
the DLL, and nothing resident. **What it
buys:** `HeapSentinel.dll+0x39C1B` becomes a function name and a source line for
everyone reading the log, and the `allocSite` / `freeSite` hints HeapSentinel
prints are resolvable against the same file.
