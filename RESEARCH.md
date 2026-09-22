# State of the art: memory-error detection, and what survives being retrofitted into a closed 64-bit game

This is the research behind HeapSentinel. It is deliberately written from the
constraint outwards: **we cannot recompile Skyrim, we do not own its allocator,
and we must not crash the game.** Everything below is judged by whether it
survives that constraint.

The question the project asks is narrow and answerable:

> Can an SKSE plugin, loaded into an already-running Skyrim SE/AE process,
> *proactively* detect dangling references and use-after-free, fail safe
> instead of crashing, and produce a loud, precise report (stack + screenshot)?

The short answer: **not in general, but yes for the classes that actually kill
this install**, and the difference between the two is the whole design.

---

## 1. Taxonomy

Memory-safety machinery falls into five families. Only three of them can be
retrofitted into a live process.

| Family | Examples | Retrofittable? |
|---|---|---|
| **Replacement allocators** (you own malloc) | hardened_malloc, Scudo, PartitionAlloc, mimalloc-secure | No — the game's allocator is compiled in |
| **Sampled guard-page detectors** | GWP-ASan, Electric Fence, PageHeap, Application Verifier | **Yes** — for a sampled subset we serve ourselves |
| **Full instrumentation / shadow memory** | ASan, HWASan, KASan, Valgrind Memcheck, Dr. Memory | No — needs recompilation or emulation |
| **Hardware tagging** | ARM MTE, Intel MPX, LAM/UAI, pkeys, CET | Mostly no — see §5 |
| **Pointer-integrity / lifetime mitigations** | DangNull, FreeSentry, CRCount, MarkUs, CFI vtable checks | **Partly** — the side-table versions |

The last row is the one people forget, and it is where "automatically fixing"
lives: instead of *detecting* the bad access, you *invalidate the pointer* or
*refuse the operation* so the access cannot happen.

---

## 2. Replacement allocators (what we cannot have, and what to steal)

### 2.1 hardened_malloc (GrapheneOS)

Sources: [hardened_malloc README](https://github.com/GrapheneOS/hardened_malloc).

Design, in its own terms:

- **Mutable allocator state lives in a dedicated metadata region**, separate
  from the objects. This is what gives "reliable, deterministic protections
  against invalid free including double frees" — you can tell from the address
  range which size class, arena and metadata a pointer belongs to.
- **Per-size-class regions with their own random bases**, loosely inspired by
  PartitionAlloc's partitioning.
- **Slab canaries**: 8 bytes at the end of an allocation; the first byte is
  always zero (to contain missing-NUL string overflows), the other 7 are a
  per-slab random value; verified on free.
- **Zero-on-free** (`CONFIG_ZERO_ON_FREE`): small allocations are zeroed on
  free, which both mitigates UAF reads and purges data.
- **Write-after-free check** (`CONFIG_WRITE_AFTER_FREE_CHECK`): on
  reallocation, assert the block is *still* zero. If it is not, someone wrote
  after free. This is the cleverest single idea in the allocator: it converts a
  silent write-after-free into a deterministic report at realloc time.
- **Slot randomization** (`CONFIG_SLOT_RANDOMIZE`).
- **Quarantine**, as both randomized arrays and queues, scaled per size class,
  with **explicit double-free detection for quarantined allocations**.
- **Guard slabs**: `CONFIG_GUARD_SLABS_INTERVAL=1` leaves an unused,
  memory-protected slab between every slab; large allocations get guard regions
  on both sides and are unmapped on free.
- **Sealed metadata** (`CONFIG_SEAL_METADATA`): Memory Protection Keys revoke
  access to allocator state outside the allocator code; the metadata region is
  surrounded by high-entropy guard regions.
- **MTE** on arm64 (§5).
- Four arenas, locking split per size class; **no thread caching** for small
  slabs, deliberately.
- It **aborts** on detection. It is a mitigation, not a debugger.

The `light` preset drops quarantine, write-after-free check and slot
randomization and raises the guard interval to 8, keeping canaries and
zero-on-free. That is the same performance/coverage dial we expose.

### 2.2 Scudo (LLVM)

Source: [Scudo Hardened Allocator](https://llvm.org/docs/ScudoHardenedAllocator.html).

- **Primary allocator** for small sizes (reserved regions carved into equal
  blocks, 32-/64-bit specific), **Secondary** for large sizes (direct OS
  mappings with guard pages).
- **Chunk header checksum**: on every operation the header is verified; a
  mismatch is reported as `"corrupted chunk header"`.
- **State checks**: `"invalid chunk state"` on a double free, `"race on chunk
  header"` on concurrent manipulation, `"misaligned pointer"`.
- **Sized-dealloc checks**: `dealloc_type_mismatch` and `delete_size_mismatch`.
- **Quarantine**: global plus per-thread, `quarantine_size_kb`,
  `thread_local_quarantine_size_kb`, `quarantine_max_chunk_size` — off by
  default, "fairly costly in terms of performance and memory footprint".
- **Zero / pattern fill** on allocation (`zero_contents`,
  `pattern_fill_contents`).
- It **integrates GWP-ASan** and is the default on Android/Fuchsia.

### 2.3 PartitionAlloc (Chromium)

Source: [PartitionAlloc.md](https://chromium.googlesource.com/chromium/src/+/main/base/allocator/partition_allocator/PartitionAlloc.md).

- **Partition isolation**: different partitions live in different address-space
  regions; a region is only ever reused for the same partition. A page contains
  only objects of one bucket. This is type-confusion defence.
- **Guard pages** at the beginning and end of every partition region, so linear
  overflows cannot cross partitions or reach metadata.
- **Metadata is out-of-line**, in a dedicated region surrounded by guard pages —
  with the exception of freelist pointers.
- **Freelist pointer encoding**: stored byte-reversed so a partial overwrite
  destroys the pointer rather than forming a nearby valid one, plus an
  **encoded shadow copy** to detect corruption.
- **Slot spans** have explicit states (full/empty/active/decommitted) and are
  decommitted back to the OS.

### 2.4 mimalloc (secure mode)

Source: [mimalloc](https://github.com/microsoft/mimalloc).

- **Free-list sharding** (per page) and **multi-sharding** (thread-local vs
  concurrent lists) — the big performance idea.
- **Secure mode** (`MI_SECURE=ON`): guard pages, randomized allocation,
  encrypted free lists, faster double-free detection, ~10 % average penalty.
- Bounded worst-case allocation time; metadata separated from objects in v3.

### 2.5 The ancestors and cousins

- **OpenBSD malloc**: the direct ancestor of hardened_malloc — hash table of
  allocations, canaries, randomized allocation, `free` fills with `0xDF`.
- **DieHard / DieHarder** (PLDI'06 / OOPSLA'06): randomized allocation and
  replication to tolerate heap errors rather than detect them.
- **jemalloc / tcmalloc**: size-class + thread-cache designs; not hardening
  focused, included only as the baseline.

### 2.6 What transfers

We cannot change Skyrim's block layout, size classes or free-list encoding.
What transfers is the *reasoning*:

- address-range → metadata mapping (we do it with a side table);
- canary + verify-on-reuse (we can poison the payload the allocator does not own);
- quarantine + double-free detection (our ledger);
- guard regions (our sampled guarded pool);
- randomization (our sampled pool);
- abort-on-detect → **fail-safe-and-log** (inverted, per the project goal).

---

## 3. Sampled guard-page detectors (the technique that actually fits)

### 3.1 GWP-ASan

Source: [GWP-ASan](https://llvm.org/docs/GwpAsan.html).

GWP-ASan is "the classic Electric Fence Malloc Debugger, with a key
adaptation": only a **small random percentage** of allocations are sampled, and
only those get guard pages. The sampled allocation is placed in its own
guarded slot — one or more accessible pages, flanked by `PROT_NONE` guard
pages — and the alignment is randomly chosen left or right so under- and
overflows are equally likely to be caught.

On free, the slot is made inaccessible; **any subsequent access faults**. The
fault handler then reports the access, plus the allocation and deallocation
stacks. Quoting the doc: *"the use-after-free detection for a sampled
allocation is transient"* — freed slots are randomly reused, which keeps memory
overhead fixed (≈40 KiB per process at defaults, `MaxSimultaneousAllocations=16`,
`SampleRate=5000`).

This is the single most valuable technique for our problem. It gives
**deterministic** UAF/OOB faults for the sampled subset at near-zero cost, with
precise provenance. The catch, and it is a real one, is §7.3: the engine has
never seen our region, so it must never inspect a sampled block's heap.

### 3.2 Electric Fence

Allocate each block so it ends exactly at a page boundary, followed by an
inaccessible page. Deterministic, and unusably slow/memory-hungry for a real
workload — which is exactly why GWP-ASan samples.

### 3.3 Windows PageHeap / Application Verifier

Source: [GFlags and PageHeap](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-and-pageheap).

PageHeap "reserve[s] memory at the boundary of each allocation to detect
attempts to access memory beyond the allocation". Two modes: **standard** (fill
patterns at the end of each allocation, checked on free) and **full** (a guard
page per allocation). Full page heap on a 3.5 GB game heap is not viable, and
the game's `MemoryManager`/`ScrapHeap` suballocates inside pages anyway, so
per-allocation page protection is impossible for the engine's own blocks.

`HeapSetInformation(HeapEnableTerminationOnCorruption)` only makes the *CRT*
heap abort on detected corruption; it does not add detection.

---

## 4. Full instrumentation (what we cannot have)

- **AddressSanitizer**: [docs](https://clang.llvm.org/docs/AddressSanitizer.html).
  Compiler instrumentation plus a shadow-memory runtime; detects heap/stack/
  global OOB, UAF, double-free, invalid free; typical slowdown **2×**. Requires
  recompilation — impossible for `SkyrimSE.exe` and every closed plugin.
- **HWASan / KASan**: hardware-assisted or kernel variants; same
  recompilation requirement.
- **Valgrind Memcheck**: dynamic binary instrumentation with bit-level
  definedness; 10–50× slowdown and no Windows/x64 support for the game.
- **Dr. Memory / DynamoRIO**: [drmemory.org](https://drmemory.org/). DynamoRIO
  based, runs *unmodified* Windows binaries and detects UAF, uninitialised
  reads, invalid frees, leaks. This is the closest thing to ASan for a closed
  binary — but it instruments every instruction, so it is an **offline
  reproduction tool**, not something to play through. It is still the right
  tier for bugs the in-process sentinel cannot neutralise.
- **Intel MPX**: dead (deprecated, removed from GCC/LLVM).
- **Intel CET / Shadow Stack**: control-flow integrity, not data lifetime. It
  would catch a corrupted return address, not a dangling data pointer.

---

## 5. Hardware tagging and protection keys on this machine

The target is an **AMD Ryzen 9 5950X (Zen 3), Windows 10 x64**, running under
Wine/Proton.

- **ARM MTE**: [Android MTE docs](https://source.android.com/docs/security/test/memory-safety/arm-mte).
  Each allocation gets a tag; the CPU checks pointer tag vs memory tag on every
  load/store. SYNC mode faults immediately; ASYNC defers to the next kernel
  entry; ASYMM checks reads synchronously and writes asynchronously. It is the
  ideal primitive for this problem — and it is **arm64-only**. Zen 3 has no
  MTE.
- **Intel LAM (Linear Address Masking) / AMD UAI (Upper Address Ignore)**: let
  software use otherwise-ignored pointer bits for tagging. LAM is Intel-only
  and newer than this CPU; UAI is Zen 5-era. Not available, not exposed by
  Windows 10.
- **Memory Protection Keys (PKU/PKEY)**: per-thread revocation of access to a
  set of pages, the mechanism behind hardened_malloc's `CONFIG_SEAL_METADATA`.
  Windows does not expose pkeys through a supported Win32 API. We can only put
  the ledger in a guarded region.
- **Hardware watchpoints (DR0–DR7)**: only **four** address breakpoints, and
  they trap every access. Useful to bisect one specific object interactively,
  not as a detector.

Conclusion: **no hardware memory tagging is usable here.** The retrofitted
detector must be built from page protection (VirtualAlloc/VirtualProtect) plus
software bookkeeping.

---

## 6. Pointer-integrity and lifetime mitigations (the "auto-fix" family)

This is where "prevent the crash" actually comes from.

- **Pointer invalidation / nulling**: DangNull and FreeSentry (both NDSS'15)
  track the causal relations or the pointers themselves and null out (or
  invalidate) every pointer to a block at free time, so a later dereference is
  a clean null-pointer fault rather than a UAF. **CRCount** (CCS'18) does it
  with reference counting; **MarkUs** (IEEE S&P'20) uses a quarantine plus
  pointer marking. This is the *correct* answer to "fix it", and it is
  impossible for us: it requires rewriting every store that could hold a
  pointer, i.e. recompilation.
- **Delayed free / reuse (FFM-style, Oscar-style)**: never reuse a freed
  virtual address, so a UAF can only touch an unmapped page. Requires owning
  the address space; too expensive at game scale.
- **Reference-count validation**: CRCount's core observation — if you can see
  AddRef/Release, you can detect an over-release *before* it frees the object.
  This is exactly our `GRefCountImpl` guard, and it is the highest-value,
  lowest-cost item in the whole design because it needs no allocator ownership.
- **Vtable / CFI checks**: validating that a "vtable" pointer is a plausible
  vtable in a loaded image, and that its first slot is executable, is a
  poor-man's CFI. It is precisely the check that would have caught the TrueHUD
  crash (`RAX = 0x141A2E20C`, misaligned, inside `.rdata`).

**The honest framing**: we cannot invalidate pointers, but we *can*
(a) refuse the specific dangerous operation (skip the destructor dispatch),
(b) make the bad access fault on a page we control, or (c) make the value read
recognisable (poison) and verify it later.

---

## 7. The Skyrim allocator landscape (what is actually there)

Everything below is from the pinned CommonLibSSE-NG checkout
(`lib/CommonLibSSE-NG/include/RE/…`), which is why the code can stay portable:
the plugin references `REL::RelocationID` / `RELOCATION_ID` and `RE::` types,
not raw offsets.

### 7.1 The engine heap

- **`RE::MemoryManager`** (`RE/M/MemoryManager.h`, 0x480 bytes) — the facade.
  Holds `IMemoryHeap* heaps[]`, `heapsByContext[127]`, a per-thread
  `ThreadScrapHeap*`, `bigAllocHeap`, `emergencyHeap`, `defaultHeap`,
  `BSSmallBlockAllocator*`, `CompactingStore::Store*`, and counters.
  CommonLibSSE-NG IDs: `GetSingleton` (11045/11141), `Allocate` (66859/68115),
  `Deallocate` (66861/68117), `Reallocate` (66860/68116), `GetThreadScrapHeap`
  (66841/68088). **This is the single chokepoint for engine allocations.**
- **`RE::ScrapHeap`** (`RE/S/ScrapHeap.h`, an `IMemoryStore`) — the per-thread
  region allocator. `Block{ sizeFlags; prev; }` header (`Size()` masks
  `~(3<<62)`), `smallBlocks[6]` free lists, `freeList` red-black tree,
  `ContainsBlockImpl()` and `Size()` that read the block header, `reserveSize`
  64 MiB / `minCommit` 128 KiB, `VirtualFree` in the destructor. IDs:
  `Allocate` 68144, `Deallocate` 68146, `Size` 68148, `ContainsBlockImpl`
  68141, `DeallocateAlignImpl` 68140, `dtor` 68157.
- **`RE::MemoryHeap : AbstractHeap : IMemoryHeap`** (`RE/M/MemoryHeap.h`,
  `RE/A/AbstractHeap.h`) — the large heaps. `AbstractHeap` has
  `smallFreeLists[32]`, `largeFreeTrees[32]`, a `blockHead`/`blockTail` chain
  of `HeapBlock`s and live stats (`memAllocated`, `numBlocks`, `numFreeBlocks`).
- **`RE::HeapBlock`** (`RE/H/HeapBlock.h`) — **this is the find of the survey**.
  Each block header is `memSize`, `previous`, a `Free`/`Used` union and
  `nextFree`. The `Used` variant carries `memContext` bits, **22 `stackTrace`
  bits** and 2 `checkPoint` bits, with `GetStackTrace()`, `GetCheckPoint()`,
  `GetMemContext()`. In other words **the engine already stores per-allocation
  stack-trace/checkpoint metadata in its own block headers** (it is what the
  "memory problem pass" diagnostics use). A sentinel can read that for free
  instead of maintaining its own stack table, at least for `MemoryHeap`-backed
  allocations.
- **`RE::BSSmallBlockAllocator`** (`RE/B/BSSmallBlockAllocator.h`) — pooled
  small blocks, `Pool` with a `BSCriticalSection`, `MegaBlockPage`,
  `BlockPageInternal` with a `check` field. `AllocateAlignImpl` id 68428.
- **`RE::ZeroOverheadHeap`** (`RE/Z/ZeroOverheadHeap.h`) — a bump allocator
  with **no per-allocation header**; `Deallocate` is a no-op and `Size` cannot
  be read back. Anything relying on reading a size header must exclude it.
- **`RE::CompactingStore::Store`** (`RE/C/CompactingStore.h`) — a compacting
  store with 66 small free lists, used by the engine for movable data.

### 7.2 The other heaps (not `MemoryManager`)

- **Havok**: `RE::hkMemoryRouter` / `hkThreadMemory` / `hkMemoryAllocator`
  (`RE/H/hkMemoryRouter.h`, `hkLifoAllocator.h`) — Havok physics has its own
  router and thread memory. Not covered by MemoryManager hooks.
- **Scaleform**: `RE::GMemoryHeap` / `RE::GMemoryHeapPT` — the Scaleform
  allocator. This is the one that matters for the crashes that motivated the
  project. IDs: `Alloc` 84498/84499, `AllocAutoHeap` 84501/84502,
  `AllocSysDirect` 84504, **`Free` 84520**, `FreeSysDirect` 84523, `Realloc`
  84540, `GetUsableSize` 84536, `CreateHeap` 84513, `CreateArena` 84511,
  `DestroyArena` 84518.
- **Scaleform refcounting**: `RE::GRefCountImpl` — `AddRef` 82195, **`Release`
  82197** (the function that crashes: `lock xadd [rcx+8],-1; … mov rax,[rcx];
  jmp [rax]`), `GRefCountImplCore::dtor` 33606, `dtor_impl` 82192.
- **The CRT**: `ucrtbase`/`msvcp140` — the game's own `malloc`/`new` and every
  plugin DLL's static CRT. Not covered by MemoryManager.
- **Direct OS calls**: `VirtualAlloc`/`HeapAlloc` — not covered.

### 7.3 The coverage consequence

A `MemoryManager` shadow allocator covers **engine objects**, not Scaleform
objects, not plugin-CRT objects, not Havok objects. For the crashes in this
project the relevant layer is **Scaleform** (`GMemoryHeapPT` + `GRefCountImpl`),
so the design hooks those *in addition to* MemoryManager. And a sampled guarded
allocation must never be handed back to the engine's heap code: the engine's
`ContainsBlockImpl`/`Size` would not recognise it. Sampled blocks must be
intercepted on the way back out (our `Deallocate`/`Reallocate` hooks) or not
sampled at all.

---

## 8. Transfer matrix

| Technique | Source | Transfers | Notes |
|---|---|---|---|
| Address-range → metadata mapping | hardened_malloc, PartitionAlloc | **Yes** | Side-table ledger, sharded, lock-free |
| Double-free / invalid-free detection | hardened_malloc, Scudo | **Yes** | Deterministic, cheap; highest value |
| Quarantine + delayed reuse | hardened_malloc, Scudo, ASan | **Sampled only** | We can't delay the engine's free list |
| Guard pages (sampled) | GWP-ASan, Electric Fence | **Yes** | The core detection mechanism |
| Left/right randomized alignment | GWP-ASan | **Yes** | In the sampled pool |
| Slot randomization | hardened_malloc, Scudo | **Yes** | In the sampled pool |
| Canary + verify on reuse | hardened_malloc, Scudo | **Sampled**, plus payload-only for engine blocks | Must preserve `Block`/free-list metadata |
| Zero/poison on free | hardened_malloc, Scudo | **Payload only** | Clobbering the header breaks `Size()` |
| Write-after-free check | hardened_malloc | **Yes, adapted** | Poison + verify on realloc |
| Freelist pointer encoding | PartitionAlloc | **No** | We don't own the free list |
| Metadata sealing (pkeys) | hardened_malloc | **Partly** | Guarded region only; no pkeys on Windows |
| Sized-dealloc mismatch | hardened_malloc, Scudo | **Yes** | Record size at alloc, compare at free |
| MTE / LAM / UAI | ARM/Intel/AMD | **No** | Not on Zen 3 / Windows 10 |
| Pointer nulling (DangNull/FreeSentry/CRCount) | NDSS'15, CCS'18 | **Refcount only** | We can refuse the release, not rewrite stores |
| Vtable / CFI validation | CET-adjacent | **Yes** | Cheap, catches the observed crash |
| Full shadow memory (ASan) | LLVM | **No** | Needs recompilation |
| Dynamic instrumentation (Dr. Memory) | DynamoRIO | **Offline only** | Reproduction tier, not playable |

---

## 9. Design consequences

1. **Two independent detection tiers**, because they fail in different ways:
   - *Tier A, always-on, cheap, safe*: shadow ledger on the hooked allocators
     (double free, invalid free, sized-dealloc mismatch), plus the
     `GRefCountImpl::Release` vtable guard with optional fail-safe. This is the
     tier that would have turned the TrueHUD crash into a one-line report.
   - *Tier B, opt-in, sampled*: GWP-ASan-style guarded pool for a size range,
     giving deterministic UAF/OOB faults with alloc/free stacks. Riskier
     because sampled blocks are foreign to the engine, hence opt-in.
2. **Fail safe, never repair.** Skipping a destructor dispatch leaks; it does
   not "fix" the object graph. Repair is out of scope by construction (§6).
3. **Never allocate or take a contended lock inside a hook.** Thread-local
   rings, preallocated sharded tables, deferred symbolization and I/O.
4. **Portability via CommonLibSSE-NG.** All targets are `REL::RelocationID` /
   `RELOCATION_ID` + `RE::` types, so SE/AE/VR address selection is the
   library's job, not ours. Verified IDs for 1.7.104 are in §7.
5. **The report is a first-class feature**, not a log line: kind of error,
   faulting address classified (module / guarded slot / ledger-known-freed /
   poison / unmapped), the pre-crash stack, the alloc and free stacks, the
   object bytes, and optionally a screenshot and a freeze.

---

## 10. References

- hardened_malloc — <https://github.com/GrapheneOS/hardened_malloc>
- Scudo — <https://llvm.org/docs/ScudoHardenedAllocator.html>
- PartitionAlloc — <https://chromium.googlesource.com/chromium/src/+/main/base/allocator/partition_allocator/PartitionAlloc.md>
- mimalloc — <https://github.com/microsoft/mimalloc>
- GWP-ASan — <https://llvm.org/docs/GwpAsan.html>
- AddressSanitizer — <https://clang.llvm.org/docs/AddressSanitizer.html>
- ARM MTE — <https://source.android.com/docs/security/test/memory-safety/arm-mte>
- GFlags and PageHeap — <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-and-pageheap>
- Dr. Memory — <https://drmemory.org/>
- CommonLibSSE-NG — the pinned checkout under `lib/CommonLibSSE-NG/include/RE/`
- Pointer invalidation line of work: DangNull and FreeSentry (NDSS 2015),
  CRCount (CCS 2018), MarkUs (IEEE S&P 2020) — described in §6.
