# State of the art: memory-error detection, and what survives being retrofitted into a closed 64-bit game

This is the research behind HeapSentinel. It is written from the constraint
outwards: **we cannot recompile Skyrim, we do not own its allocator, and we
must not crash the game.** Everything below is judged by whether it survives
that constraint.

The question the project asks is narrow and answerable:

> Can an SKSE plugin, loaded into an already-running Skyrim SE/AE process,
> *proactively* detect dangling references and use-after-free, fail safe
> instead of crashing, and produce a loud, precise report (stack + screenshot)?

The short answer: **not in general, but yes for the classes that actually kill
this install**, and the difference between the two is the whole design.

---

## 1. Taxonomy

Memory-safety machinery falls into five families. Only three can be
retrofitted into a live process.

| Family | Examples | Retrofittable? |
|---|---|---|
| **Replacement allocators** (you own malloc) | hardened_malloc, Scudo, PartitionAlloc, mimalloc-secure | No — the game's allocator is compiled in |
| **Sampled guard-page detectors** | GWP-ASan, Electric Fence, PageHeap, Application Verifier | **Yes** — for a sampled subset we serve ourselves |
| **Full instrumentation / shadow memory** | ASan, HWASan, KASan, Valgrind Memcheck, Dr. Memory | No — needs recompilation or emulation |
| **Hardware tagging** | ARM MTE, Intel MPX, LAM/UAI, pkeys, CET | Mostly no — see §6 |
| **Pointer-integrity / lifetime mitigations** | DangNull, FreeSentry, CRCount, MarkUs, CFI vtable checks | **Partly** — the side-table versions |

The last row is where "automatically fixing" lives: instead of *detecting* the
bad access, you *invalidate the pointer* or *refuse the operation* so the
access cannot happen.

---

## 2. Replacement allocators (what we cannot have, and what to steal)

### 2.1 hardened_malloc (GrapheneOS)

Source: [hardened_malloc README](https://github.com/GrapheneOS/hardened_malloc).

- **Mutable allocator state lives in a dedicated metadata region**, separate
  from the objects — this is what gives "reliable, deterministic protections
  against invalid free including double frees". From an address you can tell
  which size class/arena/metadata it belongs to.
- **Per-size-class regions with their own random bases**, inspired by
  PartitionAlloc.
- **Slab canaries**: 8 bytes at the end of an allocation; first byte always
  zero (contains missing-NUL string overflows), other 7 per-slab random;
  verified on free.
- **Zero-on-free** (`CONFIG_ZERO_ON_FREE`).
- **Write-after-free check** (`CONFIG_WRITE_AFTER_FREE_CHECK`): on
  reallocation, assert the block is *still* zero. The cleverest idea in the
  allocator: it converts a silent write-after-free into a deterministic report
  at realloc time.
- **Slot randomization** (`CONFIG_SLOT_RANDOMIZE`).
- **Quarantine** as randomized arrays *and* queues, per size class, with
  explicit double-free detection for quarantined allocations.
- **Guard slabs**: `CONFIG_GUARD_SLABS_INTERVAL=1` leaves an unused,
  memory-protected slab between every slab; large allocations get guard regions
  on both sides and are unmapped on free.
- **Sealed metadata** (`CONFIG_SEAL_METADATA`): Memory Protection Keys revoke
  access to allocator state outside the allocator; metadata sits in an isolated
  region with high-entropy guard regions.
- Four arenas, locking split per size class; **no thread caching** for small
  slabs.
- It **aborts** on detection — a mitigation, not a debugger.

`light` drops quarantine, write-after-free check and slot randomization and
raises the guard interval to 8, keeping canaries and zero-on-free. That is the
same performance/coverage dial we expose.

### 2.2 Scudo (LLVM)

Source: [Scudo](https://llvm.org/docs/ScudoHardenedAllocator.html).

- Primary allocator (small, equal-size blocks) + Secondary (large, direct OS
  mappings with guard pages).
- **Chunk header checksum** → `"corrupted chunk header"`.
- **State checks**: `"invalid chunk state"` (double free), `"race on chunk
  header"`, `"misaligned pointer"`.
- **Sized-dealloc checks**: `dealloc_type_mismatch`, `delete_size_mismatch`.
- **Quarantine** (global + per-thread, `quarantine_size_kb`,
  `thread_local_quarantine_size_kb`), off by default, "fairly costly".
- **Zero / pattern fill** on allocation.
- Integrates GWP-ASan; default on Android/Fuchsia.

### 2.3 PartitionAlloc (Chromium)

Source: [PartitionAlloc.md](https://chromium.googlesource.com/chromium/src/+/main/base/allocator/partition_allocator/PartitionAlloc.md).

- **Partition isolation**: partitions in different address-space regions, a
  region only reused for the same partition, a page holds only one bucket →
  type-confusion defence.
- **Guard pages** at both ends of every partition region.
- **Metadata out-of-line**, in a dedicated region surrounded by guard pages —
  except freelist pointers.
- **Freelist pointer encoding**: byte-reversed, plus an encoded shadow copy to
  detect corruption.
- Slot spans have full/empty/active/decommitted states and are decommitted back
  to the OS.

### 2.4 mimalloc (secure mode)

Source: [mimalloc](https://github.com/microsoft/mimalloc).

- Free-list sharding + multi-sharding (thread-local vs concurrent lists).
- **Secure mode** (`MI_SECURE=ON`): guard pages, randomized allocation,
  encrypted free lists, faster double-free detection, ~10 % penalty.
- Metadata separated from objects in v3.

### 2.5 Ancestors and cousins

- **OpenBSD malloc** — the ancestor: allocation hash table, canaries, randomized
  allocation, `free` fills with `0xDF`.
- **DieHard / DieHarder** — randomized allocation and replication to *tolerate*
  heap errors rather than detect them.
- **jemalloc / tcmalloc** — the size-class + thread-cache baseline.

### 2.6 What transfers

We cannot change Skyrim's block layout, size classes or free-list encoding.
What transfers is the reasoning: address-range → metadata mapping (side table);
canary + verify-on-reuse (payload-only); quarantine + double-free detection
(ledger); guard regions (sampled pool); randomization (sampled pool);
abort-on-detect → **fail-safe-and-log**.

---

## 3. Sampled guard-page detectors (the technique that fits)

### 3.1 GWP-ASan

Sources: [LLVM GWP-ASan](https://llvm.org/docs/GwpAsan.html),
[Chromium GWP-ASan](https://www.chromium.org/Home/chromium-security/articles/gwp-asan/),
[Trail of Bits, 2025](https://blog.trailofbits.com/2025/12/16/use-gwp-asan-to-detect-exploits-in-production-environments/).

"Electric Fence, with a key adaptation": only a **small random percentage** of
allocations is sampled, and only those get guard pages.

- Each sampled allocation gets its own guarded slot — one or more accessible
  pages flanked by two `PROT_NONE` guard pages.
- **Randomly left- or right-aligned** so under- and overflows are equally
  likely to be caught.
- **On free the slot is made inaccessible**; any later access faults, and the
  handler reports the access plus the allocation and deallocation stacks.
- **Transient detection**: freed slots are reused round-robin, which forms a
  rudimentary quarantine (`ReservedSlots − MaxSimultaneousAllocations`) and
  keeps overhead fixed.
- LLVM defaults: `MaxSimultaneousAllocations=16`, `SampleRate=5000`,
  `PerfectlyRightAlign=false` (alignment rounds up to a power of two ≤16, which
  leaves an alignment gap that small overruns can hide in — the Trail of Bits
  caveat). Fixed overhead ≈ **40 KiB per process** at defaults.
- Chromium's production numbers are more useful for sizing: **≈400 bytes of
  metadata per slot** (mostly compressed alloc/dealloc stacks) against **4 KB
  per allocation**; **1/1000 sampling with 16 slots exhausts the pool on
  long-lived allocations, while 1/8000 with 64 slots samples the whole
  process lifetime**; **up to 5 % regression from the instrumentation alone,
  however low the sampling rate**; ~90 % of findings are use-after-frees.
  Chromium also **maps the region at high addresses** to reduce wild-pointer
  false hits, and disables it for 32-bit.
- Trail of Bits: "GWP-ASan typically guards less than 0.1 % of allocations".

This is the most valuable technique for our problem: **deterministic** UAF/OOB
faults for the sampled subset at near-zero cost, with precise provenance. The
catch (§9.3) is that the engine has never seen our region.

### 3.2 Electric Fence

End each allocation at a page boundary followed by an inaccessible page.
Deterministic and unusably slow/memory-hungry for a real workload — which is
exactly why GWP-ASan samples.

### 3.3 Windows PageHeap / Application Verifier

Sources: [GFlags and PageHeap](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-and-pageheap),
[Application Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier-testing-applications),
[Chromium page heap notes](https://www.chromium.org/developers/testing/page-heap-for-chrome/),
[randomascii](https://randomascii.wordpress.com/2011/12/07/increased-reliability-through-more-crashes/).

- **Standard page heap** writes fill patterns at the end of each allocation and
  examines them **on free** — detection is delayed, "failures are more difficult
  to debug".
- **Full page heap** places an inaccessible page at the end of each allocation,
  so the overrun faults immediately.
- Cost: "every allocation takes a minimum of **4 KB of memory and at least 8 KB
  of address space**". Measured on a real shipping game: **170 fps → 3.7 fps**
  (~46× slower) with the heap growing **0.8 GB → 2.9 GB** at only 0.8 GB of
  normal heap. Overruns fault near `…000`, use-after-free near `…FFF`.
- **It cannot be enabled for a running process**: PageHeap "is only active if
  PageHeap verification was enabled before the image was launched", and
  "Application Verifier cannot be enabled for a running process". Settings live
  in IFEO and persist.
- The scaling workaround is AppVerifier's **RandRate** — guard only 8–15 % of
  allocations. That is GWP-ASan, 15 years earlier.
- `HeapSetInformation(HeapEnableTerminationOnCorruption)` is a **fail-fast
  mitigation**, not a detector: it fires only when the heap manager itself
  notices metadata corruption, cannot be disabled once set, and gives no
  coverage for a UAF read on a recycled block.
- **Segment Heap** (Windows 10+) is opt-in via manifest/IFEO, and even then
  "not all heaps created by the process will be managed by the Segment Heap" —
  the NT heap is still used for some. There is no runtime API to convert an
  existing heap.

**Conclusion**: all of these are pre-launch, whole-process, debugger-attached,
and either blow up memory or only detect on free. They are viable as
**ground-truth oracles during offline reproduction**, not as an in-process
retrofit.

---

## 4. Full instrumentation (what we cannot have)

- **AddressSanitizer**: [docs](https://clang.llvm.org/docs/AddressSanitizer.html).
  Compiler instrumentation + shadow-memory runtime; heap/stack/global OOB, UAF,
  double-free, invalid free; typical slowdown **2×**. Requires recompilation —
  impossible for `SkyrimSE.exe` and every closed plugin.
- **HWASan / KASan**: same recompilation requirement.
- **Valgrind Memcheck**: dynamic binary instrumentation with bit-level
  definedness; 10–50× slowdown, no Windows/x64 support for the game.
- **Dr. Memory / DynamoRIO**: [drmemory.org](https://drmemory.org/). Runs
  *unmodified* Windows binaries and detects UAF, uninitialised reads, invalid
  frees, leaks. The closest thing to ASan for a closed binary — but it
  instruments every instruction, so it is an **offline reproduction tier**, not
  something to play through. It is still the right tool for bugs the
  in-process sentinel cannot neutralise.
- **Intel MPX**: dead; removed from GCC 9.1 / Linux 5.6 / glibc 2.35 / QEMU 4.0;
  and it "provides no protection against temporal memory safety errors" — it
  would not detect UAF even if it existed.

---

## 5. Detouring: mechanics, and which library is correct

Sources: [Detours interception](https://github.com/microsoft/Detours/wiki/OverviewInterception),
[DetourUpdateThread](https://github.com/microsoft/Detours/wiki/DetourUpdateThread),
[MinHook](https://github.com/TsudaKageyu/minhook),
[SafetyHook](https://github.com/cursey/safetyhook),
[funchook](https://github.com/kubo/funchook),
[CommonLibSSE-NG Trampoline](https://github.com/CharmedBaryon/CommonLibSSE-NG/blob/main/include/SKSE/Trampoline.h),
[/hotpatch](https://learn.microsoft.com/en-us/cpp/build/reference/hotpatch-create-hotpatchable-image).

All inline-hook engines do the same thing: overwrite the target's first N bytes
with a jump, preserve the overwritten instructions in a trampoline. Detours
states the algorithm: copy instructions "until at least 5 bytes have been
copied"; **if the target function is fewer than 5 bytes, abort**.

| Library | Thread handling | Prologue relocation | Notes |
|---|---|---|---|
| **Detours** | Manual: `DetourUpdateThread` must enlist every thread; "Threads not enlisted … may attempt to execute an illegal combination of old and new code". Transactional, chainable, CFG registration. | "simple table-driven disassembler"; only the ≥5-byte contract is documented | The reference implementation |
| **MinHook** | Suspends/resumes **all threads** on every `MH_EnableHook` (use `MH_QueueEnableHook`/`MH_ApplyQueued`) | HDE64, a **length-only** disassembler; follows a leading relative branch; does not advertise general RIP-relative relocation | Smallest; what HeapSentinel v0.1 uses |
| **SafetyHook** | Suspends all threads **and fixes the IP** of affected threads | Fixes RIP-relative displacements, fixes rel32, widens short branches, handles branches into the trampoline; bddisasm | The correctness-first choice; C++23 + Zydis |
| **funchook** | none documented | diStorm3 / Zydis / capstone selectable | **Archived/unmaintained** |
| **SKSE trampoline** | **none** — no thread enumeration at all | **none** — no instruction-length decoding | It is a *branch writer*: `write_branch<5/6>` overwrites exactly one existing instruction and computes the target from the original displacement. Correct only for replacing an existing `call`/`jmp` instruction, not for an arbitrary function prologue |

- On x64, images are always treated as hotpatchable (with `/functionpadmin`),
  but the 5-byte `E9` patch is still a data race against any core executing
  inside the rewritten bytes. Detours' documented failure mode is exactly that;
  MinHook and SafetyHook solve it by suspending all other threads, and
  SafetyHook additionally fixes their IPs.
- Hooking a **hot** function adds an unconditional branch, destroys inlining
  and I-cache locality, and does nothing for callers that inlined the function.
- Multiple mods hooking the same function is normal; only Detours-style layered
  transactions handle it cleanly.

**Design consequence**: HeapSentinel v0.1 uses MinHook because its targets
(`MemoryManager::Allocate/Deallocate/Reallocate`, `GRefCountImpl::Release`)
have conventional prologues and MinHook is the lightest dependency. The
research says the upgrade path is **SafetyHook** (IP fix-up + RIP-relative
relocation) and that we should verify each target's prologue before installing
rather than trusting the address. Both are on the roadmap; the SKSE trampoline
is deliberately not used.

---

## 6. Hardware tagging and protection keys on this machine

Target: **AMD Ryzen 9 5950X (Zen 3), Windows 10 x64**, under Wine/Proton.

| Primitive | Present on Zen 3? | Exposed by Windows 10 x64? | Usable for UAF detection? |
|---|---|---|---|
| **ARM MTE** | No — Armv8.5-A/Armv9 only | n/a | No |
| **Intel LAM** | No — Arrow Lake/Lunar Lake/Xeon 6 E-core | No documented API | No |
| **AMD UAI** | No — Zen 4+ | No documented API | No |
| **Intel MPX** | No — Intel-only, removed from 2019+ HW | Deprecated/removed | No (and no temporal safety anyway) |
| **CET / Shadow Stack** | **Yes** — Zen 3 supports CET_SS | Yes, per-process opt-in | **No** — control-flow only |
| **PKU / PKEY** | **Yes** — Zen 3 has PKE (`RDPKRU`/`WRPKRU`) | **No documented Win32 API** | Hardware exists but unreachable; page-granular, unprivileged, bypassed by syscalls |
| **HW watchpoints (DR0–DR3)** | Yes | Yes (`SetThreadContext` → `EXCEPTION_SINGLE_STEP`) | **Yes, but ≤4 addresses/thread, ≤8 bytes each, aligned, per-thread** |

Sources: [Linux MTE docs](https://docs.kernel.org/arch/arm64/memory-tagging-extension.html),
[Android MTE](https://source.android.com/docs/security/test/memory-safety/arm-mte),
[LAM (LWN)](https://lwn.net/Articles/902094/),
[UAI (LWN)](https://lwn.net/Articles/888914/),
[AMD PKE](https://www.phoronix.com/news/AMD-PRM-PCID-PKEY),
[Intel MPX](https://en.wikipedia.org/wiki/Intel_MPX),
[Windows HESP](https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection),
[protection keys](https://docs.kernel.org/core-api/protection-keys.html),
[Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants),
[hardware breakpoints](https://ling.re/hardware-breakpoints/).

MTE details worth keeping: allocation tags are **4 bits per 16-byte granule**
stored with physical memory; the logical tag comes from bits 59–56 of the
pointer (TBI); SYNC faults immediately, ASYNC defers to the next kernel entry,
ASYMM checks reads synchronously and writes asynchronously; with
`M_MEMTAG_TUNING_UAF` it gives "uniform ~93 % probability of detecting both
spatial and temporal bugs". It is the ideal primitive for this problem and it
is simply not on x86.

**Conclusion**: no hardware memory tagging is usable here. The detector must be
page protection (`VirtualAlloc`/`VirtualProtect`) plus software bookkeeping.
Hardware watchpoints are a supplement for ≤4 pre-identified addresses.

v0.6 implements that supplement (DESIGN §13). It is precisely because the four
slots are per-thread and cannot cover a heap that the implementation is a
*sampled* detector with an explicit arming strategy, an alloc-site filter, a
bounded pending queue and a hold timeout - not a shadow heap. What it adds over
page protection is the one thing page protection cannot give: the identity of
the **writer**, at the moment of the write.

---

## 7. Pointer-integrity and lifetime mitigations (the "auto-fix" family)

- **Pointer invalidation / nulling**: DangNull and FreeSentry (NDSS'15) track
  the causal relations or the pointers themselves and null out every pointer to
  a block at free time, so a later dereference is a clean null fault rather than
  a UAF. **CRCount** (CCS'18) does it with reference counting; **MarkUs**
  (IEEE S&P'20) uses a quarantine plus pointer marking. This is the *correct*
  answer to "fix it" and it is impossible for us: it requires rewriting every
  store that could hold a pointer, i.e. recompilation.
- **Delayed free / reuse (FFM, Oscar)**: never reuse a freed virtual address, so
  a UAF can only touch an unmapped page. Requires owning the address space.
- **Reference-count validation**: CRCount's core observation — if you can see
  AddRef/Release, you can detect an over-release *before* it frees the object.
  This is exactly our `GRefCountImpl` guard, and it is the highest-value,
  lowest-cost item in the design because it needs no allocator ownership.
- **Vtable / CFI checks**: validating that a "vtable" pointer is plausible and
  that its first slot is executable is a poor-man's CFI, and precisely the check
  that catches the TrueHUD crash (`RAX = 0x141A2E20C`, misaligned, in `.rdata`).

**Honest framing**: we cannot invalidate pointers, but we *can* (a) refuse the
specific dangerous operation, (b) make the bad access fault on a page we
control, or (c) make the value read recognisable (poison) and verify it later.

---

## 8. Vectored exception handling: semantics and constraints

Sources: [VEH](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling),
[AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler),
[guard pages](https://learn.microsoft.com/en-us/windows/win32/Memory/creating-guard-pages),
[VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect).

- "Vectored handlers are called in the order that they were added, after the
  debugger gets a first chance notification, but before the system begins
  unwinding the stack." `First != 0` = called first.
- Return `EXCEPTION_CONTINUE_EXECUTION` to resume at the faulting instruction;
  `EXCEPTION_CONTINUE_SEARCH` to continue the handler chain.
- **`CONTINUE_EXECUTION` re-executes the faulting instruction.** If you did not
  make it succeed, you get an infinite loop. For a page-protection fault the fix
  is to restore access and retry.
- **`PAGE_GUARD` is one-shot**: the system clears the modifier after the first
  access, so repeated detection requires the single-step re-arm dance
  (`EFlags |= 0x100`, handle `STATUS_SINGLE_STEP`, re-`VirtualProtect`).
- "The handler should not call functions that acquire synchronization objects or
  allocate memory, because this can cause problems."
- `VirtualProtect` must not be used on `HeapAlloc`/`LocalAlloc`/`GlobalAlloc`
  blocks: "multiple memory blocks can exist on a single page" and "the heap
  manager assumes that all pages in the heap grant at least read and write
  access". Guarded memory must therefore be a **dedicated pool** returned by our
  own allocator — which is why detouring is a prerequisite, not an alternative.
- If the DLL owning the handler unloads, the handler stays registered: always
  `RemoveVectoredExceptionHandler`.

**Design consequences**: register first (`First != 0`) so we run before
CrashLoggerSSE; fix up only faults inside our own pool; return
`EXCEPTION_CONTINUE_SEARCH` for everything else so we never swallow a real
crash; and keep the handler allocation-free. (v0.1's `Report` builds
`std::string`s — a documented hazard to fix with a preallocated ring buffer.)

---

## 9. The Skyrim allocator landscape

Everything below is from the pinned CommonLibSSE-NG checkout
(`lib/CommonLibSSE-NG/include/RE/…`), which is why the code can stay portable:
targets are `REL::RelocationID`/`RELOCATION_ID` and `RE::` types, not raw
offsets.

### 9.1 The engine heap

- **`RE::MemoryManager`** (`RE/M/MemoryManager.h`, 0x480 bytes) — the facade.
  `heaps[]`, `heapsByContext[127]`, per-thread `ThreadScrapHeap*`,
  `bigAllocHeap`, `emergencyHeap`, `defaultHeap`, `BSSmallBlockAllocator*`,
  `CompactingStore::Store*`, counters. IDs: `GetSingleton` (11045/11141),
  `Allocate` (66859/68115), `Deallocate` (66861/68117), `Reallocate`
  (66860/68116), `GetThreadScrapHeap` (66841/68088), `Size` (66849/68100),
  `AutoScrapBuffer` ctor/dtor (66853/68108, 66854/68109), init (66862/68121).
- **`RE::ScrapHeap`** (`RE/S/ScrapHeap.h`, an `IMemoryStore`) — per-thread
  region allocator over `VirtualAlloc` (reserve 64 MiB, commit 128 KiB).
  `Block{ sizeFlags; prev; }` header (`Size()` masks `~(3<<62)`),
  `smallBlocks[6]`, `freeList` red-black tree, `ContainsBlockImpl()`,
  `Size()` reading the header. IDs: ctor 66882/68142, `Allocate` 66884/68144,
  `Deallocate` 66885/68146, `Clean` 66891/68152, `InsertFreeBlock` 66894/68155,
  `RemoveFreeBlock` 66895/68156, dtor 66883/68143.
- **`RE::MemoryHeap : AbstractHeap : IMemoryHeap`** (`RE/M/MemoryHeap.h`,
  `RE/A/AbstractHeap.h`) — the large heaps. `AbstractHeap` has
  `smallFreeLists[32]`, `largeFreeTrees[32]`, a `blockHead`/`blockTail` chain
  of `HeapBlock`s, and live stats (`memAllocated`, `numBlocks`,
  `numFreeBlocks`).
- **`RE::HeapBlock`** (`RE/H/HeapBlock.h`) — **the find of the survey**. Header
  is `memSize`, `previous`, a `Free`/`Used` union, `nextFree`. The `Used`
  variant carries `memContext` bits, **22 `stackTrace` bits** and 2
  `checkPoint` bits, with `GetStackTrace()`, `GetCheckPoint()`,
  `GetMemContext()`. **The engine already stores per-allocation
  stack-trace/checkpoint metadata in its own block headers.** A sentinel can
  read that for free instead of maintaining a parallel stack table, at least for
  `MemoryHeap`-backed allocations.
- **`RE::BSSmallBlockAllocator`** (`RE/B/BSSmallBlockAllocator.h`) — pooled
  small blocks, `Pool` with a `BSCriticalSection`, `MegaBlockPage`,
  `BlockPageInternal` with a `check` field. `AllocateAlignImpl` 68428.
- **`RE::ZeroOverheadHeap`** (`RE/Z/ZeroOverheadHeap.h`) — bump allocator with
  **no per-allocation header**; `Deallocate` is a no-op and `Size` cannot be
  read back. Anything reading a size header must exclude it.
- **`RE::CompactingStore::Store`** (`RE/C/CompactingStore.h`) — compacting store
  with 66 small free lists and a `batchDeallocateTlsSlot` (batched deallocation
  is highly relevant to UAF timing).

### 9.2 The other heaps (not `MemoryManager`)

- **Havok**: `RE::hkMemoryRouter` / `hkThreadMemory` / `hkMemoryAllocator` /
  `hkLifoAllocator`.
- **Scaleform**: `RE::GMemoryHeap` / `RE::GMemoryHeapPT` — the allocator that
  matters for the crashes that motivated the project. IDs: `Alloc` 84498/84499,
  `AllocAutoHeap` 84501/84502, `AllocSysDirect` 84504, **`Free` 84520**,
  `FreeSysDirect` 84523, `Realloc` 84540, `GetUsableSize` 84536, `CreateHeap`
  84513, `CreateArena` 84511, `DestroyArena` 84518.
- **Scaleform refcounting**: `RE::GRefCountImpl` — `AddRef` 82195, **`Release`
  82197** (the crash: `lock xadd [rcx+8],-1; … mov rax,[rcx]; jmp [rax]`),
  `GRefCountImplCore::dtor` 33606, `dtor_impl` 82192.
- **The CRT** (`ucrtbase`/`msvcp140`) and every plugin's static CRT — not
  covered by MemoryManager.
- **Direct OS calls** (`VirtualAlloc`/`HeapAlloc`) — not covered.

### 9.3 Coverage consequence

A `MemoryManager` shadow allocator covers **engine objects**, not Scaleform
objects, not plugin-CRT objects, not Havok objects. For the crashes in this
project the relevant layer is **Scaleform** (`GMemoryHeapPT` +
`GRefCountImpl`), so those are hooked in addition. And a sampled guarded block
must never be handed back to the engine's heap code: the engine's
`ContainsBlockImpl`/`Size` would not recognise it, so frees and reallocs of our
blocks must be intercepted — or the block must not be sampled at all.

---

## 10. Skyrim prior art: nobody has built this

Sources: [CrashLoggerSSE](https://github.com/alandtse/CrashLoggerSSE),
[EngineFixesSkyrim64](https://github.com/aers/EngineFixesSkyrim64),
[.NET Script Framework](https://github.com/meh321/NetScriptFramework),
[SkyrimCrashGuard](https://github.com/parkerchace/SkyrimCrashGuard),
[community-shaders#1654](https://github.com/community-shaders/skyrim-community-shaders/issues/1654).

- **CrashLoggerSSE** is a **post-crash VEH dumper**: `Crash::Install` at
  `SKSEPluginLoad`, frames captured with `RtlCaptureStackBackTrace` from an
  `_EXCEPTION_RECORD`/`_CONTEXT`, the faulting instruction disassembled with
  Zydis, and PDB symbolization through the DIA SDK (`msdia140.dll`). The
  familiar `-> NNNN+0xNN` field is CommonLibSSE-NG's `REL::Offset2ID`
  inverting an offset back to an Address Library **id** (so it is an id, not a
  byte offset). It cannot see heap corruption or allocation provenance.
- **Trainwreck** is the successor crash logger; no public source, no documented
  internals.
- **.NET Script Framework** is a managed framework with `Memory.Allocate` (its
  own allocator) and the "possible relevant objects" crash-log section — object
  introspection, not allocator sanitization.
- **EngineFixes** is the one plugin that systematically hooks the allocators —
  to **replace** them with tbbmalloc/CRT: `MemoryManager` (66859/68115 etc.),
  `ScrapHeap` (ctor/Allocate/Deallocate 66882–66885, and it stubs
  `Clean`/`InsertFreeBlock`/`RemoveFreeBlock`/dtor), the Scaleform
  `GMemoryHeap` (via the heap-init call site 80300/82323 + 0xED/0x16C), Havok,
  and the render-pass cache. It installs extremely early through the
  `d3dx9_42.dll` preloader. It is known to be incompatible with RaceMenu's
  NIOverride and has a history of allocator-related crashes. It *replaces*, it
  does not *instrument*.
- **GCBugFix** fixes the Papyrus VM garbage collector (one array item cleaned
  per VM frame); **BugFixesSSE** and **ActorLimitFix** patch engine limits —
  none hook the allocator.
- **SkyrimCrashGuard** is VEH-based crash *recovery* (six layers: known site,
  instruction pattern, learned site, register fixup, instruction skip, function
  return, deep stack walk) and explicitly does **not** free or track memory:
  "Memory tracking does NOT free memory — it only monitors and warns".
- **When this ecosystem actually hunts a heap bug, it uses Application
  Verifier**, not a plugin: in the Community Shaders heap-corruption
  investigation the recommendation was AppVerifier, with the note that
  "CrashloggerSSE doesn't catch heap corruption or appverifier breakpoints", and
  the bug was ultimately fixed mod-side rather than detected.

**So: the hooks are well mapped, the API surface exists, and no one has used it
for shadow-memory/poisoning or access-time detection.** HeapSentinel is filling
a real gap, and §9 gives the exact chokepoints EngineFixes already proves are
hookable.

---

## 11. Transfer matrix

| Technique | Source | Transfers | Notes |
|---|---|---|---|
| Address-range → metadata mapping | hardened_malloc, PartitionAlloc | **Yes** | Side-table ledger, sharded, lock-free |
| Double-free / invalid-free detection | hardened_malloc, Scudo | **Yes** | Deterministic, cheap; highest value |
| Quarantine + delayed reuse | hardened_malloc, Scudo, ASan | **Sampled only** | Can't delay the engine's free list |
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
| PageHeap / AppVerifier | Microsoft | **Offline only** | Pre-launch, whole-process, 4 KB/alloc |
| Hardware watchpoints | x86 DR0–DR3 | **Targeted only** | ≤4 addresses/thread, ≤8 bytes |
| Reading the engine's own alloc stacks | `HeapBlock::Used` | **Yes** | Free provenance for `MemoryHeap` blocks |

---

## 12. Design consequences

1. **Two independent detection tiers**, because they fail in different ways:
   - *Tier A, always-on, cheap, safe*: shadow ledger on the hooked allocators
     (double free, invalid free, sized-dealloc mismatch) plus the
     `GRefCountImpl::Release` vtable guard with optional fail-safe. This is the
     tier that would have turned the TrueHUD crash into a one-line report.
   - *Tier B, opt-in, sampled*: GWP-ASan-style guarded pool for a size range,
     giving deterministic UAF/OOB faults with alloc/free stacks. Riskier
     because sampled blocks are foreign to the engine, hence opt-in.
2. **Fail safe, never repair.** Skipping a destructor dispatch leaks; it does
   not fix the object graph. Repair is out of scope by construction (§7).
3. **Never allocate or take a contended lock inside a hook or the VEH.**
   Thread-local rings, preallocated sharded tables, deferred symbolization and
   I/O. (v0.1 violates this in `Report`; it is a roadmap item.)
4. **Portability via CommonLibSSE-NG.** All targets are `REL::RelocationID` /
   `RELOCATION_ID` + `RE::` types, so SE/AE/VR address selection is the
   library's job. Verified 1.7.104 ids are in §9.
5. **The report is a first-class feature**: kind, faulting/object address
   classified, pre-crash stack, alloc and free stacks, object bytes, registers,
   and optionally a screenshot and a freeze.
6. **Upgrade MinHook to SafetyHook** (or verify prologues before installing)
   once the hooks are proven; MinHook's length-only relocator is the weakest
   link in the current build.

---

## 13. References

Allocators and detectors:
[hardened_malloc](https://github.com/GrapheneOS/hardened_malloc) ·
[Scudo](https://llvm.org/docs/ScudoHardenedAllocator.html) ·
[PartitionAlloc](https://chromium.googlesource.com/chromium/src/+/main/base/allocator/partition_allocator/PartitionAlloc.md) ·
[mimalloc](https://github.com/microsoft/mimalloc) ·
[GWP-ASan (LLVM)](https://llvm.org/docs/GwpAsan.html) ·
[GWP-ASan (Chromium)](https://www.chromium.org/Home/chromium-security/articles/gwp-asan/) ·
[GWP-ASan in production (Trail of Bits)](https://blog.trailofbits.com/2025/12/16/use-gwp-asan-to-detect-exploits-in-production-environments/) ·
[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) ·
[Dr. Memory](https://drmemory.org/)

Windows and hardware:
[GFlags and PageHeap](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-and-pageheap) ·
[Application Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier-testing-applications) ·
[Chromium page heap notes](https://www.chromium.org/developers/testing/page-heap-for-chrome/) ·
[randomascii page heap measurements](https://randomascii.wordpress.com/2011/12/07/increased-reliability-through-more-crashes/) ·
[HeapSetInformation](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsetinformation) ·
[Segment Heap internals](https://blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf) ·
[ARM MTE (kernel)](https://docs.kernel.org/arch/arm64/memory-tagging-extension.html) ·
[ARM MTE (Android)](https://source.android.com/docs/security/test/memory-safety/arm-mte) ·
[Intel LAM](https://lwn.net/Articles/902094/) ·
[AMD UAI](https://lwn.net/Articles/888914/) ·
[AMD PKE](https://www.phoronix.com/news/AMD-PRM-PCID-PKEY) ·
[Intel MPX](https://en.wikipedia.org/wiki/Intel_MPX) ·
[protection keys](https://docs.kernel.org/core-api/protection-keys.html) ·
[Windows HESP](https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection) ·
[Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants) ·
[hardware breakpoints](https://ling.re/hardware-breakpoints/)

Hooking and exceptions:
[Detours interception](https://github.com/microsoft/Detours/wiki/OverviewInterception) ·
[DetourUpdateThread](https://github.com/microsoft/Detours/wiki/DetourUpdateThread) ·
[MinHook](https://github.com/TsudaKageyu/minhook) ·
[SafetyHook](https://github.com/cursey/safetyhook) ·
[funchook](https://github.com/kubo/funchook) ·
[CommonLibSSE-NG Trampoline](https://github.com/CharmedBaryon/CommonLibSSE-NG/blob/main/include/SKSE/Trampoline.h) ·
[/hotpatch](https://learn.microsoft.com/en-us/cpp/build/reference/hotpatch-create-hotpatchable-image) ·
[VEH](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling) ·
[AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectorexceptionhandler) ·
[guard pages](https://learn.microsoft.com/en-us/windows/win32/Memory/creating-guard-pages) ·
[VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

Skyrim:
[CrashLoggerSSE](https://github.com/alandtse/CrashLoggerSSE) ·
[EngineFixesSkyrim64](https://github.com/aers/EngineFixesSkyrim64) ·
[.NET Script Framework](https://github.com/meh321/NetScriptFramework) ·
[SkyrimCrashGuard](https://github.com/parkerchace/SkyrimCrashGuard) ·
[community-shaders#1654](https://github.com/community-shaders/skyrim-community-shaders/issues/1654) ·
CommonLibSSE-NG headers under `lib/CommonLibSSE-NG/include/RE/`

Pointer invalidation line of work: DangNull and FreeSentry (NDSS 2015), CRCount
(CCS 2018), MarkUs (IEEE S&P 2020).
