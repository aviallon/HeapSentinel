# `hooks/` — committed hook-target verification tables

One table per **exact game build**. The plugin refuses to install a hook whose
target it cannot verify against the table for the running binary, and reports
`DEGRADED` instead.

| file | what it is |
|---|---|
| `skyrimse-<version>-<sha256-prefix>.json` | the verification table for one exact build |
| `addresslibrary-<version>.json` | the id→offset slice the table was built from, committed so CI can cross-check every RVA |

## Identity

`identity` records the cheap, runtime-available facts plus the full hash:

| field | why |
|---|---|
| `size` | the on-disk size of `SkyrimSE.exe`; cheap to read, catches a re-packed build |
| `timeDateStamp` | the PE `TimeDateStamp`; survives a re-download of the same build |
| `sizeOfImage` | `OptionalHeader.SizeOfImage`; catches a different link layout |
| `sha256` | the full digest, recorded by the generator and checked by CI/dev tooling — **not** recomputed at load time (38 MB) |
| `version` | `1.7.104.0`, as read from the Address Library header |

At load time the plugin compares the three cheap fields only. That is deliberate:
the full SHA-256 would add ~0.2 s to every game start for no extra safety, since
a mismatch on any of the three cheap fields already refuses every hook.

## Per-target record

```json
{
  "target": "GMemoryHeapPT::Free",
  "kind": "vtable",
  "seId": 0,
  "aeId": 84520,
  "name": "GMemoryHeapPT::Free_*",
  "rva": 18337680,
  "pdataExtent": 45,
  "slotLength": 45,
  "prologueLength": 32,
  "prologueHash": 12008167501414941817,
  "vtable": { "id": 242891, "name": "??_7GMemoryHeapPT@@6B@", "rva": 27903248, "slot": 12 }
}
```

* `aeId` — the AE Address Library id the installer resolves via
  `REL::RelocationID(0, aeId)`.
* `seId` — the SE id as declared in `src/Hooks/HookTargets.def`. Recorded for
  provenance; **not verified** (the table is AE-only).
* `name` — from `meh321/AddressLibraryDatabase` (see provenance below).
* `rva` — image-base-relative address of the function.
* `pdataExtent` — length of the `.pdata` unwind region that starts at the RVA
  (`null` when the function has no unwind entry, e.g. a leaf function).
* `slotLength` — distance to the next distinct `.pdata` begin: an upper bound on
  how far the function's code can extend before another one starts. The prologue
  read is bounded by `min(prologueLength, pdataExtent ?? slotLength)` so it can
  never run into the next function.
* `prologueLength` / `prologueHash` — the number of bytes and the 64-bit
  **FNV-1a** hash of the function's first bytes (`N = 32`, shortened when the
  bound above requires it). FNV-1a, not SHA-256, because this is an accidental-
  mismatch detector, not a security boundary, and the same 20 lines implement it
  identically in C++ and Python (pinned by a unit test).
* `vtable` — for a virtual target: the Address Library id of the vtable symbol,
  its RVA, and the slot index that must hold the function. The runtime check
  reads that slot and requires it to equal `base + rva`.

## Licensing: hashes and offsets, not code

**No byte of `SkyrimSE.exe` is committed.** A 32-byte prologue × 14 targets is
~450 bytes, but it is still a verbatim extract of Bethesda's copyrighted binary,
and it is unnecessary: a hash verifies identity exactly as well. The table
carries an RVA, a length and a hash. `licensing.prologueBytesCommitted` is
`false` and CI fails if it ever becomes true.

If a future mismatch ever needs to be *localised* rather than merely detected, a
small, explicitly documented set of anchor bytes could be added — that would be
a conscious decision with its own rationale, not a default.

**Name provenance.** The `name` fields come from
[`meh321/AddressLibraryDatabase`](https://github.com/meh321/AddressLibraryDatabase)
(`skyrimae.rename`, commit `0379cb6`). That repository carries **no LICENSE
file** (checked 2026-09-22). What is committed here is a handful of symbol names
used as identifiers and provenance, not a copy of the database. The `names`
block in each table records the source, the commit and this licence status, so
the provenance is explicit rather than silently vendored.

## Regenerating

Supporting a new game version is meant to be mechanical and reviewable:

```
tools/gen-hooktable.py \
  --exe       "<path>/SkyrimSE.exe" \
  --versionlib "<path>/Data/SKSE/Plugins/versionlib-1-7-104-0.bin" \
  --names     "<path>/skyrimae.rename"
```

It writes the table, the Address Library slice, and the embedded header
`src/Hooks/HookTableData.gen.h`. Then review the diff (the point of committing
the table is that a changed RVA, slot or hash is *visible* in review) and commit
all three. The exe is never copied into the repository.

The generator **fails** when:

* the Address Library does not name the exe it was given;
* a target id is absent from the Address Library;
* a vtable slot does not hold the expected function (investigate the layout —
  do not just update the slot number);
* fewer than 8 bytes are available for a prologue hash;
* the target list in `src/Hooks/HookTargets.def` is malformed or duplicated.

## CI

`tools/check-hooktable.py` runs as its own CI job and needs no game binary and
no third-party Address Library file:

* **completeness** — every target in `src/Hooks/HookTargets.def` has an entry,
  and every entry names a target that exists in the source. Adding a hook
  without a verified signature fails the build.
* **ids** — kind / se id / ae id / vtable id / slot agree between source and
  table.
* **consistency** — every record's RVA equals the committed Address Library
  slice's offset for its id (and the vtable's RVA likewise). The slice records
  the Address Library file's SHA-256, so the dev-side regeneration is auditable;
  CI cannot re-read that file because it is a third-party mod file that is not
  redistributable.
* **internal** — no duplicate RVAs, vtable slots unique per vtable id, prologue
  signatures distinct, no two prologue windows overlap, every field present and
  in range, identity self-consistent with the filename.
* **embedded** — `src/Hooks/HookTableData.gen.h` is byte-identical to the header
  regenerated from the committed JSON, so the DLL's copy cannot drift.

## Honest limits

* **Identity, not semantics.** A hook can sit at the right address with the right
  prologue and still be wrong for our purpose. The `GMemoryHeapPT` argument
  counts came from disassembly precisely because the header comment order was
  wrong; no signature check would have caught that. This table complements the
  disassembly-derived signatures, it does not replace them.
* **AE-only**, matching the existing `RelocationID(0, ae)` convention. The SE
  ids in `HookTargets.def` are recorded, not verified.
* **Mod DLLs are not covered.** For attribution the plugin prints
  `module+offset`, and resolution happens offline against that mod's shipped PDB.
* A prologue hash proves the bytes match *the build the table was generated
  from*. It does not prove those bytes mean what the hook assumes they mean.
