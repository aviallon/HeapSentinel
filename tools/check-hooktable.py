#!/usr/bin/env python3
"""Validate HeapSentinel's committed hook-target verification table.

This is the CI gate that replaces "we trust the Address Library blindly". It
needs no game binary and no third-party Address Library file: it checks the
committed data against the committed data, plus the canonical target list in the
source. It exits non-zero on the first category of failure it finds, and prints
every individual violation it saw, so a red job names what is wrong.

Checks
------
  completeness   every target in src/Hooks/HookTargets.def has a table entry,
                 and every table entry names a target that exists in the source.
                 -> adding a hook without a verified signature FAILS THE BUILD.
  ids            kind / se id / ae id / vtable id / vtable slot agree between
                 the source and the table.
  consistency    each record's rva matches the id->offset slice committed
                 alongside it (hooks/addresslibrary-*.json), which the generator
                 read from the Address Library. The slice records the Address
                 Library's SHA-256 so the dev-side regeneration is auditable.
  internal       no duplicate RVAs; vtable slots unique per vtable id; prologue
                 signatures distinct; no two prologue windows overlap; every
                 field present and in range; identity self-consistent.
  embedded       src/Hooks/HookTableData.gen.h is byte-identical to the header
                 regenerated from the committed JSON.

Run from the repository root:  tools/check-hooktable.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

DEFS = os.path.join(ROOT, "src", "Hooks", "HookTargets.def")
HOOKS_DIR = os.path.join(ROOT, "hooks")
HEADER = os.path.join(ROOT, "src", "Hooks", "HookTableData.gen.h")

REQUIRED_RECORD_FIELDS = (
    "target", "kind", "seId", "aeId", "name", "rva",
    "pdataExtent", "slotLength", "prologueLength", "prologueHash",
)

errors: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)
    print(f"::error::{msg}")


def load_generator():
    path = os.path.join(HERE, "gen-hooktable.py")
    spec = importlib.util.spec_from_file_location("gen_hooktable", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_table_against_defs(table: dict, defs: list, def_path: str) -> None:
    records = {r.get("target"): r for r in table["targets"]}
    src = {d["target"]: d for d in defs}

    missing = sorted(set(src) - set(records))
    extra = sorted(set(records) - set(src))
    if missing:
        err(f"{def_path}: target(s) with no entry in the committed table: "
            f"{', '.join(missing)}. Regenerate the table with tools/gen-hooktable.py.")
    if extra:
        err(f"committed table has entr(ies) for target(s) not in {def_path}: "
            f"{', '.join(extra)}. Remove the stale entry or add the target to the source.")

    for name in sorted(set(src) & set(records)):
        s, r = src[name], records[name]
        if r["kind"] != s["kind"]:
            err(f"{name}: kind {r['kind']!r} in the table, {s['kind']!r} in the source")
        if r["seId"] != s["seId"]:
            err(f"{name}: seId {r['seId']} in the table, {s['seId']} in the source")
        if r["aeId"] != s["aeId"]:
            err(f"{name}: aeId {r['aeId']} in the table, {s['aeId']} in the source")
        if s["kind"] == "vtable":
            vt = r.get("vtable")
            if not vt:
                err(f"{name}: source declares a vtable target but the table has no vtable block")
            else:
                if vt["id"] != s["vtableId"]:
                    err(f"{name}: vtable id {vt['id']} in the table, {s['vtableId']} in the source")
                if vt["slot"] != s["vtableSlot"]:
                    err(f"{name}: vtable slot {vt['slot']:#x} in the table, "
                        f"{s['vtableSlot']:#x} in the source")
        elif "vtable" in r:
            err(f"{name}: source declares an rva target but the table carries a vtable block")


def check_consistency(table: dict, slice_: dict, slice_path: str) -> None:
    if slice_["version"] != table["identity"]["version"]:
        err(f"{slice_path}: version {slice_['version']} does not match the table's "
            f"{table['identity']['version']}")
    if slice_["sha256"] != table["addressLibrary"]["sha256"]:
        err(f"{slice_path}: Address Library sha256 disagrees with the table's")
    base = slice_["base"]
    offsets = slice_["offsets"]

    used = set()
    for r in table["targets"]:
        used.add(str(r["aeId"]))
        got = offsets.get(str(r["aeId"]))
        if got is None:
            err(f"{r['target']}: aeId {r['aeId']} is not in {os.path.basename(slice_path)}")
        elif got != r["rva"]:
            err(f"{r['target']}: rva {r['rva']:#x} disagrees with the Address Library slice's "
                f"{got:#x} for id {r['aeId']}")
        if "vtable" in r:
            used.add(str(r["vtable"]["id"]))
            got = offsets.get(str(r["vtable"]["id"]))
            if got is None:
                err(f"{r['target']}: vtable id {r['vtable']['id']} is not in the slice")
            elif got != r["vtable"]["rva"]:
                err(f"{r['target']}: vtable rva {r['vtable']['rva']:#x} disagrees with the "
                    f"slice's {got:#x} for id {r['vtable']['id']}")
    extra = sorted(set(offsets) - used, key=int)
    if extra:
        err(f"{os.path.basename(slice_path)}: unused id(s) {', '.join(extra)} - the slice "
            f"must contain exactly the ids the table needs")
    if base != 0x140000000:
        err(f"{os.path.basename(slice_path)}: unexpected image base {base:#x}")


def check_internal(table: dict, path: str) -> None:
    ident = table["identity"]
    for field in ("module", "version", "size", "timeDateStamp", "sizeOfImage", "sha256"):
        if field not in ident:
            err(f"{path}: identity is missing {field!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", ident.get("sha256", "")):
        err(f"{path}: identity.sha256 is not a 64-char lowercase hex digest")
    expected_name = f"skyrimse-{ident['version']}-{ident['sha256'][:8]}.json"
    if os.path.basename(path) != expected_name:
        err(f"{path}: filename should be {expected_name}")

    if table.get("licensing", {}).get("prologueBytesCommitted") is not False:
        err(f"{path}: licensing.prologueBytesCommitted must be false - no bytes of the "
            f"game binary may be committed")

    rvas: dict[int, str] = {}
    slots: dict[tuple, str] = {}
    sigs: dict[tuple, str] = {}
    windows: list[tuple[int, int, str]] = []

    for r in table["targets"]:
        name = r.get("target", "<unnamed>")
        for field in REQUIRED_RECORD_FIELDS:
            if field not in r:
                err(f"{path}: {name}: missing field {field!r}")
        if not r.get("name"):
            err(f"{path}: {name}: empty meh321 name - the table must record provenance")
        if r.get("kind") not in ("rva", "vtable"):
            err(f"{path}: {name}: bad kind {r.get('kind')!r}")
        if not r.get("rva"):
            err(f"{path}: {name}: rva is 0")
        length = r.get("prologueLength", 0)
        if not 8 <= length <= 64:
            err(f"{path}: {name}: prologueLength {length} out of range [8, 64]")
        if not r.get("prologueHash"):
            err(f"{path}: {name}: prologueHash is 0")
        if r.get("pdataExtent") is not None and r["pdataExtent"] < length:
            err(f"{path}: {name}: prologueLength {length} exceeds the .pdata extent "
                f"{r['pdataExtent']}")
        if r.get("slotLength") is not None and r["slotLength"] < length:
            err(f"{path}: {name}: prologueLength {length} exceeds the slot length "
                f"{r['slotLength']} - the read would run into the next function")
        if r.get("kind") == "vtable" and "vtable" not in r:
            err(f"{path}: {name}: vtable kind without a vtable block")
        if r.get("kind") == "rva" and "vtable" in r:
            err(f"{path}: {name}: rva kind with a vtable block")

        if r.get("rva") in rvas:
            err(f"{path}: duplicate rva {r['rva']:#x} shared by {rvas[r['rva']]} and {name}")
        rvas.setdefault(r.get("rva"), name)

        if "vtable" in r:
            key = (r["vtable"]["id"], r["vtable"]["slot"])
            if key in slots:
                err(f"{path}: vtable id {key[0]} slot {key[1]:#x} claimed by both "
                    f"{slots[key]} and {name}")
            slots.setdefault(key, name)

        sig = (length, r.get("prologueHash"))
        if sig in sigs:
            err(f"{path}: prologue signature collision between {sigs[sig]} and {name}")
        sigs.setdefault(sig, name)

        windows.append((r.get("rva", 0), r.get("rva", 0) + length, name))

    windows.sort()
    for (a0, a1, n0), (b0, b1, n1) in zip(windows, windows[1:]):
        if b0 < a1:
            err(f"{path}: prologue windows of {n0} [{a0:#x},{a1:#x}) and {n1} "
                f"[{b0:#x},{b1:#x}) overlap")


def check_header_in_sync(gen) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "HookTableData.gen.h")
        gen.emit_header(HOOKS_DIR, out)
        with open(out, "rb") as f:
            regenerated = f.read()
    try:
        with open(HEADER, "rb") as f:
            committed = f.read()
    except FileNotFoundError:
        err(f"{HEADER} is missing - run tools/gen-hooktable.py")
        return
    if regenerated != committed:
        err(f"{os.path.relpath(HEADER, ROOT)} is out of sync with hooks/*.json - "
            f"regenerate it with tools/gen-hooktable.py --emit-header hooks "
            f"{os.path.relpath(HEADER, ROOT)}")


def main() -> int:
    gen = load_generator()
    defs = gen.load_targets(DEFS)

    tables = sorted(f for f in os.listdir(HOOKS_DIR)
                    if f.startswith("skyrimse-") and f.endswith(".json"))
    if not tables:
        err(f"{HOOKS_DIR}: no committed skyrimse-*.json table")
        return 1

    for filename in tables:
        path = os.path.join(HOOKS_DIR, filename)
        with open(path, encoding="utf-8") as f:
            table = json.load(f)
        if table.get("schema") != "heapsentinel.hooktable/1":
            err(f"{path}: unexpected schema {table.get('schema')!r}")
            continue
        slice_name = f"addresslibrary-{table['identity']['version']}.json"
        slice_path = os.path.join(HOOKS_DIR, slice_name)
        try:
            with open(slice_path, encoding="utf-8") as f:
                slice_ = json.load(f)
        except FileNotFoundError:
            err(f"{path}: no {slice_name} committed alongside it")
            continue
        check_table_against_defs(table, defs, os.path.relpath(DEFS, ROOT))
        check_consistency(table, slice_, os.path.relpath(slice_path, ROOT))
        check_internal(table, os.path.relpath(path, ROOT))
        print(f"checked {os.path.relpath(path, ROOT)}: {len(table['targets'])} targets")

    check_header_in_sync(gen)

    if errors:
        print(f"\nFAILED: {len(errors)} problem(s)")
        return 1
    print("\nOK: completeness, ids, consistency, internal invariants and the embedded "
          "header all agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
