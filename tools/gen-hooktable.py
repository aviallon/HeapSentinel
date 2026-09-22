#!/usr/bin/env python3
"""Regenerate HeapSentinel's committed hook-target verification table.

Usage
-----
  tools/gen-hooktable.py --exe <SkyrimSE.exe> --versionlib <versionlib.bin> \
                         --names <skyrimae.rename> --out-dir hooks
  tools/gen-hooktable.py --emit-header hooks src/Hooks/HookTableData.gen.h

The first form is the only one that needs the game: it reads the exact build
identity (size, PE TimeDateStamp, SizeOfImage, SHA-256), resolves every hook
target listed in src/Hooks/HookTargets.def through the Address Library, checks
each virtual target against the engine's own vtable, hashes each target's
prologue and writes:

  hooks/skyrimse-<version>-<sha256-prefix>.json   the table (one per exact build)
  hooks/addresslibrary-<version>.json             the id->offset slice it used
  src/Hooks/HookTableData.gen.h                   the same table embedded in the DLL

The second form needs nothing but the committed JSON, so CI regenerates the
embedded header from the committed table and fails if the two have drifted.
That is why the DLL can verify itself on an install that only copied the DLL:
the verified bytes travel inside it, and the committed JSON stays the reviewable
source of truth.

Nothing from SkyrimSE.exe is written to the repository: each record carries an
RVA, a length and a 64-bit hash of the first N bytes, never the bytes.
"""

from __future__ import annotations

import argparse
import array
import hashlib
import json
import os
import re
import struct
import sys

BASE = 0x140000000
PROLOGUE_BYTES = 32
MIN_PROLOGUE_BYTES = 8
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3

HOOK_TARGET_RE = re.compile(
    r'^HOOK_TARGET\(\s*(\w+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*(k\w+)\s*,'
    r'\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)\s*$'
)


def fnv1a64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- PE


class PE:
    """Minimal PE reader. Addresses are RVAs (image-base relative)."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.d = f.read()
        d = self.d
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe : pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: not a PE file")
        self.nsec, self.timedate = struct.unpack_from("<HI", d, pe + 6)
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        opt = pe + 24
        self.imagebase = struct.unpack_from("<Q", d, opt + 24)[0]
        self.sizeofimage = struct.unpack_from("<I", d, opt + 56)[0]
        secs = []
        off = opt + optsz
        for _ in range(self.nsec):
            name = d[off : off + 8].rstrip(b"\0").decode(errors="replace")
            vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", d, off + 8)
            secs.append({"name": name, "rva": rva, "vsize": vsize,
                         "rawptr": rawptr, "rawsize": rawsize})
            off += 40
        self.secs = secs
        self._pdata = None

    def sec(self, name: str):
        for s in self.secs:
            if s["name"] == name:
                return s
        return None

    def rva2off(self, rva: int):
        for s in self.secs:
            span = max(s["vsize"], s["rawsize"])
            if s["rva"] <= rva < s["rva"] + span:
                delta = rva - s["rva"]
                if delta < s["rawsize"]:
                    return s["rawptr"] + delta
        return None

    def read(self, rva: int, n: int):
        o = self.rva2off(rva)
        return self.d[o : o + n] if o is not None else None

    def qword(self, rva: int):
        b = self.read(rva, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

    def pdata(self):
        """(begin_rva, end_rva, unwind_rva) triples from .pdata."""
        if self._pdata is None:
            s = self.sec(".pdata")
            if s is None:
                self._pdata = []
            else:
                n = s["rawsize"] // 12
                self._pdata = [
                    struct.unpack_from("<III", self.d, s["rawptr"] + i * 12)
                    for i in range(n)
                ]
        return self._pdata

    def text_ranges(self):
        return [(s["rva"], s["rva"] + s["vsize"])
                for s in self.secs if s["name"].startswith(".text")]

    def in_text(self, va: int) -> bool:
        rva = va - self.imagebase
        return any(a <= rva < b for a, b in self.text_ranges())

    def pdata_extent(self, rva: int):
        """Length of the .pdata entry that starts exactly at rva, or None.

        MSVC emits one RUNTIME_FUNCTION per unwind region; a function with
        funclets can therefore be split into several. This returns the first
        region's length verbatim rather than guessing at a merge (adjacent
        entries can belong to different functions), and slot_length() below
        gives the safe upper bound.
        """
        ends = [e for (b, e, _u) in self.pdata() if b == rva]
        return (max(ends) - rva) if ends else None

    def slot_length(self, rva: int):
        """Distance to the next distinct .pdata begin - an upper bound on how
        far this function's code can extend before another one starts."""
        begins = sorted({b for (b, _e, _u) in self.pdata() if b > rva})
        return (begins[0] - rva) if begins else None


# ---------------------------------------------------------------- Address Library


class AddressLibrary:
    """Format-5 Address Library: 96-byte header then a dense uint32 array
    indexed by id; VA = imagebase + offset. This is the same reader
    CommonLibSSE-NG uses (REL/IDDB.h, Format::SSEv5)."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            d = f.read()
        self.size = len(d)
        fmt = struct.unpack_from("<i", d, 0)[0]
        if fmt != 5:
            raise ValueError(f"{path}: Address Library format {fmt}, expected 5")
        self.format = fmt
        self.version = struct.unpack_from("<4I", d, 4)
        self.name = d[20:84].split(b"\0")[0].decode("latin1")
        self.pointer_size, self.data_format, self.count = struct.unpack_from("<iii", d, 84)
        arr = array.array("I")
        arr.frombytes(d[96 : 96 + self.count * 4])
        self.offsets = arr

    @property
    def version_string(self) -> str:
        return ".".join(str(v) for v in self.version)

    def rva(self, id_: int):
        if id_ < 0 or id_ >= self.count:
            return None
        off = self.offsets[id_]
        return off or None

    def id_of_rva(self, rva: int):
        for i, o in enumerate(self.offsets):
            if o == rva:
                return i
        return None

    def slice_for(self, ids) -> dict:
        out = {}
        for i in sorted(set(ids)):
            rva = self.rva(i)
            if rva is None:
                raise ValueError(f"Address Library id {i} is absent in {self.path}")
            out[str(i)] = rva
        return out


def load_names(path: str) -> dict:
    """meh321/AddressLibraryDatabase `skyrimae.rename`: '<id> <name>' lines."""
    names = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            sp = line.find(" ")
            if sp > 0:
                try:
                    names[int(line[:sp])] = line[sp + 1 :].strip()
                except ValueError:
                    pass
    return names


# ------------------------------------------------------------------ target list


def load_targets(def_path: str):
    targets = []
    seen = set()
    with open(def_path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.split("//", 1)[0].strip()
            if not line:
                continue
            m = HOOK_TARGET_RE.match(line)
            if not m:
                raise ValueError(f"{def_path}:{lineno}: unparsable HOOK_TARGET line: {raw.strip()!r}")
            enum, name, kind, se, ae, vt, slot = m.groups()
            kind = "rva" if kind == "kRva" else "vtable" if kind == "kVtable" else None
            if kind is None:
                raise ValueError(f"{def_path}:{lineno}: unknown kind {kind!r}")
            if enum in seen:
                raise ValueError(f"{def_path}:{lineno}: duplicate enum id {enum}")
            seen.add(enum)
            if name in {t["target"] for t in targets}:
                raise ValueError(f"{def_path}:{lineno}: duplicate target name {name!r}")
            if kind == "vtable" and (int(vt) == 0 or int(slot) == 0):
                raise ValueError(f"{def_path}:{lineno}: vtable target needs a vtable id and slot")
            if kind == "rva" and (int(vt) != 0 or int(slot) != 0):
                raise ValueError(f"{def_path}:{lineno}: rva target must not carry a vtable id/slot")
            targets.append({
                "enum": enum, "target": name, "kind": kind,
                "seId": int(se), "aeId": int(ae),
                "vtableId": int(vt), "vtableSlot": int(slot),
            })
    if not targets:
        raise ValueError(f"{def_path}: no HOOK_TARGET entries")
    return targets


# ------------------------------------------------------------------- generation


def build_table(exe_path: str, vlib_path: str, names_path: str, def_path: str):
    pe = PE(exe_path)
    vlib = AddressLibrary(vlib_path)
    names = load_names(names_path)
    targets = load_targets(def_path)

    # Sanity: the Address Library we were handed must describe this exact exe.
    if vlib.name != os.path.basename(exe_path):
        raise ValueError(f"Address Library names {vlib.name!r}, expected {os.path.basename(exe_path)!r}")

    records = []
    used_ids = set()
    for t in targets:
        fn_rva = vlib.rva(t["aeId"])
        if fn_rva is None:
            raise ValueError(f"target {t['target']}: AE id {t['aeId']} absent from the Address Library")
        used_ids.add(t["aeId"])
        fn_va = BASE + fn_rva

        rec = {
            "target": t["target"],
            "kind": t["kind"],
            "seId": t["seId"],
            "aeId": t["aeId"],
            "name": names.get(t["aeId"], ""),
            "rva": fn_rva,
            "pdataExtent": pe.pdata_extent(fn_rva),
            "slotLength": pe.slot_length(fn_rva),
        }

        if t["kind"] == "vtable":
            vt_rva = vlib.rva(t["vtableId"])
            if vt_rva is None:
                raise ValueError(f"target {t['target']}: vtable id {t['vtableId']} absent")
            used_ids.add(t["vtableId"])
            slot = t["vtableSlot"]
            actual = pe.qword(vt_rva + slot * 8)
            if actual != fn_va:
                raise ValueError(
                    f"target {t['target']}: vtable {names.get(t['vtableId'], t['vtableId'])} "
                    f"slot {slot:#x} holds {actual and hex(actual)}, expected {fn_va:#x}. "
                    f"The engine's vtable layout does not match this target list - "
                    f"do NOT regenerate blindly; re-derive the slot from the binary.")
            rec["vtable"] = {
                "id": t["vtableId"],
                "name": names.get(t["vtableId"], ""),
                "rva": vt_rva,
                "slot": slot,
            }

        # Prologue: never read past the next function's first byte.
        avail = rec["pdataExtent"] or rec["slotLength"]
        if avail is None:
            raise ValueError(f"target {t['target']}: no .pdata entry and no following "
                             f"entry; cannot bound the prologue read")
        length = min(PROLOGUE_BYTES, avail)
        if length < MIN_PROLOGUE_BYTES:
            raise ValueError(f"target {t['target']}: only {length} bytes available for a "
                             f"prologue hash (need >= {MIN_PROLOGUE_BYTES})")
        prologue = pe.read(fn_rva, length)
        if prologue is None or len(prologue) != length:
            raise ValueError(f"target {t['target']}: cannot read {length} bytes at rva {fn_rva:#x}")
        rec["prologueLength"] = length
        rec["prologueHash"] = fnv1a64(prologue)
        records.append(rec)

    identity = {
        "module": os.path.basename(exe_path),
        "version": vlib.version_string,
        "size": os.path.getsize(exe_path),
        "timeDateStamp": pe.timedate,
        "sizeOfImage": pe.sizeofimage,
        "sha256": sha256_file(exe_path),
    }

    table = {
        "schema": "heapsentinel.hooktable/1",
        "generator": "tools/gen-hooktable.py",
        "identity": identity,
        "addressLibrary": {
            "file": os.path.basename(vlib_path),
            "format": vlib.format,
            "version": vlib.version_string,
            "pointerSize": vlib.pointer_size,
            "dataFormat": vlib.data_format,
            "offsetCount": vlib.count,
            "size": vlib.size,
            "sha256": sha256_file(vlib_path),
        },
        "names": {
            "source": "meh321/AddressLibraryDatabase",
            "url": "https://github.com/meh321/AddressLibraryDatabase",
            "file": os.path.basename(names_path),
            "licence": "the repository carries no LICENSE file (checked 2026-09-22); "
                       "names are recorded here as identifiers/provenance only, and no "
                       "bulk data from it is vendored",
        },
        "licensing": {
            "policy": "hashes + offsets + names only",
            "prologueBytesCommitted": False,
            "note": "No byte of SkyrimSE.exe is committed. Each record carries an RVA, "
                    "a length and a 64-bit FNV-1a hash of the first N bytes, which "
                    "verifies identity exactly as well as a verbatim prologue would.",
        },
        "hash": {"algorithm": "fnv1a64", "offsetBasis": hex(FNV_OFFSET), "prime": hex(FNV_PRIME)},
        "targets": records,
    }

    slice_ = {
        "schema": "heapsentinel.addresslibrary/1",
        "version": vlib.version_string,
        "file": os.path.basename(vlib_path),
        "format": vlib.format,
        "pointerSize": vlib.pointer_size,
        "dataFormat": vlib.data_format,
        "offsetCount": vlib.count,
        "size": vlib.size,
        "sha256": sha256_file(vlib_path),
        "base": BASE,
        "note": "Only the ids the committed hook table needs. Committed so CI can check "
                "each record's id->rva without the third-party Address Library file, "
                "which is not redistributable and is not in this repository.",
        "offsets": vlib.slice_for(used_ids),
    }
    return table, slice_


def write_json(path: str, obj) -> None:
    text = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


# -------------------------------------------------------------- embedded header


HEADER_PREAMBLE = """#pragma once

// GENERATED by tools/gen-hooktable.py - DO NOT EDIT BY HAND.
//
// This header embeds the committed hook-target tables verbatim, so the plugin
// always has the verified bytes for the running build even when only the DLL was
// installed. `tools/check-hooktable.py` regenerates it from hooks/*.json in CI
// and fails the build if the two have drifted.
//
// The raw-string delimiter is HSJSON; no committed table contains )HSJSON".

#include <cstddef>

namespace hs
{
	struct EmbeddedHookTable
	{
		const char* source;  // repository-relative path of the committed file
		const char* json;    // its exact bytes
	};

	inline constexpr EmbeddedHookTable kEmbeddedHookTables[] = {
"""


def emit_header(hooks_dir: str, out_path: str) -> None:
    files = sorted(f for f in os.listdir(hooks_dir)
                   if f.startswith("skyrimse-") and f.endswith(".json"))
    if not files:
        raise ValueError(f"{hooks_dir}: no skyrimse-*.json tables to embed")
    parts = [HEADER_PREAMBLE]
    for f in files:
        with open(os.path.join(hooks_dir, f), encoding="utf-8") as fh:
            text = fh.read()
        if ")HSJSON\"" in text:
            raise ValueError(f"{f}: contains the raw-string delimiter")
        parts.append(f'\t\t{{ "hooks/{f}",\n')
        parts.append(f'\t\t\tR"HSJSON({text})HSJSON" }},\n')
    parts.append("\t};\n")
    parts.append("\tinline constexpr std::size_t kEmbeddedHookTableCount =\n")
    parts.append("\t\t(sizeof(kEmbeddedHookTables) / sizeof(kEmbeddedHookTables[0]));\n")
    parts.append("}\n")
    out = "".join(parts)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)


# --------------------------------------------------------------------------- CLI


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe")
    ap.add_argument("--versionlib")
    ap.add_argument("--names")
    ap.add_argument("--defs", default="src/Hooks/HookTargets.def")
    ap.add_argument("--out-dir", default="hooks")
    ap.add_argument("--header", default="src/Hooks/HookTableData.gen.h")
    ap.add_argument("--emit-header", nargs=2, metavar=("HOOKS_DIR", "OUT_H"),
                    help="regenerate the embedded header from committed JSON (no exe needed)")
    args = ap.parse_args(argv)

    if args.emit_header:
        emit_header(args.emit_header[0], args.emit_header[1])
        print(f"wrote {args.emit_header[1]} from {args.emit_header[0]}")
        return 0

    if not (args.exe and args.versionlib and args.names):
        ap.error("--exe, --versionlib and --names are required to generate a table")

    table, slice_ = build_table(args.exe, args.versionlib, args.names, args.defs)
    os.makedirs(args.out_dir, exist_ok=True)

    ident = table["identity"]
    table_path = os.path.join(args.out_dir, f"skyrimse-{ident['version']}-{ident['sha256'][:8]}.json")
    slice_path = os.path.join(args.out_dir, f"addresslibrary-{table['addressLibrary']['version']}.json")
    write_json(table_path, table)
    write_json(slice_path, slice_)
    emit_header(args.out_dir, args.header)

    print(f"identity: {ident['module']} {ident['version']} size={ident['size']} "
          f"timestamp={hex(ident['timeDateStamp'])} sizeofimage={hex(ident['sizeOfImage'])}")
    print(f"sha256:   {ident['sha256']}")
    print(f"wrote {table_path} ({len(table['targets'])} targets)")
    print(f"wrote {slice_path} ({len(slice_['offsets'])} ids)")
    print(f"wrote {args.header}")
    for r in table["targets"]:
        vt = f" vtable={r['vtable']['name']}[{r['vtable']['slot']:#x}]" if "vtable" in r else ""
        print(f"  {r['target']:46s} rva={r['rva']:#09x} len={r['prologueLength']:2d} "
              f"hash={r['prologueHash']:#018x}{vt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
