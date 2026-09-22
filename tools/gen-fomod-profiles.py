#!/usr/bin/env python3
"""Single source of truth for HeapSentinel's ini profiles and its FOMOD.

Why this exists
---------------
FOMOD cannot generate a file's contents. Its only file mechanism is "copy this
staged file to that destination", optionally gated on flags set by the user's
selections. So a profile is shipped as a pre-composed HeapSentinel.ini variant
and the wizard copies the selected variant to SKSE/Plugins/HeapSentinel.ini.

Hand-maintained ini variants drift from the code. This project has already been
bitten twice: a deployed ini pinned ``[Ledger] uCapacity=1048576`` against a 4 M
compiled default (so the ledger saturated and silently stopped recording), and a
deployed ini omitted ``[ScaleformHeap]`` entirely (so the compiled defaults
applied and the user's explicit engine-only choice was not honoured). Therefore
there is exactly ONE definition of every key/comment/default here, and every
artifact -- the standalone config, all five profile variants, the FOMOD
ModuleConfig.xml and fomod/info.xml -- is emitted from it:

    python3 tools/gen-fomod-profiles.py            # write into the repo
    python3 tools/gen-fomod-profiles.py --check    # fail if any file is stale
    python3 tools/gen-fomod-profiles.py --out DIR  # write somewhere else

`tools/validate_fomod.py` runs --check plus the key-name / XML / packaging
checks, and CI runs it (see the `fomod` job in .github/workflows/build.yml).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# The one definition: every section, key, comment and compiled default.
# ---------------------------------------------------------------------------
# `default` MUST match the parser in src/Config.cpp (and the member default in
# src/Config.h). The validator asserts that every key here is actually read by
# Config.cpp, and that every key Config.cpp reads appears in every emitted ini --
# so a renamed key, or a profile that forgets a whole section, fails CI.

SECTIONS = [
    {
        "name": "General",
        "keys": [
            {
                "name": "bEnabled",
                "kind": "bool",
                "default": True,
                "comment": ["Master switch. 0 installs nothing at all."],
            },
        ],
    },
    {
        "name": "Ledger",
        "keys": [
            {
                "name": "bEnabled",
                "kind": "bool",
                "default": True,
                "comment": [
                    "Shadow allocation ledger: ptr -> {size, thread, alloc/free site, stacks}.",
                    "Fail-open: when it is full or not ready, every hook passes through.",
                ],
            },
            {
                "name": "uCapacity",
                "kind": "int",
                "default": 4194304,
                "comment": [
                    "One entry per live allocation. Skyrim has well over a million live engine",
                    "allocations, and the Scaleform hooks add another large population on top, so",
                    "the default is 4 M (1<<22). The table is bounded: probing stops after 64 slots",
                    "and the oldest freed entry is evicted when it is full. The effective size is",
                    "logged at startup (\"ledger: N shards x M slots\"); if the log also shows a",
                    "growing \"insert failures\" count, raise this value.",
                    "NOTE: a deployed HeapSentinel.ini overrides this default - some older installs",
                    "pin uCapacity=1048576, which saturates and silently stops recording.",
                ],
            },
            {
                "name": "uShards",
                "kind": "int",
                "default": 64,
                "comment": [],
            },
            {
                "name": "uStackDepth",
                "kind": "int",
                "default": 12,
                "comment": ["Frames captured per alloc/free. 0 keeps only the immediate return address."],
            },
        ],
    },
    {
        "name": "GuardPool",
        "keys": [
            {
                "name": "bEnabled",
                "kind": "bool",
                "default": False,
                "comment": [
                    "GWP-ASan-style sampled allocations with guard pages. OPT-IN: a sampled block",
                    "was never returned by any engine heap, so the engine must never inspect it",
                    "with ContainsBlockImpl/Size. The hooks route frees and reallocs of our blocks",
                    "back to us, but that is the whole safety argument.",
                ],
            },
            {
                "name": "uSampleRate",
                "kind": "int",
                "default": 2000,
                "comment": ["1 in N allocations is sampled."],
            },
            {
                "name": "uSlots",
                "kind": "int",
                "default": 64,
                "comment": [],
            },
            {
                "name": "uMaxSize",
                "kind": "int",
                "default": 3072,
                "comment": ["Requests larger than this pass straight through (one data page per slot)."],
            },
            {
                "name": "bFixUp",
                "kind": "bool",
                "default": True,
                "comment": ["1 = on a guarded-slot fault, re-protect the page and let the game continue."],
            },
        ],
    },
    {
        "name": "RefCountGuard",
        "keys": [
            {
                "name": "bEnabled",
                "kind": "bool",
                "default": True,
                "comment": ["Validate the vtable before GRefCountImpl::Release dispatches a destructor."],
            },
            {
                "name": "bFailSafe",
                "kind": "bool",
                "default": False,
                "comment": [
                    "0 = log and let the engine do what it was going to do (it will probably",
                    "    crash, but nothing is hidden).",
                    "1 = skip the dispatch entirely, turning the crash into a leak.",
                ],
            },
        ],
    },
    {
        "name": "ScaleformHeap",
        "keys": [
            {
                "name": "bEnabled",
                "kind": "bool",
                "default": True,
                "comment": [
                    "Track Scaleform/GFx allocations (GMemoryHeapPT) in the same shadow ledger.",
                    "These objects do NOT come from RE::MemoryManager, so without this section the",
                    "plugin is blind to the GFxResource use-after-free crashes. Same fail-open",
                    "discipline as the engine hooks: if the ledger is full or not ready, the hook",
                    "passes straight through and never blocks or logs on the hot path.",
                ],
            },
            {
                "name": "bCaptureStacks",
                "kind": "bool",
                "default": True,
                "comment": [
                    "Capture call stacks for Scaleform alloc/free. The free stack is what names",
                    "the mod that freed the object, so this defaults on. Set to 0 for a cheaper",
                    "run that records only the immediate return address.",
                ],
            },
            {
                "name": "bPoisonOnFree",
                "kind": "bool",
                "default": True,
                "comment": [
                    "Poison-on-free: on GMemoryHeapPT::Free, overwrite the block's first qword (the",
                    "vtable pointer) with a unique poison address inside a reserved, never-committed",
                    "region, and DELAY the real free briefly. A later virtual call through the dead",
                    "object then faults at an address that maps back to the ledger record, with the",
                    "alloc stack AND the free stack - deterministically, with no dependence on how",
                    "the heap recycled the memory. Bounded and fail-open: over budget or not ready",
                    "calls the original immediately. This is the fast path for recent frees; the",
                    "free ring below is the general attribution for everything else.",
                ],
            },
            {
                "name": "uPoisonMaxBlocks",
                "kind": "int",
                "default": 65536,
                "comment": [
                    "Address-space budget (not RAM): up to this many blocks held poisoned at once.",
                    "Rounded up to a power of two. The oldest is really freed when the budget hits.",
                ],
            },
            {
                "name": "uPoisonMaxBytes",
                "kind": "int",
                "default": 67108864,
                "comment": [
                    "Retained-bytes budget; the oldest is really freed when this is reached. 64 MiB.",
                ],
            },
            {
                "name": "uFreeRingCapacity",
                "kind": "int",
                "default": 1048576,
                "comment": [
                    "Durable free records (separate from the main ledger so engine allocations keep",
                    "flowing). Evict-oldest when full; occupancy and eviction count are logged every",
                    "60 s, so a lossy run is legible. 1M records is ~64 MiB.",
                ],
            },
        ],
    },
    {
        "name": "WeakLib",
        "keys": [
            {
                "name": "bEnabled",
                "kind": "bool",
                "default": True,
                "comment": [
                    "GFxResourceWeakLib context hooks: PinResource, RemoveResourceOnRelease,",
                    "UnpinResource, GFxResource::AddRef. Low frequency (menu load/close), not per",
                    "allocation. They record the pin/remove history of a resource so the crash",
                    "report can say whether it was pinned and whether it deregistered.",
                ],
            },
            {
                "name": "uEventCapacity",
                "kind": "int",
                "default": 16384,
                "comment": [],
            },
        ],
    },
    {
        "name": "Reporting",
        "keys": [
            {
                "name": "bScreenshot",
                "kind": "bool",
                "default": False,
                "comment": [],
            },
            {
                "name": "bFreeze",
                "kind": "bool",
                "default": False,
                "comment": [],
            },
            {
                "name": "bVeh",
                "kind": "bool",
                "default": True,
                "comment": [],
            },
            {
                "name": "bReportUntrackedFree",
                "kind": "bool",
                "default": False,
                "comment": [
                    "Untracked frees are not necessarily invalid (allocations made before the",
                    "hooks were installed are untracked too), so this is off by default.",
                ],
            },
            {
                "name": "bSymbolHint",
                "kind": "bool",
                "default": True,
                "comment": [
                    "Print alloc/free sites as module+0xOFFSET and hint that a shipped PDB resolves",
                    "the offset to a function name (CBPC shipped one; check the mod's folder).",
                ],
            },
            {
                "name": "uMaxReportsPerSecond",
                "kind": "int",
                "default": 20,
                "comment": [],
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Profiles. Memory numbers are the measured/derived ones from the code:
#   ledger entry  = 112 B (version + key + AllocationInfo) -> 1 M = ~115 MiB,
#                   4 M = ~460 MiB (including the ~10-bit/element bloom filter)
#   stack ring    = 64 Ki entries x 200 B = ~14 MiB, only when uStackDepth > 0
#   free ring     = 64 B/record -> 1 M = ~64 MiB, 2 M = ~128 MiB, 128 K = ~8 MiB
#   poison        = up to uPoisonMaxBytes withheld (RAM), address space reserved
#   bloom         = 10 bits/element for the ledger and the free ring
# ---------------------------------------------------------------------------


@dataclass
class Profile:
    name: str          # file stem, also the FOMOD flag value
    title: str         # button label
    type: str          # FOMOD plugin type: Required|Recommended|Optional
    cost: str          # one-line headline cost, used in the ini header
    description: str   # FOMOD <description>
    overrides: dict = field(default_factory=dict)  # {(section, key): value}

    def value(self, section: str, key: str, default):
        return self.overrides.get((section, key), default)


_BALANCED_DESC = """Recommended default. 1,048,576 ledger entries (~115 MiB),
call stacks on (~14 MiB stack ring), Scaleform free ring with 1,048,576 records
(~64 MiB), poison-on-free with up to 64 MiB withheld, and roughly 2.5 MiB of
bloom filters. Total resident cost is roughly 260 MiB.

This is the profile to run for normal play and for most crash hunts: it tracks
the engine allocators, the Scaleform GMemoryHeapPT and the GFxResourceWeakLib
paths, and it keeps the deterministic poison fast path. What you give up versus
Max attribution is depth, not coverage: the ledger and free ring evict older
records sooner, and the poison quarantine holds half as many bytes, so a
delayed use-after-free may find its free record already evicted. Nothing else
is lost."""

_MAX_DESC = """For hunting one specific, hard-to-reproduce crash. 4,194,304
ledger entries (~460 MiB), call stacks on (~14 MiB), Scaleform free ring with
2,097,152 records (~128 MiB), poison-on-free with up to 128 MiB withheld, and
roughly 7.5 MiB of bloom filters. Total resident cost is roughly 735 MiB.

What you give up is memory headroom: on a heavily modded, memory-tight setup,
this profile can itself contribute to the memory pressure that triggers the
crash. Use it for a targeted session with the failing setup, capture the
report, then switch back. It does not detect anything Balanced does not; it
merely remembers more of the past."""

_LOW_DESC = """1,048,576 ledger entries (~115 MiB), call stacks OFF, Scaleform
tracking on but poison-on-free OFF, Scaleform free ring with 131,072 records
(~8 MiB), and roughly 1.4 MiB of bloom filters. Total resident cost is roughly
125 MiB.

What you give up: stack attribution and the deterministic poison fast path.
Provenance degrades to the immediate return address (module+0xOFFSET, which a
shipped PDB can still resolve to a function), and a use-after-free is no longer
made deterministic by poison. The general free ring still answers "which module
freed it", but over a much shorter window (~1/8 of Balanced). Choose it when
resident memory matters more than attribution detail."""

_ENGINE_DESC = """Engine-only, the pre-0.2 HeapSentinel behaviour. The
Scaleform GMemoryHeapPT hooks, poison-on-free and the GFxResourceWeakLib context
hooks are all off. 1,048,576 ledger entries (~115 MiB), call stacks on
(~14 MiB), and roughly 1.25 MiB of bloom filters. Total resident cost is roughly
130 MiB.

What you give up: every kind of Scaleform/GFxResource attribution. This profile
is blind to the GFxResource use-after-free crashes that 0.2 and 0.3 were added
for. Only choose it if Scaleform tracking is itself suspect on your setup, or
if you deliberately want the older, narrower behaviour."""

_CUSTOM_DESC = """Install the fully commented HeapSentinel.ini for hand-editing.
It ships with the plugin's compiled-in defaults: 4,194,304 ledger entries
(~460 MiB), call stacks on (~14 MiB), Scaleform free ring with 1,048,576 records
(~64 MiB), poison-on-free with up to 64 MiB withheld, and roughly 6.3 MiB of
bloom filters, for a total of roughly 600 MiB.

This is deliberately NOT the recommended default - Balanced, above, is. Install
this only if you intend to edit Data/SKSE/Plugins/HeapSentinel.ini yourself.
Every key is present and commented in the file, so a value you do not touch
keeps its compiled default rather than silently reverting. The guarded pool
([GuardPool]) is documented there but left OFF: it is opt-in and unverified, and
it is not offered as a normal wizard choice."""

PROFILES = [
    Profile(
        name="balanced",
        title="Balanced (recommended)",
        type="Recommended",
        cost="~260 MiB resident with the shipped settings",
        description=_BALANCED_DESC,
        overrides={
            ("Ledger", "uCapacity"): 1048576,
        },
    ),
    Profile(
        name="max-attribution",
        title="Max attribution (larger ledger + poison budget)",
        type="Optional",
        cost="~735 MiB resident with the shipped settings",
        description=_MAX_DESC,
        overrides={
            ("Ledger", "uCapacity"): 4194304,
            ("ScaleformHeap", "uPoisonMaxBlocks"): 262144,
            ("ScaleformHeap", "uPoisonMaxBytes"): 134217728,
            ("ScaleformHeap", "uFreeRingCapacity"): 2097152,
        },
    ),
    Profile(
        name="low-memory",
        title="Low memory / low overhead",
        type="Optional",
        cost="~125 MiB resident with the shipped settings",
        description=_LOW_DESC,
        overrides={
            ("Ledger", "uCapacity"): 1048576,
            ("Ledger", "uStackDepth"): 0,
            ("ScaleformHeap", "bCaptureStacks"): False,
            ("ScaleformHeap", "bPoisonOnFree"): False,
            ("ScaleformHeap", "uFreeRingCapacity"): 131072,
        },
    ),
    Profile(
        name="engine-only",
        title="Engine-only (pre-0.2 behaviour)",
        type="Optional",
        cost="~130 MiB resident with the shipped settings",
        description=_ENGINE_DESC,
        overrides={
            ("Ledger", "uCapacity"): 1048576,
            ("ScaleformHeap", "bEnabled"): False,
            ("ScaleformHeap", "bCaptureStacks"): False,
            ("ScaleformHeap", "bPoisonOnFree"): False,
            ("ScaleformHeap", "uFreeRingCapacity"): 131072,
            ("WeakLib", "bEnabled"): False,
        },
    ),
    Profile(
        name="custom",
        title="Custom (fully commented defaults, edit after install)",
        type="Optional",
        cost="~600 MiB resident before you edit it",
        description=_CUSTOM_DESC,
        overrides={},
    ),
]

PROFILE_BY_NAME = {p.name: p for p in PROFILES}

# The standalone Data/SKSE/Plugins ini (used by the loose-file/manual archive)
# is the same fully-commented file as the Custom profile.
DEFAULT_PROFILE = PROFILE_BY_NAME["custom"]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

ACTIVE_PROFILES = {p.name for p in PROFILES}


def _fmt(kind: str, value) -> str:
    if kind == "bool":
        return "1" if value else "0"
    return str(value)


def render_ini(profile: Profile, *, is_default: bool) -> str:
    lines: list[str] = []
    lines.append("; HeapSentinel - Data/SKSE/Plugins/HeapSentinel.ini")
    if is_default:
        lines.append("; Every value here is the compiled-in default; delete the file to use them.")
    else:
        lines.append(f"; FOMOD profile: {profile.title}")
        lines.append(f"; Estimated resident cost: {profile.cost}.")
        lines.append("; This file lists every key, so nothing silently falls back to a compiled default.")
    lines.append("")
    for section in SECTIONS:
        lines.append(f"[{section['name']}]")
        for key in section["keys"]:
            for comment in key["comment"]:
                lines.append(f"; {comment}")
            value = profile.value(section["name"], key["name"], key["default"])
            lines.append(f"{key['name']}={_fmt(key['kind'], value)}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def read_version() -> str:
    """set_version("0.3.0") from xmake.lua, so the FOMOD cannot drift from the build."""
    for line in (REPO_ROOT / "xmake.lua").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("set_version("):
            return line.split('"')[1]
    raise SystemExit("gen-fomod-profiles: could not read set_version() from xmake.lua")


def render_info_xml(version: str) -> str:
    description = (
        "HeapSentinel is an SKSE plugin that retrofits a memory sentinel onto a "
        "running Skyrim SE/AE process. It does not fix crashes: it tells you which "
        "mod caused one, by tracking the engine and Scaleform allocators, keeping a "
        "shadow ledger with alloc and free call stacks, and printing provenance from "
        "a vectored exception handler. Pick a memory / attribution profile in the "
        "installer."
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<fomod>\n"
        "  <Name>HeapSentinel</Name>\n"
        "  <Author>aviallon</Author>\n"
        f"  <Version>{escape(version)}</Version>\n"
        f"  <Description>{escape(description)}</Description>\n"
        "  <Website>https://github.com/aviallon/HeapSentinel</Website>\n"
        "</fomod>\n"
    )


_EXPLANATION = """HeapSentinel is an SKSE plugin that retrofits a memory sentinel onto the running game. It does NOT fix crashes. It tells you WHICH MOD caused one.

What it does:
- Hooks the engine's allocators (RE::MemoryManager) and Scaleform's GMemoryHeapPT, plus the refcount and GFxResourceWeakLib paths.
- Keeps a shadow ledger of every tracked block, with the allocation and the free call stacks.
- A vectored exception handler catches the fault and prints PROVENANCE: which module freed the object, and from where.
- Optional poison-on-free overwrites a freed Scaleform object's vtable with a reserved poison address and delays the real free, so a later virtual call through the dead object faults deterministically at an address that maps back to the ledger record, with both the alloc and the free stack.

What it is NOT:
- It is not a crash fix and not a stability mod. It cannot repair a use-after-free; it exists to identify the mod that caused it. Install it while hunting a crash, read the report, then remove it or keep it as you prefer.
- It is not a general antivirus for memory corruption, and it does not detect a bug it was never able to observe.

Cost and privacy:
- Memory: the profile you choose on the next page costs roughly 125-735 MiB of resident memory; the recommended Balanced profile is about 260 MiB. Each profile states its own number.
- Per-allocation cost: every tracked allocation pays a small extra cost on the hot path (a bloom pre-filter, a sharded lock-free ledger insert, and, when stacks are on, a call-stack capture).
- Nothing leaves the machine. Reports are written to the SKSE log next to the DLL; there is no network code.

Choose a configuration profile on the next page."""


def render_module_config(version: str) -> str:
    out: list[str] = []
    out.append('<?xml version="1.0" encoding="UTF-8"?>')
    out.append('<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')
    out.append('        xsi:noNamespaceSchemaLocation="http://qconsulting.ca/fo3/ModConfig5.0.xsd">')
    out.append(f"  <moduleName>HeapSentinel {escape(version)}</moduleName>")
    out.append("  <requiredInstallFiles>")
    for source in ("SKSE/Plugins/HeapSentinel.dll", "README.md", "RESEARCH.md", "DESIGN.md"):
        out.append(f'    <file source="{source}" destination="{source}" />')
    out.append("  </requiredInstallFiles>")

    out.append('  <installSteps order="Explicit">')

    # Step 1: explanation. A single Required plugin in a SelectExactlyOne group
    # is the standard way to get a page of prose with no real choice.
    out.append('    <installStep name="HeapSentinel">')
    out.append("      <optionalFileGroups>")
    out.append('        <group name="Install HeapSentinel" type="SelectExactlyOne">')
    out.append('          <plugins order="Explicit">')
    out.append('            <plugin name="Install HeapSentinel">')
    out.append(f"              <description>{escape(_EXPLANATION)}</description>")
    # The FOMOD schema requires a plugin to carry either <files> or
    # <conditionFlags>; the explanation plugin installs nothing itself (the DLL
    # is in <requiredInstallFiles>), so give it a flag no pattern depends on.
    out.append("              <conditionFlags>")
    out.append('                <flag name="step">intro</flag>')
    out.append("              </conditionFlags>")
    out.append("              <typeDescriptor>")
    out.append('                <type name="Required" />')
    out.append("              </typeDescriptor>")
    out.append("            </plugin>")
    out.append("          </plugins>")
    out.append("        </group>")
    out.append("      </optionalFileGroups>")
    out.append("    </installStep>")

    # Step 2: the profile SelectExactlyOne.
    out.append('    <installStep name="Configuration profile">')
    out.append("      <optionalFileGroups>")
    out.append('        <group name="Memory / attribution trade-off" type="SelectExactlyOne">')
    out.append('          <plugins order="Explicit">')
    for profile in PROFILES:
        out.append(f'            <plugin name="{escape(profile.title)}">')
        out.append(f"              <description>{escape(profile.description)}</description>")
        out.append("              <conditionFlags>")
        out.append(f'                <flag name="profile">{profile.name}</flag>')
        out.append("              </conditionFlags>")
        out.append("              <typeDescriptor>")
        out.append(f'                <type name="{profile.type}" />')
        out.append("              </typeDescriptor>")
        out.append("            </plugin>")
    out.append("          </plugins>")
    out.append("        </group>")
    out.append("      </optionalFileGroups>")
    out.append("    </installStep>")

    out.append("  </installSteps>")

    # Conditional install: exactly one pattern matches, because SelectExactlyOne
    # sets exactly one `profile` flag value.
    out.append("  <conditionalFileInstalls>")
    out.append("    <patterns>")
    for profile in PROFILES:
        out.append("      <pattern>")
        out.append('        <dependencies operator="And">')
        out.append(f'          <flagDependency flag="profile" value="{profile.name}" />')
        out.append("        </dependencies>")
        out.append("        <files>")
        out.append(
            f'          <file source="fomod/profiles/{profile.name}.ini" '
            'destination="SKSE/Plugins/HeapSentinel.ini" />'
        )
        out.append("        </files>")
        out.append("      </pattern>")
    out.append("    </patterns>")
    out.append("  </conditionalFileInstalls>")

    out.append("</config>")
    return "\n".join(out) + "\n"


def build_outputs() -> dict[str, str]:
    """Every committed artifact, as {repo-relative posix path: text}."""
    version = read_version()
    outputs: dict[str, str] = {}

    outputs["config/HeapSentinel.ini"] = render_ini(DEFAULT_PROFILE, is_default=True)
    for profile in PROFILES:
        outputs[f"fomod/profiles/{profile.name}.ini"] = render_ini(profile, is_default=False)
    outputs["fomod/info.xml"] = render_info_xml(version)
    outputs["fomod/ModuleConfig.xml"] = render_module_config(version)
    return outputs


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate HeapSentinel's ini profiles and FOMOD.")
    parser.add_argument("--out", default=str(REPO_ROOT), help="directory to write into (default: repo root)")
    parser.add_argument("--check", action="store_true", help="do not write; fail if committed files are stale")
    args = parser.parse_args(argv)

    outputs = build_outputs()

    if args.check:
        stale = []
        for rel, content in outputs.items():
            path = REPO_ROOT / rel
            if not path.is_file():
                stale.append(f"{rel}: MISSING")
            elif path.read_text(encoding="utf-8") != content:
                stale.append(f"{rel}: DIFFERS")
        if stale:
            print("ERROR: generated FOMOD artifacts are stale:", file=sys.stderr)
            for item in stale:
                print(f"  {item}", file=sys.stderr)
            print("Run: python3 tools/gen-fomod-profiles.py", file=sys.stderr)
            return 1
        print(f"up to date: {len(outputs)} generated file(s)")
        return 0

    out_root = Path(args.out)
    for rel, content in outputs.items():
        path = out_root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))