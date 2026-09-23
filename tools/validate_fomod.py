#!/usr/bin/env python3
"""Validate HeapSentinel's FOMOD before it becomes a release asset.

This is the check that must be able to FAIL. It does seven independent things,
each of which is a real gate rather than a "well-formed" smoke test:

  1. UP TO DATE: regenerate every artifact from tools/gen-fomod-profiles.py and
     fail if any committed file differs. Hand-edits to a profile or to
     ModuleConfig.xml are therefore rejected. (This is the drift gate: the
     project has twice shipped a deployed ini that disagreed with the code.)

  2. META.INI: the MO2/Amethyst metadata is present, has a ``[General]``
     section, and its ``version`` equals the ``xmake.lua`` version. A shipped
     meta.ini that lies about the version is exactly the class of bug the
     version-derived archive name fixed.

  3. KEY NAMES: every key in every profile must be read by src/Config.cpp, and
     every key src/Config.cpp reads must appear in every profile and in the
     standalone config. A renamed key -- or a profile that forgets a whole
     section such as [ScaleformHeap] -- fails here.

  4. XML: the FOMOD is well-formed, validates against the vendored FOMOD schema
     (fomod/schema/ModConfig5.0.xsd) when xmllint is available, and satisfies
     the structural rules the schema is vague about (one Recommended default in
     the SelectExactlyOne profile group; every profile flag has exactly one
     conditional pattern and vice versa).

  5. PACKAGE LAYOUT: every <file source="..."> in ModuleConfig.xml resolves to a
     real file in the package, and the package carries the FOMOD, the DLL and a
     profile ini per choice.

  6. CONDITIONAL LOGIC: an independent simulation of the FOMOD flag rules
     asserts that selecting each profile installs that profile's ini to
     SKSE/Plugins/HeapSentinel.ini and no other profile's ini.

  7. ARCHIVE: optionally builds the installable zip and re-checks its contents.

Usage:
    python3 tools/validate_fomod.py --dll path/to/HeapSentinel.dll
    python3 tools/validate_fomod.py --dll ... --zip HeapSentinel-0.3.0-fomod.zip
    python3 tools/validate_fomod.py                  # skips the DLL/zip checks

Exit status is 0 only if every applicable check passed.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = REPO_ROOT / "fomod" / "schema" / "ModConfig5.0.xsd"
MODULECONFIG = REPO_ROOT / "fomod" / "ModuleConfig.xml"
INFOXML = REPO_ROOT / "fomod" / "info.xml"

REQUIRED_FILES = ("SKSE/Plugins/HeapSentinel.dll", "SKSE/Plugins/HeapSentinel.pdb", "README.md", "RESEARCH.md", "DESIGN.md", "meta.ini")


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_fomod_profiles", REPO_ROOT / "tools" / "gen-fomod-profiles.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module  # dataclass resolution needs __module__ in sys.modules
    spec.loader.exec_module(module)
    return module


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.skips: list[str] = []

    def fail(self, message: str) -> None:
        self.failures.append(message)
        print(f"  FAIL: {message}")

    def ok(self, message: str) -> None:
        print(f"  ok:   {message}")

    def skip(self, message: str) -> None:
        self.skips.append(message)
        print(f"  SKIP: {message}")


# ---------------------------------------------------------------------------
# 1. generated artifacts are up to date
# ---------------------------------------------------------------------------

def check_up_to_date(c: Checker, gen) -> None:
    print("[1] generated artifacts are up to date")
    outputs = gen.build_outputs()
    for rel, content in outputs.items():
        path = REPO_ROOT / rel
        if not path.is_file():
            c.fail(f"{rel} is missing (run tools/gen-fomod-profiles.py)")
        elif path.read_text(encoding="utf-8") != content:
            c.fail(f"{rel} differs from generated output (run tools/gen-fomod-profiles.py)")
    if not c.failures:
        c.ok(f"{len(outputs)} generated files match the generator")


# ---------------------------------------------------------------------------
# 2. every generated key exists in the parser, and vice versa
# ---------------------------------------------------------------------------

def parser_keys() -> set[tuple[str, str]]:
    source = (REPO_ROOT / "src" / "Config.cpp").read_text(encoding="utf-8")
    pairs = re.findall(r'Read(?:Bool|UInt|String)\("([^"]+)",\s*"([^"]+)"', source)
    return {(section, key) for section, key in pairs}


def ini_keys(text: str) -> dict[tuple[str, str], str]:
    """{(section, key): value} for a rendered ini. Ignores comments/blanks."""
    found: dict[tuple[str, str], str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            found[(section, key.strip())] = value.strip()
    return found


def check_meta_ini(c: Checker, gen) -> None:
    print("[2] meta.ini is present and tells the truth about the version")
    path = REPO_ROOT / "meta.ini"
    if not path.is_file():
        c.fail("meta.ini is missing (run tools/gen-fomod-profiles.py)")
        return
    values = ini_keys(path.read_text(encoding="utf-8"))
    general = {key: value for (section, key), value in values.items()
               if section == "General"}
    if not general:
        c.fail("meta.ini has no [General] section")
        return
    version = gen.read_version()
    if general.get("version") != version:
        c.fail(f"meta.ini version is {general.get('version')!r}, xmake.lua says {version!r}")
    else:
        c.ok(f"meta.ini has [General] and version == xmake.lua ({version})")

    if general.get("gameName") != "skyrimspecialedition":
        c.fail(f"meta.ini gameName is {general.get('gameName')!r}, expected 'skyrimspecialedition'")
    if general.get("fileCategory") != "MAIN":
        c.fail(f"meta.ini fileCategory is {general.get('fileCategory')!r}, expected 'MAIN'")
    if not general.get("nexusName"):
        c.fail("meta.ini has no nexusName (canonical display name)")
    # This mod is not on Nexus: a populated id would make the manager try to
    # update a page that does not exist.
    for key in ("modid", "fileid"):
        if general.get(key, "").strip():
            c.fail(f"meta.ini fabricates {key}={general[key]!r}; this mod has no Nexus page")


def check_keys(c: Checker, gen) -> None:
    print("[3] ini keys agree with src/Config.cpp")
    known = parser_keys()
    if not known:
        c.fail("no keys parsed from src/Config.cpp - the parser regex broke")
        return

    targets = {"config/HeapSentinel.ini": gen.render_ini(gen.DEFAULT_PROFILE, is_default=True)}
    for profile in gen.PROFILES:
        targets[f"fomod/profiles/{profile.name}.ini"] = gen.render_ini(profile, is_default=False)

    for rel, text in targets.items():
        present = ini_keys(text)
        unknown = sorted(set(present) - known)
        missing = sorted(known - set(present))
        for section, key in unknown:
            c.fail(f"{rel}: key [{section}] {key} is not read by src/Config.cpp")
        for section, key in missing:
            c.fail(f"{rel}: src/Config.cpp reads [{section}] {key} but the profile omits it")
        if not unknown and not missing:
            c.ok(f"{rel}: {len(present)} keys, all known and complete")

    # The profile set itself must be known to the generator, and every known
    # parser key must be covered by the definition (not only by luck).
    defined = {
        (section["name"], key["name"]) for section in gen.SECTIONS for key in section["keys"]
    }
    for section, key in sorted(known - defined):
        c.fail(f"src/Config.cpp reads [{section}] {key} but the generator does not define it")


# ---------------------------------------------------------------------------
# 3. XML well-formedness, schema, structure
# ---------------------------------------------------------------------------

def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def check_xml(c: Checker, gen) -> None:
    print("[4] ModuleConfig.xml / info.xml are valid FOMOD")
    try:
        root = ET.parse(MODULECONFIG).getroot()
    except ET.ParseError as exc:
        c.fail(f"ModuleConfig.xml is not well-formed: {exc}")
        return
    c.ok("ModuleConfig.xml is well-formed")

    if strip_ns(root.tag) != "config":
        c.fail(f"ModuleConfig.xml root is <{strip_ns(root.tag)}>, expected <config>")
        return

    # FOMOD schema validation (the vendored schema is the upstream spec, with a
    # one-character typo fixed: type=" xs:string" -> type="xs:string"). xmllint
    # is the same libxml2 engine the XSD was written against.
    if shutil.which("xmllint"):
        import subprocess

        proc = subprocess.run(
            ["xmllint", "--noout", "--schema", str(SCHEMA), str(MODULECONFIG)],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            c.ok("ModuleConfig.xml validates against fomod/schema/ModConfig5.0.xsd")
        else:
            for line in (proc.stderr or proc.stdout).splitlines():
                if "validity error" in line or "fails to validate" in line:
                    c.fail(f"schema: {line.strip()}")
    else:
        c.skip("xmllint not found - schema validation skipped (structural checks still run)")

    # Structure: two steps, a single explanation plugin, and a profile group
    # that is a SelectExactlyOne with exactly one Recommended default.
    steps = [e for e in root if strip_ns(e.tag) == "installSteps"]
    step_list = list(steps[0]) if steps else []
    if len(step_list) != 2:
        c.fail(f"expected 2 install steps, found {len(step_list)}")
    else:
        c.ok("ModuleConfig.xml has the explanation step and the profile step")

    explanation_plugins: list[ET.Element] = []
    profile_group: ET.Element | None = None
    for step in step_list:
        for groups in step:
            if strip_ns(groups.tag) != "optionalFileGroups":
                continue
            for group in groups:
                if strip_ns(group.tag) != "group":
                    continue
                name = group.get("name", "")
                if name == "Memory / attribution trade-off":
                    profile_group = group
                for plugins in group:
                    if strip_ns(plugins.tag) != "plugins":
                        continue
                    for plugin in plugins:
                        if strip_ns(plugin.tag) == "plugin":
                            if name == "Install HeapSentinel":
                                explanation_plugins.append(plugin)

    if len(explanation_plugins) != 1:
        c.fail(f"expected exactly 1 explanation plugin, found {len(explanation_plugins)}")
    else:
        text = "".join(explanation_plugins[0].itertext()).lower()
        for needle in ("does not fix crashes", "which mod caused", "nothing leaves the machine"):
            if needle not in text:
                c.fail(f"explanation step is missing the honest claim {needle!r}")
        c.ok("explanation plugin is present and states what the plugin is/is not")

    if profile_group is None:
        c.fail("profile group 'Memory / attribution trade-off' not found")
        return
    if profile_group.get("type") != "SelectExactlyOne":
        c.fail("profile group must be SelectExactlyOne")

    plugins = []
    for plugins_el in profile_group:
        if strip_ns(plugins_el.tag) == "plugins":
            plugins = [p for p in plugins_el if strip_ns(p.tag) == "plugin"]
    if len(plugins) != len(gen.PROFILES):
        c.fail(f"profile group has {len(plugins)} plugins, expected {len(gen.PROFILES)}")

    recommended = 0
    for plugin in plugins:
        td = None
        for child in plugin:
            if strip_ns(child.tag) == "typeDescriptor":
                td = child
        if td is not None and any(
            strip_ns(t.tag) == "type" and t.get("name") == "Recommended" for t in td
        ):
            recommended += 1
    if recommended != 1:
        c.fail(f"profile group has {recommended} Recommended plugins, expected exactly 1")
    else:
        c.ok("exactly one profile is the Recommended default")

    # Every profile flag has exactly one conditional pattern, and every pattern
    # names a real profile.
    patterns: list[ET.Element] = []
    for cfi in root:
        if strip_ns(cfi.tag) != "conditionalFileInstalls":
            continue
        for pats in cfi:
            for pat in pats:
                if strip_ns(pat.tag) == "pattern":
                    patterns.append(pat)
    flag_values: list[str] = []
    for pat in patterns:
        for dep in pat.iter():
            if strip_ns(dep.tag) == "flagDependency" and dep.get("flag") == "profile":
                flag_values.append(dep.get("value", ""))
    expected = [p.name for p in gen.PROFILES]
    if sorted(flag_values) != sorted(expected):
        c.fail(f"conditional patterns cover {sorted(flag_values)}, expected {sorted(expected)}")
    elif len(flag_values) != len(expected):
        c.fail("a profile flag is covered by more than one conditional pattern")
    else:
        c.ok("each profile has exactly one conditional-install pattern")

    # info.xml
    try:
        info = ET.parse(INFOXML).getroot()
    except (ET.ParseError, FileNotFoundError) as exc:
        c.fail(f"info.xml problem: {exc}")
        return
    info_text = {strip_ns(e.tag): (e.text or "").strip() for e in info}
    for field in ("Name", "Author", "Version", "Description"):
        if not info_text.get(field):
            c.fail(f"info.xml is missing <{field}>")
    version = gen.read_version()
    if info_text.get("Version") != version:
        c.fail(f"info.xml Version is {info_text.get('Version')!r}, xmake.lua says {version!r}")
    else:
        c.ok("info.xml is well-formed and its version matches xmake.lua")


# ---------------------------------------------------------------------------
# 4. package layout
# ---------------------------------------------------------------------------

def check_package(c: Checker, gen, dll: Path | None, pdb: Path | None, stage: Path) -> None:
    print("[5] package layout")
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    # The repo files the FOMOD references, plus the build-produced DLL.
    for rel in ["fomod/ModuleConfig.xml", "fomod/info.xml"] + [
        f"fomod/profiles/{p.name}.ini" for p in gen.PROFILES
    ]:
        dest = stage / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / rel, dest)
    for rel in ("README.md", "RESEARCH.md", "DESIGN.md"):
        shutil.copyfile(REPO_ROOT / rel, stage / rel)
    # The MO2/Amethyst metadata is a declared FOMOD file and must be in the
    # package exactly as generated.
    shutil.copyfile(REPO_ROOT / "meta.ini", stage / "meta.ini")

    if dll is not None:
        dest = stage / "SKSE" / "Plugins" / "HeapSentinel.dll"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(dll, dest)
    if pdb is not None:
        dest = stage / "SKSE" / "Plugins" / "HeapSentinel.pdb"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pdb, dest)

    root = ET.parse(MODULECONFIG).getroot()
    sources: list[str] = []
    for file_el in root.iter():
        if strip_ns(file_el.tag) == "file":
            source = file_el.get("source")
            destination = file_el.get("destination")
            if not source or not destination:
                c.fail(f"a <file> has an empty source or destination: {file_el.attrib}")
                continue
            sources.append(source)
    for source in sources:
        if not (stage / source).is_file():
            if source == "SKSE/Plugins/HeapSentinel.dll" and dll is None:
                c.skip(f"{source} not staged (no --dll given)")
            elif source == "SKSE/Plugins/HeapSentinel.pdb" and pdb is None:
                c.skip(f"{source} not staged (no --pdb given)")
            else:
                c.fail(f"<file source={source!r}> does not exist in the package")
    if dll is not None:
        if not (stage / "SKSE/Plugins/HeapSentinel.dll").is_file():
            c.fail("the DLL was not staged")
        else:
            c.ok("the DLL is staged at SKSE/Plugins/HeapSentinel.dll")
    if pdb is not None:
        staged = stage / "SKSE/Plugins/HeapSentinel.pdb"
        if not staged.is_file():
            c.fail("the PDB was not staged")
        elif "MSF" not in staged.read_bytes()[:64].decode("latin-1", "ignore"):
            c.fail("the staged PDB does not look like a Windows PDB (no MSF signature)")
        else:
            c.ok("the PDB is staged next to the DLL at SKSE/Plugins/HeapSentinel.pdb")

    # Every declared profile must be present as a file, and every staged profile
    # must be declared.
    declared_sources = set(sources)
    for profile in gen.PROFILES:
        rel = f"fomod/profiles/{profile.name}.ini"
        if rel not in declared_sources:
            c.fail(f"profile {profile.name} is not referenced by ModuleConfig.xml")
        if not (stage / rel).is_file():
            c.fail(f"profile file {rel} is missing from the package")
    c.ok(f"{len(gen.PROFILES)} profile variants are present and declared")

    if (stage / "meta.ini").is_file():
        meta_values = ini_keys((stage / "meta.ini").read_text(encoding="utf-8"))
        meta_general = {k: v for (s, k), v in meta_values.items() if s == "General"}
        if meta_general.get("version") != gen.read_version():
            c.fail("the packaged meta.ini version disagrees with xmake.lua")
        else:
            c.ok("the packaged meta.ini is present, has [General], and matches xmake.lua")
    else:
        c.fail("meta.ini is missing from the package")


# ---------------------------------------------------------------------------
# 5. independent conditional-flag simulation
# ---------------------------------------------------------------------------

def simulate_selection(root: ET.Element, selections: dict[str, list[str]]):
    """A deliberately small, independent FOMOD resolver.

    Returns (required, conditional). `selections` is {step_name: {group_name:
    [plugin_name, ...]}}. It is NOT the manager's code: agreement between this
    and the manager is the point (see tools/check-amethyst-fomod.py).
    """
    def flag_dep_met(dep: ET.Element, flags: dict[str, str]) -> bool:
        tag = strip_ns(dep.tag)
        if tag == "flagDependency":
            return flags.get(dep.get("flag", "")) == dep.get("value", "")
        if tag == "dependencies":
            subs = [flag_dep_met(child, flags) for child in dep]
            operator = dep.get("operator", "And")
            return all(subs) if operator == "And" else any(subs)
        # fileDependency / engine gates are not used by this FOMOD.
        return True

    required: list[str] = []
    for files_el in root:
        if strip_ns(files_el.tag) == "requiredInstallFiles":
            for file_el in files_el:
                if strip_ns(file_el.tag) == "file":
                    required.append(file_el.get("source", ""))

    flags: dict[str, str] = {}
    for step in root.iter():
        if strip_ns(step.tag) != "installStep":
            continue
        by_group = selections.get(step.get("name", ""), {})
        for groups in step:
            if strip_ns(groups.tag) != "optionalFileGroups":
                continue
            for group in groups:
                if strip_ns(group.tag) != "group":
                    continue
                chosen = set(by_group.get(group.get("name", ""), []))
                for plugins in group:
                    if strip_ns(plugins.tag) != "plugins":
                        continue
                    for plugin in plugins:
                        if strip_ns(plugin.tag) != "plugin":
                            continue
                        if group.get("type") == "SelectAll" or plugin.get("name") in chosen:
                            for child in plugin:
                                if strip_ns(child.tag) == "conditionFlags":
                                    for flag in child:
                                        flags[flag.get("name", "")] = (flag.text or "").strip()

    conditional: list[tuple[str, str]] = []
    for cfi in root:
        if strip_ns(cfi.tag) != "conditionalFileInstalls":
            continue
        for pats in cfi:
            for pat in pats:
                if strip_ns(pat.tag) != "pattern":
                    continue
                deps = [ch for ch in pat if strip_ns(ch.tag) == "dependencies"]
                if deps and flag_dep_met(deps[0], flags):
                    for files_el in pat:
                        if strip_ns(files_el.tag) == "files":
                            for file_el in files_el:
                                if strip_ns(file_el.tag) == "file":
                                    conditional.append(
                                        (file_el.get("source", ""), file_el.get("destination", ""))
                                    )
    return required, conditional


def check_conditional(c: Checker, gen) -> None:
    print("[6] conditional-install flag simulation")
    root = ET.parse(MODULECONFIG).getroot()

    titles = {p.title: p.name for p in gen.PROFILES}
    base_selection = {
        "HeapSentinel": {"Install HeapSentinel": ["Install HeapSentinel"]},
    }
    seen_sources: set[str] = set()
    for profile in gen.PROFILES:
        selection = dict(base_selection)
        selection["Configuration profile"] = {"Memory / attribution trade-off": [profile.title]}
        required, conditional = simulate_selection(root, selection)
        expected_src = f"fomod/profiles/{profile.name}.ini"
        dests = [dest for _, dest in conditional]
        if conditional != [(expected_src, "SKSE/Plugins/HeapSentinel.ini")]:
            c.fail(f"profile {profile.name}: conditional installs are {conditional!r}")
            continue
        if dests != ["SKSE/Plugins/HeapSentinel.ini"]:
            c.fail(f"profile {profile.name}: unexpected destination {dests!r}")
            continue
        seen_sources.add(conditional[0][0])
        c.ok(f"{profile.title} -> {conditional[0][0]}")
    if len(seen_sources) == len(gen.PROFILES):
        c.ok("every profile selects a distinct ini file")
    else:
        c.fail(f"only {len(seen_sources)} distinct profile inis are reachable")


# ---------------------------------------------------------------------------
# 6. archive
# ---------------------------------------------------------------------------

def build_zip(c: Checker, stage: Path, zip_path: Path) -> None:
    print("[7] archive")
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(stage).as_posix())
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    failures_before = len(c.failures)
    required = {
        "fomod/ModuleConfig.xml",
        "fomod/info.xml",
        "SKSE/Plugins/HeapSentinel.dll",
        "SKSE/Plugins/HeapSentinel.pdb",
        "meta.ini",
    }
    for name in sorted(required):
        if name not in names:
            c.fail(f"{name} missing from {zip_path.name}")
    if not any(n.startswith("fomod/profiles/") for n in names):
        c.fail("no profile inis in the archive")
    if len(c.failures) == failures_before:
        c.ok(f"{zip_path.name}: {len(names)} entries, FOMOD + DLL + profiles present")


# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate HeapSentinel's FOMOD.")
    parser.add_argument("--dll", type=Path, default=None, help="built HeapSentinel.dll to stage")
    parser.add_argument("--pdb", type=Path, default=None, help="built HeapSentinel.pdb to stage next to the DLL")
    parser.add_argument("--zip", type=Path, default=None, help="write the FOMOD archive here")
    parser.add_argument("--stage", type=Path, default=None, help="staging directory (default: temp)")
    args = parser.parse_args(argv)

    gen = load_generator()
    c = Checker()

    check_up_to_date(c, gen)
    check_meta_ini(c, gen)
    check_keys(c, gen)
    check_xml(c, gen)

    stage = args.stage or Path(tempfile.mkdtemp(prefix="hs-fomod-stage-"))
    try:
        check_package(c, gen, args.dll, args.pdb, stage)
        check_conditional(c, gen)
        if args.zip is not None:
            build_zip(c, stage, args.zip)
        elif args.stage is None:
            shutil.rmtree(stage, ignore_errors=True)
    finally:
        pass

    print()
    if c.skips:
        print(f"{len(c.skips)} check(s) skipped:")
        for item in c.skips:
            print(f"  - {item}")
    if c.failures:
        print(f"RESULT: FAILED ({len(c.failures)} failure(s))")
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))