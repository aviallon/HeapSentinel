#!/usr/bin/env python3
"""Cross-check the FOMOD against Amethyst's OWN resolver, headlessly.

`src/cli.py` has no "install a mod archive" subcommand, so the manager's GUI
cannot be driven to install a FOMOD from the shell. But the part of Amethyst
that decides *which files a FOMOD installs* is pure, stdlib-only logic
(`Utils.fomod.parser` + `Utils.fomod.installer.resolve_files`). This script
imports that code directly, points it at the built archive, performs the
three-phase install the manager performs (required -> plugin files ->
conditional files, last write wins), and asserts the resulting
SKSE/Plugins/HeapSentinel.ini is byte-for-byte the selected profile.

That is a genuine end-to-end check of the installer logic, using the manager's
own implementation rather than ours. It does NOT run the GUI, and it does NOT
touch the user's game install or active profile.

Usage:
    python3 tools/check-amethyst-fomod.py \
        --amethyst-src ~/Programing/Opensource/Amethyst-Mod-Manager/src \
        --zip /tmp/HeapSentinel-0.3.0-fomod.zip
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from xml.etree import ElementTree as ET


def load_amethyst(src: Path):
    sys.path.insert(0, str(src))
    from Utils.fomod.parser import detect_fomod, parse_module_config  # type: ignore
    from Utils.fomod.installer import get_default_selections, resolve_files  # type: ignore

    return detect_fomod, parse_module_config, get_default_selections, resolve_files


def profile_titles(module_config_path: Path) -> list[str]:
    root = ET.parse(module_config_path).getroot()
    titles = []
    for plugin in root.iter():
        tag = plugin.tag.split("}", 1)[1] if "}" in plugin.tag else plugin.tag
        if tag != "plugin":
            continue
        if any(
            (f.tag.split("}", 1)[1] if "}" in f.tag else f.tag) == "conditionFlags"
            and any(
                (fl.tag.split("}", 1)[1] if "}" in fl.tag else fl.tag) == "flag"
                and fl.get("name") == "profile"
                for fl in f
            )
            for f in plugin
        ):
            titles.append(plugin.get("name", ""))
    return titles


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--amethyst-src", type=Path, required=True)
    parser.add_argument("--zip", type=Path, required=True)
    args = parser.parse_args(argv)

    detect_fomod, parse_module_config, get_default_selections, resolve_files = load_amethyst(
        args.amethyst_src
    )

    extract_root = Path(tempfile.mkdtemp(prefix="hs-amethyst-"))
    install_root = Path(tempfile.mkdtemp(prefix="hs-install-"))
    failures: list[str] = []
    try:
        with zipfile.ZipFile(args.zip) as zf:
            zf.extractall(extract_root)

        found = detect_fomod(str(extract_root))
        if not found:
            print("FAIL: Amethyst's detect_fomod did not find fomod/ModuleConfig.xml")
            return 1
        mod_root, cfg_path = found
        print(f"detect_fomod -> {cfg_path}")
        config = parse_module_config(cfg_path)
        print(f"moduleName   -> {config.name}")

        titles = profile_titles(Path(cfg_path))
        print(f"profiles     -> {titles}")
        if not titles:
            print("FAIL: no profile plugins found")
            return 1

        # 1. Amethyst's own defaults must select the Recommended profile.
        default_sel: dict[str, dict[str, list[str]]] = {}
        flag_state: dict[str, str] = {}
        for i, step in enumerate(config.steps):
            selection = get_default_selections(step, flag_state, set())
            default_sel[str(i)] = selection
            for group in step.groups:
                for plugin in group.plugins:
                    if plugin.name in selection.get(group.name, []):
                        flag_state.update(plugin.condition_flags)
        default_resolved = resolve_files(config, default_sel)
        default_ini = [
            (s, d) for s, d, _ in default_resolved if d == "SKSE/Plugins/HeapSentinel.ini"
        ]
        if default_ini != [("fomod/profiles/balanced.ini", "SKSE/Plugins/HeapSentinel.ini")]:
            failures.append(f"Amethyst defaults resolved to {default_ini!r}, expected balanced.ini")
        else:
            print("defaults     -> fomod/profiles/balanced.ini (Recommended)")

        # 2. Each explicit profile choice installs exactly its own ini.
        for title in titles:
            selection = {
                "HeapSentinel": {"Install HeapSentinel": ["Install HeapSentinel"]},
                "Configuration profile": {"Memory / attribution trade-off": [title]},
            }
            resolved = resolve_files(config, selection)
            ini_files = [(s, d) for s, d, _ in resolved if d == "SKSE/Plugins/HeapSentinel.ini"]
            sources = [s for s, _ in ini_files]
            if len(sources) != 1:
                failures.append(f"{title!r}: expected 1 ini install, got {ini_files!r}")
                continue

            slug = Path(sources[0]).stem
            expected_path = Path(mod_root) / "fomod" / "profiles" / f"{slug}.ini"
            if not expected_path.is_file():
                failures.append(f"{title!r}: resolved to missing {expected_path}")
                continue

            # Perform the install exactly as the manager does, into a scratch dir.
            out = Path(tempfile.mkdtemp(prefix=f"hs-{slug}-", dir=install_root))
            for src, dst, _ in resolved:
                source = Path(mod_root) / src
                destination = out / dst
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            installed = (out / "SKSE" / "Plugins" / "HeapSentinel.ini").read_text(encoding="utf-8")
            expected = expected_path.read_text(encoding="utf-8")
            if installed != expected:
                failures.append(f"{title!r}: installed ini != {expected_path.name}")
            else:
                print(f"install      -> {title!r}: SKSE/Plugins/HeapSentinel.ini == {expected_path.name}")
    finally:
        shutil.rmtree(extract_root, ignore_errors=True)
        shutil.rmtree(install_root, ignore_errors=True)

    print()
    if failures:
        for item in failures:
            print(f"FAIL: {item}")
        return 1
    print("RESULT: Amethyst's resolver installs the intended profile ini for every choice")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))