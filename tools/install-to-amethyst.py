#!/usr/bin/env python3
"""Install a HeapSentinel release into the local Amethyst profile, headlessly.

Why this exists
---------------
Amethyst's CLI (`amethyst-mod-manager-cli`) can deploy a profile but cannot
install a mod archive, and the GUI is not required to install one: the same
library that the GUI calls is importable. This script drives it end to end:

    extract -> FOMOD resolve (one profile) -> stage into the profile's mods/
    -> write meta.ini -> re-point the deployed HeapSentinel.ini's
    [Watchpoints] bEnabled -> drop stale HeapSentinel-* folders
    -> edit modlist.txt -> FileGraphService.refresh(profile_dir)
    -> (host) amethyst-mod-manager-cli deploy skyrim_se default -> verify

The filegraph refresh is the step whose absence made an earlier deploy REMOVE
the plugin: the filegraph is a cache, and deploy's `ensure_ready()` trusts it.
Without refresh it did not know the new mod directory existed, planned an empty
deployment, and unlinked the old DLL/PDB.

Safety:
  * The game-running guard gates ONLY the deploy. Installing, resolving,
    staging, writing meta.ini and refreshing the catalog are safe mid-session;
    deploying is not. `pgrep -af 'SkyrimSE[.]exe'` is run on the HOST (flatpak's
    PID namespace cannot see the game), and the bracket is mandatory so the
    pattern cannot match the invoking shell's own command line.
  * This script never writes into the game directory. Amethyst deploys; the
    script only stages, indexes and verifies.
  * Idempotent: the target mod folder is replaced, stale folders and modlist
    rows are removed, and re-running installs the same result.

Run it on the HOST:

    python3 tools/install-to-amethyst.py \
        --archive HeapSentinel-0.6.1-fomod.zip \
        [--loose-dll HeapSentinel.dll] [--loose-pdb HeapSentinel.pdb] \
        [--fomod-profile balanced] [--profile default] [--skip-deploy]

It re-executes itself with `flatpak run --command=python3 io.github.Amethyst.ModManager`
for the library-dependent part (`--inner`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

FLATPAK_ID = "io.github.Amethyst.ModManager"
DEFAULT_GAME = "skyrim_se"
DEFAULT_PROFILE = "default"
DEFAULT_FOMOD_PROFILE = "balanced"
PROFILE_GROUP = "Memory / attribution trade-off"

# The guard pattern. Capital S/E as the process name is `SkyrimSE.exe`, and the
# bracket so `pgrep -f` cannot match the shell that runs it.
GAME_PATTERN = "SkyrimSE[.]exe"


def log(msg: str) -> None:
    print(f"[hs-install] {msg}", flush=True)


def die(msg: str, code: int = 2) -> "NoReturn":  # type: ignore[name-defined]
    print(f"[hs-install] ERROR: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# Host side
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def game_running() -> bool:
    """True when the game process is visible from the HOST. Flatpak's PID
    namespace cannot see it, so this must run outside the sandbox."""
    try:
        proc = subprocess.run(
            ["pgrep", "-af", GAME_PATTERN],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        die("pgrep not found; refusing to guess whether the game is running")
    if proc.returncode == 0 and proc.stdout.strip():
        for line in proc.stdout.splitlines():
            log(f"game process: {line.strip()}")
        return True
    return False


def find_member(zf: zipfile.ZipFile, suffix: str) -> str:
    suffix = suffix.lower()
    for name in zf.namelist():
        normalised = name.replace("\\", "/").lower()
        if normalised.endswith(suffix):
            return name
    raise KeyError(suffix)


def version_from_name(path: Path) -> str | None:
    m = re.search(r"HeapSentinel-(\d+\.\d+\.\d+)", path.name)
    return m.group(1) if m else None


def read_ini(path: Path, section: str, key: str):
    if not path or not Path(path).is_file():
        return None
    current = None
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current == section and "=" in line:
            k, _, v = line.partition("=")
            if k.strip().lower() == key.lower():
                return v.strip()
    return None


def verify_archive(archive: Path) -> dict:
    """Pre-install checks that do not need the manager."""
    if not archive.is_file():
        die(f"archive not found: {archive}")
    result: dict = {"archive": str(archive)}
    with zipfile.ZipFile(archive) as zf:
        names = [n.replace("\\", "/") for n in zf.namelist()]
        result["dll_member"] = find_member(zf, "skse/plugins/heapsentinel.dll")
        result["pdb_member"] = find_member(zf, "skse/plugins/heapsentinel.pdb")
        result["dll_sha256"] = sha256_bytes(zf.read(result["dll_member"]))
        result["pdb_sha256"] = sha256_bytes(zf.read(result["pdb_member"]))
        result["has_fomod"] = any(
            n.lower().endswith("fomod/moduleconfig.xml") for n in names
        )
        result["has_meta_ini"] = any(
            n.lower() == "meta.ini" for n in names
        )
        # The release asset NAME must agree with the content version.
        if "meta.ini" in names:
            # read the root meta.ini member (first exact match)
            meta_name = next(n for n in zf.namelist() if n.replace("\\", "/") == "meta.ini")
            meta_text = zf.read(meta_name).decode("utf-8", "replace")
            m = re.search(r"^version\s*=\s*(\S+)", meta_text, re.MULTILINE)
            meta_version = m.group(1) if m else None
            name_version = version_from_name(archive)
            result["name_version"] = name_version
            result["meta_version"] = meta_version
            if name_version and meta_version and name_version != meta_version:
                die(
                    f"archive name says {name_version} but meta.ini says "
                    f"{meta_version} - the asset lies about itself"
                )
    log(f"archive: {archive.name}")
    log(f"  FOMOD: {result['has_fomod']}, meta.ini: {result['has_meta_ini']}")
    log(f"  DLL sha256: {result['dll_sha256']}")
    log(f"  PDB sha256: {result['pdb_sha256']}")
    if not result["has_meta_ini"]:
        log("WARNING: the archive does not carry meta.ini (expected from v0.6.1)")
    return result


def locate_deployed(game_data) -> dict:
    base = Path(game_data) / "SKSE" / "Plugins"
    return {
        "dll": base / "HeapSentinel.dll",
        "pdb": base / "HeapSentinel.pdb",
        "ini": base / "HeapSentinel.ini",
    }


def verify_deployment(game_data: Path, archive: Path, expected: dict,
                      loose_dll: Path | None, loose_pdb: Path | None) -> bool:
    deployed = locate_deployed(game_data)
    ok = True
    log("verification:")

    for label in ("dll", "pdb", "ini"):
        path = deployed[label]
        if not os.path.lexists(path):
            log(f"  FAIL: {path} does not exist")
            ok = False
        elif not path.is_file():
            log(f"  FAIL: {path} exists but is not a readable file (broken symlink?)")
            ok = False

    if deployed["dll"].is_file():
        actual = sha256_file(deployed["dll"])
        log(f"  deployed DLL sha256: {actual}")
        if actual != expected["dll_sha256"]:
            log(f"  FAIL: deployed DLL differs from the release archive "
                f"({expected['dll_sha256']})")
            ok = False
        else:
            log("  ok: deployed DLL sha256 == the FOMOD archive's DLL")
        if loose_dll is not None:
            loose = sha256_file(loose_dll)
            if loose != actual:
                log(f"  FAIL: loose release asset {loose_dll.name} ({loose}) "
                    "differs from the deployed DLL")
                ok = False
            else:
                log("  ok: loose release DLL == deployed DLL")

    if deployed["pdb"].is_file():
        actual_pdb = sha256_file(deployed["pdb"])
        log(f"  deployed PDB sha256: {actual_pdb} ({deployed['pdb'].stat().st_size} bytes)")
        with open(deployed["pdb"], "rb") as f:
            head = f.read(64)
        if b"MSF" not in head:
            log("  FAIL: deployed PDB is not a Windows PDB (no MSF signature)")
            ok = False
        elif actual_pdb != expected["pdb_sha256"]:
            log("  FAIL: deployed PDB differs from the release archive's PDB")
            ok = False
        else:
            log("  ok: deployed HeapSentinel.pdb is a Windows PDB and matches the archive")
        if loose_pdb is not None and sha256_file(loose_pdb) != actual_pdb:
            log(f"  FAIL: loose release asset {loose_pdb.name} differs from the deployed PDB")
            ok = False

    if deployed["ini"].is_file():
        b_enabled = read_ini(deployed["ini"], "Watchpoints", "bEnabled")
        log(f"  deployed ini [Watchpoints] bEnabled={b_enabled}")
        if b_enabled != "1":
            log("  FAIL: [Watchpoints] bEnabled is not 1 - the user's enabled "
                "watchpoints setting did not survive the reinstall")
            ok = False
        else:
            log("  ok: [Watchpoints] bEnabled=1 survived")
    return ok


def share_path(path: Path) -> Path:
    """Return *path* as seen from inside the flatpak.

    The sandbox has a PRIVATE /tmp, so an archive passed from the host as
    /tmp/... does not exist inside it. Copy anything outside $HOME into a
    shared cache directory under $HOME first.
    """
    path = path.resolve()
    home = Path.home().resolve()
    try:
        path.relative_to(home)
        return path
    except ValueError:
        pass
    shared = home / ".cache" / "heapsentinel-install"
    shared.mkdir(parents=True, exist_ok=True)
    dest = shared / path.name
    shutil.copyfile(path, dest)
    log(f"copied {path} -> {dest} (flatpak has a private /tmp)")
    return dest


def host_main(args) -> int:
    archive = Path(args.archive).resolve()
    expected = verify_archive(archive)

    running = game_running()
    if running:
        log("the game is RUNNING: install + index will proceed, DEPLOY is skipped")
    else:
        log("game is not running: deploy is allowed")

    script = Path(__file__).resolve()
    inner_archive = share_path(archive)
    inner_cmd = [
        "flatpak", "run", "--command=python3", FLATPAK_ID, str(script),
        "--inner",
        "--archive", str(inner_archive),
        "--game", args.game,
        "--profile", args.profile,
        "--fomod-profile", args.fomod_profile,
        "--watchpoints-b-enabled", args.watchpoints_b_enabled,
        "--mod-name", args.mod_name or "",
        "--data-dir", str(args.data_dir),
    ]
    log(f"running inner installer in flatpak: {' '.join(inner_cmd)}")
    proc = subprocess.run(inner_cmd, capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        die(f"inner installer failed (exit {proc.returncode})", proc.returncode)

    result_line = next(
        (ln for ln in reversed(proc.stdout.splitlines()) if ln.startswith("HS_RESULT ")),
        None,
    )
    if result_line is None:
        die("inner installer produced no HS_RESULT line")
    result = json.loads(result_line[len("HS_RESULT "):])
    log(f"staged '{result['mod_name']}' at {result['mod_dir']} "
        f"(fomod profile: {result.get('fomod_profile') or 'n/a'})")

    if args.skip_deploy:
        log("--skip-deploy given: not deploying")
        return 0
    if running:
        log("game is running: NOT deploying. Re-run when the game is closed, "
            "or deploy from Amethyst. The freshly installed mod is staged and indexed.")
        return 0

    log("deploying via amethyst-mod-manager-cli ...")
    deploy = subprocess.run(
        ["flatpak", "run", "--command=amethyst-mod-manager-cli", FLATPAK_ID,
         "deploy", args.game, args.profile],
        capture_output=True, text=True,
    )
    sys.stdout.write(deploy.stdout)
    sys.stderr.write(deploy.stderr)
    if deploy.returncode != 0:
        die(f"deploy failed (exit {deploy.returncode})", deploy.returncode)

    loose_dll = Path(args.loose_dll).resolve() if args.loose_dll else None
    loose_pdb = Path(args.loose_pdb).resolve() if args.loose_pdb else None
    if loose_dll is not None and not loose_dll.is_file():
        die(f"--loose-dll not found: {loose_dll}")
    if loose_pdb is not None and not loose_pdb.is_file():
        die(f"--loose-pdb not found: {loose_pdb}")

    if not verify_deployment(args.data_dir, archive, expected, loose_dll, loose_pdb):
        die("deployment verification FAILED", 1)
    log("SUCCESS: HeapSentinel staged, indexed, deployed and verified")
    return 0


# ---------------------------------------------------------------------------
# Inner side (inside the flatpak, with Amethyst's library importable)
# ---------------------------------------------------------------------------

def pick_profile_plugin(config, wanted: str) -> tuple[int, str, str] | None:
    for i, step in enumerate(config.steps):
        for group in step.groups:
            if group.name != PROFILE_GROUP:
                continue
            for plugin in group.plugins:
                if wanted in (plugin.name, plugin.condition_flags.get("profile", "")):
                    return i, group.name, plugin.name
    return None


def patch_ini_value(path: Path, section: str, key: str, value: str) -> bool:
    if not path.is_file():
        return False
    lines = path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    current = None
    for i, raw in enumerate(lines):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current == section and "=" in line:
            k, _, _v = line.partition("=")
            if k.strip().lower() == key.lower():
                lines[i] = f"{key}={value}"
                path.write_text("\n".join(lines) + "\n",
                                encoding="utf-8", errors="surrogateescape")
                return True
    lines.append(f"[{section}]")
    lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8",
                    errors="surrogateescape")
    return True


def edit_modlist(profile_dir: Path, mod_name: str) -> None:
    from Utils.mods.modlist import (modlist_lock, read_modlist, write_modlist,
                                    ModEntry)
    modlist_path = profile_dir / "modlist.txt"

    # Back up before editing (timestamped, never clobber an existing backup).
    if modlist_path.is_file():
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = modlist_path.with_name(f"modlist.txt.bak-pre-{mod_name}-{stamp}")
        shutil.copyfile(modlist_path, backup)
        log(f"backed up modlist.txt -> {backup.name}")

    with modlist_lock(modlist_path):
        entries = read_modlist(modlist_path)
        kept: list = []
        removed: list[str] = []
        for entry in entries:
            if (entry.name.lower().startswith("heapsentinel")
                    and entry.name != mod_name):
                removed.append(entry.name)
                continue
            kept.append(entry)
        target = next((e for e in kept if e.name == mod_name), None)
        if target is not None:
            target.enabled = True
            target.locked = False
        else:
            kept.insert(0, ModEntry(name=mod_name, enabled=True, locked=False))
        write_modlist(modlist_path, kept)
    if removed:
        log(f"removed stale modlist rows: {', '.join(removed)}")
    present = next((e for e in read_modlist(modlist_path) if e.name == mod_name), None)
    if present is None or not present.enabled:
        die(f"'{mod_name}' is not an enabled modlist entry after the edit")
    log(f"modlist.txt: +{mod_name} (enabled)")


def inner_main(args) -> int:
    import app_bootstrap  # type: ignore
    app_bootstrap.setup_environment()

    import zipfile as _zipfile
    from datetime import datetime

    from Utils.games.discovery import discover_games
    from Utils.fomod.parser import detect_fomod, parse_module_config
    from Utils.fomod.installer import (get_default_selections, update_flags,
                                       resolve_files)
    from Utils.mods.install import (stage_file_list, _copy_file_list)
    from Nexus.nexus_meta import read_meta, write_meta, NexusModMeta
    from Utils.filegraph.service import FileGraphService

    archive = Path(args.archive)
    games = discover_games()
    game = None
    for name, g in games.items():
        if (name.lower() == args.game.lower()
                or getattr(g, "game_id", "").lower() == args.game.lower()):
            game = g
            break
    if game is None:
        die(f"game '{args.game}' not found (have: {sorted(games)})")
    profile_dir = Path(game.get_profile_root()) / "profiles" / args.profile
    if not profile_dir.is_dir():
        die(f"profile directory not found: {profile_dir}")

    from Utils.mods.copy import resolve_target_staging
    staging = Path(resolve_target_staging(game, profile_dir))
    staging.mkdir(parents=True, exist_ok=True)

    mod_name = args.mod_name or archive.stem
    dest_root = staging / mod_name

    # Capture the user's [Watchpoints] bEnabled BEFORE replacing anything.
    # It must be read from every prior location (the currently deployed ini and
    # every existing HeapSentinel staged install) because the first reinstall
    # moves the value out of the old folder into the new one: reading only the
    # destination after the copy would let the FOMOD profile default (0) win and
    # silently disable the watchpoints the user enabled.
    deployed_ini = Path(args.data_dir) / "SKSE" / "Plugins" / "HeapSentinel.ini"
    prior_values = [
        read_ini(cand, "Watchpoints", "bEnabled")
        for cand in [deployed_ini]
        + sorted(staging.glob("HeapSentinel*/SKSE/Plugins/HeapSentinel.ini"))
    ]
    prior_values = [v for v in prior_values if v is not None]
    if args.watchpoints_b_enabled in ("0", "1"):
        prior = args.watchpoints_b_enabled
        log(f"[Watchpoints] bEnabled forced to {prior} by --watchpoints-b-enabled")
    elif "1" in prior_values:
        prior = "1"
    elif prior_values:
        prior = prior_values[0]
    else:
        prior = None
    if prior_values:
        log(f"previous [Watchpoints] bEnabled values: {sorted(set(prior_values))}")

    extract_dir = Path(tempfile.mkdtemp(prefix="hs-install-"))
    try:
        with _zipfile.ZipFile(archive) as zf:
            zf.extractall(extract_dir)
        detected = detect_fomod(extract_dir)
        fomod_profile = None

        if dest_root.exists():
            log(f"replacing existing mod folder: {mod_name}")
            shutil.rmtree(dest_root)
        dest_root.mkdir(parents=True, exist_ok=True)

        if detected:
            mod_root, config_path = detected
            log(f"FOMOD detected: {config_path}")
            config = parse_module_config(config_path)
            wanted = args.fomod_profile
            picks = pick_profile_plugin(config, wanted)
            if picks is None and wanted:
                available = sorted({
                    p.condition_flags.get("profile", "")
                    for step in config.steps for grp in step.groups
                    for p in grp.plugins
                    if "profile" in p.condition_flags
                })
                die(f"FOMOD profile '{wanted}' not found; available: {available}")
            selections: dict = {}
            flag_state: dict = {}
            for i, step in enumerate(config.steps):
                sels = get_default_selections(step, flag_state, set(), set(), set())
                if picks is not None and i == picks[0]:
                    sels[picks[1]] = [picks[2]]
                selections[str(i)] = sels
                flag_state = update_flags(step, sels, flag_state)
            if picks is not None:
                fomod_profile = wanted
            files = resolve_files(config, selections, set(), set(), set())
            if not files:
                die("FOMOD resolve_files returned no files")
            _copy_file_list(files, mod_root, dest_root, log, game=game)
        else:
            log("no FOMOD: staging as a plain mod")
            file_list = stage_file_list(game, str(extract_dir), mod_name=mod_name,
                                        log_fn=log)
            if not file_list:
                die("stage_file_list returned no files")
            _copy_file_list(file_list, str(extract_dir), dest_root, log, game=game)

        # --- meta.ini -----------------------------------------------------
        src_meta = extract_dir / "meta.ini"
        meta = read_meta(src_meta) if src_meta.is_file() else NexusModMeta()
        meta.installation_file = archive.name
        try:
            meta.file_size = archive.stat().st_size
        except OSError:
            pass
        meta.installed = datetime.now().isoformat(timespec="seconds")
        if detected:
            meta.is_fomod = True
        write_meta(dest_root / "meta.ini", meta)
        log(f"wrote {dest_root / 'meta.ini'} "
            f"(version={meta.version!r}, gameName={meta.game_domain!r})")

        # --- preserve the user's enabled watchpoints ----------------------
        new_ini = dest_root / "SKSE" / "Plugins" / "HeapSentinel.ini"
        if prior == "1" and read_ini(new_ini, "Watchpoints", "bEnabled") != "1":
            patch_ini_value(new_ini, "Watchpoints", "bEnabled", "1")
            log("carried forward [Watchpoints] bEnabled=1 into the new install")
        else:
            log(f"[Watchpoints] bEnabled in the new install: "
                f"{read_ini(new_ini, 'Watchpoints', 'bEnabled')} (prior: {prior})")

        # --- drop stale HeapSentinel-* mod folders ------------------------
        for entry in sorted(staging.iterdir()):
            if (entry.is_dir() and entry.name.lower().startswith("heapsentinel")
                    and entry.name != mod_name):
                shutil.rmtree(entry)
                log(f"removed stale mod folder: {entry.name}")

        # --- modlist + filegraph ------------------------------------------
        edit_modlist(profile_dir, mod_name)

        log("refreshing the filegraph catalog (this is the step that must not "
            "be skipped before deploy) ...")
        library = FileGraphService.open_library(game, profile_dir, log_fn=log)
        status = library.refresh(profile_dir)
        log(f"filegraph refreshed: {status}")
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)

    print("HS_RESULT " + json.dumps({
        "mod_name": mod_name,
        "mod_dir": str(dest_root),
        "fomod_profile": fomod_profile,
        "meta_ini": str(dest_root / "meta.ini"),
    }), flush=True)
    return 0


# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive", required=True,
                        help="release archive (.zip) to install")
    parser.add_argument("--loose-dll", default=None,
                        help="loose HeapSentinel.dll release asset, to cross-check the hash")
    parser.add_argument("--loose-pdb", default=None,
                        help="loose HeapSentinel.pdb release asset, to cross-check the hash")
    parser.add_argument("--game", default=DEFAULT_GAME)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--fomod-profile", default=DEFAULT_FOMOD_PROFILE,
                        help="FOMOD profile flag value (default: balanced)")
    parser.add_argument("--watchpoints-b-enabled", default="auto",
                        choices=["auto", "0", "1"],
                        help="[Watchpoints] bEnabled in the installed ini; auto (default) "
                             "preserves the previous value, preferring 1")
    parser.add_argument("--mod-name", default=None,
                        help="mod folder name (default: the archive stem)")
    parser.add_argument("--data-dir", default=None,
                        help="game Data directory (default: <game>/Data)")
    parser.add_argument("--skip-deploy", action="store_true")
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.inner:
        return inner_main(args)

    if args.data_dir is None:
        # Resolve the game Data dir on the host from Steam's default location.
        steam = Path.home() / ".local/share/Steam/steamapps/common"
        args.data_dir = str(steam / "Skyrim Special Edition" / "Data")
    args.data_dir = str(Path(args.data_dir).resolve())
    return host_main(args)


if __name__ == "__main__":
    raise SystemExit(main())