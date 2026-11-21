#!/usr/bin/env python3
"""Deterministic bootstrap tool for VGT HardRed first-party Go probes and pinned third-party suites."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBES_DIR = ROOT / "probes"
PROBES_BIN = PROBES_DIR / "bin"
TP_DIR = ROOT / "third_party"
TP_BIN = TP_DIR / "bin"

REPOS: list[tuple[str, str, str, list[str]]] = [
    ("gotestwaf", "https://github.com/wallarm/gotestwaf.git", "5daeba073823a57e79ba922beef0c2d92a8dd776", []),
    ("go-ftw", "https://github.com/coreruleset/go-ftw.git", "84559ca9bce1264981c67c61a1c462cadd86163a", []),
    ("event-generator", "https://github.com/falcosecurity/event-generator.git", "07d29365f0d3ba0d160a9d703c914dd293aa27e2", []),
    ("lynis", "https://github.com/CISOfy/lynis.git", "a9527dc768f447bce71205fa3f2b0f78492844c0", []),
]

ART_REPO = ("atomic-red-team", "https://github.com/redcanaryco/atomic-red-team.git", "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6")


def run_cmd(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print(f"[bootstrap] $ {' '.join(cmd)}")
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=merged_env, check=True)


def build_first_party_probes() -> None:
    PROBES_BIN.mkdir(parents=True, exist_ok=True)
    go_exe = shutil.which("go")
    if not go_exe:
        raise RuntimeError("Go toolchain ('go') not found in PATH. Install Go 1.22+ first.")

    # Linux amd64 static probes
    run_cmd(
        [go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(PROBES_BIN / "hardred-probe-linux-amd64"), "./cmd/hardred-probe"],
        cwd=PROBES_DIR,
        env={"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
    )
    run_cmd(
        [go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(PROBES_BIN / "hardred-netbench-linux-amd64"), "./cmd/hardred-netbench"],
        cwd=PROBES_DIR,
        env={"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
    )
    # Host-native netbench binary
    host_out = PROBES_BIN / ("hardred-netbench.exe" if os.name == "nt" else "hardred-netbench")
    run_cmd(
        [go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(host_out), "./cmd/hardred-netbench"],
        cwd=PROBES_DIR,
        env={"CGO_ENABLED": "0"},
    )
    print(f"[bootstrap] Built first-party Go probes in {PROBES_BIN}")


def clone_pinned_repos() -> None:
    TP_DIR.mkdir(parents=True, exist_ok=True)
    TP_BIN.mkdir(parents=True, exist_ok=True)
    git_exe = shutil.which("git")
    go_exe = shutil.which("go")
    if not git_exe:
        raise RuntimeError("Git ('git') not found in PATH.")

    for name, url, commit, _ in REPOS:
        dest = TP_DIR / name
        if not dest.exists():
            run_cmd([git_exe, "clone", "--no-checkout", url, str(dest)])
        run_cmd([git_exe, "fetch", "--depth", "1", "origin", commit], cwd=dest)
        run_cmd([git_exe, "checkout", "--force", commit], cwd=dest)

    # Atomic Red Team sparse checkout (atomics/ only)
    art_dest = TP_DIR / ART_REPO[0]
    if not art_dest.exists():
        run_cmd([git_exe, "clone", "--depth", "1", "--filter=blob:none", "--sparse", ART_REPO[1], str(art_dest)])
        run_cmd([git_exe, "sparse-checkout", "set", "atomics"], cwd=art_dest)
    run_cmd([git_exe, "fetch", "--depth", "1", "origin", ART_REPO[2]], cwd=art_dest)
    run_cmd([git_exe, "checkout", "--force", ART_REPO[2]], cwd=art_dest)

    if go_exe:
        # Build GoTestWAF
        gtw_out = TP_BIN / ("gotestwaf.exe" if os.name == "nt" else "gotestwaf")
        run_cmd([go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(gtw_out), "./cmd/"], cwd=TP_DIR / "gotestwaf", env={"CGO_ENABLED": "0"})
        run_cmd([go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(TP_BIN / "gotestwaf-linux-amd64"), "./cmd/"], cwd=TP_DIR / "gotestwaf", env={"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})

        # Build go-ftw
        ftw_out = TP_BIN / ("go-ftw.exe" if os.name == "nt" else "go-ftw")
        run_cmd([go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(ftw_out), "."], cwd=TP_DIR / "go-ftw", env={"CGO_ENABLED": "0"})
        run_cmd([go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(TP_BIN / "go-ftw-linux-amd64"), "."], cwd=TP_DIR / "go-ftw", env={"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})

        # Build Falco event-generator (Linux amd64)
        ev_dir = TP_DIR / "event-generator"
        run_cmd([go_exe, "run", "./tools/file-bundler/", "events/k8saudit/yaml"], cwd=ev_dir)
        run_cmd([go_exe, "build", "-trimpath", "-ldflags=-s -w", "-o", str(TP_BIN / "event-generator-linux-amd64"), "./cmd/event-generator"], cwd=ev_dir, env={"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap VGT HardRed probes and pinned upstream suites.")
    parser.add_argument("--probes-only", action="store_true", help="Compile first-party Go probes only.")
    args = parser.parse_args()

    build_first_party_probes()
    if not args.probes_only:
        clone_pinned_repos()
    print("[bootstrap] Complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
