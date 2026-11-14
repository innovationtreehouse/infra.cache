#!/usr/bin/env python3
"""Build GitHub Release assets in ./dist.

The version is not stored in the repo: release.yml passes the pushed tag in
FC_RELEASE_VERSION, and local/dev builds fall back to `git describe`. The
archives still ship a generated VERSION file so installed clients keep their
existing layout (/usr/local/lib/facility-cache/VERSION, ProgramData\\...\\VERSION).

Builds are reproducible: the same commit packs to byte-identical archives.
Every member gets owner 0/0 root/root, mode 0755 (source has an exec bit)
or 0644, and one fixed mtime -- SOURCE_DATE_EPOCH if set, else the commit
time (`git log -1 --format=%ct`). The gzip header carries that time and no
file name. Member order is the explicit allow-list order below.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
LINUX_FILES = [
    "linux/install.sh",
    "linux/uninstall.sh",
    "linux/lib/common.sh",
    "linux/lib/ui.sh",
    "linux/lib/facility_ui.py",
    "linux/lib/ensure_gh.sh",
    "linux/bin/facility-cache",
    "linux/bin/facility-cache-probe",
    "linux/bin/facility-apt-proxy",
    "linux/bin/treehouse-git",
    "linux/sbin/facility-cache-apply",
    "linux/sbin/facility-cache-update",
    "linux/sbin/facility-cache-ensure-gh",
    "linux/apt/00facility-cache",
    "linux/profile.d/facility-cache.sh",
    "linux/nm-dispatcher/99-facility-cache",
    "linux/systemd/facility-cache-apply.service",
    "linux/systemd/facility-cache-apply.timer",
    "linux/systemd/facility-cache-update.service",
    "linux/systemd/facility-cache-update.timer",
    "linux/bootstrap.sh",
]
WINDOWS_FILES = [
    "windows/FacilityCache.psm1",
    "windows/FacilityCache-Apply.ps1",
    "windows/FacilityCache-Update.ps1",
    "windows/Install-FacilityCache.ps1",
    "windows/Uninstall-FacilityCache.ps1",
    "windows/Status-FacilityCache.ps1",
    "windows/Install-FromGitHub.ps1",
    "windows/Treehouse-Git.ps1",
]


def resolve_version() -> str:
    """FC_RELEASE_VERSION (set from the tag by release.yml), else git describe."""
    env = os.environ.get("FC_RELEASE_VERSION", "").strip().lstrip("v")
    if env:
        return env
    try:
        described = subprocess.run(
            ["git", "-C", str(ROOT), "describe", "--tags", "--match", "v*", "--dirty"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if described:
            return described.lstrip("v")
    except (OSError, subprocess.CalledProcessError):
        pass
    return "0.0.0-dev"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


ZIP_EPOCH_MIN = 315532800  # 1980-01-01: zip timestamps cannot go earlier


def source_date_epoch() -> int:
    """SOURCE_DATE_EPOCH, else the HEAD commit time, else 1980-01-01."""
    env = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if env:
        return max(int(env), ZIP_EPOCH_MIN)
    try:
        ct = subprocess.run(
            ["git", "-C", str(ROOT), "log", "-1", "--format=%ct"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return max(int(ct), ZIP_EPOCH_MIN)
    except (OSError, subprocess.CalledProcessError, ValueError):
        return ZIP_EPOCH_MIN


def members(prefix: str, version: str, extra: list[str], files: list[str]):
    """(arcname, bytes, mode) in allow-list order; VERSION is generated."""
    yield f"{prefix}/VERSION", (version + "\n").encode("utf-8"), 0o644
    for rel in extra + files:
        src = ROOT / rel
        mode = 0o755 if src.stat().st_mode & 0o111 else 0o644
        yield f"{prefix}/{rel}", src.read_bytes(), mode


def write_tar_gz(path: Path, entries, mtime: int) -> None:
    with (
        path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=mtime) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar,
    ):
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))


def write_zip(path: Path, entries, mtime: int) -> None:
    date_time = time.gmtime(mtime)[:6]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # unix, so external_attr carries the mode
            info.external_attr = (0o100000 | mode) << 16
            zf.writestr(info, data)


def main() -> None:
    version = resolve_version()
    mtime = source_date_epoch()
    prefix = f"facility-cache-client-{version}"
    DIST.mkdir(exist_ok=True)
    for old in DIST.iterdir():
        old.unlink()

    # VERSION is generated and shipped inside the archives only -- never a
    # loose dist/ asset, so everything in dist/ stays covered by attestation.
    linux_tar = DIST / "facility-cache-client-linux.tar.gz"
    write_tar_gz(
        linux_tar,
        members(
            prefix,
            version,
            ["README.md", "defaults.env", "shared.gitconfig"],
            LINUX_FILES,
        ),
        mtime,
    )
    win_zip = DIST / "facility-cache-client-windows.zip"
    write_zip(
        win_zip,
        members(
            prefix,
            version,
            ["README.md", "defaults.json", "shared.gitconfig"],
            WINDOWS_FILES,
        ),
        mtime,
    )

    linux_sha = sha256_file(linux_tar)
    win_sha = sha256_file(win_zip)
    manifest = {
        "name": "facility-cache-client",
        "version": version,
        "min_client_version": "1.0.0",
        "assets": {
            "linux": {"name": linux_tar.name, "sha256": linux_sha},
            "windows": {"name": win_zip.name, "sha256": win_sha},
        },
    }
    man_path = DIST / "manifest.json"
    man_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    sums = DIST / "SHA256SUMS"
    lines = [
        f"{linux_sha}  {linux_tar.name}",
        f"{win_sha}  {win_zip.name}",
        f"{sha256_file(man_path)}  {man_path.name}",
    ]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")

    (DIST / "install-linux.sh").write_bytes(
        (ROOT / "linux" / "bootstrap.sh").read_bytes()
    )
    (DIST / "install-windows.ps1").write_bytes(
        (ROOT / "windows" / "Install-FromGitHub.ps1").read_bytes()
    )
    print(f"packed {version} -> {DIST}")


if __name__ == "__main__":
    main()
