"""End-to-end main() flow of linux/sbin/facility-cache-update, no root/network.

Covers the gates between "sha256 matched" and "install": nothing from the new
tarball runs before it is verified, a missing/failed attestation is fatal when
gh is available, attestation is checked against the id-pinned repo's resolved
name, an unpinned name is refused, and tar extraction is safe without the
tarfile "data" filter.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
_loader = importlib.machinery.SourceFileLoader(
    "facility_cache_update", str(ROOT / "linux" / "sbin" / "facility-cache-update")
)
_spec = importlib.util.spec_from_loader("facility_cache_update", _loader)
update = importlib.util.module_from_spec(_spec)
_loader.exec_module(update)

TARBALL = b"pretend release tarball"
NEW_NAME = "innovationtreehouse/infra.cache"


class TestUpdateFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        var = Path(self.tmp.name)
        self.state = var / "state.json"
        os.environ["FACILITY_CACHE_LOG"] = str(var / "log.jsonl")
        self.installed = []
        self.cfg = {"GITHUB_REPO": "innovationtreehouse/cache", "GITHUB_REPO_ID": "7"}
        self.meta = {"id": 7, "full_name": NEW_NAME}
        self.gh = "/usr/bin/gh"
        self.attest = mock.Mock(return_value=True)

        def fake_download(_urlopen, _req, dest, *_a, **_k):
            dest.write_bytes(TARBALL)

        def fake_run(cmd, **_k):
            # The only thing ensure_github_cli may run is the INSTALLED helper.
            self.assertEqual(cmd, ["bash", "/usr/local/sbin/facility-cache-ensure-gh"])
            return subprocess.CompletedProcess(cmd, 0, "gh version 9\n", "")

        manifest = {
            "version": "9.9.9",
            "assets": {
                "linux": {
                    "name": "c.tar.gz",
                    "sha256": hashlib.sha256(TARBALL).hexdigest(),
                }
            },
        }
        release = {
            "tag_name": "v9.9.9",
            "assets": [{"name": "c.tar.gz", "url": "https://example.invalid/a"}],
        }
        real_ui = update.Ui
        self.patches = [
            mock.patch.object(update, "VAR", var),
            mock.patch.object(update, "STATE_FILE", self.state),
            mock.patch.object(update, "installed_version", return_value="1.0.0"),
            mock.patch.object(
                update, "load_config", side_effect=lambda: dict(self.cfg)
            ),
            mock.patch.object(
                update, "repo_identity", side_effect=lambda _c: self.meta
            ),
            mock.patch.object(update, "latest_release", return_value=release),
            mock.patch.object(update, "load_manifest", return_value=manifest),
            mock.patch.object(
                update, "download_with_progress", side_effect=fake_download
            ),
            mock.patch.object(update, "verify_attestation", self.attest),
            mock.patch.object(
                update, "install_tarball", side_effect=self.installed.append
            ),
            mock.patch.object(update.shutil, "which", side_effect=lambda _n: self.gh),
            mock.patch.object(update.subprocess, "run", side_effect=fake_run),
            mock.patch.object(update.Path, "is_file", return_value=True),
            mock.patch.object(update.os, "geteuid", return_value=0),
            mock.patch.object(update, "Ui", lambda cmd: real_ui(cmd, io.StringIO())),
            mock.patch.object(sys, "argv", ["facility-cache-update"]),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        os.environ.pop("FACILITY_CACHE_LOG", None)
        self.tmp.cleanup()

    def last_result(self):
        return json.loads(self.state.read_text())["last_result"]

    def test_verified_attestation_installs_against_resolved_name(self):
        self.assertEqual(update.main(), 0)
        self.assertEqual(len(self.installed), 1)
        self.assertEqual(self.last_result(), "updated")
        args = self.attest.call_args.args
        self.assertEqual(args[1], NEW_NAME)  # not the configured pre-rename name
        self.assertEqual(args[3], "7")
        update.latest_release.assert_called_with(mock.ANY, NEW_NAME)

    def test_failed_attestation_with_gh_is_fatal(self):
        self.attest.return_value = False
        self.assertEqual(update.main(), 1)
        self.assertEqual(self.installed, [])
        self.assertIn("refused: attestation", self.last_result())

    def test_without_gh_installs_on_sha256_only_and_says_so(self):
        self.gh = None
        self.assertEqual(update.main(), 0)
        self.assertEqual(len(self.installed), 1)
        self.attest.assert_not_called()
        self.assertIn("attestation NOT verified", self.last_result())

    def test_unpinned_repo_is_refused(self):
        self.cfg["GITHUB_REPO_ID"] = ""
        self.assertEqual(update.main(), 1)
        self.assertEqual(self.installed, [])
        self.assertIn("no GITHUB_REPO_ID", self.last_result())

    def test_check_without_pin_still_reports(self):
        self.cfg["GITHUB_REPO_ID"] = ""
        with mock.patch.object(sys, "argv", ["facility-cache-update", "--check"]):
            self.assertEqual(update.main(), 0)
        self.assertFalse(self.state.exists())


class TestSafeExtractFallback(unittest.TestCase):
    """The pre-"data"-filter path (older Python 3.10 patch releases)."""

    def setUp(self):
        self._p = mock.patch.object(update, "HAS_DATA_FILTER", False)
        self._p.start()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._p.stop()
        self.tmp.cleanup()

    def _tar(self, *members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for info, data in members:
                tar.addfile(info, io.BytesIO(data) if data is not None else None)
        buf.seek(0)
        return tarfile.open(fileobj=buf, mode="r:gz")

    def _file(self, name, data=b"x", mode=0o644):
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(data), mode
        return info, data

    def _link(self, name, target, kind):
        info = tarfile.TarInfo(name)
        info.type, info.linkname = kind, target
        return info, None

    def test_plain_release_layout_extracts_with_sanitized_modes(self):
        dest = Path(self.tmp.name)
        with self._tar(self._file("p/linux/install.sh", b"#!", 0o4777)) as tar:
            update.safe_extract(tar, str(dest))
        f = dest / "p/linux/install.sh"
        self.assertEqual(f.read_bytes(), b"#!")
        self.assertEqual(f.stat().st_mode & 0o7777, 0o755)

    def test_unsafe_members_are_refused(self):
        dev = tarfile.TarInfo("p/dev")
        dev.type = tarfile.CHRTYPE
        for bad in (
            self._file("/etc/evil"),
            self._file("p/../../evil"),
            self._link("p/l", "/etc/passwd", tarfile.SYMTYPE),
            self._link("p/h", "/etc/passwd", tarfile.LNKTYPE),
            (dev, None),
        ):
            with self.subTest(bad[0].name), self._tar(bad) as tar:
                with self.assertRaises(tarfile.TarError):
                    update.safe_extract(tar, self.tmp.name)
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
