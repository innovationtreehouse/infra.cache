"""Unit tests for the repo-identity pin in linux/sbin/facility-cache-update.

The pinned numeric repo id is what stands between a renamed-and-re-registered
GitHub name and a silent install of someone else's release, so the verdict
logic gets its own tests (pure function, no network).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The script has no .py extension, so name a SourceFileLoader explicitly.
_loader = importlib.machinery.SourceFileLoader(
    "facility_cache_update", str(ROOT / "linux" / "sbin" / "facility-cache-update")
)
spec = importlib.util.spec_from_loader("facility_cache_update", _loader)
update = importlib.util.module_from_spec(spec)
_loader.exec_module(update)

REPO = "innovationtreehouse/infra.cache"


class TestIdentityVerdict(unittest.TestCase):
    def test_matching_id_and_name_is_ok(self):
        verdict, detail = update.identity_verdict(
            "1343160243", {"id": 1343160243, "full_name": REPO}, REPO
        )
        self.assertEqual(verdict, "ok")
        # detail is the resolved name attestation is checked against
        self.assertEqual(detail, REPO)

    def test_matching_id_under_a_new_name_is_a_rename(self):
        # An install still configured with the pre-rename name.
        verdict, detail = update.identity_verdict(
            "1343160243",
            {"id": 1343160243, "full_name": REPO},
            "innovationtreehouse/cache",
        )
        self.assertEqual(verdict, "renamed")
        self.assertEqual(detail, REPO)

    def test_different_id_is_a_mismatch_even_with_the_expected_name(self):
        verdict, detail = update.identity_verdict(
            "1343160243", {"id": 999, "full_name": REPO}, REPO
        )
        self.assertEqual(verdict, "mismatch")
        self.assertIn("999", detail)
        self.assertIn("1343160243", detail)

    def test_missing_id_in_the_response_is_a_mismatch(self):
        verdict, _ = update.identity_verdict("1343160243", {}, REPO)
        self.assertEqual(verdict, "mismatch")

    def test_defaults_pin_the_real_repo_id_on_both_platforms(self):
        env = (ROOT / "defaults.env").read_text()
        self.assertIn("GITHUB_REPO_ID=1343160243", env)
        import json

        cfg = json.loads((ROOT / "defaults.json").read_text())
        self.assertEqual(cfg["GitHubRepoId"], 1343160243)

    def test_linux_defaults_use_the_post_rename_name(self):
        self.assertIn(f"GITHUB_REPO={REPO}\n", (ROOT / "defaults.env").read_text())
        self.assertEqual(update.DEFAULT_REPO, REPO)
        for rel in ("linux/lib/common.sh", "linux/bootstrap.sh"):
            text = (ROOT / rel).read_text()
            self.assertNotIn("innovationtreehouse/cache}", text, rel)
            self.assertIn(REPO, text, rel)


if __name__ == "__main__":
    unittest.main()
