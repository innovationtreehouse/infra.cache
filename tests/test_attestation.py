"""Unit tests for the attestation-bundle fetch/verify helpers in
linux/sbin/facility-cache-update.

These are the functions that turn a downloaded release archive's sha256
into a Sigstore bundle fetched from the PUBLIC (no-auth) GitHub attestations
API, and then verify that bundle offline with `gh attestation verify
--bundle`, plus the id-based certificate policy applied to gh's JSON. None
of them may raise; any doubt must come back as a failure.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
# The script has no .py extension, so name a SourceFileLoader explicitly.
_loader = importlib.machinery.SourceFileLoader(
    "facility_cache_update", str(ROOT / "linux" / "sbin" / "facility-cache-update")
)
_spec = importlib.util.spec_from_loader("facility_cache_update", _loader)
update = importlib.util.module_from_spec(_spec)
_loader.exec_module(update)

REPO = "innovationtreehouse/infra.cache"


def _fake_response(body: bytes):
    """A minimal stand-in for the object urllib.request.urlopen(...) returns
    when used as a context manager."""
    resp = mock.MagicMock()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    resp.read.return_value = body
    return resp


def _bundle_response(bundles, repository_id=1343160243):
    atts = [{"repository_id": repository_id, "bundle": b} for b in bundles]
    return _fake_response(json.dumps({"attestations": atts}).encode("utf-8"))


class TestFetchAttestationBundles(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(delete=False)
        self._tmp.write(b"some release archive bytes")
        self._tmp.close()
        self.tar_path = Path(self._tmp.name)

    def tearDown(self):
        self.tar_path.unlink(missing_ok=True)

    def test_http_error_returns_none(self):
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("no route to host"),
        ):
            result = update.fetch_attestation_bundles(self.tar_path, REPO, "")
        self.assertIsNone(result)

    def test_non_json_body_returns_none(self):
        with mock.patch(
            "urllib.request.urlopen", return_value=_fake_response(b"not json{{{")
        ):
            result = update.fetch_attestation_bundles(self.tar_path, REPO, "")
        self.assertIsNone(result)

    def test_empty_attestations_returns_none(self):
        body = json.dumps({"attestations": []}).encode("utf-8")
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(body)):
            result = update.fetch_attestation_bundles(self.tar_path, REPO, "")
        self.assertIsNone(result)

    def test_missing_bundle_key_returns_none(self):
        body = json.dumps({"attestations": [{"repository_id": 1343160243}]}).encode(
            "utf-8"
        )
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(body)):
            result = update.fetch_attestation_bundles(self.tar_path, REPO, "")
        self.assertIsNone(result)

    def test_non_dict_bundle_returns_none(self):
        body = json.dumps(
            {"attestations": [{"repository_id": 1343160243, "bundle": "not-a-dict"}]}
        ).encode("utf-8")
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(body)):
            result = update.fetch_attestation_bundles(self.tar_path, REPO, "")
        self.assertIsNone(result)

    def test_repository_id_mismatch_is_filtered_out(self):
        good = {"mediaType": "keep-me"}
        bad = {"mediaType": "drop-me"}
        body = json.dumps(
            {
                "attestations": [
                    {"repository_id": 999999999, "bundle": bad},
                    {"repository_id": 1343160243, "bundle": good},
                ]
            }
        ).encode("utf-8")
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(body)):
            result = update.fetch_attestation_bundles(
                self.tar_path, REPO, "", repo_id="1343160243"
            )
        self.assertEqual(result, [good])

    def test_repository_id_mismatch_on_all_entries_returns_none(self):
        body = json.dumps(
            {"attestations": [{"repository_id": 1, "bundle": {"a": 1}}]}
        ).encode("utf-8")
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(body)):
            result = update.fetch_attestation_bundles(
                self.tar_path, REPO, "", repo_id="999"
            )
        self.assertIsNone(result)

    def test_all_bundles_returned_when_no_repo_id_pinned(self):
        bundles = [{"n": 1}, {"n": 2}, {"n": 3}]
        with mock.patch(
            "urllib.request.urlopen", return_value=_bundle_response(bundles)
        ):
            result = update.fetch_attestation_bundles(self.tar_path, REPO, "")
        self.assertEqual(result, bundles)

    def test_stale_token_401_retries_once_without_authorization(self):
        good_body = _bundle_response([{"n": 1}])
        calls = []

        def fake_urlopen(req, timeout=30, context=None):
            calls.append(dict(req.header_items()))
            if "Authorization" in dict(req.header_items()):
                raise urllib.error.HTTPError(
                    req.full_url, 401, "Unauthorized", {}, None
                )
            return good_body

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = update.fetch_attestation_bundles(
                self.tar_path, REPO, "stale-token"
            )
        self.assertEqual(result, [{"n": 1}])
        self.assertEqual(len(calls), 2)
        self.assertIn("Authorization", calls[0])
        self.assertNotIn("Authorization", calls[1])

    def test_stale_token_403_retries_once_without_authorization(self):
        good_body = _bundle_response([{"n": 1}])

        def fake_urlopen(req, timeout=30, context=None):
            if "Authorization" in dict(req.header_items()):
                raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)
            return good_body

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = update.fetch_attestation_bundles(
                self.tar_path, REPO, "stale-token"
            )
        self.assertEqual(result, [{"n": 1}])

    def test_non_auth_http_error_is_not_retried_and_returns_none(self):
        def fake_urlopen(req, timeout=30, context=None):
            raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, None)

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = update.fetch_attestation_bundles(self.tar_path, REPO, "some-token")
        self.assertIsNone(result)


ID, OWNER_ID, VER = "1343160243", "166767539", "1.0.3"


def _cert(**over):
    """The certificate gh 2.104 reports for the real v1.0.3 release, which was
    signed before the rename (old name, same numeric ids)."""
    old = "https://github.com/innovationtreehouse/cache"
    cert = {
        "sourceRepositoryURI": old,
        "sourceRepositoryIdentifier": ID,
        "sourceRepositoryOwnerURI": "https://github.com/innovationtreehouse",
        "sourceRepositoryOwnerIdentifier": OWNER_ID,
        "sourceRepositoryRef": "refs/tags/v1.0.3",
        "buildSignerURI": f"{old}/.github/workflows/release.yml@refs/tags/v1.0.3",
        "runnerEnvironment": "github-hosted",
    }
    cert.update(over)
    return [{"verificationResult": {"signature": {"certificate": cert}}}]


class TestAttestationPolicy(unittest.TestCase):
    def check(self, results, repo_id=ID, owner_id=OWNER_ID, version=VER):
        return update.attestation_policy_failure(results, repo_id, owner_id, version)

    def test_pre_rename_release_of_the_pinned_repo_verifies(self):
        self.assertEqual(self.check(_cert()), "")

    def test_post_rename_name_verifies_too(self):
        new = "https://github.com/innovationtreehouse/infra.cache"
        results = _cert(
            sourceRepositoryURI=new,
            buildSignerURI=f"{new}/.github/workflows/release.yml@refs/tags/v1.0.3",
        )
        self.assertEqual(self.check(results), "")

    def test_a_different_repo_under_our_name_is_refused(self):
        self.assertIn("repo id", self.check(_cert(sourceRepositoryIdentifier="999")))

    def test_a_different_owner_is_refused(self):
        self.assertIn(
            "owner id", self.check(_cert(sourceRepositoryOwnerIdentifier="1"))
        )

    def test_wrong_version_tag_is_refused(self):
        self.assertIn("source ref", self.check(_cert(), version="1.0.4"))

    def test_branch_build_is_refused(self):
        old = "https://github.com/innovationtreehouse/cache"
        results = _cert(
            sourceRepositoryRef="refs/heads/evil",
            buildSignerURI=f"{old}/.github/workflows/release.yml@refs/heads/evil",
        )
        self.assertNotEqual(self.check(results), "")

    def test_other_workflow_is_refused(self):
        old = "https://github.com/innovationtreehouse/cache"
        results = _cert(
            buildSignerURI=f"{old}/.github/workflows/ci.yml@refs/tags/v1.0.3"
        )
        self.assertIn("signer", self.check(results))

    def test_signer_in_another_repo_is_refused(self):
        results = _cert(
            buildSignerURI="https://github.com/evil/x/.github/workflows/release.yml@refs/tags/v1.0.3"
        )
        self.assertIn("signer", self.check(results))

    def test_self_hosted_runner_is_refused(self):
        self.assertIn("runner", self.check(_cert(runnerEnvironment="self-hosted")))

    def test_missing_id_field_fails_closed(self):
        results = _cert()
        del results[0]["verificationResult"]["signature"]["certificate"][
            "sourceRepositoryIdentifier"
        ]
        self.assertIn("gh too old", self.check(results))

    def test_empty_or_garbage_output_fails(self):
        for bad in ([], {}, None, [{"x": 1}]):
            self.assertNotEqual(self.check(bad), "")

    def test_no_pin_fails(self):
        self.assertNotEqual(self.check(_cert(), repo_id=""), "")
        self.assertNotEqual(self.check(_cert(), owner_id=""), "")


class TestVerifyAttestation(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(delete=False)
        self._tmp.write(b"some release archive bytes")
        self._tmp.close()
        self.tar_path = Path(self._tmp.name)

    def tearDown(self):
        self.tar_path.unlink(missing_ok=True)

    def verify(self):
        return update.verify_attestation(self.tar_path, REPO, "", ID, OWNER_ID, VER)

    def run_with(self, fake_run, bundles=({"n": 1},)):
        with (
            mock.patch("shutil.which", return_value="/usr/bin/gh"),
            mock.patch.object(
                update, "fetch_attestation_bundles", return_value=list(bundles)
            ),
            mock.patch("subprocess.run", side_effect=fake_run),
        ):
            return self.verify()

    def test_fails_when_gh_missing(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertNotEqual(self.verify(), "")

    def test_fails_when_no_bundles_fetched(self):
        with (
            mock.patch("shutil.which", return_value="/usr/bin/gh"),
            mock.patch.object(update, "fetch_attestation_bundles", return_value=None),
        ):
            self.assertNotEqual(self.verify(), "")

    def test_temp_file_removed_even_when_subprocess_raises(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["path"] = cmd[cmd.index("--bundle") + 1]
            raise OSError("boom")

        self.assertNotEqual(self.run_with(fake_run), "")
        self.assertFalse(Path(captured["path"]).exists())

    def test_argv_enforces_owner_tag_ref_runner_and_json(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, json.dumps(_cert()), "")

        self.assertEqual(self.run_with(fake_run), "")
        cmd = captured["cmd"]
        self.assertEqual(cmd[cmd.index("--owner") + 1], "innovationtreehouse")
        self.assertEqual(cmd[cmd.index("--source-ref") + 1], "refs/tags/v1.0.3")
        self.assertEqual(cmd[cmd.index("--format") + 1], "json")
        self.assertIn("--deny-self-hosted-runners", cmd)
        self.assertNotIn("--repo", cmd)  # name-based; ids are checked instead

    def test_policy_failure_on_gh_success_is_a_failure(self):
        def fake_run(cmd, **kwargs):
            out = json.dumps(_cert(sourceRepositoryIdentifier="999"))
            return subprocess.CompletedProcess(cmd, 0, out, "")

        self.assertIn("repo id", self.run_with(fake_run))

    def test_gh_nonzero_is_a_failure(self):
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 1, "", "Error: bad sig\n")

        self.assertIn("bad sig", self.run_with(fake_run))

    def test_gh_without_source_ref_flag_says_too_old(self):
        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, 1, "", "unknown flag: --source-ref\n"
            )

        self.assertIn("too old", self.run_with(fake_run))

    def test_all_bundles_written_as_jsonl_lines(self):
        bundles = [{"n": 1}, {"n": 2}, {"n": 3}, {"n": 4}]
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["text"] = Path(cmd[cmd.index("--bundle") + 1]).read_text(
                encoding="utf-8"
            )
            return subprocess.CompletedProcess(cmd, 0, json.dumps(_cert()), "")

        self.assertEqual(self.run_with(fake_run, bundles), "")
        parsed = [json.loads(line) for line in captured["text"].splitlines()]
        self.assertEqual(parsed, bundles)


if __name__ == "__main__":
    unittest.main()
