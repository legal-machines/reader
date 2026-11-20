#!/usr/bin/env python3
"""The watch (watch/watch.py) says OK only when every check was done: a check
it could not do leaves it UNVERIFIED, and a file that differs stays ALARM
even without GitHub's history. The network is replaced by fakes; nothing is
fetched. Run: python3 -m unittest discover -s tests (or python3 tests/test_watch.py)."""
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("watch", os.path.join(HERE, "..", "watch", "watch.py"))
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)

HOST, REPO = "seal.example.org", "example/reader"
NOW = 2_000_000_000.0
FILES = {"index.html": b"<!doctype html>", "hub.mjs": b"export {};"}
sha = lambda b: hashlib.sha256(b).hexdigest()
SUMS = "".join(f"{sha(body)}  {name}\n" for name, body in FILES.items()).encode()


def http_error(url, code):
    e = urllib.error.HTTPError(url, code, "error", {}, None)
    e.close()  # its empty body
    return e


class Net:
    """A fake fetch: url -> bytes, an exception to raise, or missing (404)."""
    def __init__(self, answers):
        self.answers, self.asked = answers, []

    def __call__(self, url, timeout=20):
        self.asked.append(url)
        a = self.answers.get(url)
        if a is None:
            raise http_error(url, 404)
        if isinstance(a, BaseException):
            raise a
        return a, {}


def served(files=FILES, sums=SUMS, **extra):
    answers = {f"https://raw.githubusercontent.com/{REPO}/main/SHA256SUMS": sums}
    answers.update({f"https://{HOST}/{n}": b for n, b in files.items()})
    answers.update(extra)
    return answers


def commits(*items):
    """The commits API's answer: (sha, seconds before NOW), newest first."""
    import datetime
    at = lambda t: datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps([{"sha": s, "commit": {"committer": {"date": at(NOW - ago)}}} for s, ago in items]).encode()


COMMITS_URL = f"https://api.github.com/repos/{REPO}/commits?sha=main&per_page=6"


class Base(unittest.TestCase):
    def setUp(self):
        watch.notes.clear()
        watch.unverified.clear()
        p = mock.patch.object(watch, "now", lambda: NOW)
        p.start()
        self.addCleanup(p.stop)

    def files(self, answers):
        with mock.patch.object(watch, "fetch", Net(answers)):
            problems = watch.check_files(HOST, REPO)
        return problems, watch.outcome(problems)


class CheckFiles(Base):
    def test_ok(self):
        problems, state = self.files(served())
        self.assertEqual(problems, [])
        self.assertEqual(watch.unverified, [])
        self.assertEqual(state, "OK")

    def test_sums_unavailable(self):
        answers = served()
        answers[f"https://raw.githubusercontent.com/{REPO}/main/SHA256SUMS"] = http_error("sums", 503)
        problems, state = self.files(answers)
        self.assertEqual(problems, [])
        self.assertEqual(state, "UNVERIFIED")

    def test_sums_missing(self):
        answers = served()
        del answers[f"https://raw.githubusercontent.com/{REPO}/main/SHA256SUMS"]  # 404
        self.assertEqual(self.files(answers)[1], "UNVERIFIED")

    def test_sums_unreadable(self):
        for bad in (b"", b"not a sums file\n", b"\xff\xfe", b"<html>rate limited</html>\n"):
            watch.unverified.clear()
            self.assertEqual(self.files(served(sums=bad))[1], "UNVERIFIED", bad)

    def test_file_unavailable(self):
        answers = served()
        answers[f"https://{HOST}/hub.mjs"] = urllib.error.URLError("timed out")
        problems, state = self.files(answers)
        self.assertEqual(problems, [])
        self.assertEqual(state, "UNVERIFIED")
        self.assertIn("hub.mjs", " ".join(watch.unverified))

    def test_file_rate_limited(self):
        answers = served()
        answers[f"https://{HOST}/index.html"] = http_error("index", 429)
        self.assertEqual(self.files(answers)[1], "UNVERIFIED")

    def test_mismatch_without_history_is_alarm(self):
        changed = dict(FILES, **{"hub.mjs": b"export const evil = 1;"})
        for history in (http_error(COMMITS_URL, 403), http_error(COMMITS_URL, 429), urllib.error.URLError("timed out"),
                        b"{not json", b"{}", b"[]", b'[{"sha": "x"}]'):
            watch.notes.clear()
            answers = served(files=changed, **{COMMITS_URL: history})
            problems, state = self.files(answers)
            self.assertEqual(state, "ALARM", history)
            self.assertIn("hub.mjs", problems[0])

    def test_mismatch_old_publish_is_alarm(self):
        changed = dict(FILES, **{"hub.mjs": b"export const evil = 1;"})
        problems, state = self.files(served(files=changed, **{COMMITS_URL: commits(("a" * 40, 7 * 3600))}))
        self.assertEqual(state, "ALARM")

    def test_earlier_commit_passes_with_note(self):
        # GitHub Pages still serves the commit before, an hour after a publish.
        older = dict(FILES, **{"hub.mjs": b"export {}; // older"})
        older_sums = "".join(f"{sha(b)}  {n}\n" for n, b in older.items()).encode()
        answers = served(files=older, **{COMMITS_URL: commits(("new", 3600), ("old", 7200)),
                                          f"https://raw.githubusercontent.com/{REPO}/new/SHA256SUMS": SUMS,
                                          f"https://raw.githubusercontent.com/{REPO}/old/SHA256SUMS": older_sums})
        problems, state = self.files(answers)
        self.assertEqual(state, "OK")
        self.assertTrue(watch.notes)

    def test_unknown_file_minutes_after_publish_is_unverified(self):
        changed = dict(FILES, **{"hub.mjs": b"export const evil = 1;"})
        answers = served(files=changed, **{COMMITS_URL: commits(("new", 120)),
                                           f"https://raw.githubusercontent.com/{REPO}/new/SHA256SUMS": SUMS})
        problems, state = self.files(answers)
        self.assertEqual(state, "UNVERIFIED")

    def test_unknown_file_after_settling_is_alarm(self):
        changed = dict(FILES, **{"hub.mjs": b"export const evil = 1;"})
        answers = served(files=changed, **{COMMITS_URL: commits(("new", 3600))})  # the commit's sums unreadable too
        problems, state = self.files(answers)
        self.assertEqual(state, "ALARM")


class OtherChecks(Base):
    def test_ct_logs_errors(self):
        url = "https://api.certspotter.com/v1/issuances?domain=seal.example.org&expand=dns_names"
        for answer in (http_error(url, 429), http_error(url, 403), urllib.error.URLError("timed out"), b"{not json",
                       b'{"code": "rate_limited"}', b'[{"id": "1"}]'):
            watch.unverified.clear()
            with mock.patch.object(watch, "fetch", Net({url: answer})):
                self.assertEqual(watch.check_certificates("seal.example.org"), [])
            self.assertEqual(watch.outcome([]), "UNVERIFIED", answer)

    def test_webauthn_errors(self):
        url = "https://seal.example.org/.well-known/webauthn"
        with mock.patch.object(watch, "fetch", Net({url: http_error(url, 403)})):
            self.assertEqual(watch.check_webauthn("seal.example.org"), [])
        self.assertEqual(watch.outcome([]), "UNVERIFIED")
        watch.unverified.clear()
        with mock.patch.object(watch, "fetch", Net({})):  # 404: nothing there, as it should be
            self.assertEqual(watch.check_webauthn("seal.example.org"), [])
        self.assertEqual(watch.outcome([]), "OK")

    def test_a_check_that_breaks_is_unverified(self):
        def broken(*a):
            raise TimeoutError("dig")
        self.assertEqual(watch.attempt("x", [], broken), [])
        self.assertEqual(watch.outcome([]), "UNVERIFIED")


class Exit(Base):
    """run_github's exit status, which fails the GitHub run (watch.yml)."""
    def run_github(self, problems=(), unverified=()):
        def check_all(_):
            watch.unverified.extend(unverified)
            return list(problems), {}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "expected.json")
            with open(path, "w") as f:
                json.dump({"updated": "2000-01-01T00:00:00Z", "mail": {}}, f)
            with open(os.path.join(d, "keys.json"), "w") as f:
                json.dump({"updated": "2000-01-01T00:00:00Z", "domains": {}}, f)
            with mock.patch.object(watch, "check_all", check_all), redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit) as end:
                watch.run_github(path)
        return end.exception.code, out.getvalue()

    def test_ok(self):
        code, out = self.run_github()
        self.assertEqual(code, 0)
        self.assertIn("state: OK", out)

    def test_unverified_fails(self):
        code, out = self.run_github(unverified=["seal.example.org: the CT logs could not be read (HTTPError)"])
        self.assertEqual(code, 3)
        self.assertIn("state: UNVERIFIED", out)

    def test_alarm_fails(self):
        code, out = self.run_github(problems=["seal.example.org serves files that differ"], unverified=["x"])
        self.assertEqual(code, 1)
        self.assertIn("state: ALARM", out)


class GitHubRunAsSeenByTheHost(Base):
    def failed_at(self, steps):
        url = "https://api.github.com/repos/legal-machines/reader/actions/runs/7/jobs"
        body = json.dumps({"jobs": [{"steps": [{"name": n, "conclusion": c} for n, c in steps]}]}).encode()
        with mock.patch.object(watch, "fetch", Net({url: body})):
            return watch.github_unverified({"id": 7})

    def test_steps(self):
        self.assertTrue(self.failed_at([("Check", "success"), ("Verified", "failure")]))
        self.assertFalse(self.failed_at([("Check", "failure"), ("Verified", "skipped")]))
        with mock.patch.object(watch, "fetch", Net({})):  # jobs unreadable: a problem, as before
            self.assertFalse(watch.github_unverified({"id": 7}))


if __name__ == "__main__":
    unittest.main()
