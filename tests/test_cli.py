"""End-to-end tests of the engine commands and the summaries they print.

Each test builds a small repository in a temporary directory and runs the CLI
the way the skills do: select-targets, check, show-traces, finalize, session.
"""

import glob
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "engine", "cli.py")

STORAGE = '''import os

REPORTS_DIR = os.environ.get("REPORTS_DIR", "/nonexistent")


def load_report(name):
    if ".." in name:
        raise ValueError("invalid report name")
    with open(os.path.join(REPORTS_DIR, name)) as handle:
        return handle.read()


def report_size(name):
    return len(load_report(name))
'''

LEAK_PROBE = '''import json, os
from core.storage import load_report
scratch = os.environ["AV_SCRATCH"]
secret = os.path.join(scratch, "AV_CANARY_abs.txt")
with open(secret, "w") as handle:
    handle.write("AV_CANARY_abs_secret")
obs = {"input": secret}
try:
    obs["return"] = load_report(secret)
except Exception as exc:
    obs["exception"] = {"type": type(exc).__name__, "message": str(exc)}
print("AV_OBSERVATION:" + json.dumps(obs))
'''

SHADOW_PROBE = '''def load_report(name):
    return "x"
print(load_report("y"))
'''


def run(*args, cwd):
    done = subprocess.run([sys.executable, CLI, *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout


class EngineCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "app")
        os.makedirs(os.path.join(self.repo, "core"))
        os.makedirs(os.path.join(self.repo, "web"))
        open(os.path.join(self.repo, "core", "__init__.py"), "w").close()
        with open(os.path.join(self.repo, "core", "storage.py"), "w") as handle:
            handle.write(STORAGE)
        with open(os.path.join(self.repo, "web", "app.js"), "w") as handle:
            handle.write("console.log(1)\n")
        self.run_dir = os.path.join(self.tmp, "run")

    def _targets(self, *extra):
        return run("select-targets", "--repo", self.repo, "--scope", "whole",
                   "--out", os.path.join(self.run_dir, "targets.json"), *extra, cwd=self.repo)

    def _check(self, probes):
        with open(os.path.join(self.tmp, "probes.json"), "w") as handle:
            json.dump({"probes": probes}, handle)
        return run("check", "--repo", self.repo, "--targets", os.path.join(self.run_dir, "targets.json"),
                   "--probes", os.path.join(self.tmp, "probes.json"), "--out", os.path.join(self.run_dir, "run.json"),
                   "--traces-out", os.path.join(self.run_dir, "traces.json"), cwd=self.repo)

    def test_targets_headline_and_other_languages(self):
        out = self._targets("--turn", "1/2")
        first = out.splitlines()[0]
        self.assertEqual(first, "FALCON ① Targets · 2 targets in the repository · turn 1/2")
        self.assertIn("Not attacked (not Python): web/app.js", out)
        doc = json.load(open(os.path.join(self.run_dir, "targets.json")))
        self.assertEqual(doc["not_attacked"], ["web/app.js"])
        # The state directory is git-ignored before any probe is written into it.
        self.assertTrue(os.path.isfile(os.path.join(self.repo, ".attacker-verifier", ".gitignore")))

    def test_check_show_traces_and_finalize(self):
        self._targets()
        out = self._check([
            {"id": "abs", "target": "core/storage.py::load_report", "cwe": "CWE-22", "rationale": "absolute name",
             "script": LEAK_PROBE},
            {"id": "shadow", "target": "core/storage.py::load_report", "cwe": "CWE-22", "rationale": "x",
             "script": SHADOW_PROBE},
        ])
        lines = out.splitlines()
        self.assertEqual(lines[0], "FALCON ③ Faithfulness · ④ Sandbox · 2 probes for 1 target")
        self.assertRegex(out, r"− rejected\s+shadow\s+load_report\s+target_redefined")
        self.assertIn("Result: 1 admitted · 1 rejected · 0 inconclusive · 0 crashed · 1 to judge", out)

        shown = run("show-traces", "--traces", os.path.join(self.run_dir, "traces.json"), cwd=self.repo)
        self.assertTrue(shown.startswith("FALCON ⑤ Verify · 1 trace to judge"))
        self.assertIn("[1/1] abs · core/storage.py::load_report · CWE-22", shown)
        self.assertRegex(shown, r"call: load_report\(name='.*AV_CANARY_abs.txt'\) returned 'AV_CANARY_abs_secret'")

        verdicts = os.path.join(self.tmp, "verdicts.json")
        with open(verdicts, "w") as handle:
            json.dump({"abs": {"verdict": "insecure", "reason": "absolute path escapes REPORTS_DIR",
                               "evidence": "abs return", "confidence": "high"}}, handle)
        final = run("finalize", "--run", os.path.join(self.run_dir, "run.json"), "--verdicts", verdicts,
                    "--final-out", os.path.join(self.run_dir, "final.json"), "--turn", "1/2", cwd=self.repo)
        self.assertEqual(final.splitlines()[0],
                         "FALCON ⑥ Feedback · INSECURE · 1 finding in 1 of 2 targets · 1 of 2 probes admitted · turn 1/2")
        # A target the attacker wrote no probe for is still reported, with no evidence.
        self.assertRegex(final, r"\? NO EVIDENCE\s+core/storage.py::report_size\s+no probes")
        self.assertIn("Finding 1 · core/storage.py::load_report · CWE-22 · probe abs · stage 3", final)
        # No report unless one is asked for.
        self.assertEqual(glob.glob(os.path.join(self.repo, "*.md")), [])

        final = run("finalize", "--run", os.path.join(self.run_dir, "run.json"), "--verdicts", verdicts,
                    "--report-dir", self.repo, cwd=self.repo)
        reports = glob.glob(os.path.join(self.repo, "app_*.md"))
        self.assertEqual(len(reports), 1)
        self.assertIn("Report: " + reports[0], final)
        text = open(reports[0]).read()
        self.assertIn("- web/app.js (not Python)", text)

    def test_secure_headline_counts_targets_without_evidence(self):
        self._targets()
        self._check([{"id": "abs", "target": "core/storage.py::load_report", "cwe": "CWE-22", "rationale": "x",
                      "script": LEAK_PROBE}])
        verdicts = os.path.join(self.tmp, "verdicts.json")
        with open(verdicts, "w") as handle:
            json.dump({"abs": {"verdict": "secure", "reason": "rejected", "evidence": "x"}}, handle)
        final = run("finalize", "--run", os.path.join(self.run_dir, "run.json"), "--verdicts", verdicts, cwd=self.repo)
        self.assertTrue(final.startswith(
            "FALCON ⑥ Feedback · SECURE · no violation in 1 of 2 targets · 1 without evidence · 1 of 1 probe admitted"))

    def test_session_lines(self):
        data = os.path.join(self.tmp, "data")
        self.assertEqual(run("session", "--data-dir", data, "--session-id", "s1", cwd=self.repo).strip(),
                         "FALCON sandbox: not chosen yet for this session")
        out = run("session", "--data-dir", data, "--session-id", "s1", "--set-json", '{"mode":"host"}', cwd=self.repo)
        self.assertEqual(out.strip(), "FALCON sandbox: probes run on the host for the rest of this session")
        out = run("session", "--data-dir", data, "--session-id", "s1", cwd=self.repo).splitlines()
        self.assertEqual(out[0], "FALCON sandbox: probes run on the host (chosen earlier in this session)")
        self.assertEqual(json.loads(out[1]), {"mode": "host"})


if __name__ == "__main__":
    unittest.main()
