"""Smoke tests for veilbox. Standard library only, no network."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veilbox import TOOL_NAME, TOOL_VERSION
from veilbox.cli import main
from veilbox.core import generate_profile, validate_profile, run_audit

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_DIR = os.path.join(REPO_ROOT, "demos", "01-basic")
LEAK = os.path.join(DEMO_DIR, "signals-leaking.json")
CLEAN = os.path.join(DEMO_DIR, "signals-clean.json")


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "veilbox")
        self.assertTrue(TOOL_VERSION)


class TestFingerprint(unittest.TestCase):
    def test_default_profile_is_coherent(self):
        prof = generate_profile(seed="smoke-1")
        self.assertEqual(validate_profile(prof), [])

    def test_seed_is_reproducible(self):
        a = generate_profile(seed="same").to_dict()
        b = generate_profile(seed="same").to_dict()
        self.assertEqual(a, b)

    def test_rotate_differs(self):
        a = generate_profile(seed="seed-a").fingerprint_id()
        b = generate_profile(seed="seed-b").fingerprint_id()
        self.assertNotEqual(a, b)

    def test_all_seeds_stay_coherent(self):
        # Property: no seed should ever produce an incoherent profile.
        for i in range(200):
            prof = generate_profile(seed=f"prop-{i}")
            self.assertEqual(validate_profile(prof), [], f"seed prop-{i} leaked")


class TestAudit(unittest.TestCase):
    def test_empty_signals_score_zero(self):
        report = run_audit({})
        self.assertEqual(report.traceability_score, 0)
        self.assertEqual(report.verdict, "ANONYMOUS")

    def test_clean_demo_is_anonymous(self):
        with open(CLEAN, encoding="utf-8") as fh:
            signals = json.load(fh)
        report = run_audit(signals)
        self.assertEqual(report.traceability_score, 0, report.to_dict())
        self.assertEqual(len(report.leaks), 0)

    def test_leaking_demo_is_traceable(self):
        with open(LEAK, encoding="utf-8") as fh:
            signals = json.load(fh)
        report = run_audit(signals)
        self.assertEqual(report.traceability_score, 100, report.to_dict())
        self.assertEqual(report.verdict, "FULLY-TRACEABLE")
        rules = {r.check for r in report.leaks}
        self.assertEqual(rules, {
            "webrtc_leak", "dns_leak", "ip_proxy_mismatch",
            "tz_geo_mismatch", "fingerprint_coherence",
        })


class TestCli(unittest.TestCase):
    def test_fingerprint_exit_zero(self):
        self.assertEqual(main(["fingerprint", "--seed", "x"]), 0)

    def test_validate_only_clean(self):
        self.assertEqual(main(["fingerprint", "--seed", "x", "--validate-only"]), 0)

    def test_audit_clean_no_fail(self):
        self.assertEqual(main(["audit", "--signals", CLEAN, "--fail-on", "25"]), 0)

    def test_audit_leak_fails_gate(self):
        self.assertEqual(main(["audit", "--signals", LEAK, "--fail-on", "25"]), 1)

    def test_dns_and_proxy_emit(self):
        self.assertEqual(main(["dns"]), 0)
        self.assertEqual(main(["proxy"]), 0)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)

    def test_main_module_version(self):
        proc = subprocess.run(
            [sys.executable, "-m", "veilbox", "--version"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("veilbox", proc.stdout)


if __name__ == "__main__":
    unittest.main()
