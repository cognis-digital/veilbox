"""Tests for the three active-fingerprinting consistency vectors added to the
leak self-audit: TLS/HTTP2 Client-Hint consistency, font-enumeration entropy,
and navigator.plugins/mediaDevices coherence vs the declared platform.

Standard library only, no network."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veilbox.core import (
    generate_profile,
    run_audit,
    _check_client_hint_consistency,  # noqa: F401
    _check_font_entropy,
    _check_navigator_coherence,  # noqa: F401
    _ua_os_token,
    _normalize_ch_platform,
    _CHECK_WEIGHTS,
)


def _result(signals, check):
    return next(c for c in run_audit(signals).results if c.check == check)


class TestClientHintConsistency(unittest.TestCase):
    def test_mismatch_is_leak(self):
        r = _result({"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                     "ua_platform": '"macOS"'}, "client_hint_consistency")
        self.assertEqual(r.status, "leak")
        self.assertEqual(r.evidence["ua_os_token"], "Windows")
        self.assertEqual(r.evidence["client_hint_platform"], "macOS")

    def test_match_is_pass(self):
        r = _result({"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                     "ua_platform": '"Windows"'}, "client_hint_consistency")
        self.assertEqual(r.status, "pass")

    def test_android_ua_maps_to_android_not_linux(self):
        # Android UA strings literally contain "Linux"; ordering must win.
        r = _result({"user_agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8)",
                     "ua_platform": '"Android"'}, "client_hint_consistency")
        self.assertEqual(r.status, "pass")
        # And an Android UA mislabelled as Linux must be caught.
        r2 = _result({"user_agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8)",
                      "ua_platform": '"Linux"'}, "client_hint_consistency")
        self.assertEqual(r2.status, "leak")

    def test_sec_ch_ua_platform_alias(self):
        r = _result({"user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                     "sec_ch_ua_platform": "macOS"}, "client_hint_consistency")
        self.assertEqual(r.status, "pass")

    def test_missing_pair_skips(self):
        self.assertEqual(_result({"user_agent": "x"},
                                 "client_hint_consistency").status, "skipped")
        self.assertEqual(_result({"ua_platform": '"Windows"'},
                                 "client_hint_consistency").status, "skipped")

    def test_unrecognized_ua_skips(self):
        r = _result({"user_agent": "CustomBot/1.0", "ua_platform": '"Windows"'},
                    "client_hint_consistency")
        self.assertEqual(r.status, "skipped")

    def test_ua_os_token_ordering(self):
        self.assertEqual(_ua_os_token("Mozilla/5.0 (Linux; Android 14)"), "Android")
        self.assertEqual(_ua_os_token("X11; Linux x86_64"), "Linux")
        self.assertEqual(_ua_os_token("Macintosh; Intel Mac OS X"), "macOS")
        self.assertIsNone(_ua_os_token("nothing here"))

    def test_normalize_strips_quotes(self):
        self.assertEqual(_normalize_ch_platform('"Windows"'), "Windows")
        self.assertEqual(_normalize_ch_platform("'macOS'"), "macOS")
        self.assertIsNone(_normalize_ch_platform(None))


class TestFontEntropy(unittest.TestCase):
    def test_foreign_font_is_leak(self):
        r = _result({"fonts": ["Segoe UI", "Consolas"],
                     "declared_platform": "macos"}, "font_entropy")
        self.assertEqual(r.status, "leak")
        self.assertIn("Segoe UI", r.evidence["foreign_fonts"])

    def test_native_fonts_pass(self):
        r = _result({"fonts": ["Segoe UI", "Consolas", "Calibri"],
                     "declared_platform": "windows"}, "font_entropy")
        self.assertEqual(r.status, "pass")

    def test_ubiquitous_fonts_not_foreign(self):
        # Arial is shared across platforms; declaring it on linux is not a leak.
        r = _result({"fonts": ["DejaVu Sans", "Arial"],
                     "declared_platform": "linux"}, "font_entropy")
        self.assertEqual(r.status, "pass")

    def test_entropy_ceiling_is_leak(self):
        r = _result({"fonts": [f"Font{i}" for i in range(45)],
                     "declared_platform": "windows"}, "font_entropy")
        self.assertEqual(r.status, "leak")
        self.assertEqual(r.evidence["font_count"], 45)

    def test_missing_pair_skips(self):
        self.assertEqual(_result({"fonts": ["Arial"]}, "font_entropy").status,
                         "skipped")
        self.assertEqual(_result({"declared_platform": "windows"},
                                 "font_entropy").status, "skipped")

    def test_unknown_platform_skips(self):
        r = _result({"fonts": ["Arial"], "declared_platform": "haiku"},
                    "font_entropy")
        self.assertEqual(r.status, "skipped")

    def test_generated_profile_fonts_are_clean(self):
        # A coherent generated profile's own fonts must never trip this vector.
        for fam in ("windows", "macos", "linux"):
            prof = generate_profile(seed=f"font-{fam}", os_family=fam,
                                    browser="firefox")
            r = _check_font_entropy({"fonts": prof.fonts,
                                     "declared_platform": fam})
            self.assertEqual(r.status, "pass", f"{fam}: {r.evidence}")


class TestNavigatorCoherence(unittest.TestCase):
    def test_android_no_touch_is_leak(self):
        r = _result({"declared_platform": "android", "touch_support": False},
                    "navigator_coherence")
        self.assertEqual(r.status, "leak")

    def test_desktop_touch_is_leak(self):
        r = _result({"declared_platform": "windows", "touch_support": True},
                    "navigator_coherence")
        self.assertEqual(r.status, "leak")

    def test_firefox_plugins_is_leak(self):
        r = _result({"declared_platform": "windows", "browser": "firefox",
                     "navigator_plugins": ["pdf-viewer"]}, "navigator_coherence")
        self.assertEqual(r.status, "leak")

    def test_mobile_plugins_is_leak(self):
        r = _result({"declared_platform": "android", "touch_support": True,
                     "navigator_plugins": ["x"]}, "navigator_coherence")
        self.assertEqual(r.status, "leak")

    def test_labelled_media_without_permission_is_leak(self):
        r = _result({"declared_platform": "windows",
                     "media_devices": [{"kind": "videoinput", "label": "HD Cam"}]},
                    "navigator_coherence")
        self.assertEqual(r.status, "leak")

    def test_unlabelled_media_is_fine(self):
        r = _result({"declared_platform": "windows", "touch_support": False,
                     "media_devices": [{"kind": "videoinput", "label": ""}],
                     "navigator_plugins": []}, "navigator_coherence")
        self.assertEqual(r.status, "pass")

    def test_coherent_desktop_passes(self):
        r = _result({"declared_platform": "macos", "touch_support": False,
                     "browser": "safari", "navigator_plugins": []},
                    "navigator_coherence")
        self.assertEqual(r.status, "pass")

    def test_coherent_mobile_passes(self):
        r = _result({"declared_platform": "android", "touch_support": True,
                     "navigator_plugins": []}, "navigator_coherence")
        self.assertEqual(r.status, "pass")

    def test_platform_only_skips(self):
        r = _result({"declared_platform": "windows"}, "navigator_coherence")
        self.assertEqual(r.status, "skipped")

    def test_missing_platform_skips(self):
        r = _result({"touch_support": True}, "navigator_coherence")
        self.assertEqual(r.status, "skipped")

    def test_unknown_platform_skips(self):
        r = _result({"declared_platform": "haiku", "touch_support": True},
                    "navigator_coherence")
        self.assertEqual(r.status, "skipped")


class TestVectorsFeedScore(unittest.TestCase):
    def test_three_new_vectors_registered(self):
        for key in ("client_hint_consistency", "font_entropy",
                    "navigator_coherence"):
            self.assertIn(key, _CHECK_WEIGHTS)
        names = {r.check for r in run_audit({}).results}
        self.assertIn("client_hint_consistency", names)
        self.assertIn("font_entropy", names)
        self.assertIn("navigator_coherence", names)

    def test_new_vectors_raise_traceability_score(self):
        # Only the three new vectors are evaluable, and all leak => score 100.
        signals = {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "ua_platform": '"macOS"',
            "fonts": ["Helvetica Neue", "Segoe UI"],
            "declared_platform": "macos",
            "browser": "firefox",
            "navigator_plugins": ["pdf"],
            "touch_support": False,
        }
        report = run_audit(signals)
        self.assertEqual(report.traceability_score, 100)
        self.assertEqual(report.verdict, "FULLY-TRACEABLE")
        leaks = {r.check for r in report.leaks}
        self.assertEqual(leaks, {"client_hint_consistency", "font_entropy",
                                 "navigator_coherence"})

    def test_partial_new_vector_score(self):
        # Only client-hint evaluable + leaking => 12/12 == 100.
        report = run_audit({
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "ua_platform": '"Linux"'})
        self.assertEqual(report.traceability_score, 100)

    def test_clean_new_vectors_score_zero(self):
        report = run_audit({
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "ua_platform": '"Windows"',
            "fonts": ["Segoe UI", "Calibri"], "declared_platform": "windows",
            "touch_support": False, "navigator_plugins": [], "browser": "chrome"})
        self.assertEqual(report.traceability_score, 0)
        self.assertEqual(report.verdict, "ANONYMOUS")


if __name__ == "__main__":
    unittest.main()
