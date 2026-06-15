"""Tests for hardened error-handling and edge-case paths added to veilbox.

Covers:
  - audit --signals pointing to a missing file           -> exit 2
  - audit --signals with a JSON array (not an object)    -> exit 2
  - audit --fail-on out of range                         -> exit 2
  - _profile_from_dict with a non-dict input             -> ProfileError
  - fingerprint_coherence check with a non-dict profile  -> leak (not crash)
  - proxy_chain_config with bad hop types                -> ValueError
  - MCP server receiving a valid-JSON non-object message -> -32600 error
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veilbox.cli import main
from veilbox.core import (
    ProfileError,
    _profile_from_dict,
    proxy_chain_config,
    run_audit,
)
from veilbox import mcp_server


class TestAuditCliEdgeCases(unittest.TestCase):
    """CLI hardening: bad signal files and out-of-range flags."""

    def test_missing_signals_file_exits_2(self):
        rc = main(["audit", "--signals", "/no/such/file/signals.json"])
        self.assertEqual(rc, 2)

    def test_signals_json_array_not_object_exits_2(self):
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False) as f:
            json.dump(["not", "an", "object"], f)
            path = f.name
        try:
            rc = main(["audit", "--signals", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_fail_on_above_100_exits_2(self):
        rc = main(["audit", "--fail-on", "101"])
        self.assertEqual(rc, 2)

    def test_fail_on_negative_exits_2(self):
        rc = main(["audit", "--fail-on", "-1"])
        self.assertEqual(rc, 2)

    def test_fail_on_zero_is_accepted(self):
        # 0 is the boundary minimum; an empty audit scores 0, so this returns 1
        # (score 0 >= threshold 0).
        rc = main(["audit", "--fail-on", "0"])
        self.assertEqual(rc, 1)

    def test_fail_on_100_is_accepted(self):
        # score of empty audit is 0, which is < 100, so exit 0.
        rc = main(["audit", "--fail-on", "100"])
        self.assertEqual(rc, 0)


class TestProfileFromDictHardening(unittest.TestCase):
    """_profile_from_dict must never silently accept garbage input."""

    def test_non_dict_string_raises_profile_error(self):
        with self.assertRaises(ProfileError) as ctx:
            _profile_from_dict("not-a-dict")
        self.assertIn("JSON object", str(ctx.exception))

    def test_non_dict_list_raises_profile_error(self):
        with self.assertRaises(ProfileError) as ctx:
            _profile_from_dict([1, 2, 3])
        self.assertIn("JSON object", str(ctx.exception))

    def test_non_dict_none_raises_profile_error(self):
        with self.assertRaises(ProfileError):
            _profile_from_dict(None)

    def test_missing_fields_still_raises_profile_error(self):
        with self.assertRaises(ProfileError) as ctx:
            _profile_from_dict({"seed": "x"})
        self.assertIn("missing fields", str(ctx.exception))


class TestFpCoherenceCheckWithBadProfile(unittest.TestCase):
    """fingerprint_coherence check must return a 'leak' result — never crash —
    when the supplied profile value is not a valid dict."""

    def _get_fp_check(self, signals):
        report = run_audit(signals)
        return next(r for r in report.results if r.check == "fingerprint_coherence")

    def test_profile_as_string_is_leak_not_crash(self):
        r = self._get_fp_check({"profile": "not-a-dict"})
        self.assertEqual(r.status, "leak")
        self.assertIn("parsed", r.detail)

    def test_profile_as_list_is_leak_not_crash(self):
        r = self._get_fp_check({"profile": [1, 2, 3]})
        self.assertEqual(r.status, "leak")

    def test_profile_as_int_is_leak_not_crash(self):
        r = self._get_fp_check({"profile": 42})
        self.assertEqual(r.status, "leak")


class TestProxyChainConfigValidation(unittest.TestCase):
    """proxy_chain_config must reject non-list or non-string hop values."""

    def test_non_list_hops_raises(self):
        with self.assertRaises((ValueError, TypeError)):
            proxy_chain_config(hops="socks5://example.com:1080")

    def test_non_string_entries_raise(self):
        with self.assertRaises(ValueError) as ctx:
            proxy_chain_config(hops=["valid-hop", 1234])
        self.assertIn("non-string", str(ctx.exception))

    def test_empty_list_falls_back_to_placeholders(self):
        out = proxy_chain_config(hops=[])
        self.assertIn("PLACEHOLDER", out)


class TestMcpNonObjectRequest(unittest.TestCase):
    """MCP server must respond with -32600 when given valid JSON that is not
    an object, rather than crashing with an AttributeError."""

    def _send(self, payload: str) -> dict:
        import io
        inp = io.StringIO(payload + "\n")
        out = io.StringIO()
        mcp_server.run_mcp_server(stdin=inp, stdout=out)
        return json.loads(out.getvalue().strip())

    def test_json_array_returns_invalid_request(self):
        resp = self._send('["not", "an", "object"]')
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32600)

    def test_json_string_returns_invalid_request(self):
        resp = self._send('"just a string"')
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32600)

    def test_json_number_returns_invalid_request(self):
        resp = self._send("42")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32600)


if __name__ == "__main__":
    unittest.main()
