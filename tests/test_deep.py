"""Deep tests for veilbox — coherence invariants, individual leak checks,
config emitters, SARIF, and the MCP server protocol surface."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veilbox.core import (
    ProfileError,
    audit_to_sarif,
    generate_profile,
    nextdns_config,
    proxy_chain_config,
    run_audit,
    validate_profile,
    _is_private_ip,
)
from veilbox import mcp_server


class TestCoherenceInvariants(unittest.TestCase):
    def test_safari_only_macos(self):
        prof = generate_profile(seed="s", browser="safari")
        self.assertEqual(prof.os_family, "macos")
        self.assertEqual(validate_profile(prof), [])

    def test_incoherent_combo_rejected(self):
        with self.assertRaises(ProfileError):
            generate_profile(seed="s", browser="safari", os_family="windows")

    def test_unknown_browser_rejected(self):
        with self.assertRaises(ProfileError):
            generate_profile(seed="s", browser="netscape")

    def test_pinned_os_browser_locale(self):
        prof = generate_profile(seed="s", os_family="windows",
                                browser="chrome", locale="de-DE")
        self.assertEqual(prof.os_family, "windows")
        self.assertEqual(prof.timezone, "Europe/Berlin")
        self.assertEqual(prof.country, "DE")
        self.assertEqual(validate_profile(prof), [])

    def test_validate_catches_platform_mismatch(self):
        import dataclasses
        prof = generate_profile(seed="s", os_family="windows", browser="chrome")
        bad = dataclasses.replace(prof, platform="MacIntel")
        fields = {i.field for i in validate_profile(bad)}
        self.assertIn("platform", fields)

    def test_validate_catches_tz_country_mismatch(self):
        import dataclasses
        prof = generate_profile(seed="s", os_family="linux", browser="firefox",
                                locale="en-US")
        bad = dataclasses.replace(prof, timezone="Asia/Tokyo")
        fields = {i.field for i in validate_profile(bad)}
        self.assertIn("timezone", fields)

    def test_validate_catches_font_leak(self):
        import dataclasses
        prof = generate_profile(seed="s", os_family="linux", browser="firefox")
        bad = dataclasses.replace(prof, fonts=prof.fonts + ["Segoe UI"])
        fields = {i.field for i in validate_profile(bad)}
        self.assertIn("fonts", fields)

    def test_validate_catches_webgl_leak(self):
        import dataclasses
        prof = generate_profile(seed="s", os_family="linux", browser="firefox")
        bad = dataclasses.replace(
            prof, webgl_renderer="ANGLE (Apple, Apple M1, OpenGL 4.1 Metal)")
        fields = {i.field for i in validate_profile(bad)}
        self.assertIn("webgl_renderer", fields)


class TestIndividualChecks(unittest.TestCase):
    def test_webrtc_private_only_passes(self):
        r = run_audit({"webrtc_local_ips": ["10.0.0.1", "192.168.1.2"],
                       "public_ip": "203.0.113.9"})
        webrtc = next(c for c in r.results if c.check == "webrtc_leak")
        self.assertEqual(webrtc.status, "pass")

    def test_webrtc_public_leaks(self):
        r = run_audit({"webrtc_local_ips": ["203.0.113.9"],
                       "public_ip": "203.0.113.9"})
        webrtc = next(c for c in r.results if c.check == "webrtc_leak")
        self.assertEqual(webrtc.status, "leak")

    def test_missing_signal_is_skipped(self):
        r = run_audit({})
        for c in r.results:
            self.assertEqual(c.status, "skipped")
        # All skipped => score 0, not divide-by-zero.
        self.assertEqual(r.traceability_score, 0)

    def test_partial_signals_score_only_evaluated(self):
        # Only DNS evaluated, and it leaks => score should be 100 (25/25).
        r = run_audit({"dns_resolvers": ["8.8.8.8"],
                       "expected_resolvers": ["45.90.28.0"]})
        self.assertEqual(r.traceability_score, 100)
        self.assertEqual(len(r.leaks), 1)

    def test_tz_geo_unknown_country_skips(self):
        r = run_audit({"timezone": "America/New_York", "ip_geo_country": "XX"})
        tz = next(c for c in r.results if c.check == "tz_geo_mismatch")
        self.assertEqual(tz.status, "skipped")

    def test_is_private_ip(self):
        self.assertTrue(_is_private_ip("10.0.0.1"))
        self.assertTrue(_is_private_ip("192.168.1.1"))
        self.assertTrue(_is_private_ip("127.0.0.1"))
        self.assertFalse(_is_private_ip("8.8.8.8"))
        self.assertFalse(_is_private_ip("not-an-ip"))


class TestConfigEmitters(unittest.TestCase):
    def test_nextdns_yaml_has_placeholder(self):
        out = nextdns_config()
        self.assertIn("PLACEHOLDER_ID", out)
        self.assertIn("dns.nextdns.io", out)
        self.assertIn("fallback: block", out)

    def test_nextdns_json_parses(self):
        data = json.loads(nextdns_config(profile_id="abc123", fmt="json"))
        self.assertIn("abc123", data["dns"]["doh_url"])

    def test_proxy_chain_defaults_are_placeholders(self):
        out = proxy_chain_config()
        self.assertIn("PLACEHOLDER", out)
        self.assertIn("deny_direct: true", out)

    def test_proxy_chain_custom_hops(self):
        data = json.loads(proxy_chain_config(
            ["socks5://h:1", "https://h2:2"], fmt="json"))
        self.assertEqual(len(data["proxy"]["chain"]), 2)

    def test_no_real_secret_patterns(self):
        # Defensive: emitted configs must not contain anything resembling a
        # real provider key (e.g. AKIA..., sk-..., ghp_...).
        blob = nextdns_config() + proxy_chain_config()
        for bad in ("AKIA", "sk-", "ghp_", "xoxb-"):
            self.assertNotIn(bad, blob)


class TestSarif(unittest.TestCase):
    def test_sarif_shape(self):
        r = run_audit({"dns_resolvers": ["8.8.8.8"],
                       "expected_resolvers": ["45.90.28.0"]})
        sarif = audit_to_sarif(r)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "veilbox")
        self.assertEqual(run["properties"]["traceability_score"], 100)
        self.assertTrue(any(res["ruleId"] == "dns_leak"
                            for res in run["results"]))


class TestMcpServer(unittest.TestCase):
    def test_initialize(self):
        resp = mcp_server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "veilbox")

    def test_tools_list(self):
        resp = mcp_server.handle_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"generate_fingerprint", "audit_signals"})

    def test_generate_fingerprint_tool(self):
        resp = mcp_server.handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "generate_fingerprint",
                       "arguments": {"seed": "mcp-1", "browser": "safari"}},
        })
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(payload["coherent"])
        self.assertEqual(payload["profile"]["os_family"], "macos")
        self.assertFalse(resp["result"]["isError"])

    def test_audit_signals_tool_flags_leak(self):
        resp = mcp_server.handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "audit_signals",
                       "arguments": {"signals": {
                           "public_ip": "1.2.3.4", "proxy_exit_ip": "5.6.7.8",
                           "dns_resolvers": ["8.8.8.8"],
                           "expected_resolvers": ["45.90.28.0"]}}},
        })
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertGreaterEqual(payload["traceability_score"], 60)
        self.assertTrue(resp["result"]["isError"])

    def test_unknown_method(self):
        resp = mcp_server.handle_request(
            {"jsonrpc": "2.0", "id": 5, "method": "bogus"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_notification_returns_none(self):
        resp = mcp_server.handle_request({"jsonrpc": "2.0", "method": "initialized"})
        self.assertIsNone(resp)


if __name__ == "__main__":
    unittest.main()
