"""Command-line interface for veilbox."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from veilbox import TOOL_NAME, TOOL_VERSION
from veilbox.core import (
    AuditReport,
    Profile,
    ProfileError,
    audit_to_sarif,
    gather_live_signals,
    generate_profile,
    nextdns_config,
    proxy_chain_config,
    run_audit,
    validate_profile,
)

# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #

def _render_profile_table(profile: Profile) -> str:
    issues = validate_profile(profile)
    lines: List[str] = []
    lines.append(f"{TOOL_NAME} fingerprint — coherent device profile")
    lines.append("=" * 68)
    rows = [
        ("seed", profile.seed),
        ("fingerprint_id", profile.fingerprint_id()),
        ("os_family", profile.os_family),
        ("browser", profile.browser),
        ("user_agent", profile.user_agent),
        ("platform", profile.platform),
        ("oscpu", profile.oscpu),
        ("locale", profile.locale),
        ("language", profile.language),
        ("languages", ", ".join(profile.languages)),
        ("timezone", profile.timezone),
        ("country", profile.country),
        ("screen", f"{profile.screen_width}x{profile.screen_height} "
                   f"@ {profile.color_depth}-bit"),
        ("device_class", profile.device_class),
        ("device_memory_gb", profile.device_memory_gb),
        ("hardware_concurrency", profile.hardware_concurrency),
        ("touch_support", profile.touch_support),
        ("webgl_vendor", profile.webgl_vendor),
        ("webgl_renderer", profile.webgl_renderer),
        ("canvas_hint", profile.canvas_hint),
        ("fonts", ", ".join(profile.fonts)),
        ("client_hints_ua", profile.client_hints_ua),
        ("do_not_track", profile.do_not_track),
    ]
    for k, v in rows:
        lines.append(f"  {k:<22} {v}")
    lines.append("-" * 68)
    if issues:
        lines.append(f"COHERENCE: FAIL ({len(issues)} inconsistency)")
        for i in issues:
            lines.append(f"  ! {i.field}: {i.message}")
    else:
        lines.append("COHERENCE: PASS (all fields agree)")
    return "\n".join(lines)


_VERDICT_NOTE = {
    "ANONYMOUS": "no leak vectors detected among evaluated checks",
    "LOW-RISK": "minor attribution surface",
    "ATTRIBUTABLE": "one or more meaningful leaks present",
    "FULLY-TRACEABLE": "egress is effectively de-anonymized",
}


def _render_audit_table(report: AuditReport) -> str:
    lines: List[str] = []
    lines.append(f"{TOOL_NAME} audit — attribution / leak self-audit")
    lines.append(f"source: {report.source}")
    lines.append("=" * 68)
    lines.append(f"{'CHECK':<24} {'STATUS':<8} {'WEIGHT':>6}  DETAIL")
    lines.append("-" * 68)
    for r in report.results:
        lines.append(f"{r.check:<24} {r.status:<8} {r.weight:>6}  {r.detail}")
        for k, v in r.evidence.items():
            lines.append(f"    · {k}: {v}")
    lines.append("-" * 68)
    score = report.traceability_score
    lines.append(f"TRACEABILITY SCORE: {score}/100  (0 = anonymous, 100 = traceable)")
    lines.append(f"VERDICT: {report.verdict} — {_VERDICT_NOTE.get(report.verdict, '')}")
    lines.append(f"LEAKS: {len(report.leaks)}")
    return "\n".join(lines)


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        try:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text if text.endswith("\n") else text + "\n")
        except OSError as exc:
            print(f"error: cannot write to {out!r}: {exc}", file=sys.stderr)
            raise
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Self-hosted, zero-telemetry anti-fingerprint privacy "
                    "toolkit with a built-in attribution/leak self-audit. "
                    "For privacy, OPSEC, and AUTHORIZED research only.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    # fingerprint
    fp = sub.add_parser(
        "fingerprint",
        help="Generate a coherent browser/device fingerprint profile.")
    fp.add_argument("--seed", default=None,
                    help="Deterministic seed (same seed => same profile).")
    fp.add_argument("--rotate", action="store_true",
                    help="Generate a fresh coherent identity (ignores --seed).")
    fp.add_argument("--os", dest="os_family", default=None,
                    choices=("windows", "macos", "linux", "android"),
                    help="Pin the OS family (must be coherent with --browser).")
    fp.add_argument("--browser", default=None,
                    choices=("chrome", "firefox", "safari"),
                    help="Pin the browser (must be coherent with --os).")
    fp.add_argument("--locale", default=None,
                    help="Pin the locale, e.g. en-US, de-DE, ja-JP.")
    fp.add_argument("--format", choices=("table", "json"), default="table")
    fp.add_argument("--validate-only", action="store_true",
                    help="Only report coherence; exit 1 if inconsistent.")
    fp.add_argument("--out", help="Write output to this file.")

    # dns
    dns = sub.add_parser("dns", help="Emit NextDNS DoH config (templated).")
    dns.add_argument("--profile-id", default="PLACEHOLDER_ID",
                     help="Your NextDNS profile id (placeholder by default).")
    dns.add_argument("--format", choices=("yaml", "json"), default="yaml")
    dns.add_argument("--out", help="Write output to this file.")

    # proxy
    proxy = sub.add_parser("proxy", help="Emit proxy-chain config (templated).")
    proxy.add_argument("--hop", action="append", default=None, dest="hops",
                       help="A proxy hop scheme://host:port (repeatable).")
    proxy.add_argument("--format", choices=("yaml", "json"), default="yaml")
    proxy.add_argument("--out", help="Write output to this file.")

    # audit
    audit = sub.add_parser(
        "audit",
        help="Run the attribution/leak self-audit and emit a traceability score.")
    audit.add_argument("--signals", default=None,
                       help="Path to a JSON file of observed signals.")
    audit.add_argument("--live", action="store_true",
                       help="Collect best-effort live signals (degrades offline).")
    audit.add_argument("--format", choices=("table", "json", "sarif"),
                       default="table")
    audit.add_argument("--out", help="Write output to this file.")
    audit.add_argument("--fail-on", type=int, default=None, metavar="SCORE",
                       help="Exit non-zero if traceability score >= SCORE.")

    # mcp
    sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")

    return p


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #

def _run_fingerprint(args: argparse.Namespace) -> int:
    seed = None if args.rotate else args.seed
    try:
        profile = generate_profile(
            seed=seed, os_family=args.os_family,
            browser=args.browser, locale=args.locale)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # unexpected failures must not traceback
        print(f"error: unexpected problem generating profile: {exc}",
              file=sys.stderr)
        return 2

    issues = validate_profile(profile)

    try:
        if args.validate_only:
            if args.format == "json":
                _emit(json.dumps({
                    "coherent": not issues,
                    "inconsistencies": [{"field": i.field, "message": i.message}
                                        for i in issues],
                }, indent=2), args.out)
            else:
                if issues:
                    _emit("COHERENCE: FAIL\n" + "\n".join(
                        f"  ! {i.field}: {i.message}" for i in issues), args.out)
                else:
                    _emit("COHERENCE: PASS (all fields agree)", args.out)
            return 1 if issues else 0

        if args.format == "json":
            _emit(json.dumps(profile.to_dict(), indent=2), args.out)
        else:
            _emit(_render_profile_table(profile), args.out)
    except OSError:
        return 2
    return 1 if issues else 0


def _run_dns(args: argparse.Namespace) -> int:
    try:
        _emit(nextdns_config(args.profile_id, fmt=args.format), args.out)
    except OSError:
        return 2
    return 0


def _run_proxy(args: argparse.Namespace) -> int:
    try:
        _emit(proxy_chain_config(args.hops, fmt=args.format), args.out)
    except OSError:
        return 2
    return 0


def _run_audit(args: argparse.Namespace) -> int:
    if args.fail_on is not None and not (0 <= args.fail_on <= 100):
        print(
            f"error: --fail-on value {args.fail_on!r} is out of range; "
            "must be 0-100",
            file=sys.stderr,
        )
        return 2

    signals = {}
    source = "<empty>"
    if args.signals:
        if not __import__("os").path.exists(args.signals):
            print(f"error: signals file not found: {args.signals!r}",
                  file=sys.stderr)
            return 2
        try:
            with open(args.signals, "r", encoding="utf-8") as fh:
                signals = json.load(fh)
            source = args.signals
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not isinstance(signals, dict):
            print(
                f"error: signals file {args.signals!r} must contain a JSON "
                "object, not an array or scalar",
                file=sys.stderr,
            )
            return 2
    if args.live:
        live = gather_live_signals()
        # Live signals fill gaps but never override an explicit file value.
        for k, v in live.items():
            signals.setdefault(k, v)
        source = source + " + live" if args.signals else "<live>"

    report = run_audit(signals, source=source)

    try:
        if args.format == "json":
            _emit(json.dumps(report.to_dict(), indent=2), args.out)
        elif args.format == "sarif":
            _emit(json.dumps(audit_to_sarif(report), indent=2), args.out)
        else:
            _emit(_render_audit_table(report), args.out)
    except OSError:
        return 2

    if args.fail_on is not None:
        return 1 if report.traceability_score >= args.fail_on else 0
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "fingerprint":
            return _run_fingerprint(args)
        if args.command == "dns":
            return _run_dns(args)
        if args.command == "proxy":
            return _run_proxy(args)
        if args.command == "audit":
            return _run_audit(args)
        if args.command == "mcp":
            from veilbox.mcp_server import run_mcp_server
            run_mcp_server()
            return 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # unexpected; never show a raw traceback to users
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
