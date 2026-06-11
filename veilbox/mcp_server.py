"""veilbox MCP server.

Exposes the fingerprint generator and the leak self-audit as MCP tools over
stdio using newline-delimited JSON-RPC 2.0. Standard library only — no SDK —
so it runs anywhere Python does and can be wired into Cognis.Studio, Claude
Desktop, or Cursor as a local MCP server:

    {"command": "python", "args": ["-m", "veilbox", "mcp"]}

Implemented methods:
  * initialize   — handshake, advertises the tools capability
  * tools/list   — describes generate_fingerprint / audit_signals
  * tools/call   — runs a tool and returns JSON text

Zero telemetry: nothing here reaches the network.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from veilbox import TOOL_NAME, TOOL_VERSION
from veilbox.core import (
    ProfileError,
    audit_to_sarif,
    generate_profile,
    run_audit,
    validate_profile,
)

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "generate_fingerprint",
        "description": "Generate an internally-consistent browser/device "
                       "fingerprint profile (UA, platform, screen, timezone, "
                       "locale, WebGL/canvas hints, fonts) where all fields "
                       "agree. Returns the profile plus a coherence report.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "seed": {"type": "string"},
                "os_family": {"type": "string",
                              "enum": ["windows", "macos", "linux", "android"]},
                "browser": {"type": "string",
                            "enum": ["chrome", "firefox", "safari"]},
                "locale": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "audit_signals",
        "description": "Run the attribution/leak self-audit over observed "
                       "signals (WebRTC, DNS resolvers, public/proxy IP, "
                       "timezone vs IP-geo, fingerprint coherence) and return "
                       "a traceability score (0-100) plus per-check evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "signals": {"type": "object",
                            "description": "Observed-signal map (see README)."},
            },
            "required": ["signals"],
            "additionalProperties": False,
        },
    },
]


def _result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "generate_fingerprint":
        profile = generate_profile(
            seed=arguments.get("seed"),
            os_family=arguments.get("os_family"),
            browser=arguments.get("browser"),
            locale=arguments.get("locale"),
        )
        issues = validate_profile(profile)
        payload = {
            "profile": profile.to_dict(),
            "coherent": not issues,
            "inconsistencies": [{"field": i.field, "message": i.message}
                                for i in issues],
        }
        is_error = bool(issues)
    elif name == "audit_signals":
        signals = arguments.get("signals")
        if not isinstance(signals, dict):
            raise ValueError("`signals` (object) is required")
        report = run_audit(signals, source="<mcp:inline>")
        payload = report.to_dict()
        payload["sarif"] = audit_to_sarif(report)
        is_error = report.traceability_score >= 60
    else:
        raise ValueError(f"unknown tool: {name}")

    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "isError": is_error,
    }


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch a single JSON-RPC request. Returns None for notifications."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        res = _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
        return None if is_notification else res

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, arguments))
        except (ValueError, ProfileError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            return _error(req_id, -32603, f"internal error: {exc}")

    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
