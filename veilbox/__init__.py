"""veilbox — self-hosted, zero-telemetry anti-fingerprint privacy container
with a built-in attribution/leak self-audit. Part of the Cognis Neural Suite.

ETHICS: for privacy protection, OPSEC, anti-tracking, and AUTHORIZED security
research only — NOT for fraud, evading fraud-detection, or unlawful evasion.
"""

from veilbox.core import (
    TOOL_NAME,
    TOOL_VERSION,
    Profile,
    ProfileError,
    Inconsistency,
    CheckResult,
    AuditReport,
    generate_profile,
    validate_profile,
    nextdns_config,
    proxy_chain_config,
    run_audit,
    gather_live_signals,
    audit_to_sarif,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "__version__",
    "Profile",
    "ProfileError",
    "Inconsistency",
    "CheckResult",
    "AuditReport",
    "generate_profile",
    "validate_profile",
    "nextdns_config",
    "proxy_chain_config",
    "run_audit",
    "gather_live_signals",
    "audit_to_sarif",
]
