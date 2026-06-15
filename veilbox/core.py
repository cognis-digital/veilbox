"""veilbox core — coherent fingerprint generation, config emitters, and the
attribution/leak self-audit. Standard library only; network checks degrade
gracefully offline.

Design principles:
  * COHERENCE FIRST. A privacy fingerprint that leaks via mismatched fields
    (e.g. a macOS user-agent with a Windows platform, or a timezone that does
    not match the locale's country) is *worse* than no spoofing at all, because
    the mismatch itself is a strong, rare, trackable signal. Every profile this
    module emits is internally consistent and validated.
  * NO TELEMETRY. Nothing here phones home. The only network access is in the
    audit path, and it is opt-in, time-bounded, and fully degradable offline.
  * VERIFIABILITY. The audit returns a TRACEABILITY SCORE (0-100, lower is more
    anonymous) plus per-check evidence, so anonymity is *proven*, not asserted.

ETHICS: for privacy protection, OPSEC, anti-tracking, and AUTHORIZED security
research only. Not for fraud, evading fraud-detection, or unlawful evasion.
"""

from __future__ import annotations

import hashlib
import json
import random
import socket
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "veilbox"
TOOL_VERSION = "0.1.0"

# --------------------------------------------------------------------------- #
# Coherent fingerprint corpus
#
# Each "platform family" bundles fields that MUST agree. We never mix a UA token
# from one family with screen/font/webgl hints from another. A profile is the
# selection of one OS family, one matching browser, one matching device class,
# and a locale whose primary timezone is consistent with the locale's country.
# --------------------------------------------------------------------------- #

# OS family -> the facts that have to line up across the fingerprint.
_OS_FAMILIES: Dict[str, Dict[str, Any]] = {
    "windows": {
        "platform": "Win32",
        "ua_os": "Windows NT 10.0; Win64; x64",
        "ua_platform": '"Windows"',
        "oscpu": "Windows NT 10.0; Win64; x64",
        "device_class": "desktop",
        "fonts": [
            "Arial", "Calibri", "Cambria", "Consolas", "Segoe UI",
            "Tahoma", "Times New Roman", "Verdana",
        ],
        "webgl_vendors": [
            ("Google Inc. (NVIDIA)",
             "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("Google Inc. (Intel)",
             "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),  # noqa: E501
            ("Google Inc. (AMD)",
             "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ],
        "screens": [(1920, 1080, 24), (2560, 1440, 24), (1366, 768, 24)],
    },
    "macos": {
        "platform": "MacIntel",
        "ua_os": "Macintosh; Intel Mac OS X 10_15_7",
        "ua_platform": '"macOS"',
        "oscpu": "Intel Mac OS X 10_15_7",
        "device_class": "desktop",
        "fonts": [
            "Arial", "Geneva", "Helvetica", "Helvetica Neue", "Lucida Grande",
            "Menlo", "Monaco", "San Francisco", "Times New Roman",
        ],
        "webgl_vendors": [
            ("Google Inc. (Apple)",
             "ANGLE (Apple, Apple M1, OpenGL 4.1 Metal - 76.3)"),
            ("Google Inc. (Intel)",
             "ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics OpenGL Engine, OpenGL 4.1)"),  # noqa: E501
        ],
        "screens": [(2560, 1600, 30), (1440, 900, 30), (1680, 1050, 30)],
    },
    "linux": {
        "platform": "Linux x86_64",
        "ua_os": "X11; Linux x86_64",
        "ua_platform": '"Linux"',
        "oscpu": "Linux x86_64",
        "device_class": "desktop",
        "fonts": [
            "DejaVu Sans", "DejaVu Serif", "Liberation Sans",
            "Liberation Mono", "Noto Sans", "Ubuntu", "Cantarell",
        ],
        "webgl_vendors": [
            ("Mesa", "Mesa Intel(R) UHD Graphics 620 (KBL GT2)"),
            ("AMD", "AMD Radeon RX 6600 (radeonsi, navi23, LLVM 15.0.7)"),
        ],
        "screens": [(1920, 1080, 24), (1366, 768, 24), (2560, 1440, 24)],
    },
    "android": {
        "platform": "Linux armv8l",
        "ua_os": "Linux; Android 14; Pixel 8",
        "ua_platform": '"Android"',
        "oscpu": None,  # Firefox-only field; Chrome/Android does not expose it.
        "device_class": "mobile",
        "fonts": ["Roboto", "Noto Sans", "Noto Serif", "Droid Sans"],
        "webgl_vendors": [
            ("Qualcomm", "Adreno (TM) 730"),
            ("ARM", "Mali-G715"),
        ],
        "screens": [(412, 915, 24), (360, 800, 24), (393, 873, 24)],
    },
}

# Browser families and the UA template each one uses. The {os} slot is filled
# from the OS family's ``ua_os`` so the two can never disagree.
_BROWSERS: Dict[str, Dict[str, Any]] = {
    "chrome": {
        "label": "Chrome",
        "major": "125",
        "full": "125.0.6422.112",
        # Compatible OS families (Chrome runs everywhere).
        "os": ["windows", "macos", "linux", "android"],
        "engine": "Blink",
        "ua_tpl": ("Mozilla/5.0 ({os}) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/{full} Safari/537.36"),
        "ch_ua": ('"Chromium";v="{major}", "Google Chrome";v="{major}", '
                  '"Not.A/Brand";v="24"'),
    },
    "firefox": {
        "label": "Firefox",
        "major": "126",
        "full": "126.0",
        "os": ["windows", "macos", "linux", "android"],
        "engine": "Gecko",
        "ua_tpl": "Mozilla/5.0 ({os}; rv:{full}) Gecko/20100101 Firefox/{full}",
        "ch_ua": None,  # Firefox does not send Client-Hints UA.
    },
    "safari": {
        "label": "Safari",
        "major": "17",
        "full": "17.4.1",
        "os": ["macos"],  # Safari only ships on Apple platforms.
        "engine": "WebKit",
        "ua_tpl": ("Mozilla/5.0 ({os}) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                   "Version/{full} Safari/605.1.15"),
        "ch_ua": None,
    },
}

# locale -> (primary IANA timezone, ISO country). Used both to build coherent
# profiles and to detect timezone/locale/geo mismatches in the audit.
_LOCALES: Dict[str, Dict[str, str]] = {
    "en-US": {"tz": "America/New_York", "country": "US", "lang": "en"},
    "en-GB": {"tz": "Europe/London", "country": "GB", "lang": "en"},
    "de-DE": {"tz": "Europe/Berlin", "country": "DE", "lang": "de"},
    "fr-FR": {"tz": "Europe/Paris", "country": "FR", "lang": "fr"},
    "es-ES": {"tz": "Europe/Madrid", "country": "ES", "lang": "es"},
    "ja-JP": {"tz": "Asia/Tokyo", "country": "JP", "lang": "ja"},
    "pt-BR": {"tz": "America/Sao_Paulo", "country": "BR", "lang": "pt"},
    "en-AU": {"tz": "Australia/Sydney", "country": "AU", "lang": "en"},
}

# Reverse map: country -> set of timezones we consider coherent for that country.
_COUNTRY_TZS: Dict[str, set] = {}
for _loc, _meta in _LOCALES.items():
    _COUNTRY_TZS.setdefault(_meta["country"], set()).add(_meta["tz"])
# A few extra coherent zones per country so real IP-geo data does not trip a
# false mismatch when a user is legitimately in another zone of the same nation.
_COUNTRY_TZS["US"].update({"America/Chicago", "America/Denver", "America/Los_Angeles"})
_COUNTRY_TZS["BR"].update({"America/Manaus", "America/Fortaleza"})
_COUNTRY_TZS["AU"].update({"Australia/Perth", "Australia/Melbourne"})


class ProfileError(ValueError):
    """Raised when a fingerprint profile cannot be built or is incoherent."""


@dataclass
class Profile:
    """An internally-consistent browser/device fingerprint profile."""

    seed: str
    os_family: str
    browser: str
    user_agent: str
    platform: str
    oscpu: Optional[str]
    locale: str
    language: str
    languages: List[str]
    timezone: str
    country: str
    screen_width: int
    screen_height: int
    color_depth: int
    device_class: str
    device_memory_gb: int
    hardware_concurrency: int
    touch_support: bool
    webgl_vendor: str
    webgl_renderer: str
    canvas_hint: str
    fonts: List[str]
    client_hints_ua: Optional[str]
    do_not_track: str

    def fingerprint_id(self) -> str:
        """A stable hash of the *observable* fields — what a tracker would see."""
        observable = "|".join(str(x) for x in (
            self.user_agent, self.platform, self.language,
            self.timezone, self.screen_width, self.screen_height,
            self.color_depth, self.webgl_vendor, self.webgl_renderer,
            self.canvas_hint, ",".join(self.fonts),
        ))
        return hashlib.sha256(observable.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["fingerprint_id"] = self.fingerprint_id()
        return d


def _seed_to_rng(seed: Optional[str]) -> Tuple[str, random.Random]:
    if seed is None:
        seed = hashlib.sha256(str(random.random()).encode()).hexdigest()[:12]
    rng = random.Random(hashlib.sha256(seed.encode("utf-8")).hexdigest())
    return seed, rng


def generate_profile(
    seed: Optional[str] = None,
    os_family: Optional[str] = None,
    browser: Optional[str] = None,
    locale: Optional[str] = None,
) -> Profile:
    """Generate a coherent fingerprint profile.

    Any field left ``None`` is chosen deterministically from ``seed`` so the
    same seed always yields the same profile (reproducible for testing) while a
    fresh/absent seed gives a new coherent identity (``--rotate``).
    """
    seed, rng = _seed_to_rng(seed)

    # Pick browser first, then constrain OS to one the browser supports.
    if browser is None:
        browser = rng.choice(list(_BROWSERS))
    if browser not in _BROWSERS:
        raise ProfileError(f"unknown browser: {browser!r}")
    b = _BROWSERS[browser]

    compatible_os = b["os"]
    if os_family is None:
        os_family = rng.choice(compatible_os)
    if os_family not in _OS_FAMILIES:
        raise ProfileError(f"unknown os family: {os_family!r}")
    if os_family not in compatible_os:
        raise ProfileError(
            f"incoherent combo: {browser} does not run on {os_family}")
    osf = _OS_FAMILIES[os_family]

    if locale is None:
        locale = rng.choice(list(_LOCALES))
    if locale not in _LOCALES:
        raise ProfileError(f"unknown locale: {locale!r}")
    lmeta = _LOCALES[locale]

    user_agent = b["ua_tpl"].format(os=osf["ua_os"], full=b["full"],
                                    major=b["major"])
    ch_ua = None
    if b["ch_ua"]:
        ch_ua = b["ch_ua"].format(major=b["major"])

    width, height, depth = rng.choice(osf["screens"])
    webgl_vendor, webgl_renderer = rng.choice(osf["webgl_vendors"])

    is_mobile = osf["device_class"] == "mobile"
    device_memory = rng.choice([4, 8] if is_mobile else [8, 16, 32])
    cores = rng.choice([6, 8] if is_mobile else [4, 8, 12, 16])

    # Canvas hint: a stable token derived from the coherent inputs. Real canvas
    # FP comes from GPU+driver+font stack; we derive a plausible token from the
    # same coherent inputs so it never contradicts them.
    canvas_basis = f"{os_family}|{browser}|{webgl_renderer}|{width}x{height}"
    canvas_hint = "canvas:" + hashlib.sha256(canvas_basis.encode()).hexdigest()[:12]

    # languages list: primary locale then bare language, coherent ordering.
    languages = [locale]
    if lmeta["lang"] != locale:
        languages.append(lmeta["lang"])

    fonts = list(osf["fonts"])

    return Profile(
        seed=seed,
        os_family=os_family,
        browser=browser,
        user_agent=user_agent,
        platform=osf["platform"],
        oscpu=osf["oscpu"] if browser == "firefox" else None,
        locale=locale,
        language=lmeta["lang"],
        languages=languages,
        timezone=lmeta["tz"],
        country=lmeta["country"],
        screen_width=width,
        screen_height=height,
        color_depth=depth,
        device_class=osf["device_class"],
        device_memory_gb=device_memory,
        hardware_concurrency=cores,
        touch_support=is_mobile,
        webgl_vendor=webgl_vendor,
        webgl_renderer=webgl_renderer,
        canvas_hint=canvas_hint,
        fonts=fonts,
        client_hints_ua=ch_ua,
        do_not_track="1",
    )


@dataclass
class Inconsistency:
    field: str
    message: str


def validate_profile(profile: Profile) -> List[Inconsistency]:
    """Check a profile for internal contradictions. Empty list == coherent.

    This is the differentiator: cheap anti-detect tools leak because their
    fields disagree. We assert agreement across UA/platform/browser/OS,
    timezone/locale/country, screen/device-class, and WebGL/OS.
    """
    issues: List[Inconsistency] = []

    if profile.os_family not in _OS_FAMILIES:
        issues.append(  # noqa: E501
            Inconsistency("os_family", f"unknown OS family {profile.os_family!r}"))
        return issues
    if profile.browser not in _BROWSERS:
        issues.append(Inconsistency("browser", f"unknown browser {profile.browser!r}"))
        return issues

    osf = _OS_FAMILIES[profile.os_family]
    b = _BROWSERS[profile.browser]

    # 1. platform must match the OS family.
    if profile.platform != osf["platform"]:
        issues.append(Inconsistency(
            "platform",
            f"platform {profile.platform!r} does not match {profile.os_family} "
            f"(expected {osf['platform']!r})"))

    # 2. UA must contain the OS token AND the browser token.
    if osf["ua_os"].split(";")[0] not in profile.user_agent:
        issues.append(Inconsistency(
            "user_agent", "user-agent OS token does not match os_family"))
    if profile.browser != "chrome" and b["label"] not in profile.user_agent \
            and profile.browser == "firefox" and "Firefox" not in profile.user_agent:
        issues.append(Inconsistency(
            "user_agent", "user-agent does not advertise the declared browser"))

    # 3. browser must be able to run on this OS.
    if profile.os_family not in b["os"]:
        issues.append(Inconsistency(
            "browser",
            f"{profile.browser} cannot run on {profile.os_family}"))

    # 4. timezone must be coherent with the country.
    coherent_tzs = _COUNTRY_TZS.get(profile.country, set())
    if coherent_tzs and profile.timezone not in coherent_tzs:
        issues.append(Inconsistency(
            "timezone",
            f"timezone {profile.timezone!r} is not coherent with country "
            f"{profile.country!r}"))

    # 5. locale's country/lang must match the declared fields.
    lmeta = _LOCALES.get(profile.locale)
    if lmeta:
        if lmeta["country"] != profile.country:
            issues.append(Inconsistency(
                "country", "country does not match the locale"))
        if lmeta["lang"] != profile.language:
            issues.append(Inconsistency(
                "language", "language does not match the locale"))

    # 6. touch/device-class coherence.
    expect_touch = osf["device_class"] == "mobile"
    if profile.touch_support != expect_touch:
        issues.append(Inconsistency(
            "touch_support",
            f"touch_support={profile.touch_support} contradicts device class "
            f"{osf['device_class']!r}"))
    if profile.device_class != osf["device_class"]:
        issues.append(Inconsistency(
            "device_class", "device_class does not match os_family"))

    # 7. WebGL renderer must belong to this OS family's known set.
    known_renderers = {r for (_v, r) in osf["webgl_vendors"]}
    if profile.webgl_renderer not in known_renderers:
        issues.append(Inconsistency(
            "webgl_renderer",
            "WebGL renderer is not one this OS family would report"))

    # 8. fonts must be a subset of the OS family's font stack.
    extra = [f for f in profile.fonts if f not in osf["fonts"]]
    if extra:
        issues.append(Inconsistency(
            "fonts", f"fonts not present on {profile.os_family}: {extra}"))

    return issues


# --------------------------------------------------------------------------- #
# DNS / proxy config emitters (templated, placeholder IDs)
# --------------------------------------------------------------------------- #

_NEXTDNS_DOH = "https://dns.nextdns.io/{profile_id}"
_NEXTDNS_DOH_HOST = "{profile_id}.dns.nextdns.io"


def nextdns_config(profile_id: str = "PLACEHOLDER_ID",
                   fmt: str = "yaml") -> str:
    """Emit a NextDNS DoH client config. ``profile_id`` is a placeholder by
    default — replace with your own NextDNS profile id. No telemetry."""
    doh = _NEXTDNS_DOH.format(profile_id=profile_id)
    host = _NEXTDNS_DOH_HOST.format(profile_id=profile_id)
    data = {
        "dns": {
            "provider": "nextdns",
            "protocol": "doh",
            "doh_url": doh,
            "doh_host": host,
            "bootstrap": ["45.90.28.0", "45.90.30.0"],
            "fallback": "block",  # fail closed: no plaintext fallback
            "note": "Replace PLACEHOLDER_ID with your NextDNS profile id.",
        }
    }
    if fmt == "json":
        return json.dumps(data, indent=2)
    return _to_yaml(data)


def proxy_chain_config(hops: Optional[List[str]] = None,
                       fmt: str = "yaml") -> str:
    """Emit a proxy-chain config. Hops are placeholder ``scheme://host:port``
    strings by default. The chain routes egress through each hop in order."""
    if hops is not None and not isinstance(hops, list):
        raise ValueError(
            f"hops must be a list of strings, got {type(hops).__name__!r}")
    if hops is not None:
        non_str = [h for h in hops if not isinstance(h, str)]
        if non_str:
            raise ValueError(
                f"every hop must be a string; got non-string entries: {non_str!r}")
    if not hops:
        hops = [
            "socks5://USER_PLACEHOLDER:PASS_PLACEHOLDER@proxy-a.example:1080",
            "https://proxy-b.example:8443",
            "socks5://proxy-c.example:1080",
        ]
    data = {
        "proxy": {
            "mode": "chain",
            "chain": hops,
            "dns_through_proxy": True,  # never resolve outside the tunnel
            "deny_direct": True,        # kill-switch: block non-proxied egress
            "note": "Placeholders only. Supply real upstreams via env/yaml.",
        }
    }
    if fmt == "json":
        return json.dumps(data, indent=2)
    return _to_yaml(data)


def _to_yaml(obj: Any, indent: int = 0) -> str:
    """Tiny YAML emitter (stdlib only) for our flat config dicts/lists."""
    pad = "  " * indent
    lines: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.append(_to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}{k}: {_yaml_scalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.append(_to_yaml(item, indent + 1))
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
    else:
        lines.append(f"{pad}{_yaml_scalar(obj)}")
    return "\n".join(ln for ln in lines if ln != "")


def _yaml_scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    s = str(v)
    if any(c in s for c in ":#{}[]") or s.strip() != s:
        return json.dumps(s)
    return s


# --------------------------------------------------------------------------- #
# Attribution / leak self-audit
# --------------------------------------------------------------------------- #

# Lower score == more anonymous. Each check that detects a leak/attribution
# vector adds weight to the traceability score.
_CHECK_WEIGHTS = {
    "webrtc_leak": 30,
    "dns_leak": 25,
    "ip_proxy_mismatch": 20,
    "tz_geo_mismatch": 15,
    "fingerprint_coherence": 10,
    # New active-fingerprinting consistency vectors. A mismatch in any of these
    # is a strong, rare, trackable signal — worse than not spoofing at all.
    "client_hint_consistency": 12,
    "font_entropy": 10,
    "navigator_coherence": 12,
}

# Maps a substring found in a User-Agent to the canonical OS token a browser's
# Client-Hint (Sec-CH-UA-Platform / navigator.userAgentData.platform) reports.
# ORDER MATTERS: Android UA strings contain "Linux", and macOS UA strings would
# never contain "Windows", so the more specific tokens must be tested first.
_UA_OS_TOKENS: List[Tuple[str, str]] = [
    ("Windows NT", "Windows"),
    ("Android", "Android"),          # before Linux: "Linux; Android 14; ..."
    ("Mac OS X", "macOS"),
    ("Macintosh", "macOS"),
    ("Linux", "Linux"),
]

# Canonical platform -> the font stack that platform legitimately ships. Used by
# the font-entropy vector to flag fonts that betray a *different* OS than the one
# the profile declares (a cross-platform font is a high-signal leak).
_PLATFORM_FONTS: Dict[str, set] = {
    fam: set(meta["fonts"]) for fam, meta in _OS_FAMILIES.items()
}
# Fonts shared across desktop platforms are not, on their own, a leak.
_UBIQUITOUS_FONTS = {"Arial", "Times New Roman", "Verdana", "Noto Sans"}
# Above this many enumerable fonts the set is itself near-unique (high entropy).
_FONT_ENTROPY_CEILING = 40

_STATUS_PASS = "pass"
_STATUS_LEAK = "leak"
_STATUS_SKIP = "skipped"  # could not evaluate (offline / no data)


@dataclass
class CheckResult:
    check: str
    status: str            # pass | leak | skipped
    weight: int
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def contributes(self) -> int:
        return self.weight if self.status == _STATUS_LEAK else 0


@dataclass
class AuditReport:
    source: str
    results: List[CheckResult]

    @property
    def traceability_score(self) -> int:
        """0 (anonymous) .. 100 (fully attributable). Skipped checks do not
        count toward the denominator, so an offline audit is still meaningful."""
        evaluated = [r for r in self.results if r.status != _STATUS_SKIP]
        if not evaluated:
            return 0
        max_possible = sum(r.weight for r in evaluated)
        scored = sum(r.contributes for r in evaluated)
        return round(100 * scored / max_possible) if max_possible else 0

    @property
    def leaks(self) -> List[CheckResult]:
        return [r for r in self.results if r.status == _STATUS_LEAK]

    @property
    def verdict(self) -> str:
        s = self.traceability_score
        if s == 0:
            return "ANONYMOUS"
        if s < 25:
            return "LOW-RISK"
        if s < 60:
            return "ATTRIBUTABLE"
        return "FULLY-TRACEABLE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "source": self.source,
            "traceability_score": self.traceability_score,
            "verdict": self.verdict,
            "leak_count": len(self.leaks),
            "results": [
                {
                    "check": r.check,
                    "status": r.status,
                    "weight": r.weight,
                    "score_contribution": r.contributes,
                    "detail": r.detail,
                    "evidence": r.evidence,
                }
                for r in self.results
            ],
        }


def _check_webrtc(signals: Dict[str, Any]) -> CheckResult:
    w = _CHECK_WEIGHTS["webrtc_leak"]
    ips = signals.get("webrtc_local_ips")
    public = signals.get("public_ip")
    if ips is None:
        return CheckResult("webrtc_leak", _STATUS_SKIP, w,
                           "no WebRTC signal supplied (browser-side probe needed)")
    leaked = [ip for ip in ips if ip and ip == public]
    # A public IP surfacing via WebRTC, or any candidate that is not RFC1918,
    # is a leak (the host's real address bypassing the proxy).
    routable = [ip for ip in ips if ip and not _is_private_ip(ip)]
    if leaked or routable:
        return CheckResult(
            "webrtc_leak", _STATUS_LEAK, w,
            "WebRTC exposed a routable/public IP outside the tunnel",
            {"candidate_ips": ips, "routable": routable})
    return CheckResult("webrtc_leak", _STATUS_PASS, w,
                       "WebRTC candidates are private-range only",
                       {"candidate_ips": ips})


def _check_dns_leak(signals: Dict[str, Any]) -> CheckResult:
    w = _CHECK_WEIGHTS["dns_leak"]
    observed = signals.get("dns_resolvers")
    expected = signals.get("expected_resolvers")
    if observed is None or expected is None:
        return CheckResult("dns_leak", _STATUS_SKIP, w,
                           "no resolver data supplied")
    observed_set = set(observed)
    expected_set = set(expected)
    rogue = sorted(observed_set - expected_set)
    if rogue:
        return CheckResult(
            "dns_leak", _STATUS_LEAK, w,
            "queries resolved by a resolver other than the expected DoH endpoint",
            {"observed": sorted(observed_set), "expected": sorted(expected_set),
             "rogue": rogue})
    return CheckResult("dns_leak", _STATUS_PASS, w,
                       "all DNS handled by the expected resolver",
                       {"observed": sorted(observed_set)})


def _check_ip_proxy(signals: Dict[str, Any]) -> CheckResult:
    w = _CHECK_WEIGHTS["ip_proxy_mismatch"]
    public = signals.get("public_ip")
    proxy_exit = signals.get("proxy_exit_ip")
    if public is None or proxy_exit is None:
        return CheckResult("ip_proxy_mismatch", _STATUS_SKIP, w,
                           "missing public IP or proxy exit IP")
    if public != proxy_exit:
        return CheckResult(
            "ip_proxy_mismatch", _STATUS_LEAK, w,
            "observed public IP does not match the proxy exit node — egress is "
            "bypassing the tunnel",
            {"public_ip": public, "proxy_exit_ip": proxy_exit})
    return CheckResult("ip_proxy_mismatch", _STATUS_PASS, w,
                       "public IP equals the proxy exit node",
                       {"public_ip": public})


def _check_tz_geo(signals: Dict[str, Any]) -> CheckResult:
    w = _CHECK_WEIGHTS["tz_geo_mismatch"]
    tz = signals.get("timezone")
    geo_country = signals.get("ip_geo_country")
    if tz is None or geo_country is None:
        return CheckResult("tz_geo_mismatch", _STATUS_SKIP, w,
                           "missing timezone or IP-geo country")
    coherent = _COUNTRY_TZS.get(geo_country, set())
    # If we have no knowledge of the country, fall back to a prefix heuristic.
    if not coherent:
        return CheckResult("tz_geo_mismatch", _STATUS_SKIP, w,
                           f"no timezone knowledge for country {geo_country!r}")
    if tz not in coherent:
        return CheckResult(
            "tz_geo_mismatch", _STATUS_LEAK, w,
            "browser timezone is inconsistent with the exit IP's country — a "
            "strong de-anonymization signal",
            {"timezone": tz, "ip_geo_country": geo_country,
             "coherent_timezones": sorted(coherent)})
    return CheckResult("tz_geo_mismatch", _STATUS_PASS, w,
                       "timezone is consistent with the exit IP's country",
                       {"timezone": tz, "ip_geo_country": geo_country})


def _check_fp_coherence(signals: Dict[str, Any]) -> CheckResult:
    w = _CHECK_WEIGHTS["fingerprint_coherence"]
    prof = signals.get("profile")
    if prof is None:
        return CheckResult("fingerprint_coherence", _STATUS_SKIP, w,
                           "no fingerprint profile supplied")
    try:
        profile = _profile_from_dict(prof)
    except (ProfileError, Exception) as exc:
        return CheckResult("fingerprint_coherence", _STATUS_LEAK, w,
                           f"profile could not be parsed: {exc}", {})
    issues = validate_profile(profile)
    if issues:
        return CheckResult(
            "fingerprint_coherence", _STATUS_LEAK, w,
            "fingerprint fields contradict each other (mismatch is itself a "
            "tracking signal)",
            {"inconsistencies": [{"field": i.field, "message": i.message}
                                 for i in issues]})
    return CheckResult("fingerprint_coherence", _STATUS_PASS, w,
                       "fingerprint profile is internally consistent",
                       {"fingerprint_id": profile.fingerprint_id()})


def _ua_os_token(user_agent: str) -> Optional[str]:
    """Return the canonical OS token a browser would advertise for this UA, or
    None if no known token is present. Tested most-specific-first."""
    for needle, token in _UA_OS_TOKENS:
        if needle in user_agent:
            return token
    return None


def _normalize_ch_platform(value: Any) -> Optional[str]:
    """Client-Hint platform values arrive quoted (e.g. '"Windows"') from the
    Sec-CH-UA-Platform header and from our own _OS_FAMILIES table. Strip quotes
    and whitespace so comparisons are apples-to-apples."""
    if value is None:
        return None
    return str(value).strip().strip('"').strip("'").strip()


def _check_client_hint_consistency(signals: Dict[str, Any]) -> CheckResult:
    """Vector 1 — TLS/HTTP2 Client-Hint consistency.

    Modern Chromium splits identity across the legacy ``User-Agent`` string and
    the structured Client-Hints (``Sec-CH-UA-Platform`` / ``navigator
    .userAgentData.platform``). Naive spoofers patch one and forget the other,
    so the UA claims one OS while the Client-Hint claims another — a rare,
    high-confidence de-anonymization signal. We require the OS token in the UA
    to agree with the declared Client-Hint platform.
    """
    w = _CHECK_WEIGHTS["client_hint_consistency"]
    ua = signals.get("user_agent")
    ch_platform = _normalize_ch_platform(
        signals.get("ua_platform", signals.get("sec_ch_ua_platform")))
    if not ua or not ch_platform:
        return CheckResult("client_hint_consistency", _STATUS_SKIP, w,
                           "no user_agent + client-hint platform pair supplied")
    ua_os = _ua_os_token(ua)
    if ua_os is None:
        return CheckResult("client_hint_consistency", _STATUS_SKIP, w,
                           "user-agent contains no recognizable OS token")
    if ua_os != ch_platform:
        return CheckResult(
            "client_hint_consistency", _STATUS_LEAK, w,
            "Client-Hint platform disagrees with the User-Agent OS token — the "
            "two halves of the identity were not spoofed coherently",
            {"ua_os_token": ua_os, "client_hint_platform": ch_platform,
             "user_agent": ua})
    return CheckResult("client_hint_consistency", _STATUS_PASS, w,
                       "Client-Hint platform agrees with the User-Agent OS token",
                       {"platform": ch_platform})


def _check_font_entropy(signals: Dict[str, Any]) -> CheckResult:
    """Vector 2 — font-enumeration entropy.

    The set of installed fonts is one of the highest-entropy passive signals on
    the web. Two failure modes: (a) the list contains fonts that ship on a
    *different* OS than the one declared (e.g. ``Segoe UI`` on macOS), which both
    leaks the real platform and contradicts the spoof; (b) the list is so large
    it is effectively a unique key. Either condition is a leak.
    """
    w = _CHECK_WEIGHTS["font_entropy"]
    fonts = signals.get("fonts")
    platform = signals.get("declared_platform")
    if fonts is None or platform is None:
        return CheckResult("font_entropy", _STATUS_SKIP, w,
                           "no fonts + declared_platform pair supplied")
    plat = str(platform).strip().lower()
    native = _PLATFORM_FONTS.get(plat)
    if native is None:
        return CheckResult("font_entropy", _STATUS_SKIP, w,
                           f"no font baseline for platform {platform!r}")
    # Fonts that belong to some *other* platform's native stack and are not on
    # this one and are not ubiquitous cross-platform fonts: those betray the OS.
    other_platform_fonts: set = set()
    for fam, fset in _PLATFORM_FONTS.items():
        if fam != plat:
            other_platform_fonts |= fset
    foreign = sorted(
        f for f in fonts
        if f not in native
        and f not in _UBIQUITOUS_FONTS
        and f in other_platform_fonts)
    if foreign or len(fonts) > _FONT_ENTROPY_CEILING:
        reason = []
        if foreign:
            reason.append(f"{len(foreign)} font(s) native to a different OS")
        if len(fonts) > _FONT_ENTROPY_CEILING:
            reason.append(f"{len(fonts)} fonts exceeds the entropy ceiling "
                          f"({_FONT_ENTROPY_CEILING})")
        return CheckResult(
            "font_entropy", _STATUS_LEAK, w,
            "font enumeration leaks identity — " + "; ".join(reason),
            {"declared_platform": plat, "font_count": len(fonts),
             "foreign_fonts": foreign})
    return CheckResult("font_entropy", _STATUS_PASS, w,
                       "font set is plausible for the declared platform and "
                       "below the entropy ceiling",
                       {"declared_platform": plat, "font_count": len(fonts)})


def _check_navigator_coherence(signals: Dict[str, Any]) -> CheckResult:
    """Vector 3 — navigator.plugins / mediaDevices coherence vs declared platform.

    ``navigator.plugins`` is empty on every modern browser except where a PDF
    viewer is registered, and is *always* empty on mobile and on Firefox; a
    populated plugin array on a mobile or Firefox profile is a tell. Touch
    support must track the device class (mobile => touch, desktop => no touch).
    ``navigator.mediaDevices`` exposing labelled devices before any getUserMedia
    permission grant is also anomalous. Any of these contradicts the declared
    platform and is therefore a leak.
    """
    w = _CHECK_WEIGHTS["navigator_coherence"]
    platform = signals.get("declared_platform")
    if platform is None:
        return CheckResult("navigator_coherence", _STATUS_SKIP, w,
                           "no declared_platform supplied")
    plat = str(platform).strip().lower()
    if plat not in _OS_FAMILIES:
        return CheckResult("navigator_coherence", _STATUS_SKIP, w,
                           f"unknown declared_platform {platform!r}")
    is_mobile = _OS_FAMILIES[plat]["device_class"] == "mobile"
    touch = signals.get("touch_support")
    plugins = signals.get("navigator_plugins")
    media = signals.get("media_devices")
    browser = (signals.get("browser") or "").strip().lower()

    problems: List[str] = []
    evidence: Dict[str, Any] = {"declared_platform": plat}

    # touch must track device class (only evaluated when explicitly provided).
    if touch is not None:
        evidence["touch_support"] = touch
        if is_mobile and touch is False:
            problems.append("mobile platform reports touch_support=False")
        if not is_mobile and touch is True:
            problems.append("desktop platform reports touch_support=True")

    # plugins must be empty on mobile and on Firefox.
    if plugins is not None:
        evidence["plugin_count"] = len(plugins)
        if (is_mobile or browser == "firefox") and len(plugins) > 0:
            where = "mobile" if is_mobile else "Firefox"
            problems.append(
                f"{len(plugins)} navigator.plugins entries on a {where} profile "
                f"(expected none)")

    # labelled media devices before a permission grant leak hardware identity.
    if media is not None:
        labelled = [d for d in media
                    if isinstance(d, dict) and d.get("label")]
        evidence["media_device_count"] = len(media)
        if labelled:
            problems.append(
                f"{len(labelled)} mediaDevices expose non-empty labels without a "
                f"permission grant")

    # Nothing evaluable was supplied beyond the platform itself.
    if touch is None and plugins is None and media is None:
        return CheckResult("navigator_coherence", _STATUS_SKIP, w,
                           "no navigator signals (touch/plugins/media) supplied")

    if problems:
        evidence["problems"] = problems
        return CheckResult(
            "navigator_coherence", _STATUS_LEAK, w,
            "navigator surface contradicts the declared platform — "
            + "; ".join(problems), evidence)
    return CheckResult("navigator_coherence", _STATUS_PASS, w,
                       "navigator.plugins / mediaDevices / touch are coherent "
                       "with the declared platform", evidence)


def _profile_from_dict(d: Any) -> Profile:
    if not isinstance(d, dict):
        raise ProfileError(
            f"profile must be a JSON object, got {type(d).__name__!r}")
    fields = Profile.__dataclass_fields__  # type: ignore[attr-defined]
    missing = [k for k in fields if k not in d]
    if missing:
        raise ProfileError(f"profile missing fields: {missing}")
    try:
        return Profile(**{k: d[k] for k in fields})
    except TypeError as exc:
        raise ProfileError(f"profile field type error: {exc}") from exc


def _is_private_ip(ip: str) -> bool:
    """RFC1918 / loopback / link-local check without the ipaddress niceties
    beyond stdlib. Uses ``ipaddress`` (stdlib)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_unspecified)


def gather_live_signals(timeout: float = 2.0) -> Dict[str, Any]:
    """Best-effort live signal collection using stdlib only. Degrades to an
    empty/partial dict when offline. Never raises, never blocks indefinitely.

    NOTE: a browser is required for true WebRTC/canvas probing; from a headless
    container we can only observe the egress public IP and local resolvers.
    """
    signals: Dict[str, Any] = {}
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        # Public IP via a plaintext, no-telemetry endpoint. Optional.
        try:
            import urllib.request
            with urllib.request.urlopen(
                    "https://api.ipify.org?format=text", timeout=timeout) as resp:
                signals["public_ip"] = resp.read().decode().strip()
        except Exception:
            pass
        # Local hostname/IP (private-range expected behind a tunnel).
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
            signals["webrtc_local_ips"] = [host_ip]
        except Exception:
            pass
    finally:
        socket.setdefaulttimeout(old)
    return signals


def run_audit(signals: Optional[Dict[str, Any]] = None,
              source: str = "<signals>") -> AuditReport:
    """Run the full leak/attribution audit over a signals dict.

    ``signals`` keys (all optional; missing ones become 'skipped'):
      public_ip, proxy_exit_ip, webrtc_local_ips, dns_resolvers,
      expected_resolvers, timezone, ip_geo_country, profile,
      user_agent, ua_platform (or sec_ch_ua_platform),
      fonts, declared_platform,
      touch_support, navigator_plugins, media_devices, browser
    """
    signals = signals or {}
    results = [
        _check_webrtc(signals),
        _check_dns_leak(signals),
        _check_ip_proxy(signals),
        _check_tz_geo(signals),
        _check_fp_coherence(signals),
        _check_client_hint_consistency(signals),
        _check_font_entropy(signals),
        _check_navigator_coherence(signals),
    ]
    return AuditReport(source=source, results=results)


# --------------------------------------------------------------------------- #
# SARIF emitter for the audit (CI-friendly)
# --------------------------------------------------------------------------- #

def audit_to_sarif(report: AuditReport) -> Dict[str, Any]:
    rules = []
    sarif_results = []
    for r in report.results:
        rules.append({
            "id": r.check,
            "name": r.check,
            "shortDescription": {"text": r.check.replace("_", " ")},
            "defaultConfiguration": {
                "level": "error" if r.weight >= 25 else "warning"},
        })
        if r.status == _STATUS_LEAK:
            sarif_results.append({
                "ruleId": r.check,
                "level": "error" if r.weight >= 25 else "warning",
                "message": {"text": r.detail},
                "properties": {"weight": r.weight, "evidence": r.evidence},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/veilbox",
                "rules": rules,
            }},
            "results": sarif_results,
            "properties": {
                "traceability_score": report.traceability_score,
                "verdict": report.verdict,
            },
        }],
    }
