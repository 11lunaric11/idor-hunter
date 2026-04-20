"""Analysis: turn raw probes into ranked findings.

The analyzer cross-references probes across users for the same (scan, id, method)
triple. The cardinal rule: if a user who shouldn't have access gets the same
response as the owner, something is wrong.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from .scanner import Probe

# Heuristic: "substantive" response bodies are larger than this.
# Tunable — some APIs return tiny JSON for valid objects, but <50 bytes is
# almost always an error page or empty response.
_SUBSTANTIVE_LENGTH = 50

# HTTP status codes that typically indicate "you got something back"
_SUCCESS_STATUSES = {200, 201, 202, 204}

# HTTP status codes that typically indicate "access was properly denied"
_DENIAL_STATUSES = {401, 403, 404}

# Redirect destinations that indicate denial (login bounces, logouts).
# A 302 to one of these is a denial signal, not an IDOR.
_DENIAL_REDIRECT_PATHS = ("/login", "/signin", "/auth", "/logout")


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    severity: str  # critical | high | medium | low | info
    kind: str  # short tag: "idor_read", "unauth_access", etc.
    title: str
    description: str
    scan: str
    method: str
    url: str
    id: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _group_key(p: Probe) -> tuple[str, str, str]:
    return (p.scan, p.id, p.method)


def _is_substantive_success(p: Probe) -> bool:
    """Did this probe actually get meaningful data back?"""
    if p.status not in _SUCCESS_STATUSES:
        return False
    if p.status == 204:  # No Content is "success" but no data
        return False
    return p.length >= _SUBSTANTIVE_LENGTH


def _content_matches(a: Probe, b: Probe) -> bool:
    """Two responses that look like the same underlying resource."""
    if not a.content_hash or not b.content_hash:
        return False
    if a.content_hash == b.content_hash:
        return True
    # Allow 10% length drift to tolerate CSRF tokens / timestamps
    if a.length == 0 or b.length == 0:
        return False
    ratio = min(a.length, b.length) / max(a.length, b.length)
    return ratio > 0.9 and abs(a.length - b.length) < 200


def _is_denial_redirect(location: str) -> bool:
    """True if the redirect target looks like a login bounce / logout."""
    if not location:
        return False
    path = urlsplit(location).path.lower()
    return any(path == p or path.startswith(p + "/") for p in _DENIAL_REDIRECT_PATHS)


def _redirect_matches(a: Probe, b: Probe) -> bool:
    """Two 3xx responses that redirect to the same non-denial target.

    Catches IDORs where denied users get /login and allowed users get the
    resource-specific page — the body never contains the data, but the
    location header reveals it.
    """
    if not (300 <= a.status < 400 and 300 <= b.status < 400):
        return False
    if not a.location or not b.location:
        return False
    # Strip querystring; keep path + fragment.
    def _norm(url: str) -> str:
        s = urlsplit(url)
        return s.path + (f"#{s.fragment}" if s.fragment else "")
    if _norm(a.location) != _norm(b.location):
        return False
    # Login bounces are denial signals, not IDORs.
    return not _is_denial_redirect(a.location)


def analyze(probes: list[Probe]) -> list[Finding]:
    """Cross-reference probes and produce findings."""
    findings: list[Finding] = []

    groups: dict[tuple[str, str, str], list[Probe]] = defaultdict(list)
    for p in probes:
        groups[_group_key(p)].append(p)

    # Flat index for same-user cross-method lookups (Check 3). O(1) lookup
    # avoids O(probes) inner scans inside the group loop.
    by_coord: dict[tuple[str, str, str, str], Probe] = {
        (p.scan, p.id, p.user, p.method): p for p in probes
    }

    for (scan_name, id_value, method), group in groups.items():
        by_user: dict[str, Probe] = {p.user: p for p in group}
        # The owner is heuristically the authed user who got a successful
        # response. If multiple authed users succeed we pick the first —
        # explicit baseline_user assignment happens at config level.
        owner = next(
            (p for p in group if p.user != "__unauth__" and _is_substantive_success(p)),
            None,
        )
        # An owner is also needed for redirect-match (where body may be empty).
        if owner is None:
            owner = next(
                (
                    p
                    for p in group
                    if p.user != "__unauth__"
                    and 300 <= p.status < 400
                    and p.location
                    and not _is_denial_redirect(p.location)
                ),
                None,
            )

        # ---- Check 1: unauth access to what should be protected ----
        unauth = by_user.get("__unauth__")
        if unauth and _is_substantive_success(unauth):
            findings.append(
                Finding(
                    severity="critical",
                    kind="unauth_access",
                    title=f"Unauthenticated access to {method} {scan_name}",
                    description=(
                        f"The endpoint returned a {unauth.status} with "
                        f"{unauth.length} bytes of content to an unauthenticated "
                        f"request. Resources expecting authentication should return "
                        f"401/403."
                    ),
                    scan=scan_name,
                    method=method,
                    url=unauth.url,
                    id=id_value,
                    evidence={
                        "status": unauth.status,
                        "length": unauth.length,
                        "hash": unauth.content_hash,
                        "preview": unauth.body_preview[:300],
                    },
                )
            )

        # ---- Check 2: cross-user IDOR (content or redirect match) ----
        if owner is not None:
            for user, probe in by_user.items():
                if user in {"__unauth__", owner.user}:
                    continue
                content_hit = (
                    _is_substantive_success(probe) and _content_matches(owner, probe)
                )
                redirect_hit = _redirect_matches(owner, probe)
                if not (content_hit or redirect_hit):
                    continue
                severity = "high" if method == "GET" else "critical"
                kind = "idor_read" if method == "GET" else "idor_write"
                evidence = {
                    "owner_status": owner.status,
                    "owner_length": owner.length,
                    "owner_hash": owner.content_hash,
                    "attacker_status": probe.status,
                    "attacker_length": probe.length,
                    "attacker_hash": probe.content_hash,
                }
                if redirect_hit:
                    evidence["owner_location"] = owner.location
                    evidence["attacker_location"] = probe.location
                    evidence["match_via"] = "redirect"
                findings.append(
                    Finding(
                        severity=severity,
                        kind=kind,
                        title=(
                            f"IDOR: user {user!r} can {method} resource "
                            f"owned by {owner.user!r}"
                        ),
                        description=(
                            f"Both users received functionally identical "
                            f"responses (hash match, <10% length drift, or "
                            f"matching redirect target). This indicates "
                            f"{user!r} has unauthorized {method} access to a "
                            f"resource that appears to belong to {owner.user!r}."
                        ),
                        scan=scan_name,
                        method=method,
                        url=probe.url,
                        id=id_value,
                        evidence=evidence,
                    )
                )

        # ---- Check 3: write-verb success where read was denied ----
        # If DELETE/PUT succeeded but GET returned 403 for the same user+id,
        # that's a classic privilege escalation seam.
        if method in {"PUT", "PATCH", "DELETE", "POST"}:
            for user, probe in by_user.items():
                if user == "__unauth__":
                    continue
                if probe.status not in _SUCCESS_STATUSES:
                    continue
                # Look at GET for same user+id via pre-built index (O(1)).
                get_probe = by_coord.get((scan_name, id_value, user, "GET"))
                if get_probe and get_probe.status in _DENIAL_STATUSES:
                    findings.append(
                        Finding(
                            severity="critical",
                            kind="write_without_read",
                            title=(
                                f"{user!r} can {method} id={id_value} but GET "
                                f"returns {get_probe.status}"
                            ),
                            description=(
                                f"Access control is inconsistent across HTTP "
                                f"verbs. The user cannot read the resource "
                                f"(GET → {get_probe.status}) but the "
                                f"{method} succeeded with status {probe.status}. "
                                f"This is a classic authorization seam — the "
                                f"write path likely skips the ownership check."
                            ),
                            scan=scan_name,
                            method=method,
                            url=probe.url,
                            id=id_value,
                            evidence={
                                "write_status": probe.status,
                                "read_status": get_probe.status,
                            },
                        )
                    )

    # Sort by severity then by scan/id for stable, reviewable output
    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.scan, f.id, f.method)
    )
    return findings


def summary_stats(probes: list[Probe], findings: list[Finding]) -> dict:
    """High-level stats for the report header."""
    by_severity: dict[str, int] = defaultdict(int)
    for f in findings:
        by_severity[f.severity] += 1
    by_status: dict[int, int] = defaultdict(int)
    for p in probes:
        by_status[p.status] += 1

    return {
        "total_probes": len(probes),
        "total_findings": len(findings),
        "by_severity": dict(by_severity),
        "by_status": dict(sorted(by_status.items())),
        "errors": sum(1 for p in probes if p.error),
    }
