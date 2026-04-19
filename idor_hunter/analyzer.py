"""Analysis: turn raw probes into ranked findings.

The analyzer cross-references probes across users for the same (scan, id, method)
triple. The cardinal rule: if a user who shouldn't have access gets the same
response as the owner, something is wrong.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field

from .scanner import Probe

# Heuristic: "substantive" response bodies are larger than this.
# Tunable — some APIs return tiny JSON for valid objects, but <50 bytes is
# almost always an error page or empty response.
_SUBSTANTIVE_LENGTH = 50

# HTTP status codes that typically indicate "you got something back"
_SUCCESS_STATUSES = {200, 201, 202, 204}

# HTTP status codes that typically indicate "access was properly denied"
_DENIAL_STATUSES = {401, 403, 404}


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


def analyze(probes: list[Probe]) -> list[Finding]:
    """Cross-reference probes and produce findings."""
    findings: list[Finding] = []

    groups: dict[tuple[str, str, str], list[Probe]] = defaultdict(list)
    for p in probes:
        groups[_group_key(p)].append(p)

    for (scan_name, id_value, method), group in groups.items():
        by_user: dict[str, Probe] = {p.user: p for p in group}
        baseline = next(
            (p for u, p in by_user.items() if u not in {"__unauth__"}),
            None,
        )
        # Identify an explicit baseline if multiple authed users exist:
        # the owner is heuristically the one who gets a successful response.
        owner = next(
            (p for p in group if p.user != "__unauth__" and _is_substantive_success(p)),
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

        # ---- Check 2: cross-user IDOR (content match) ----
        if owner is not None:
            for user, probe in by_user.items():
                if user in {"__unauth__", owner.user}:
                    continue
                if not _is_substantive_success(probe):
                    continue
                if _content_matches(owner, probe):
                    severity = "high" if method == "GET" else "critical"
                    kind = "idor_read" if method == "GET" else "idor_write"
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
                                f"responses (hash match or <10% length drift). "
                                f"This indicates {user!r} has unauthorized "
                                f"{method} access to a resource that appears to "
                                f"belong to {owner.user!r}."
                            ),
                            scan=scan_name,
                            method=method,
                            url=probe.url,
                            id=id_value,
                            evidence={
                                "owner_status": owner.status,
                                "owner_length": owner.length,
                                "owner_hash": owner.content_hash,
                                "attacker_status": probe.status,
                                "attacker_length": probe.length,
                                "attacker_hash": probe.content_hash,
                            },
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
                # Look at GET for same user+id
                get_probe = next(
                    (
                        p
                        for p in probes
                        if p.scan == scan_name
                        and p.id == id_value
                        and p.user == user
                        and p.method == "GET"
                    ),
                    None,
                )
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
