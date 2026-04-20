"""Tests for the analyzer — the actual IDOR detection logic."""
from __future__ import annotations

from idor_hunter.analyzer import analyze
from idor_hunter.scanner import Probe


def _probe(
    scan="s1",
    user="alice",
    method="GET",
    id_="1",
    status=200,
    length=500,
    content_hash="aaa",
    location="",
) -> Probe:
    return Probe(
        scan=scan,
        user=user,
        method=method,
        url=f"http://t/api/{id_}",
        id=id_,
        status=status,
        length=length,
        content_hash=content_hash,
        location=location,
        elapsed_ms=10,
        body_preview="body",
    )


def test_no_findings_when_access_is_clean():
    """Owner gets data, other user gets 403 — the correct state."""
    probes = [
        _probe(user="alice", status=200, length=500, content_hash="owner"),
        _probe(user="bob", status=403, length=20, content_hash="denied"),
    ]
    findings = analyze(probes)
    assert findings == []


def test_detects_idor_when_content_matches():
    """Both users get the same response body = IDOR."""
    probes = [
        _probe(user="alice", status=200, length=500, content_hash="same"),
        _probe(user="bob", status=200, length=500, content_hash="same"),
    ]
    findings = analyze(probes)
    assert len(findings) == 1
    assert findings[0].kind == "idor_read"
    assert findings[0].severity == "high"
    assert "bob" in findings[0].title


def test_idor_write_is_critical():
    """PUT/DELETE IDORs are worse than read IDORs."""
    probes = [
        _probe(method="PUT", user="alice", status=200, length=300, content_hash="x"),
        _probe(method="PUT", user="bob", status=200, length=300, content_hash="x"),
    ]
    findings = analyze(probes)
    assert len(findings) == 1
    assert findings[0].kind == "idor_write"
    assert findings[0].severity == "critical"


def test_tolerates_small_length_drift():
    """CSRF tokens, timestamps cause tiny diffs — still same resource."""
    probes = [
        _probe(user="alice", status=200, length=1000, content_hash="a"),
        _probe(user="bob", status=200, length=1020, content_hash="b"),  # 2% drift
    ]
    findings = analyze(probes)
    assert len(findings) == 1
    assert findings[0].kind == "idor_read"


def test_ignores_large_length_difference():
    """Big size difference = genuinely different resources, no finding."""
    probes = [
        _probe(user="alice", status=200, length=500, content_hash="a"),
        _probe(user="bob", status=200, length=2000, content_hash="b"),
    ]
    findings = analyze(probes)
    assert findings == []


def test_detects_unauth_access():
    """Unauth request to a protected resource that returns real data."""
    probes = [
        _probe(user="__unauth__", status=200, length=500, content_hash="leaked"),
        _probe(user="alice", status=200, length=500, content_hash="leaked"),
    ]
    findings = analyze(probes)
    kinds = {f.kind for f in findings}
    assert "unauth_access" in kinds
    unauth_finding = next(f for f in findings if f.kind == "unauth_access")
    assert unauth_finding.severity == "critical"


def test_ignores_empty_unauth_response():
    """401 with tiny error body is the correct behavior."""
    probes = [
        _probe(user="__unauth__", status=401, length=30, content_hash="err"),
        _probe(user="alice", status=200, length=500, content_hash="data"),
    ]
    findings = analyze(probes)
    assert not any(f.kind == "unauth_access" for f in findings)


def test_write_without_read_is_flagged():
    """User can PUT but GET returns 403 — classic verb inconsistency."""
    probes = [
        _probe(method="GET", user="bob", status=403, length=20, content_hash="denied"),
        _probe(method="PUT", user="bob", status=200, length=100, content_hash="ok"),
        _probe(method="GET", user="alice", status=200, length=500, content_hash="data"),
    ]
    findings = analyze(probes)
    write_findings = [f for f in findings if f.kind == "write_without_read"]
    assert len(write_findings) == 1
    assert write_findings[0].severity == "critical"


def test_findings_sorted_by_severity():
    """Critical findings should come first for triage."""
    probes = [
        # idor_read → high
        _probe(scan="s1", user="alice", status=200, length=500, content_hash="x"),
        _probe(scan="s1", user="bob", status=200, length=500, content_hash="x"),
        # unauth_access → critical
        _probe(scan="s2", user="__unauth__", status=200, length=500, content_hash="y"),
        _probe(scan="s2", user="alice", status=200, length=500, content_hash="y"),
    ]
    findings = analyze(probes)
    severities = [f.severity for f in findings]
    # critical must appear before high
    assert severities.index("critical") < severities.index("high")


def test_204_no_content_not_substantive():
    """204 No Content shouldn't trigger findings — it's a successful no-op."""
    probes = [
        _probe(user="alice", status=204, length=0, content_hash=""),
        _probe(user="bob", status=204, length=0, content_hash=""),
    ]
    findings = analyze(probes)
    assert findings == []


def test_redirect_match_flags_idor():
    """Two users 302 to the same resource path — IDOR via redirect."""
    probes = [
        _probe(
            user="alice",
            status=302,
            length=0,
            content_hash="",
            location="/invoice/1",
        ),
        _probe(
            user="bob",
            status=302,
            length=0,
            content_hash="",
            location="/invoice/1",
        ),
    ]
    findings = analyze(probes)
    assert len(findings) == 1
    assert findings[0].kind == "idor_read"
    assert findings[0].evidence.get("match_via") == "redirect"


def test_no_unauth_finding_when_only_unauth_identity():
    """No-auth scans (e.g. CTF hash-guessing) shouldn't fire unauth_access.

    Regression: before v0.3, Check 1 fired on every substantive 200 for
    `__unauth__` — but when the scan has no authed baseline, every 200 is
    expected. Real bug reported from TryHackMe Corridor run.
    """
    probes = [
        _probe(user="__unauth__", status=200, length=500, content_hash="x"),
        _probe(
            user="__unauth__", id_="2", status=200, length=500, content_hash="y"
        ),
    ]
    findings = analyze(probes)
    assert not any(f.kind == "unauth_access" for f in findings)
    # And we emit an info-level notice so the user sees *why* checks were skipped.
    notices = [f for f in findings if f.kind == "no_auth_baseline"]
    assert len(notices) == 1
    assert notices[0].severity == "info"


def test_session_expired_detection_fires():
    """Authed user denied at same rate as unauth baseline → session expired."""
    probes = []
    # 15 probes per user, all 401 — alice's session is dead.
    for i in range(15):
        probes.append(
            _probe(user="alice", id_=str(i), status=401, length=20, content_hash="")
        )
        probes.append(
            _probe(
                user="__unauth__",
                id_=str(i),
                status=401,
                length=20,
                content_hash="",
            )
        )
    findings = analyze(probes)
    expired = [f for f in findings if f.kind == "session_expired"]
    assert len(expired) == 1
    assert "alice" in expired[0].title


def test_session_expired_does_not_fire_on_normal_denial_mix():
    """User legitimately denied on some resources → not session-expired."""
    probes = []
    # alice gets 403 on half, 200 on half — normal access pattern.
    # unauth gets 401 on all — correct denial behavior.
    for i in range(20):
        status = 200 if i < 10 else 403
        probes.append(
            _probe(
                user="alice",
                id_=str(i),
                status=status,
                length=500 if status == 200 else 20,
                content_hash="x" if status == 200 else "",
            )
        )
        probes.append(
            _probe(
                user="__unauth__",
                id_=str(i),
                status=401,
                length=20,
                content_hash="",
            )
        )
    findings = analyze(probes)
    assert not any(f.kind == "session_expired" for f in findings)


def test_login_bounce_does_not_fire():
    """Both users 302 → /login is a denial signal, not an IDOR."""
    probes = [
        _probe(
            user="alice",
            status=302,
            length=0,
            content_hash="",
            location="/login?next=/invoice/1",
        ),
        _probe(
            user="bob",
            status=302,
            length=0,
            content_hash="",
            location="/login?next=/invoice/1",
        ),
    ]
    findings = analyze(probes)
    assert findings == []
