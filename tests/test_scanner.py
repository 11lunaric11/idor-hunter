"""Tests for the scanner module.

Uses the `responses` library to mock HTTP calls so tests are deterministic.
"""
from __future__ import annotations

import json
import time

import responses

from idor_hunter.config import Config, IdSpec, Options, PlaceholderMap, Scan, User
from idor_hunter.scanner import RateLimiter, run_scans, run_scans_with_harvest


def _minimal_config(scans: tuple[Scan, ...]) -> Config:
    return Config(
        base_url="http://target.local",
        users={
            "alice": User(name="alice", cookies={"session": "alice"}),
            "bob": User(name="bob", cookies={"session": "bob"}),
        },
        scans=scans,
        options=Options(rate_limit=0, timeout=5, max_retries=0),
    )


@responses.activate
def test_scanner_hits_expected_urls():
    responses.add(responses.GET, "http://target.local/api/item/1", json={"id": 1}, status=200)
    responses.add(responses.GET, "http://target.local/api/item/2", json={"id": 2}, status=200)
    responses.add(responses.GET, "http://target.local/api/item/1", json={"id": 1}, status=200)
    responses.add(responses.GET, "http://target.local/api/item/2", json={"id": 2}, status=200)

    scan = Scan(
        name="items",
        endpoint="/api/item/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=2),
        baseline_user="alice",
        test_users=("bob",),
        include_unauth=False,
    )
    cfg = _minimal_config((scan,))

    probes = run_scans(cfg)

    # 2 ids × 2 users × 1 method = 4 probes
    assert len(probes) == 4
    assert {p.user for p in probes} == {"alice", "bob"}
    assert all(p.status == 200 for p in probes)


@responses.activate
def test_scanner_captures_error_responses():
    responses.add(responses.GET, "http://target.local/api/x/1", json={}, status=403)

    scan = Scan(
        name="x",
        endpoint="/api/x/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=1),
        baseline_user="alice",
        test_users=(),
        include_unauth=False,
    )
    cfg = _minimal_config((scan,))
    probes = run_scans(cfg)

    assert len(probes) == 1
    assert probes[0].status == 403


@responses.activate
def test_scanner_includes_unauth_probe():
    responses.add(responses.GET, "http://target.local/api/x/1", json={}, status=401)
    responses.add(responses.GET, "http://target.local/api/x/1", json={"secret": 1}, status=200)

    scan = Scan(
        name="x",
        endpoint="/api/x/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=1),
        baseline_user="alice",
        test_users=(),
        include_unauth=True,
    )
    cfg = _minimal_config((scan,))
    probes = run_scans(cfg)

    labels = [p.user for p in probes]
    assert "__unauth__" in labels
    assert "alice" in labels


@responses.activate
def test_scanner_handles_network_errors_gracefully():
    # No responses registered → connection error
    scan = Scan(
        name="x",
        endpoint="/api/x/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=1),
        baseline_user=None,
        test_users=(),
        include_unauth=True,
    )
    cfg = _minimal_config((scan,))
    probes = run_scans(cfg)

    assert len(probes) == 1
    assert probes[0].status == 0
    assert probes[0].error is not None


@responses.activate
def test_scanner_records_location_header():
    responses.add(
        responses.GET,
        "http://target.local/api/x/1",
        headers={"Location": "/login"},
        status=302,
    )

    scan = Scan(
        name="x",
        endpoint="/api/x/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=1),
        baseline_user="alice",
        test_users=(),
        include_unauth=False,
    )
    cfg = _minimal_config((scan,))
    probes = run_scans(cfg)

    assert probes[0].status == 302
    assert probes[0].location == "/login"


@responses.activate
def test_resume_path_writes_jsonl(tmp_path):
    responses.add(responses.GET, "http://target.local/api/x/1", json={}, status=200)

    scan = Scan(
        name="x",
        endpoint="/api/x/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=1),
        baseline_user="alice",
        test_users=(),
        include_unauth=False,
    )
    cfg = _minimal_config((scan,))
    resume = tmp_path / "probes.jsonl"

    run_scans(cfg, resume_path=resume)
    assert resume.exists()
    lines = resume.read_text().strip().split("\n")
    assert len(lines) == 1


def test_rate_limiter_enforces_interval():
    """5 req/s should take at least ~0.8s for 5 requests (4 intervals)."""
    rl = RateLimiter(per_second=5)
    start = time.monotonic()
    for _ in range(5):
        rl.wait()
    elapsed = time.monotonic() - start
    # First call is ~free; expect at least 4 × 0.2s = 0.8s total, minus jitter
    assert elapsed >= 0.7


def test_rate_limiter_disabled_is_fast():
    rl = RateLimiter(per_second=0)
    start = time.monotonic()
    for _ in range(100):
        rl.wait()
    assert time.monotonic() - start < 0.1


@responses.activate
def test_dedup_baseline_in_test_users(capsys):
    """baseline_user listed in test_users is deduplicated, not probed twice."""
    responses.add(responses.GET, "http://target.local/api/x/1", json={}, status=200)

    scan = Scan(
        name="x",
        endpoint="/api/x/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=1),
        baseline_user="alice",
        test_users=("alice",),  # redundant: same as baseline
        include_unauth=False,
    )
    cfg = _minimal_config((scan,))
    probes = run_scans(cfg)

    # Only one probe (alice), not two
    assert len(probes) == 1
    # And a warning should have been emitted
    err = capsys.readouterr().err
    assert "baseline_user" in err and "alice" in err


@responses.activate
def test_resume_skips_already_probed_coords(tmp_path):
    """Probes already recorded in resume JSONL are replayed, not re-fetched.

    Before v0.3, resume wrote the log but didn't skip on restart — every
    rerun re-probed everything. This is the real resume behavior.
    """
    resume = tmp_path / "probes.jsonl"
    # Pre-populate with a completed probe for id=1 as alice.
    prior = {
        "scan": "x",
        "user": "alice",
        "method": "GET",
        "url": "http://target.local/api/x/1",
        "id": "1",
        "status": 200,
        "length": 100,
        "content_hash": "prior",
        "location": "",
        "elapsed_ms": 5,
        "body_preview": "prior",
        "error": None,
        "discovered_via": None,
    }
    resume.write_text(json.dumps(prior) + "\n")

    # Only register a response for id=2 — if the scanner tries to hit id=1
    # again, `responses` will raise ConnectionError.
    responses.add(
        responses.GET, "http://target.local/api/x/2", json={}, status=200
    )

    scan = Scan(
        name="x",
        endpoint="/api/x/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=2),
        baseline_user="alice",
        test_users=(),
        include_unauth=False,
    )
    cfg = _minimal_config((scan,))
    probes = run_scans(cfg, resume_path=resume)

    # Both probes in the returned list: loaded-from-log + newly-fetched.
    assert len(probes) == 2
    ids = {p.id for p in probes}
    assert ids == {"1", "2"}
    # Only one HTTP call actually happened (for id=2).
    assert len(responses.calls) == 1
    # The prior probe kept its hash.
    prior_probe = next(p for p in probes if p.id == "1")
    assert prior_probe.content_hash == "prior"


@responses.activate
def test_harvest_replays_uuids_from_response_bodies():
    """First-pass body leaks a UUID; harvest pass probes it."""
    seed = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    leaked = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    # First pass: seed returns a body containing `leaked`
    responses.add(
        responses.GET,
        f"http://target.local/api/res/{seed}",
        json={"id": seed, "related": leaked, "payload": "x" * 100},
        status=200,
    )
    # Second pass probes `leaked`
    responses.add(
        responses.GET,
        f"http://target.local/api/res/{leaked}",
        json={"id": leaked, "payload": "y" * 100},
        status=200,
    )

    scan = Scan(
        name="res",
        endpoint="/api/res/{id}",
        methods=("GET",),
        ids=IdSpec(kind="list", values=(seed,)),
        baseline_user="alice",
        test_users=(),
        include_unauth=False,
    )
    cfg = Config(
        base_url="http://target.local",
        users={"alice": User(name="alice", cookies={"session": "alice"})},
        scans=(scan,),
        options=Options(
            rate_limit=0,
            timeout=5,
            max_retries=0,
            harvest_ids=True,
            harvest_max_ids=50,
        ),
    )

    probes = run_scans_with_harvest(cfg)

    ids = [p.id for p in probes]
    assert seed in ids
    assert leaked in ids

    harvested = [p for p in probes if p.discovered_via]
    assert len(harvested) == 1
    assert harvested[0].id == leaked
    assert seed in harvested[0].discovered_via


def _multi_scan(placeholders: PlaceholderMap, endpoint: str) -> Scan:
    """Build a Scan with an explicit multi-placeholder map.

    Bypasses Scan.from_dict (which historically rejected multi-placeholder
    configs); we want to exercise the scanner layer directly.
    """
    return Scan(
        name="multi",
        endpoint=endpoint,
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=1),  # ignored once placeholders is set
        baseline_user="alice",
        test_users=(),
        include_unauth=False,
        placeholders=placeholders,
    )


@responses.activate
def test_cartesian_scanner_iteration():
    """Two-placeholder scan produces the full Cartesian product of URLs."""
    pm = PlaceholderMap(specs={
        "org_id": IdSpec(kind="list", values=("acme", "globex")),
        "id": IdSpec(kind="numeric", start=1, end=3),
    })
    expected_urls = {
        f"http://target.local/api/org/{org}/item/{i}"
        for org in ("acme", "globex")
        for i in (1, 2, 3)
    }
    for url in expected_urls:
        responses.add(responses.GET, url, json={}, status=200)

    scan = _multi_scan(pm, "/api/org/{org_id}/item/{id}")
    cfg = _minimal_config((scan,))

    probes = run_scans(cfg)

    assert len(probes) == 6
    assert {p.url for p in probes} == expected_urls
    assert all(p.status == 200 for p in probes)


@responses.activate
def test_cartesian_single_placeholder_unchanged():
    """1-placeholder scan still produces value-only Probe.id (backcompat)."""
    for i in (1, 2):
        responses.add(
            responses.GET, f"http://target.local/api/item/{i}", json={}, status=200
        )

    scan = Scan(
        name="items",
        endpoint="/api/item/{id}",
        methods=("GET",),
        ids=IdSpec(kind="numeric", start=1, end=2),
        baseline_user="alice",
        test_users=(),
        include_unauth=False,
    )
    cfg = _minimal_config((scan,))
    probes = run_scans(cfg)

    assert len(probes) == 2
    # Probe.id stays the bare value for single-placeholder scans — matters
    # for the v0.3 pin (test_backcompat) and CSV readability.
    assert {p.id for p in probes} == {"1", "2"}


@responses.activate
def test_cartesian_three_placeholders():
    """3-placeholder scan = product of all three dimensions."""
    pm = PlaceholderMap(specs={
        "tenant": IdSpec(kind="list", values=("t1", "t2")),
        "org_id": IdSpec(kind="list", values=("a", "b")),
        "id": IdSpec(kind="numeric", start=1, end=2),
    })
    expected_urls = {
        f"http://target.local/api/{t}/org/{o}/item/{i}"
        for t in ("t1", "t2")
        for o in ("a", "b")
        for i in (1, 2)
    }
    for url in expected_urls:
        responses.add(responses.GET, url, json={}, status=200)

    scan = _multi_scan(pm, "/api/{tenant}/org/{org_id}/item/{id}")
    cfg = _minimal_config((scan,))

    probes = run_scans(cfg)

    assert len(probes) == 8
    assert {p.url for p in probes} == expected_urls


@responses.activate
def test_probe_id_format_multi_placeholder():
    """Probe.id uses `k=v,k=v` format (declaration order) for multi-placeholder scans.

    Single-placeholder scans keep the bare-value format (see
    test_cartesian_single_placeholder_unchanged). The multi format has to be
    deterministic — skip/resume keys (scan, user, method, id) need to match
    across runs, and analyzer groups on id.
    """
    pm = PlaceholderMap(specs={
        "org_id": IdSpec(kind="list", values=("acme",)),
        "id": IdSpec(kind="numeric", start=7, end=7),
    })
    responses.add(
        responses.GET, "http://target.local/api/org/acme/item/7", json={}, status=200
    )
    scan = _multi_scan(pm, "/api/org/{org_id}/item/{id}")
    cfg = _minimal_config((scan,))

    probes = run_scans(cfg)

    assert len(probes) == 1
    assert probes[0].id == "org_id=acme,id=7"


@responses.activate
def test_probe_id_grouping_consistent_across_runs():
    """Re-running the same multi-placeholder scan produces byte-identical Probe.ids.

    Analyzer groups on (scan, id, method); resume keys are (scan, user, method, id).
    Both depend on Probe.id being deterministic across runs. This is paranoid —
    Python 3.7+ guarantees dict insertion order, and we build the PlaceholderMap
    from that — but the contract is load-bearing enough to pin.
    """
    pm = PlaceholderMap(specs={
        "org_id": IdSpec(kind="list", values=("acme", "globex")),
        "id": IdSpec(kind="numeric", start=1, end=2),
    })
    for org in ("acme", "globex"):
        for i in (1, 2):
            responses.add(
                responses.GET,
                f"http://target.local/api/org/{org}/item/{i}",
                json={}, status=200,
            )

    def _run_once():
        scan = _multi_scan(pm, "/api/org/{org_id}/item/{id}")
        cfg = _minimal_config((scan,))
        return sorted(p.id for p in run_scans(cfg))

    assert _run_once() == _run_once()
