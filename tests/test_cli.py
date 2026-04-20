"""Smoke tests for the CLI entry point.

These exercise the exit-code contract CI depends on: 2 for bad config,
0 for clean runs, 1 when critical/high findings are present.
"""
from __future__ import annotations

import json

import responses

from idor_hunter.cli import main


def _write_config(path, base_url="http://target.local"):
    path.write_text(
        f"""\
target:
  base_url: "{base_url}"
auth:
  users:
    - name: alice
      cookies: {{session: "alice"}}
    - name: bob
      cookies: {{session: "bob"}}
scans:
  - name: "x"
    endpoint: "/api/x/{{id}}"
    methods: [GET]
    ids:
      type: numeric
      range: [1, 1]
    baseline_user: alice
    test_users: [bob]
    include_unauth: false
options:
  rate_limit: 0
""",
        encoding="utf-8",
    )


def test_missing_config_exits_2(tmp_path, capsys):
    rc = main(["-c", str(tmp_path / "nope.yaml"), "-o", str(tmp_path / "out"), "--quiet"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "config" in err.lower()


@responses.activate
def test_clean_run_writes_artifacts_exit_0(tmp_path):
    # Two users get *different* responses — no IDOR
    responses.add(
        responses.GET, "http://target.local/api/x/1",
        json={"id": 1, "data": "A" * 200}, status=200,
    )
    responses.add(
        responses.GET, "http://target.local/api/x/1",
        json={"error": "forbidden"}, status=403,
    )

    cfg = tmp_path / "scan.yaml"
    _write_config(cfg)
    out = tmp_path / "out"

    rc = main(["-c", str(cfg), "-o", str(out), "--quiet"])

    assert rc == 0
    assert (out / "report.html").exists()
    assert (out / "findings.json").exists()
    assert (out / "probes.csv").exists()

    payload = json.loads((out / "findings.json").read_text())
    assert payload["findings"] == []


def test_zero_probe_scan_exits_2(tmp_path, capsys):
    """Empty probe set is a setup error, not a clean run.

    Common causes: bad endpoint/config, target unreachable, numeric range
    inverted. Previously exited 0 with empty reports — looked clean, was useless.
    """
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(
        """\
target:
  base_url: "http://target.local"
scans:
  - name: "empty"
    endpoint: "/api/x/{id}"
    methods: [GET]
    ids:
      type: numeric
      range: [5, 4]
    include_unauth: true
options:
  rate_limit: 0
""",
        encoding="utf-8",
    )
    out = tmp_path / "out"

    rc = main(["-c", str(cfg), "-o", str(out), "--quiet"])

    assert rc == 2
    err = capsys.readouterr().err
    assert "zero probes" in err.lower() or "no probes" in err.lower()


def count(self) -> int:
    if self.kind == "numeric":
        return max(0, self.end - self.start + 1)


@responses.activate
def test_critical_finding_exits_1(tmp_path):
    # Both users get identical substantive responses — IDOR fires
    body = {"id": 1, "data": "leaked-secret-" * 20}
    responses.add(responses.GET, "http://target.local/api/x/1", json=body, status=200)
    responses.add(responses.GET, "http://target.local/api/x/1", json=body, status=200)

    cfg = tmp_path / "scan.yaml"
    _write_config(cfg)
    out = tmp_path / "out"

    rc = main(["-c", str(cfg), "-o", str(out), "--quiet"])

    assert rc == 1
    payload = json.loads((out / "findings.json").read_text())
    assert any(f["severity"] in {"critical", "high"} for f in payload["findings"])


def test_all_errored_probes_exits_2(tmp_path, capsys):
    """Unreachable target → exit 2 with actionable stderr, not silent 0.

    Distinct from zero-probe: probes were attempted and all failed with
    network errors. Silent-failure mode v0.3 closes.
    """
    cfg = tmp_path / "dead.yaml"
    cfg.write_text(
        """\
target:
  base_url: "http://127.0.0.1:1"
scans:
  - name: "dead"
    endpoint: "/api/x/{id}"
    methods: [GET]
    ids:
      type: numeric
      range: [1, 3]
    include_unauth: true
options:
  timeout: 1
  max_retries: 0
  rate_limit: 0
""",
        encoding="utf-8",
    )
    out = tmp_path / "out"

    rc = main(["-c", str(cfg), "-o", str(out), "--quiet"])

    assert rc == 2
    err = capsys.readouterr().err
    assert "network" in err.lower() or "unreachable" in err.lower()
