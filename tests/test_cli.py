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
