"""Tests for config loading and validation."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from idor_hunter.config import Config, ConfigError, IdSpec, load_config


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
    return p


VALID_CONFIG = """
target:
  base_url: "http://target.local"

auth:
  users:
    - name: alice
      cookies:
        session: "alice-cookie"
    - name: bob
      cookies:
        session: "bob-cookie"

scans:
  - name: "invoice enumeration"
    endpoint: "/api/invoice/{id}"
    methods: [GET, PUT]
    ids:
      type: numeric
      range: [1, 10]
    baseline_user: alice
    test_users: [bob]

options:
  rate_limit: 20
  timeout: 5
"""


def test_load_valid_config(tmp_path: Path):
    path = _write(tmp_path, "c.yaml", VALID_CONFIG)
    cfg = load_config(path)

    assert isinstance(cfg, Config)
    assert cfg.base_url == "http://target.local"
    assert set(cfg.users.keys()) == {"alice", "bob"}
    assert cfg.users["alice"].cookies["session"] == "alice-cookie"
    assert len(cfg.scans) == 1
    assert cfg.scans[0].methods == ("GET", "PUT")
    assert cfg.scans[0].baseline_user == "alice"
    assert cfg.options.rate_limit == 20.0


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


def test_missing_base_url_raises(tmp_path: Path):
    path = _write(tmp_path, "c.yaml", """
        target: {}
        scans:
          - name: x
            endpoint: "/x/{id}"
            ids: {type: numeric, range: [1, 2]}
    """)
    with pytest.raises(ConfigError, match="base_url"):
        load_config(path)


def test_endpoint_missing_id_placeholder(tmp_path: Path):
    path = _write(tmp_path, "c.yaml", """
        target: {base_url: "http://t"}
        scans:
          - name: bad
            endpoint: "/api/users"
            ids: {type: numeric, range: [1, 2]}
    """)
    with pytest.raises(ConfigError, match=r"\{id\}"):
        load_config(path)


def test_unknown_user_reference(tmp_path: Path):
    path = _write(tmp_path, "c.yaml", """
        target: {base_url: "http://t"}
        auth:
          users:
            - name: alice
        scans:
          - name: s
            endpoint: "/api/{id}"
            ids: {type: numeric, range: [1, 2]}
            baseline_user: carol
    """)
    with pytest.raises(ConfigError, match="carol"):
        load_config(path)


def test_id_spec_numeric_iter():
    spec = IdSpec(kind="numeric", start=3, end=5)
    assert list(spec.iter_ids()) == ["3", "4", "5"]
    assert spec.count() == 3


def test_id_spec_list_iter():
    spec = IdSpec(kind="list", values=("uuid-a", "uuid-b"))
    assert list(spec.iter_ids()) == ["uuid-a", "uuid-b"]
    assert spec.count() == 2


def test_id_spec_list_requires_values(tmp_path: Path):
    path = _write(tmp_path, "c.yaml", """
        target: {base_url: "http://t"}
        scans:
          - name: s
            endpoint: "/api/{id}"
            ids: {type: list, values: []}
    """)
    with pytest.raises(ConfigError, match="non-empty"):
        load_config(path)


def test_empty_scans_list(tmp_path: Path):
    path = _write(tmp_path, "c.yaml", """
        target: {base_url: "http://t"}
        scans: []
    """)
    with pytest.raises(ConfigError, match="at least one scan"):
        load_config(path)
