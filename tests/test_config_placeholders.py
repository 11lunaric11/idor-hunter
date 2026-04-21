"""Tests for v0.4 named-placeholder config parsing.

The v0.3 `ids: {type: ..., range: ...}` shape produces a single-placeholder
`PlaceholderMap({"id": <spec>})`. The v0.4 `ids: {name: {type: ...}, ...}`
shape produces a multi-placeholder map. Scan validates that the set of
placeholder names in the endpoint template matches the set of declared
placeholders — catching silently-broken v0.3 configs that happened to work.
"""
from __future__ import annotations

import pytest

from idor_hunter.config import (
    ConfigError,
    IdSpec,
    PlaceholderMap,
    load_config,
)


def _write_cfg(tmp_path, yaml_str):
    p = tmp_path / "c.yaml"
    p.write_text(yaml_str)
    return p


_V03_YAML = """
target: {base_url: http://t.local}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: /api/x/{id}
    methods: [GET]
    ids:
      type: numeric
      range: [1, 3]
    baseline_user: a
options: {}
"""


_V04_YAML = """
target: {base_url: http://t.local}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: /api/org/{org_id}/item/{id}
    methods: [GET]
    ids:
      org_id:
        type: list
        values: ["acme", "globex"]
      id:
        type: numeric
        range: [1, 50]
    baseline_user: a
options: {}
"""


def test_v03_single_placeholder_still_parses(tmp_path):
    """Old shape: ids block has top-level `type`/`range` → PlaceholderMap({"id": spec})."""
    cfg = load_config(_write_cfg(tmp_path, _V03_YAML))
    scan = cfg.scans[0]
    assert set(scan.placeholders.specs.keys()) == {"id"}
    spec = scan.placeholders.specs["id"]
    assert spec.kind == "numeric"
    assert spec.start == 1
    assert spec.end == 3


def test_v04_multi_placeholder_parses():
    """New shape: each key under `ids` is a placeholder name → full map.

    Tests `PlaceholderMap.from_dict` directly rather than `load_config`
    because `Scan.from_dict` currently gates multi-placeholder configs
    with a ConfigError (see test_multi_placeholder_rejected_until_scanner_support
    and the transitional block in config.py). When scanner.py gains
    Cartesian iteration, this test can go back to using `load_config`.
    """
    pm = PlaceholderMap.from_dict({
        "org_id": {"type": "list", "values": ["acme", "globex"]},
        "id": {"type": "numeric", "range": [1, 50]},
    })
    assert set(pm.specs.keys()) == {"org_id", "id"}
    assert pm.specs["org_id"].kind == "list"
    assert pm.specs["org_id"].values == ("acme", "globex")
    assert pm.specs["id"].kind == "numeric"
    assert pm.specs["id"].end == 50


def test_multi_placeholder_rejected_until_scanner_support(tmp_path):
    """Transitional: multi-placeholder configs raise ConfigError in v0.4-dev.

    The config layer parses multi-placeholder specs fine (see
    test_v04_multi_placeholder_parses, which exercises PlaceholderMap
    directly), but scanner.py doesn't yet support Cartesian iteration.
    Until it does, Scan.from_dict rejects configs with >1 placeholder
    rather than silently producing wrong URLs — this preserves the
    v0.3 "silent failures are loud" thesis during the v0.4 build.

    Delete this test and the gate in config.py when the scanner lands.
    """
    yaml_str = """
target: {base_url: "http://t.local"}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: /api/org/{org_id}/item/{id}
    methods: [GET]
    ids:
      org_id:
        type: list
        values: ["acme"]
      id:
        type: numeric
        range: [1, 3]
    baseline_user: a
options: {}
"""
    with pytest.raises(ConfigError, match="multi-placeholder endpoints not yet"):
        load_config(_write_cfg(tmp_path, yaml_str))


def test_endpoint_missing_declared_placeholder_raises(tmp_path):
    """Config declares `org_id` but endpoint doesn't use it → ConfigError."""
    yaml_str = """
target: {base_url: http://t.local}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: /api/item/{id}
    methods: [GET]
    ids:
      org_id:
        type: list
        values: ["acme"]
      id:
        type: numeric
        range: [1, 3]
    baseline_user: a
options: {}
"""
    with pytest.raises(ConfigError, match="org_id"):
        load_config(_write_cfg(tmp_path, yaml_str))


def test_endpoint_has_undeclared_placeholder_raises(tmp_path):
    """Endpoint uses `{org_id}` but no ID spec declared → ConfigError."""
    yaml_str = """
target: {base_url: http://t.local}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: /api/org/{org_id}/item/{id}
    methods: [GET]
    ids:
      id:
        type: numeric
        range: [1, 3]
    baseline_user: a
options: {}
"""
    with pytest.raises(ConfigError, match="org_id"):
        load_config(_write_cfg(tmp_path, yaml_str))


def test_placeholder_cartesian_count():
    pm = PlaceholderMap(specs={
        "org_id": IdSpec(kind="list", values=("a", "b", "c")),
        "id": IdSpec(kind="numeric", start=1, end=5),
    })
    assert pm.count() == 15


def test_placeholder_cartesian_combinations():
    """iter_combinations yields every (org_id, id) pair as a name→value dict."""
    pm = PlaceholderMap(specs={
        "org_id": IdSpec(kind="list", values=("a", "b")),
        "id": IdSpec(kind="numeric", start=1, end=3),
    })
    combos = list(pm.iter_combinations())
    assert len(combos) == 6
    for c in combos:
        assert set(c.keys()) == {"org_id", "id"}
    # every combo distinct
    tuples = {tuple(sorted(c.items())) for c in combos}
    assert len(tuples) == 6
    # values are the product of the two IdSpec iterations
    org_ids = {c["org_id"] for c in combos}
    ids = {c["id"] for c in combos}
    assert org_ids == {"a", "b"}
    assert ids == {"1", "2", "3"}


def test_empty_ids_block_raises(tmp_path):
    """`ids: {}` → ConfigError, not a silently-empty scan."""
    yaml_str = """
target: {base_url: http://t.local}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: /api/item/{id}
    methods: [GET]
    ids: {}
    baseline_user: a
options: {}
"""
    with pytest.raises(ConfigError, match="empty"):
        load_config(_write_cfg(tmp_path, yaml_str))


def test_invalid_placeholder_name_in_endpoint_raises(tmp_path):
    """Endpoint `/api/{id with spaces}` → ConfigError, not silent mis-substitution."""
    yaml_str = """
target: {base_url: http://t.local}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: "/api/item/{id with spaces}"
    methods: [GET]
    ids:
      "id with spaces":
        type: numeric
        range: [1, 3]
    baseline_user: a
options: {}
"""
    with pytest.raises(ConfigError, match="placeholder"):
        load_config(_write_cfg(tmp_path, yaml_str))


def test_reserved_placeholder_names_rejected(tmp_path):
    """Placeholder literally named `type` trips v0.3 shape detection — helpful error."""
    yaml_str = """
target: {base_url: http://t.local}
auth: {users: [{name: a}]}
scans:
  - name: s
    endpoint: /api/item/{type}
    methods: [GET]
    ids:
      type:
        type: list
        values: ["A", "B"]
    baseline_user: a
options: {}
"""
    with pytest.raises(ConfigError, match="rename"):
        load_config(_write_cfg(tmp_path, yaml_str))
