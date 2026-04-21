"""Backward-compatibility pin tests.

These exist to guard v0.3-era configs against v0.4+ refactors. When the
config schema grows (named placeholders, multi-placeholder endpoints,
etc.) the bare `{id}` shape must keep producing the exact same URLs it
did in v0.3 — otherwise every existing user's YAML is broken silently.

If one of these fails during v0.4 work, STOP and fix the compat layer
before proceeding.
"""
from __future__ import annotations

import pytest
import responses

from idor_hunter.config import ConfigError, load_config


V03_CONFIG_YAML = """
target:
  base_url: http://target.local

auth:
  users:
    - name: alice
      cookies: {session: alice}
    - name: bob
      cookies: {session: bob}

scans:
  - name: items
    endpoint: /api/item/{id}
    methods: [GET]
    ids:
      type: numeric
      range: [1, 3]
    baseline_user: alice
    test_users: [bob]
    include_unauth: true

options:
  rate_limit: 0
  max_retries: 0
"""


@responses.activate
def test_v03_single_placeholder_config_produces_same_urls(tmp_path):
    """A v0.3 YAML with bare `{id}` must produce identical probe URLs under v0.4+.

    The contract pinned here: (a) one probe per (id, identity, method)
    combination, (b) path substitution replaces `{id}` with the stringified
    numeric id, (c) identities are unauth + baseline + test_users in that
    order, deduplicated.
    """
    from idor_hunter.scanner import run_scans

    cfg_path = tmp_path / "v03.yaml"
    cfg_path.write_text(V03_CONFIG_YAML)
    cfg = load_config(cfg_path)

    for i in range(1, 4):
        url = f"http://target.local/api/item/{i}"
        # 3 registrations per id: unauth + alice + bob
        for _ in range(3):
            responses.add(responses.GET, url, json={"id": i}, status=200)

    probes = run_scans(cfg)

    # 3 ids × 3 identities (unauth, alice, bob) × 1 method
    assert len(probes) == 9

    urls = sorted({p.url for p in probes})
    assert urls == [
        "http://target.local/api/item/1",
        "http://target.local/api/item/2",
        "http://target.local/api/item/3",
    ]

    # identity labels exactly the v0.3 set
    assert {p.user for p in probes} == {"__unauth__", "alice", "bob"}

    # every probe carries the single id that substituted into {id}
    for p in probes:
        assert p.id in {"1", "2", "3"}
        assert f"/api/item/{p.id}" in p.url


V03_SILENTLY_BROKEN_CONFIG_YAML = """
target:
  base_url: http://target.local

auth:
  users:
    - name: alice
      cookies: {session: alice}

scans:
  - name: items
    endpoint: /api/item/{id}/sub/{extra}
    methods: [GET]
    ids:
      type: numeric
      range: [1, 3]
    baseline_user: alice

options:
  rate_limit: 0
"""


def test_v03_extra_placeholder_now_errors(tmp_path):
    """A v0.3 config with an unsubstituted extra placeholder fails loudly.

    Under v0.3, Scan.from_dict only checked that `{id}` was present in the
    endpoint — any other `{...}` placeholder was left as literal text in
    the URL, producing malformed requests that no one noticed. v0.4 requires
    the endpoint's placeholder set to match the declared ID spec keys, so
    `{extra}` without a matching spec fails at load time.

    Framing for users: no *valid* v0.3 config breaks; only silently-broken
    ones now fail loudly. This test pins that framing — the config below
    parsed under v0.3 but produced nonsense URLs.
    """
    cfg_path = tmp_path / "broken.yaml"
    cfg_path.write_text(V03_SILENTLY_BROKEN_CONFIG_YAML)
    with pytest.raises(ConfigError, match="extra"):
        load_config(cfg_path)
