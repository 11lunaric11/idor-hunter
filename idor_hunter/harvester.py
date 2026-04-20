"""UUID harvesting: pull IDs out of probe response bodies for a second pass.

Numeric harvesting is intentionally not shipped — regex-based numeric
extraction against arbitrary JSON bodies has a terrible false-positive
rate (amounts, timestamps, status codes, zip codes all look like IDs).
UUIDs have a tight enough shape that the regex is high-precision.
"""
from __future__ import annotations

import re

from .scanner import Probe

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def harvest_uuids(
    probes: list[Probe],
    originals: set[str],
    cap: int,
) -> list[tuple[str, str]]:
    """Return up to `cap` (uuid, source_url) pairs.

    UUIDs are lowercased and deduplicated. Anything in `originals` is
    skipped (already tested). Order is first-seen across the probe list.
    """
    if cap <= 0:
        return []
    originals_lower = {o.lower() for o in originals}
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for p in probes:
        if not p.body_preview:
            continue
        for match in UUID_RE.findall(p.body_preview):
            uuid_lc = match.lower()
            if uuid_lc in originals_lower or uuid_lc in seen:
                continue
            seen.add(uuid_lc)
            out.append((uuid_lc, p.url))
            if len(out) >= cap:
                return out
    return out
