"""Configuration loading and validation.

Scans are described in YAML. This module parses them into typed dataclasses
so the rest of the code doesn't juggle raw dicts.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Placeholder name grammar: Python-identifier-ish. Keeps us out of the
# quoting/encoding mess that comes with arbitrary path segments.
_VALID_PLACEHOLDER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER_RE = re.compile(r"\{([^}]*)\}")

# Keys that, at the top level of the `ids` block, signal the v0.3 single-
# placeholder shape (e.g. `ids: {type: numeric, range: [1, 10]}`). In the
# v0.4 named-placeholder shape, keys are placeholder names instead. If
# someone tries to use one of these as a placeholder name, detection
# misfires and we raise a rename hint.
_OLD_SHAPE_KEYS = frozenset({"type", "range", "values"})


class ConfigError(ValueError):
    """Raised when a config file is missing required fields or malformed."""


@dataclass(frozen=True)
class User:
    name: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "User":
        if "name" not in data:
            raise ConfigError("user entry missing 'name'")
        return cls(
            name=data["name"],
            cookies=data.get("cookies", {}) or {},
            headers=data.get("headers", {}) or {},
        )


@dataclass(frozen=True)
class IdSpec:
    """How to generate the IDs we'll iterate over."""

    kind: str  # "numeric" | "list"
    start: int = 1
    end: int = 100
    values: tuple[str, ...] = ()

    def iter_ids(self):
        if self.kind == "numeric":
            return (str(i) for i in range(self.start, self.end + 1))
        if self.kind == "list":
            return iter(self.values)
        raise ConfigError(f"unknown id kind: {self.kind}")

    def count(self) -> int:
        if self.kind == "numeric":
            return max(0, self.end - self.start + 1)
        return len(self.values)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IdSpec":
        kind = data.get("type", "numeric")
        if kind == "numeric":
            rng = data.get("range", [1, 100])
            if not (isinstance(rng, list) and len(rng) == 2):
                raise ConfigError("numeric ids need 'range: [start, end]'")
            return cls(kind="numeric", start=int(rng[0]), end=int(rng[1]))
        if kind == "list":
            values = data.get("values", [])
            if not values:
                raise ConfigError("list ids need non-empty 'values'")
            return cls(kind="list", values=tuple(str(v) for v in values))
        raise ConfigError(f"unknown id type: {kind!r}")


@dataclass(frozen=True)
class PlaceholderMap:
    """Maps placeholder names (e.g. 'org_id', 'id') to their IdSpec.

    A v0.3 single-placeholder config maps to PlaceholderMap({"id": <spec>}).
    v0.4 multi-placeholder configs populate arbitrary names. Scan uses this
    to Cartesian-iterate over every combination of placeholder values.
    """

    specs: dict[str, IdSpec]

    def iter_combinations(self):
        """Yield every {name: value} dict over the Cartesian product of specs."""
        names = list(self.specs.keys())
        iterables = [list(spec.iter_ids()) for spec in self.specs.values()]
        for combo in itertools.product(*iterables):
            yield dict(zip(names, combo))

    def count(self) -> int:
        total = 1
        for spec in self.specs.values():
            total *= spec.count()
        return total

    @classmethod
    def from_dict(cls, data: Any) -> "PlaceholderMap":
        if not isinstance(data, dict):
            raise ConfigError(
                f"'ids' block must be a mapping, got {type(data).__name__}"
            )
        if not data:
            raise ConfigError("'ids' block is empty")
        # v0.3 single-placeholder shape: `type`/`range`/`values` at top level.
        if any(k in data for k in _OLD_SHAPE_KEYS):
            # Disambiguate: if a user tried to name a v0.4 placeholder `type`
            # (or range/values), detection misfires — the inner value would
            # be a dict with its own `type` key. Give them an actionable hint.
            for k in _OLD_SHAPE_KEYS:
                if k in data and isinstance(data[k], dict) and "type" in data[k]:
                    raise ConfigError(
                        f"placeholder name {k!r} collides with v0.3 schema keyword; "
                        f"rename it (e.g. {k}_val) — 'type', 'range', and 'values' "
                        f"are reserved at the top level of the ids block"
                    )
            return cls(specs={"id": IdSpec.from_dict(data)})
        # v0.4 named-placeholder shape: each key is a placeholder name.
        specs: dict[str, IdSpec] = {}
        for name, spec_data in data.items():
            if not _VALID_PLACEHOLDER_NAME.match(str(name)):
                raise ConfigError(
                    f"invalid placeholder name {name!r}: must match "
                    f"[A-Za-z_][A-Za-z0-9_]*"
                )
            if not isinstance(spec_data, dict):
                raise ConfigError(
                    f"placeholder {name!r}: expected a mapping, "
                    f"got {type(spec_data).__name__}"
                )
            specs[name] = IdSpec.from_dict(spec_data)
        return cls(specs=specs)


@dataclass(frozen=True)
class Scan:
    name: str
    endpoint: str  # must contain at least one `{name}` placeholder
    methods: tuple[str, ...]
    ids: IdSpec  # legacy single-placeholder view; scanner.py reads this
    baseline_user: str | None
    test_users: tuple[str, ...]
    body: dict[str, Any] | None = None
    include_unauth: bool = True
    # Full placeholder map (v0.4+). Defaults to None so direct construction
    # (e.g. in tests, scanner._replace_ids) keeps working; __post_init__
    # synthesizes a single-placeholder map from `ids` when not provided.
    placeholders: "PlaceholderMap | None" = None

    def __post_init__(self):
        if self.placeholders is None:
            # frozen=True → use object.__setattr__ to populate.
            object.__setattr__(
                self, "placeholders", PlaceholderMap(specs={"id": self.ids})
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scan":
        for required in ("name", "endpoint", "ids"):
            if required not in data:
                raise ConfigError(f"scan missing required field: {required!r}")
        endpoint = data["endpoint"]
        placeholders = PlaceholderMap.from_dict(data["ids"])

        # Validate endpoint placeholders exactly match declared ID specs.
        # v0.3 only checked that `{id}` appeared as a substring, so endpoints
        # like `/api/x/{id}/sub/{extra}` silently shipped `{extra}` unsubstituted.
        raw = _PLACEHOLDER_RE.findall(endpoint)
        for name in raw:
            if not _VALID_PLACEHOLDER_NAME.match(name):
                raise ConfigError(
                    f"scan {data['name']!r}: endpoint placeholder {{{name}}} "
                    f"is not a valid name (must match [A-Za-z_][A-Za-z0-9_]*)"
                )
        endpoint_names = set(raw)
        spec_names = set(placeholders.specs.keys())
        if endpoint_names != spec_names:
            missing = spec_names - endpoint_names
            extra = endpoint_names - spec_names
            errs: list[str] = []
            if extra:
                errs.append(
                    f"endpoint uses {sorted(extra)} but no ID spec declared"
                )
            if missing:
                errs.append(
                    f"ID spec for {sorted(missing)} declared but endpoint "
                    f"doesn't use it"
                )
            raise ConfigError(f"scan {data['name']!r}: {'; '.join(errs)}")

        # Legacy `ids` field. Scanner.py uses `scan.placeholders` directly,
        # but the harvester still needs a single spec to build shadow scans
        # (and skips multi-placeholder scans anyway). For multi-placeholder
        # configs we stash the first spec as a placeholder-of-last-resort;
        # harvester guards on `len(specs) == 1` before reading it.
        legacy_ids = next(iter(placeholders.specs.values()))

        methods = tuple(m.upper() for m in data.get("methods", ["GET"]))
        return cls(
            name=data["name"],
            endpoint=endpoint,
            methods=methods,
            ids=legacy_ids,
            baseline_user=data.get("baseline_user"),
            test_users=tuple(data.get("test_users", [])),
            body=data.get("body"),
            include_unauth=bool(data.get("include_unauth", True)),
            placeholders=placeholders,
        )


@dataclass(frozen=True)
class Options:
    rate_limit: float = 10.0  # requests per second (0 disables)
    timeout: float = 10.0
    resume: bool = False
    verify_tls: bool = True
    max_retries: int = 2
    harvest_ids: bool = False  # opt-in: second pass over UUIDs found in responses
    harvest_max_ids: int = 50  # per-scan cap on harvested UUIDs

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Options":
        data = data or {}
        harvest_max_ids = int(data.get("harvest_max_ids", 50))
        if harvest_max_ids < 0:
            raise ConfigError("options.harvest_max_ids must be >= 0")
        return cls(
            rate_limit=float(data.get("rate_limit", 10.0)),
            timeout=float(data.get("timeout", 10.0)),
            resume=bool(data.get("resume", False)),
            verify_tls=bool(data.get("verify_tls", True)),
            max_retries=int(data.get("max_retries", 2)),
            harvest_ids=bool(data.get("harvest_ids", False)),
            harvest_max_ids=harvest_max_ids,
        )


@dataclass(frozen=True)
class Config:
    base_url: str
    users: dict[str, User]
    scans: tuple[Scan, ...]
    options: Options

    def user(self, name: str) -> User:
        if name not in self.users:
            raise ConfigError(f"unknown user: {name!r}")
        return self.users[name]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        target = data.get("target") or {}
        base_url = target.get("base_url")
        if not base_url:
            raise ConfigError("target.base_url is required")

        auth = data.get("auth") or {}
        users_list = auth.get("users") or []
        users = {}
        for u in users_list:
            user = User.from_dict(u)
            users[user.name] = user

        scans_data = data.get("scans") or []
        if not scans_data:
            raise ConfigError("at least one scan is required")
        scans = tuple(Scan.from_dict(s) for s in scans_data)

        # cross-validate user references
        for scan in scans:
            if scan.baseline_user and scan.baseline_user not in users:
                raise ConfigError(
                    f"scan {scan.name!r} references unknown baseline_user "
                    f"{scan.baseline_user!r}"
                )
            for tu in scan.test_users:
                if tu not in users:
                    raise ConfigError(
                        f"scan {scan.name!r} references unknown test_user {tu!r}"
                    )

        return cls(
            base_url=base_url.rstrip("/"),
            users=users,
            scans=scans,
            options=Options.from_dict(data.get("options")),
        )


def load_config(path: str | Path) -> Config:
    """Load and validate a YAML config file."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ConfigError("config file must contain a YAML mapping at the top level")
    return Config.from_dict(data)
