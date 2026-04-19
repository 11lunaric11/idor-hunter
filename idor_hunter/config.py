"""Configuration loading and validation.

Scans are described in YAML. This module parses them into typed dataclasses
so the rest of the code doesn't juggle raw dicts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


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
class Scan:
    name: str
    endpoint: str  # must contain {id}
    methods: tuple[str, ...]
    ids: IdSpec
    baseline_user: str | None
    test_users: tuple[str, ...]
    body: dict[str, Any] | None = None
    include_unauth: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scan":
        for required in ("name", "endpoint", "ids"):
            if required not in data:
                raise ConfigError(f"scan missing required field: {required!r}")
        endpoint = data["endpoint"]
        if "{id}" not in endpoint:
            raise ConfigError(
                f"scan {data['name']!r}: endpoint must contain '{{id}}' placeholder"
            )
        methods = tuple(m.upper() for m in data.get("methods", ["GET"]))
        return cls(
            name=data["name"],
            endpoint=endpoint,
            methods=methods,
            ids=IdSpec.from_dict(data["ids"]),
            baseline_user=data.get("baseline_user"),
            test_users=tuple(data.get("test_users", [])),
            body=data.get("body"),
            include_unauth=bool(data.get("include_unauth", True)),
        )


@dataclass(frozen=True)
class Options:
    rate_limit: float = 10.0  # requests per second (0 disables)
    timeout: float = 10.0
    resume: bool = False
    verify_tls: bool = True
    max_retries: int = 2

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Options":
        data = data or {}
        return cls(
            rate_limit=float(data.get("rate_limit", 10.0)),
            timeout=float(data.get("timeout", 10.0)),
            resume=bool(data.get("resume", False)),
            verify_tls=bool(data.get("verify_tls", True)),
            max_retries=int(data.get("max_retries", 2)),
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
