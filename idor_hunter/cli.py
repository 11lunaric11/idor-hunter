"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze, summary_stats
from .config import ConfigError, load_config
from .reporter import write_findings_json, write_html_report, write_probes_csv
from .scanner import run_scans


BANNER = r"""
  _       __                __               __
 (_)___/ /___  _____      / /_  __  ______  / /____  _____
/ / __  / __ \/ ___/_____/ __ \/ / / / __ \/ __/ _ \/ ___/
/ / /_/ / /_/ / /  /_____/ / / / /_/ / / / / /_/  __/ /
___/\__,_/\____/_/       /_/ /_/\__,_/_/ /_/\__/\___/_/
        automated IDOR enumeration — authorized testing only
""".strip("\n")


def _progress(done: int, total: int) -> None:
    pct = (done / total * 100) if total else 0
    bar_width = 30
    filled = int(bar_width * done / total) if total else 0
    bar = "█" * filled + "░" * (bar_width - filled)
    sys.stderr.write(f"\r  scanning [{bar}] {done}/{total} ({pct:5.1f}%)")
    sys.stderr.flush()
    if done == total:
        sys.stderr.write("\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="idor-hunter",
        description=(
            "Automate IDOR enumeration: iterate IDs, diff responses "
            "across users, flag permission anomalies. "
            "ONLY use on targets you have explicit written authorization to test."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "-c", "--config", required=True, help="path to YAML scan config"
    )
    p.add_argument(
        "-o", "--out-dir",
        default="./idor-results",
        help="directory for output files (default: ./idor-results)",
    )
    p.add_argument(
        "--no-html", action="store_true", help="skip HTML report generation"
    )
    p.add_argument(
        "--no-csv", action="store_true", help="skip CSV probe dump"
    )
    p.add_argument(
        "--quiet", action="store_true", help="suppress banner and progress"
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.quiet:
        print(BANNER, file=sys.stderr)
        print(file=sys.stderr)

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.quiet:
        print(f"  target:  {config.base_url}", file=sys.stderr)
        print(f"  users:   {len(config.users)}", file=sys.stderr)
        print(f"  scans:   {len(config.scans)}", file=sys.stderr)
        total_probes = sum(
            s.ids.count() * len(s.methods) * (
                (1 if s.include_unauth else 0)
                + (1 if s.baseline_user else 0)
                + len(s.test_users)
            )
            for s in config.scans
        )
        print(f"  probes:  ~{total_probes}", file=sys.stderr)
        print(file=sys.stderr)

    resume_path = out_dir / "probes.jsonl" if config.options.resume else None
    probes = run_scans(
        config,
        progress_cb=None if args.quiet else _progress,
        resume_path=resume_path,
    )

    findings = analyze(probes)
    stats = summary_stats(probes, findings)

    # Always write findings JSON — it's the primary structured output
    write_findings_json(findings, out_dir / "findings.json")

    if not args.no_csv:
        write_probes_csv(probes, out_dir / "probes.csv")

    if not args.no_html:
        write_html_report(
            findings=findings,
            stats=stats,
            probes_count=len(probes),
            path=out_dir / "report.html",
            config_name=Path(args.config).name,
        )

    if not args.quiet:
        print(file=sys.stderr)
        print(f"  probes:    {stats['total_probes']}", file=sys.stderr)
        print(f"  findings:  {stats['total_findings']}", file=sys.stderr)
        for sev in ("critical", "high", "medium", "low", "info"):
            count = stats["by_severity"].get(sev, 0)
            if count:
                print(f"    {sev:<8} {count}", file=sys.stderr)
        print(file=sys.stderr)
        print(f"  wrote to: {out_dir}/", file=sys.stderr)
        if not args.no_html:
            print(f"    → report.html", file=sys.stderr)
        print(f"    → findings.json", file=sys.stderr)
        if not args.no_csv:
            print(f"    → probes.csv", file=sys.stderr)

    # Exit code: 0 clean, 1 if any high+ findings (useful for CI)
    if any(f.severity in {"critical", "high"} for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
