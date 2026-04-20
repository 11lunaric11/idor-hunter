"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze, summary_stats
from .config import ConfigError, load_config
from .reporter import write_findings_json, write_html_report, write_probes_csv
from .scanner import run_scans, run_scans_with_harvest


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
    harvest = p.add_mutually_exclusive_group()
    harvest.add_argument(
        "--harvest",
        dest="harvest",
        action="store_true",
        default=None,
        help="enable UUID harvesting from response bodies (overrides config)",
    )
    harvest.add_argument(
        "--no-harvest",
        dest="harvest",
        action="store_false",
        default=None,
        help="disable UUID harvesting (overrides config)",
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
    harvest_enabled = (
        args.harvest if args.harvest is not None else config.options.harvest_ids
    )
    runner = run_scans_with_harvest if harvest_enabled else run_scans
    probes = runner(
        config,
        progress_cb=None if args.quiet else _progress,
        resume_path=resume_path,
    )


    # Fail-loud on silent-failure scans. Exit 2 distinguishes "setup broken"
    # from "scan ran but found nothing" (0) and "scan found issues" (1).
    if not probes:
        print(
            "error: scan produced zero probes. Check scan config (endpoint, "
            "ID range).",
            file=sys.stderr,
        )
        return 2

    errored = sum(1 for p in probes if p.error)
    if errored == len(probes):
        example = next(p for p in probes if p.error)
        print(
            f"error: all {len(probes)} probes failed with network errors. "
            f"Target unreachable? Check base_url, VPN, firewall.",
            file=sys.stderr,
        )
        # Truncate the requests exception so the error message is readable
        err_msg = (example.error or "").split("\n")[0][:200]
        print(f"  first error: {err_msg}", file=sys.stderr)
        return 2

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
            probes=probes,
        )

    if not args.quiet:
        print(file=sys.stderr)
        print(f"  probes:    {stats['total_probes']}", file=sys.stderr)
        harvested_count = sum(1 for p in probes if p.discovered_via)
        if harvested_count:
            print(f"  harvested: {harvested_count}", file=sys.stderr)
        print(f"  findings:  {stats['total_findings']}", file=sys.stderr)
        for sev in ("critical", "high", "medium", "low", "info"):
            count = stats["by_severity"].get(sev, 0)
            if count:
                print(f"    {sev:<8} {count}", file=sys.stderr)
        print(file=sys.stderr)
        print(f"  wrote to: {out_dir}/", file=sys.stderr)
        if not args.no_html:
            print("    → report.html", file=sys.stderr)
        print("    → findings.json", file=sys.stderr)
        if not args.no_csv:
            print("    → probes.csv", file=sys.stderr)

    # Exit code: 0 clean, 1 if any high+ findings (useful for CI)
    if any(f.severity in {"critical", "high"} for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
