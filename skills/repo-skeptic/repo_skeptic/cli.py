from __future__ import annotations

import argparse
import json
import sys

from .heuristics import AuditSummary
from .service import RepoSkepticService, SnapshotScanSummary, StarAnalysisSummary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-skeptic",
        description="Verify GitHub repositories before trusting them.",
    )

    subparsers = parser.add_subparsers(dest="command")

    audit_parser = subparsers.add_parser("audit", help="Run the full repo verification audit")
    audit_parser.add_argument("target", help="GitHub repo in owner/repo form or full GitHub URL")
    audit_parser.add_argument("--stars", type=int, default=200, help="How many recent stars to sample (default: 200)")
    audit_parser.add_argument("--json", action="store_true", help="Print JSON instead of a human summary")

    stars_parser = subparsers.add_parser("star-analysis", help="Inspect recent star clustering and thin-profile signals")
    stars_parser.add_argument("target", help="GitHub repo in owner/repo form or full GitHub URL")
    stars_parser.add_argument("--stars", type=int, default=200, help="How many recent stars to sample (default: 200)")
    stars_parser.add_argument("--json", action="store_true", help="Print JSON instead of a human summary")

    snapshot_parser = subparsers.add_parser("snapshot-scan", help="Download and scan the repo snapshot for install-time risks")
    snapshot_parser.add_argument("target", help="GitHub repo in owner/repo form or full GitHub URL")
    snapshot_parser.add_argument("--json", action="store_true", help="Print JSON instead of a human summary")

    return parser


def render_text(summary: AuditSummary) -> str:
    repo_meta = summary.metadata["repo"]
    owner_meta = summary.metadata["owner"]
    maintenance_meta = summary.metadata.get("maintenance", {})
    days_since_last_commit = maintenance_meta.get("days_since_last_commit")
    recent_authors = maintenance_meta.get("unique_recent_authors")
    maintenance_line = "Maintenance: unavailable"
    if days_since_last_commit is not None and recent_authors is not None:
        maintenance_line = (
            f"Maintenance: last commit {days_since_last_commit} days ago | "
            f"{recent_authors} unique recent authors"
        )
    lines = [
        f"Target:   {summary.target}",
        f"Verdict:  {summary.verdict}",
        f"Score:    {summary.score}/100",
        f"Repo:     {repo_meta['stars']} stars | {repo_meta['forks']} forks | {repo_meta['contributors']} contributors | {repo_meta['open_issues']} open issues | {repo_meta['open_prs']} open PRs",
        f"Owner:    {owner_meta['login']} ({owner_meta['type']}) | {owner_meta['public_repos']} public repos | {owner_meta['followers']} followers",
        maintenance_line,
        "",
        "Findings:",
    ]
    if not summary.findings:
        lines.append("  - No high-signal heuristics fired. Manual review is still required before running code.")
    else:
        for finding in summary.findings:
            lines.append(f"  - [{finding.severity}] {finding.title}: {finding.detail}")
            for evidence in finding.evidence[:3]:
                lines.append(f"      {evidence}")
    lines.extend([
        "",
        "Next step:",
        "  Read the install hooks and suspicious files before you clone or install anything.",
    ])
    return "\n".join(lines)


def render_star_analysis_text(summary: StarAnalysisSummary) -> str:
    repo_meta = summary.repo
    owner_meta = summary.owner
    stars_meta = summary.stars
    lines = [
        f"Target:   {summary.target}",
        f"Repo:     {repo_meta['stars']} stars | {repo_meta['forks']} forks",
        f"Owner:    {owner_meta['login']} ({owner_meta['type']}) | {owner_meta['public_repos']} public repos | {owner_meta['followers']} followers",
        "",
        "Star Analysis:",
        f"  - Sampled recent stars: {stars_meta['sampled_recent_stars']}",
        f"  - Largest day share:    {stars_meta['largest_day_share']:.0%}",
        f"  - Largest hour share:   {stars_meta['largest_hour_share']:.0%}",
    ]
    thin_ratio = stars_meta.get("thin_recent_stargazer_ratio")
    if thin_ratio is None:
        lines.append("  - Thin-profile ratio:    unavailable")
    else:
        lines.append(f"  - Thin-profile ratio:    {thin_ratio:.0%}")
    return "\n".join(lines)


def render_snapshot_scan_text(summary: SnapshotScanSummary) -> str:
    scan = summary.scan
    lines = [
        f"Target:   {summary.target}",
        "",
        "Snapshot Scan:",
        f"  - Install scripts:      {len(scan['install_scripts'])}",
        f"  - Suspicious commands:  {len(scan['suspicious_commands'])}",
        f"  - Suspicious files:     {len(scan['suspicious_files'])}",
    ]
    if scan["install_scripts"]:
        lines.append("  - First install hook:   " + scan["install_scripts"][0])
    if scan["suspicious_commands"]:
        lines.append("  - First command hit:    " + scan["suspicious_commands"][0])
    if scan["suspicious_files"]:
        lines.append("  - First file hit:       " + scan["suspicious_files"][0])
    if summary.registries:
        lines.append("")
        lines.append("Registry Presence:")
        for ecosystem, present in sorted(summary.registries.items()):
            lines.append(f"  - {ecosystem}: {'present' if present else 'missing'}")
    return "\n".join(lines)


def normalize_argv(argv: list[str] | None) -> list[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return args
    known_commands = {"audit", "star-analysis", "snapshot-scan"}
    if args[0] in known_commands:
        return args
    if args[0].startswith("-"):
        return args
    return ["audit", *args]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalize_argv(argv))
    if getattr(args, "command", None) is None and not hasattr(args, "target"):
        parser.print_help()
        return 2
    service = RepoSkepticService()
    try:
        if args.command == "star-analysis":
            summary = service.star_analysis(args.target, stars=args.stars)
            if args.json:
                print(json.dumps(summary.as_dict(), indent=2))
            else:
                print(render_star_analysis_text(summary))
            return 0
        if args.command == "snapshot-scan":
            summary = service.snapshot_scan(args.target)
            if args.json:
                print(json.dumps(summary.as_dict(), indent=2))
            else:
                print(render_snapshot_scan_text(summary))
            return 0
        summary = service.audit(args.target, stars=args.stars)
    except Exception as exc:
        parser.exit(status=1, message=f"repo-skeptic failed: {exc}\n")

    if args.json:
        print(json.dumps(summary.as_dict(), indent=2))
    else:
        print(render_text(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
