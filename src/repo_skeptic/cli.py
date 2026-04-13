from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .github_api import GitHubClient, registry_presence
from .heuristics import (
    AuditSummary,
    age_in_days,
    analyze_star_burst,
    build_findings,
    inspect_snapshot,
    normalize_repo_target,
    parse_iso_datetime,
    score_findings,
    summarize_release_assets,
)


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


def profile_thinness_ratio(stargazers: list[dict[str, Any]], *, sample_size: int = 25) -> float | None:
    sampled = [entry.get("user", {}) for entry in stargazers[:sample_size] if entry.get("user", {}).get("login")]
    if not sampled:
        return None
    thin_profiles = 0
    for profile in sampled:
        if int(profile.get("public_repos", 0)) == 0 and int(profile.get("followers", 0)) == 0:
            thin_profiles += 1
    return thin_profiles / len(sampled)


def fetch_star_context(target: str, *, stars: int = 200) -> dict[str, Any]:
    owner, repo = normalize_repo_target(target)
    client = GitHubClient()
    repo_payload = client.repo(owner, repo)
    owner_payload = client.owner(owner)
    stargazers = client.stargazers(owner, repo, int(repo_payload.get("stargazers_count", 0)), limit=stars)
    star_burst = analyze_star_burst([entry.get("starred_at") for entry in stargazers])
    thin_stargazer_ratio = profile_thinness_ratio(list(reversed(stargazers)))
    return {
        "owner": owner,
        "repo": repo,
        "client": client,
        "repo_payload": repo_payload,
        "owner_payload": owner_payload,
        "stargazers": stargazers,
        "star_burst": star_burst,
        "thin_stargazer_ratio": thin_stargazer_ratio,
    }


def perform_star_analysis(target: str, *, stars: int = 200) -> dict[str, Any]:
    context = fetch_star_context(target, stars=stars)
    repo_payload = context["repo_payload"]
    owner_payload = context["owner_payload"]
    return {
        "target": f"{context['owner']}/{context['repo']}",
        "repo": {
            "html_url": repo_payload.get("html_url"),
            "description": repo_payload.get("description"),
            "created_at": repo_payload.get("created_at"),
            "stars": int(repo_payload.get("stargazers_count", 0)),
            "forks": int(repo_payload.get("forks_count", 0)),
        },
        "owner": {
            "login": owner_payload.get("login"),
            "type": owner_payload.get("type"),
            "created_at": owner_payload.get("created_at"),
            "public_repos": int(owner_payload.get("public_repos", 0)),
            "followers": int(owner_payload.get("followers", 0)),
        },
        "stars": {
            "sampled_recent_stars": len(context["stargazers"]),
            "largest_day_share": context["star_burst"].get("largest_day_share", 0.0),
            "largest_hour_share": context["star_burst"].get("largest_hour_share", 0.0),
            "thin_recent_stargazer_ratio": context["thin_stargazer_ratio"],
        },
    }


def perform_snapshot_scan(target: str) -> dict[str, Any]:
    owner, repo = normalize_repo_target(target)
    client = GitHubClient()
    snapshot_handle, snapshot_dir = client.download_snapshot(owner, repo)
    try:
        scan_result = inspect_snapshot(snapshot_dir)
    finally:
        snapshot_handle.cleanup()
    registry_checks = registry_presence(scan_result.package_names)
    return {
        "target": f"{owner}/{repo}",
        "scan": scan_result.as_dict(),
        "registries": registry_checks,
    }


def perform_audit(target: str, *, stars: int = 200) -> AuditSummary:
    context = fetch_star_context(target, stars=stars)
    owner = context["owner"]
    repo = context["repo"]
    client = context["client"]
    repo_payload = context["repo_payload"]
    owner_payload = context["owner_payload"]
    stargazers = context["stargazers"]
    star_burst = context["star_burst"]
    thin_stargazer_ratio = context["thin_stargazer_ratio"]

    open_issues = client.count_issues(owner, repo)
    open_prs = client.count_prs(owner, repo)
    contributors = len(client.contributors(owner, repo))
    releases = client.releases(owner, repo)
    risky_release_assets = summarize_release_assets(releases)

    snapshot_handle, snapshot_dir = client.download_snapshot(owner, repo)
    try:
        scan_result = inspect_snapshot(snapshot_dir)
    finally:
        snapshot_handle.cleanup()

    registry_checks = registry_presence(scan_result.package_names)
    findings = build_findings(
        owner_age_days=age_in_days(parse_iso_datetime(owner_payload.get("created_at"))),
        owner_public_repos=int(owner_payload.get("public_repos", 0)),
        repo_age_days=age_in_days(parse_iso_datetime(repo_payload.get("created_at"))),
        stars=int(repo_payload.get("stargazers_count", 0)),
        forks=int(repo_payload.get("forks_count", 0)),
        open_issues=open_issues,
        open_prs=open_prs,
        contributors=contributors,
        star_burst=star_burst,
        suspicious_star_accounts_ratio=thin_stargazer_ratio,
        scan_result=scan_result,
        risky_release_assets=risky_release_assets,
        registry_presence=registry_checks,
    )
    score, verdict = score_findings(findings)

    metadata = {
        "repo": {
            "owner": owner,
            "name": repo,
            "html_url": repo_payload.get("html_url"),
            "description": repo_payload.get("description"),
            "created_at": repo_payload.get("created_at"),
            "default_branch": repo_payload.get("default_branch"),
            "stars": int(repo_payload.get("stargazers_count", 0)),
            "forks": int(repo_payload.get("forks_count", 0)),
            "open_issues": open_issues,
            "open_prs": open_prs,
            "contributors": contributors,
        },
        "owner": {
            "login": owner_payload.get("login"),
            "type": owner_payload.get("type"),
            "created_at": owner_payload.get("created_at"),
            "public_repos": int(owner_payload.get("public_repos", 0)),
            "followers": int(owner_payload.get("followers", 0)),
        },
        "stars": {
            "sampled_recent_stars": len(stargazers),
            "largest_day_share": star_burst.get("largest_day_share", 0.0),
            "largest_hour_share": star_burst.get("largest_hour_share", 0.0),
            "thin_recent_stargazer_ratio": thin_stargazer_ratio,
        },
        "scan": scan_result.as_dict(),
        "registries": registry_checks,
        "releases": {
            "count": len(releases),
            "risky_assets": risky_release_assets,
        },
    }

    return AuditSummary(target=f"{owner}/{repo}", score=score, verdict=verdict, findings=findings, metadata=metadata)


def render_text(summary: AuditSummary) -> str:
    repo_meta = summary.metadata["repo"]
    owner_meta = summary.metadata["owner"]
    lines = [
        f"Target:   {summary.target}",
        f"Verdict:  {summary.verdict}",
        f"Score:    {summary.score}/100",
        f"Repo:     {repo_meta['stars']} stars | {repo_meta['forks']} forks | {repo_meta['contributors']} contributors | {repo_meta['open_issues']} open issues | {repo_meta['open_prs']} open PRs",
        f"Owner:    {owner_meta['login']} ({owner_meta['type']}) | {owner_meta['public_repos']} public repos | {owner_meta['followers']} followers",
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


def render_star_analysis_text(summary: dict[str, Any]) -> str:
    repo_meta = summary["repo"]
    owner_meta = summary["owner"]
    stars_meta = summary["stars"]
    lines = [
        f"Target:   {summary['target']}",
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


def render_snapshot_scan_text(summary: dict[str, Any]) -> str:
    scan = summary["scan"]
    lines = [
        f"Target:   {summary['target']}",
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
    if summary["registries"]:
        lines.append("")
        lines.append("Registry Presence:")
        for ecosystem, present in sorted(summary["registries"].items()):
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
    try:
        if args.command == "star-analysis":
            summary = perform_star_analysis(args.target, stars=args.stars)
            if args.json:
                print(json.dumps(summary, indent=2))
            else:
                print(render_star_analysis_text(summary))
            return 0
        if args.command == "snapshot-scan":
            summary = perform_snapshot_scan(args.target)
            if args.json:
                print(json.dumps(summary, indent=2))
            else:
                print(render_snapshot_scan_text(summary))
            return 0
        summary = perform_audit(args.target, stars=args.stars)
    except Exception as exc:
        parser.exit(status=1, message=f"repo-skeptic failed: {exc}\n")

    if args.json:
        print(json.dumps(summary.as_dict(), indent=2))
    else:
        print(render_text(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
