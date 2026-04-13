from __future__ import annotations

import argparse
import json
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
    parser.add_argument("target", help="GitHub repo in owner/repo form or full GitHub URL")
    parser.add_argument("--stars", type=int, default=200, help="How many recent stars to sample (default: 200)")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a human summary")
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


def perform_audit(target: str, *, stars: int = 200) -> AuditSummary:
    owner, repo = normalize_repo_target(target)
    client = GitHubClient()

    repo_payload = client.repo(owner, repo)
    owner_payload = client.owner(owner)
    stargazers = client.stargazers(owner, repo, int(repo_payload.get("stargazers_count", 0)), limit=stars)
    star_burst = analyze_star_burst([entry.get("starred_at") for entry in stargazers])
    thin_stargazer_ratio = profile_thinness_ratio(list(reversed(stargazers)))

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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
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
