from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .github_api import GitHubClient, registry_presence
from .heuristics import (
    AuditSummary,
    CommitContinuity,
    ScanResult,
    age_in_days,
    analyze_star_burst,
    build_findings,
    inspect_snapshot,
    normalize_repo_target,
    parse_iso_datetime,
    score_findings,
    summarize_commit_continuity,
    summarize_release_assets,
)


@dataclass(slots=True)
class RepoContext:
    owner: str
    repo: str
    repo_payload: dict[str, Any]
    owner_payload: dict[str, Any]
    stargazers: list[dict[str, Any]]
    star_burst: dict[str, float]
    thin_stargazer_ratio: float | None


@dataclass(slots=True)
class SnapshotContext:
    scan_result: ScanResult
    registries: dict[str, bool]


@dataclass(slots=True)
class MaintenanceSummary:
    sampled_recent_commits: int
    last_commit_at: str | None
    days_since_last_commit: int | None
    unique_recent_authors: int
    recent_authors: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "sampled_recent_commits": self.sampled_recent_commits,
            "last_commit_at": self.last_commit_at,
            "days_since_last_commit": self.days_since_last_commit,
            "unique_recent_authors": self.unique_recent_authors,
            "recent_authors": self.recent_authors,
        }


@dataclass(slots=True)
class StarAnalysisSummary:
    target: str
    repo: dict[str, Any]
    owner: dict[str, Any]
    stars: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "repo": self.repo,
            "owner": self.owner,
            "stars": self.stars,
        }


@dataclass(slots=True)
class SnapshotScanSummary:
    target: str
    scan: dict[str, Any]
    registries: dict[str, bool]

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan": self.scan,
            "registries": self.registries,
        }


class RepoSkepticService:
    def __init__(self, client: GitHubClient | None = None) -> None:
        self.client = client or GitHubClient()

    def _profile_thinness_ratio(self, stargazers: list[dict[str, Any]], *, sample_size: int = 25) -> float | None:
        sampled = [entry.get("user", {}) for entry in stargazers[:sample_size] if entry.get("user", {}).get("login")]
        if not sampled:
            return None
        thin_profiles = 0
        for profile in sampled:
            if int(profile.get("public_repos", 0)) == 0 and int(profile.get("followers", 0)) == 0:
                thin_profiles += 1
        return thin_profiles / len(sampled)

    def _fetch_repo_context(self, target: str, *, stars: int = 200) -> RepoContext:
        owner, repo = normalize_repo_target(target)
        repo_payload = self.client.repo(owner, repo)
        owner_payload = self.client.owner(owner)
        stargazers = self.client.stargazers(owner, repo, int(repo_payload.get("stargazers_count", 0)), limit=stars)
        star_burst = analyze_star_burst([entry.get("starred_at") for entry in stargazers])
        thin_stargazer_ratio = self._profile_thinness_ratio(list(reversed(stargazers)))
        return RepoContext(
            owner=owner,
            repo=repo,
            repo_payload=repo_payload,
            owner_payload=owner_payload,
            stargazers=stargazers,
            star_burst=star_burst,
            thin_stargazer_ratio=thin_stargazer_ratio,
        )

    def _scan_snapshot(self, owner: str, repo: str) -> SnapshotContext:
        snapshot_handle, snapshot_dir = self.client.download_snapshot(owner, repo)
        try:
            scan_result = inspect_snapshot(snapshot_dir)
        finally:
            snapshot_handle.cleanup()
        return SnapshotContext(
            scan_result=scan_result,
            registries=registry_presence(scan_result.package_names),
        )

    def _summarize_maintenance(self, owner: str, repo: str) -> MaintenanceSummary:
        commits = self.client.recent_commits(owner, repo, limit=20)
        continuity: CommitContinuity = summarize_commit_continuity(commits)
        last_commit_at = parse_iso_datetime(continuity.last_commit_at)
        return MaintenanceSummary(
            sampled_recent_commits=continuity.sampled_recent_commits,
            last_commit_at=continuity.last_commit_at,
            days_since_last_commit=age_in_days(last_commit_at),
            unique_recent_authors=continuity.unique_recent_authors,
            recent_authors=continuity.recent_authors,
        )

    def star_analysis(self, target: str, *, stars: int = 200) -> StarAnalysisSummary:
        context = self._fetch_repo_context(target, stars=stars)
        repo_payload = context.repo_payload
        owner_payload = context.owner_payload
        return StarAnalysisSummary(
            target=f"{context.owner}/{context.repo}",
            repo={
                "html_url": repo_payload.get("html_url"),
                "description": repo_payload.get("description"),
                "created_at": repo_payload.get("created_at"),
                "stars": int(repo_payload.get("stargazers_count", 0)),
                "forks": int(repo_payload.get("forks_count", 0)),
            },
            owner={
                "login": owner_payload.get("login"),
                "type": owner_payload.get("type"),
                "created_at": owner_payload.get("created_at"),
                "public_repos": int(owner_payload.get("public_repos", 0)),
                "followers": int(owner_payload.get("followers", 0)),
            },
            stars={
                "sampled_recent_stars": len(context.stargazers),
                "largest_day_share": context.star_burst.get("largest_day_share", 0.0),
                "largest_hour_share": context.star_burst.get("largest_hour_share", 0.0),
                "thin_recent_stargazer_ratio": context.thin_stargazer_ratio,
            },
        )

    def snapshot_scan(self, target: str) -> SnapshotScanSummary:
        owner, repo = normalize_repo_target(target)
        snapshot = self._scan_snapshot(owner, repo)
        return SnapshotScanSummary(
            target=f"{owner}/{repo}",
            scan=snapshot.scan_result.as_dict(),
            registries=snapshot.registries,
        )

    def audit(self, target: str, *, stars: int = 200) -> AuditSummary:
        context = self._fetch_repo_context(target, stars=stars)
        owner = context.owner
        repo = context.repo
        repo_payload = context.repo_payload
        owner_payload = context.owner_payload

        open_issues = self.client.count_issues(owner, repo)
        open_prs = self.client.count_prs(owner, repo)
        contributors = len(self.client.contributors(owner, repo))
        releases = self.client.releases(owner, repo)
        maintenance = self._summarize_maintenance(owner, repo)
        risky_release_assets = summarize_release_assets(releases)
        snapshot = self._scan_snapshot(owner, repo)
        findings = build_findings(
            owner_age_days=age_in_days(parse_iso_datetime(owner_payload.get("created_at"))),
            owner_public_repos=int(owner_payload.get("public_repos", 0)),
            repo_age_days=age_in_days(parse_iso_datetime(repo_payload.get("created_at"))),
            days_since_last_commit=maintenance.days_since_last_commit,
            unique_recent_commit_authors=maintenance.unique_recent_authors,
            stars=int(repo_payload.get("stargazers_count", 0)),
            forks=int(repo_payload.get("forks_count", 0)),
            open_issues=open_issues,
            open_prs=open_prs,
            contributors=contributors,
            star_burst=context.star_burst,
            suspicious_star_accounts_ratio=context.thin_stargazer_ratio,
            scan_result=snapshot.scan_result,
            risky_release_assets=risky_release_assets,
            registry_presence=snapshot.registries,
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
                "sampled_recent_stars": len(context.stargazers),
                "largest_day_share": context.star_burst.get("largest_day_share", 0.0),
                "largest_hour_share": context.star_burst.get("largest_hour_share", 0.0),
                "thin_recent_stargazer_ratio": context.thin_stargazer_ratio,
            },
            "scan": snapshot.scan_result.as_dict(),
            "registries": snapshot.registries,
            "maintenance": maintenance.as_dict(),
            "releases": {
                "count": len(releases),
                "risky_assets": risky_release_assets,
            },
        }

        return AuditSummary(target=f"{owner}/{repo}", score=score, verdict=verdict, findings=findings, metadata=metadata)
