from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import re
from typing import Any

INSTALL_SCRIPT_KEYS = {"preinstall", "install", "postinstall", "prepare"}
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".dylib",
    ".so",
    ".bat",
    ".cmd",
    ".ps1",
    ".scr",
    ".jar",
    ".appimage",
    ".msi",
}
TEXT_FILE_SUFFIXES = {
    ".json",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".tsx",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".txt",
    ".md",
}
NETWORK_EXEC_PATTERNS: dict[str, re.Pattern[str]] = {
    "network_shell": re.compile(r"\b(?:curl|wget)\b[^\n]{0,160}\b(?:sh|bash|zsh|python|node)\b", re.IGNORECASE),
    "powershell_download": re.compile(r"powershell[^\n]{0,160}(?:downloadstring|invoke-webrequest)", re.IGNORECASE),
    "base64_exec": re.compile(r"(?:base64\s+-d|Buffer\.from\([^\n]{0,120}base64|atob\()", re.IGNORECASE),
    "child_process_exec": re.compile(r"child_process\.(?:exec|execSync|spawn|spawnSync)", re.IGNORECASE),
    "eval_like": re.compile(r"\b(?:eval|new Function)\b"),
}
OBFUSCATED_STRING = re.compile(r"[A-Za-z0-9+/]{180,}={0,2}")
PACKAGE_NAME_PATTERNS = {
    "npm": re.compile(r'"name"\s*:\s*"([^"]+)"'),
    "cargo": re.compile(r'^name\s*=\s*"([^"]+)"', re.MULTILINE),
}


@dataclass(slots=True)
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    penalty: int
    evidence: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    install_scripts: list[str]
    suspicious_commands: list[str]
    suspicious_files: list[str]
    package_names: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "install_scripts": self.install_scripts,
            "suspicious_commands": self.suspicious_commands,
            "suspicious_files": self.suspicious_files,
            "package_names": self.package_names,
        }


@dataclass(slots=True)
class AuditSummary:
    target: str
    score: int
    verdict: str
    findings: list[Finding]
    metadata: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "score": self.score,
            "verdict": self.verdict,
            "findings": [finding.as_dict() for finding in self.findings],
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class CommitContinuity:
    sampled_recent_commits: int
    last_commit_at: str | None
    unique_recent_authors: int
    recent_authors: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "sampled_recent_commits": self.sampled_recent_commits,
            "last_commit_at": self.last_commit_at,
            "unique_recent_authors": self.unique_recent_authors,
            "recent_authors": self.recent_authors,
        }


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def age_in_days(created_at: datetime | None, *, now: datetime | None = None) -> int | None:
    if created_at is None:
        return None
    current = now or now_utc()
    return max((current - created_at).days, 0)


def normalize_repo_target(target: str) -> tuple[str, str]:
    stripped = target.strip().rstrip("/")
    if stripped.startswith("https://github.com/"):
        stripped = stripped.removeprefix("https://github.com/")
    elif stripped.startswith("http://github.com/"):
        stripped = stripped.removeprefix("http://github.com/")
    parts = [part for part in stripped.split("/") if part]
    if len(parts) < 2:
        raise ValueError(f"Expected owner/repo or GitHub URL, got: {target}")
    return parts[0], parts[1]


def analyze_star_burst(starred_at_values: list[str]) -> dict[str, float]:
    timestamps = [parse_iso_datetime(value) for value in starred_at_values if value]
    timestamps = [value for value in timestamps if value is not None]
    if len(timestamps) < 5:
        return {"sample_size": float(len(timestamps)), "largest_day_share": 0.0, "largest_hour_share": 0.0}
    day_counts = Counter(ts.strftime("%Y-%m-%d") for ts in timestamps)
    hour_counts = Counter(ts.strftime("%Y-%m-%dT%H") for ts in timestamps)
    sample_size = len(timestamps)
    return {
        "sample_size": float(sample_size),
        "largest_day_share": max(day_counts.values()) / sample_size,
        "largest_hour_share": max(hour_counts.values()) / sample_size,
    }


def summarize_commit_continuity(commits: list[dict[str, Any]]) -> CommitContinuity:
    recent_authors: list[str] = []
    last_commit_at: str | None = None

    for index, commit in enumerate(commits):
        if index == 0:
            last_commit_at = commit.get("commit", {}).get("author", {}).get("date")
        author_payload = commit.get("author") or {}
        author_login = author_payload.get("login")
        author_name = commit.get("commit", {}).get("author", {}).get("name")
        author = author_login or author_name
        if author and author not in recent_authors:
            recent_authors.append(author)

    return CommitContinuity(
        sampled_recent_commits=len(commits),
        last_commit_at=last_commit_at,
        unique_recent_authors=len(recent_authors),
        recent_authors=recent_authors[:5],
    )


def inspect_snapshot(snapshot_dir: Path) -> ScanResult:
    install_scripts: list[str] = []
    suspicious_commands: list[str] = []
    suspicious_files: list[str] = []
    package_names: dict[str, str] = {}

    for path in snapshot_dir.rglob("*"):
        if path.is_dir() or ".git" in path.parts:
            continue
        suffix = path.suffix.lower()
        rel_path = str(path.relative_to(snapshot_dir))
        if suffix in SUSPICIOUS_EXTENSIONS:
            suspicious_files.append(rel_path)
        if path.stat().st_size > 1_500_000 and suffix not in TEXT_FILE_SUFFIXES:
            continue
        if suffix not in TEXT_FILE_SUFFIXES and path.name not in {"package.json", "pyproject.toml", "Cargo.toml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        if path.name == "package.json":
            try:
                package_json = json.loads(text)
            except json.JSONDecodeError:
                package_json = {}
            scripts = package_json.get("scripts", {})
            if isinstance(scripts, dict):
                for key, value in scripts.items():
                    if key in INSTALL_SCRIPT_KEYS:
                        install_scripts.append(f"{rel_path}:{key}={value}")
            package_name = package_json.get("name")
            if isinstance(package_name, str) and package_name:
                package_names["npm"] = package_name
        elif path.name == "pyproject.toml":
            match = re.search(r'^name\s*=\s*"([^"]+)"', text, re.MULTILINE)
            if match:
                package_names.setdefault("pypi", match.group(1))
        elif path.name == "Cargo.toml":
            match = PACKAGE_NAME_PATTERNS["cargo"].search(text)
            if match:
                package_names.setdefault("cargo", match.group(1))

        for pattern_name, pattern in NETWORK_EXEC_PATTERNS.items():
            if pattern.search(text):
                suspicious_commands.append(f"{rel_path}:{pattern_name}")
        if OBFUSCATED_STRING.search(text):
            suspicious_commands.append(f"{rel_path}:long_base64_blob")

    return ScanResult(
        install_scripts=sorted(set(install_scripts)),
        suspicious_commands=sorted(set(suspicious_commands)),
        suspicious_files=sorted(set(suspicious_files)),
        package_names=package_names,
    )


def summarize_release_assets(releases: list[dict[str, Any]]) -> list[str]:
    risky_assets: list[str] = []
    for release in releases:
        for asset in release.get("assets", []):
            name = asset.get("name", "")
            if Path(name).suffix.lower() in SUSPICIOUS_EXTENSIONS:
                risky_assets.append(f"{release.get('tag_name', 'untagged')}:{name}")
    return risky_assets


def build_findings(*,
    owner_age_days: int | None,
    owner_public_repos: int | None,
    repo_age_days: int | None,
    days_since_last_commit: int | None,
    unique_recent_commit_authors: int,
    stars: int,
    forks: int,
    open_issues: int,
    open_prs: int,
    contributors: int,
    star_burst: dict[str, float],
    suspicious_star_accounts_ratio: float | None,
    scan_result: ScanResult,
    risky_release_assets: list[str],
    registry_presence: dict[str, bool],
) -> list[Finding]:
    findings: list[Finding] = []

    if owner_age_days is not None and owner_age_days < 30:
        findings.append(Finding(
            id="new-owner-account",
            severity="high",
            title="Owner account is very new",
            detail=f"The repository owner account is only {owner_age_days} days old.",
            penalty=18,
            evidence=[f"owner_age_days={owner_age_days}"],
        ))
    elif owner_age_days is not None and owner_age_days < 180 and (owner_public_repos or 0) < 3:
        findings.append(Finding(
            id="thin-owner-history",
            severity="medium",
            title="Owner history is thin",
            detail=f"Owner age is {owner_age_days} days with only {owner_public_repos or 0} public repos.",
            penalty=10,
            evidence=[f"owner_age_days={owner_age_days}", f"owner_public_repos={owner_public_repos or 0}"],
        ))

    if repo_age_days is not None and repo_age_days < 14 and stars >= 100:
        findings.append(Finding(
            id="new-repo-high-stars",
            severity="high",
            title="Very new repo with high star count",
            detail=f"Repo is {repo_age_days} days old but already has {stars} stars.",
            penalty=18,
            evidence=[f"repo_age_days={repo_age_days}", f"stars={stars}"],
        ))
    elif repo_age_days is not None and repo_age_days < 30 and repo_age_days > 0 and (stars / repo_age_days) > 50:
        findings.append(Finding(
            id="fast-star-growth",
            severity="medium",
            title="Unusually fast star growth",
            detail=f"Repo averages {stars / repo_age_days:.1f} stars per day over {repo_age_days} days.",
            penalty=12,
            evidence=[f"stars_per_day={stars / repo_age_days:.1f}"],
        ))

    if days_since_last_commit is not None and stars >= 500 and days_since_last_commit > 365:
        findings.append(Finding(
            id="stale-maintenance",
            severity="medium",
            title="Visible maintainer activity is stale",
            detail=f"The latest sampled commit is {days_since_last_commit} days old despite the repo having {stars} stars.",
            penalty=10,
            evidence=[f"days_since_last_commit={days_since_last_commit}", f"stars={stars}"],
        ))
    elif days_since_last_commit is not None and stars >= 2_000 and days_since_last_commit > 180:
        findings.append(Finding(
            id="aging-maintenance",
            severity="low",
            title="Maintainer activity has slowed materially",
            detail=f"The latest sampled commit is {days_since_last_commit} days old on a repo with {stars} stars.",
            penalty=4,
            evidence=[f"days_since_last_commit={days_since_last_commit}", f"stars={stars}"],
        ))

    if (
        days_since_last_commit is not None
        and days_since_last_commit > 30
        and stars >= 3_000
        and unique_recent_commit_authors <= 1
        and contributors <= 2
    ):
        findings.append(Finding(
            id="single-maintainer-continuity",
            severity="low",
            title="Recent maintenance appears concentrated in one person",
            detail="The recent commit sample points to a narrow maintainer bench for a widely-trusted repo.",
            penalty=4,
            evidence=[
                f"days_since_last_commit={days_since_last_commit}",
                f"unique_recent_commit_authors={unique_recent_commit_authors}",
                f"contributors={contributors}",
            ],
        ))

    if stars >= 500 and open_issues == 0 and open_prs == 0 and contributors <= 3:
        findings.append(Finding(
            id="engagement-mismatch",
            severity="high",
            title="Popularity and activity do not match",
            detail="High-star repos usually have visible issue or PR traffic and more than a few contributors.",
            penalty=14,
            evidence=[f"stars={stars}", f"open_issues={open_issues}", f"open_prs={open_prs}", f"contributors={contributors}"],
        ))

    if star_burst.get("largest_day_share", 0.0) >= 0.5:
        findings.append(Finding(
            id="star-burst-day",
            severity="medium",
            title="Recent stars are heavily clustered",
            detail=f"{star_burst['largest_day_share']:.0%} of sampled recent stars landed on the same day.",
            penalty=12,
            evidence=[f"largest_day_share={star_burst['largest_day_share']:.2f}", f"sample_size={int(star_burst['sample_size'])}"],
        ))
    elif star_burst.get("largest_hour_share", 0.0) >= 0.3:
        findings.append(Finding(
            id="star-burst-hour",
            severity="medium",
            title="Recent stars are concentrated within one hour",
            detail=f"{star_burst['largest_hour_share']:.0%} of sampled recent stars landed within the same hour.",
            penalty=8,
            evidence=[f"largest_hour_share={star_burst['largest_hour_share']:.2f}", f"sample_size={int(star_burst['sample_size'])}"],
        ))

    if suspicious_star_accounts_ratio is not None and suspicious_star_accounts_ratio >= 0.5:
        findings.append(Finding(
            id="empty-stargazer-profiles",
            severity="medium",
            title="Many sampled stargazers have thin profiles",
            detail=f"{suspicious_star_accounts_ratio:.0%} of sampled recent stargazers had 0 public repos and 0 followers.",
            penalty=10,
            evidence=[f"suspicious_star_accounts_ratio={suspicious_star_accounts_ratio:.2f}"],
        ))

    if scan_result.install_scripts:
        findings.append(Finding(
            id="install-scripts-present",
            severity="high",
            title="Install-time scripts are present",
            detail="The repo defines install or prepare hooks. Read them before you run package managers.",
            penalty=12,
            evidence=scan_result.install_scripts[:6],
        ))

    if scan_result.suspicious_commands:
        findings.append(Finding(
            id="suspicious-commands",
            severity="high",
            title="Suspicious command patterns found in source",
            detail="The snapshot contains network-exec, obfuscation, or shell-launch patterns that deserve manual review.",
            penalty=24,
            evidence=scan_result.suspicious_commands[:8],
        ))

    if scan_result.suspicious_files:
        findings.append(Finding(
            id="bundled-binaries",
            severity="high",
            title="Precompiled binaries are bundled in the repo",
            detail="Unexpected executable artifacts raise the review bar, especially for repos that claim to be scripts or source-only tools.",
            penalty=16,
            evidence=scan_result.suspicious_files[:8],
        ))

    if risky_release_assets:
        findings.append(Finding(
            id="release-binaries",
            severity="medium",
            title="Release assets include executable binaries",
            detail="Prefer building from source when a repo distributes precompiled binaries through GitHub releases.",
            penalty=10,
            evidence=risky_release_assets[:8],
        ))

    missing_registries = [name for name, present in registry_presence.items() if not present]
    if missing_registries:
        findings.append(Finding(
            id="missing-registry-entry",
            severity="low",
            title="Package metadata exists but registry entry was not found",
            detail="Registry absence is not proof of abuse, but it weakens claims that the project is already broadly used downstream.",
            penalty=4,
            evidence=missing_registries,
        ))

    return findings


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    score = max(0, 100 - sum(finding.penalty for finding in findings))
    if score >= 75:
        verdict = "low-risk"
    elif score >= 50:
        verdict = "needs-review"
    else:
        verdict = "high-risk"
    return score, verdict
