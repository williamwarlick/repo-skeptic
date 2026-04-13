import unittest

from repo_skeptic.cli import (
    normalize_argv,
    render_text,
    render_snapshot_scan_text,
    render_star_analysis_text,
)
from repo_skeptic.heuristics import AuditSummary
from repo_skeptic.service import SnapshotScanSummary, StarAnalysisSummary


class RepoSkepticCliTests(unittest.TestCase):
    def test_normalize_argv_defaults_to_audit(self) -> None:
        self.assertEqual(normalize_argv(["owner/repo"]), ["audit", "owner/repo"])

    def test_normalize_argv_preserves_explicit_subcommand(self) -> None:
        self.assertEqual(normalize_argv(["star-analysis", "owner/repo"]), ["star-analysis", "owner/repo"])

    def test_render_star_analysis_text_includes_ratios(self) -> None:
        summary = StarAnalysisSummary(
            target="owner/repo",
            repo={"stars": 100, "forks": 20},
            owner={"login": "owner", "type": "User", "public_repos": 4, "followers": 10},
            stars={
                "sampled_recent_stars": 12,
                "largest_day_share": 0.5,
                "largest_hour_share": 0.25,
                "thin_recent_stargazer_ratio": 0.1,
            },
        )
        text = render_star_analysis_text(summary)
        self.assertIn("Largest day share", text)
        self.assertIn("50%", text)

    def test_render_snapshot_scan_text_includes_first_hits(self) -> None:
        summary = SnapshotScanSummary(
            target="owner/repo",
            scan={
                "install_scripts": ["package.json:postinstall=curl ..."],
                "suspicious_commands": ["bootstrap.sh:network_shell"],
                "suspicious_files": ["bin/tool.exe"],
                "package_names": {"npm": "demo"},
            },
            registries={"npm": True},
        )
        text = render_snapshot_scan_text(summary)
        self.assertIn("First install hook", text)
        self.assertIn("present", text)

    def test_render_text_includes_maintenance_summary(self) -> None:
        summary = AuditSummary(
            target="owner/repo",
            score=92,
            verdict="low-risk",
            findings=[],
            metadata={
                "repo": {"stars": 100, "forks": 20, "contributors": 3, "open_issues": 4, "open_prs": 1},
                "owner": {"login": "owner", "type": "User", "public_repos": 4, "followers": 10},
                "maintenance": {"days_since_last_commit": 12, "unique_recent_authors": 2},
            },
        )
        text = render_text(summary)
        self.assertIn("Maintenance: last commit 12 days ago", text)


if __name__ == "__main__":
    unittest.main()
