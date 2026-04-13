from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


@dataclass(slots=True)
class GitHubClient:
    gh_bin: str = "gh"

    def _run_gh_json(self, *args: str) -> Any:
        command = [self.gh_bin, *args]
        completed = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(completed.stdout)

    def _run_gh_file(self, output_path: Path, *args: str) -> None:
        command = [self.gh_bin, *args]
        with output_path.open("wb") as handle:
            subprocess.run(command, check=True, stdout=handle, stderr=subprocess.PIPE)

    def repo(self, owner: str, repo: str) -> dict[str, Any]:
        return self._run_gh_json("api", f"repos/{owner}/{repo}")

    def owner(self, owner: str) -> dict[str, Any]:
        try:
            return self._run_gh_json("api", f"users/{owner}")
        except subprocess.CalledProcessError:
            return self._run_gh_json("api", f"orgs/{owner}")

    def count_issues(self, owner: str, repo: str) -> int:
        payload = self._run_gh_json(
            "api",
            "-X",
            "GET",
            "search/issues",
            "-f",
            f"q=repo:{owner}/{repo} is:issue is:open",
            "-F",
            "per_page=1",
        )
        return int(payload.get("total_count", 0))

    def count_prs(self, owner: str, repo: str) -> int:
        payload = self._run_gh_json(
            "api",
            "-X",
            "GET",
            "search/issues",
            "-f",
            f"q=repo:{owner}/{repo} is:pr is:open",
            "-F",
            "per_page=1",
        )
        return int(payload.get("total_count", 0))

    def contributors(self, owner: str, repo: str) -> list[dict[str, Any]]:
        return self._run_gh_json("api", f"repos/{owner}/{repo}/contributors?per_page=100")

    def releases(self, owner: str, repo: str) -> list[dict[str, Any]]:
        return self._run_gh_json("api", f"repos/{owner}/{repo}/releases?per_page=20")

    def stargazers(self, owner: str, repo: str, stars_count: int, *, limit: int = 200) -> list[dict[str, Any]]:
        if stars_count <= 0 or limit <= 0:
            return []
        stargazers: list[dict[str, Any]] = []
        cursor: str | None = None
        remaining = min(limit, 500)
        query = """
        query($owner: String!, $repo: String!, $perPage: Int!, $before: String) {
          repository(owner: $owner, name: $repo) {
            stargazers(last: $perPage, before: $before) {
              pageInfo {
                hasPreviousPage
                startCursor
              }
              edges {
                starredAt
                node {
                  login
                  ... on User {
                    followers {
                      totalCount
                    }
                    repositories(ownerAffiliations: OWNER, privacy: PUBLIC) {
                      totalCount
                    }
                  }
                }
              }
            }
          }
        }
        """
        while remaining > 0:
            page_size = min(remaining, 100)
            args = [
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-F",
                f"owner={owner}",
                "-F",
                f"repo={repo}",
                "-F",
                f"perPage={page_size}",
            ]
            if cursor:
                args.extend(["-F", f"before={cursor}"])
            payload = self._run_gh_json(*args)
            page = payload["data"]["repository"]["stargazers"]
            edges = page.get("edges", [])
            if not edges:
                break
            stargazers[0:0] = [
                {
                    "starred_at": edge.get("starredAt"),
                    "user": {
                        "login": edge["node"]["login"],
                        "followers": edge["node"].get("followers", {}).get("totalCount", 0),
                        "public_repos": edge["node"].get("repositories", {}).get("totalCount", 0),
                    },
                }
                for edge in edges
                if edge.get("node", {}).get("login")
            ]
            remaining -= len(edges)
            if not page["pageInfo"].get("hasPreviousPage"):
                break
            cursor = page["pageInfo"].get("startCursor")
        return stargazers[-limit:]
    def download_snapshot(self, owner: str, repo: str) -> tuple[TemporaryDirectory[str], Path]:
        temp_dir = TemporaryDirectory(prefix=f"repo-skeptic-{owner}-{repo}-")
        archive_path = Path(temp_dir.name) / "snapshot.tar.gz"
        self._run_gh_file(archive_path, "api", f"repos/{owner}/{repo}/tarball")
        extract_dir = Path(temp_dir.name) / "snapshot"
        extract_dir.mkdir()
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(extract_dir, filter="data")
        extracted_children = list(extract_dir.iterdir())
        if len(extracted_children) != 1:
            raise RuntimeError("Unexpected tarball layout while extracting repo snapshot")
        return temp_dir, extracted_children[0]


def registry_presence(package_names: dict[str, str]) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for ecosystem, package_name in package_names.items():
        checks[ecosystem] = _check_registry(ecosystem, package_name)
    return checks


def _check_registry(ecosystem: str, package_name: str) -> bool:
    encoded = urllib.parse.quote(package_name, safe="@/")
    url_map = {
        "npm": f"https://registry.npmjs.org/{encoded}",
        "pypi": f"https://pypi.org/pypi/{encoded}/json",
        "cargo": f"https://crates.io/api/v1/crates/{encoded}",
    }
    url = url_map.get(ecosystem)
    if not url:
        return False
    request = urllib.request.Request(url, headers={"User-Agent": "repo-skeptic/0.1.0"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        return False
    except urllib.error.URLError:
        return False
