# repo-skeptic

`repo-skeptic` verifies GitHub repositories before you trust, clone, or run them.

The repo is structured in two layers:

- root `scripts/` for direct human and CI usage
- embedded `skills/repo-skeptic/` as the self-contained install payload for `skills.sh`

It checks:

- account age and owner history
- repo age versus star count
- star clustering in recent history
- stars/issues/PR/contributor ratio mismatches
- install-time scripts in `package.json`
- suspicious shell, network-exec, obfuscation, and bundled binaries
- executable release assets
- package metadata that does not resolve in npm / PyPI / crates.io

## Package layout

- `scripts/`
  Stable shell entrypoints for humans, CI, and other tools.
- `skills/repo-skeptic/`
  Self-contained `skills.sh` install payload, including docs, scripts, and Python implementation.
- `skills/repo-skeptic/repo_skeptic/`
  Importable Python package with a thin CLI layer and a deeper `RepoSkepticService` orchestration layer.

## Why this exists

Stars, polished READMEs, and even active-looking issues are cheap to fake. This tool is intentionally conservative: it never executes target repo code. It only reads GitHub metadata, downloads a source snapshot tarball, and scans the files as text.

## Requirements

- Python 3.11+
- [`gh`](https://cli.github.com/) authenticated with `repo` scope

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or bootstrap the local environment with:

```bash
./scripts/bootstrap.sh
```

## Usage

```bash
./scripts/audit-repo.sh owner/repo
./scripts/audit-repo-json.sh owner/repo
./scripts/star-analysis.sh owner/repo
./scripts/snapshot-scan.sh owner/repo
repo-skeptic owner/repo
repo-skeptic star-analysis owner/repo
repo-skeptic snapshot-scan owner/repo
repo-skeptic https://github.com/owner/repo --json
```

Programmatic use:

```python
from repo_skeptic import RepoSkepticService

service = RepoSkepticService()
summary = service.audit("owner/repo", stars=50)
print(summary.verdict, summary.score)
```

## skills.sh

Install the embedded skill directly from GitHub:

```bash
npx skills add williamwarlick/repo-skeptic --skill repo-skeptic
```

List the skills that `skills` detects in this repo:

```bash
npx skills add williamwarlick/repo-skeptic --list
```

An installed `repo-skeptic` skill includes its own scripts and Python implementation inside the installed skill directory. It does not rely on files outside the skill folder.

Example:

```bash
repo-skeptic anthropics/claude-code
```

## Output

The CLI produces:

- a `score` from 0-100
- a `verdict` of `low-risk`, `needs-review`, or `high-risk`
- concrete findings with evidence lines

This is a review assistant, not a malware verdict engine. A clean score does not mean a repo is safe.

## Design notes

- Recent-star analysis samples the newest GitHub stargazers available through the GitHub GraphQL API.
- Thin-profile stargazer checks sample up to 25 recent stargazers and look for empty profiles.
- Registry checks are presence checks only. They do not prove downstream adoption.
- The scanner is intentionally heuristic-based and should be extended for your threat model.
- The embedded skill lives at `skills/repo-skeptic/` and contains the Python implementation plus callable scripts, so a `skills.sh` install is functional on its own.
- The CLI is intentionally thin; `RepoSkepticService` owns repo normalization, star analysis, snapshot lifecycle, and audit orchestration.

## Development

```bash
PYTHONPATH=skills/repo-skeptic python -m unittest discover -s tests
PYTHONPATH=skills/repo-skeptic python -m repo_skeptic.cli owner/repo --json
./scripts/audit-repo.sh owner/repo
```
