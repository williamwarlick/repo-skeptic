---
name: repo-skeptic
description: Verify GitHub repositories before trusting them. Use when the user wants to audit a GitHub repo, assess whether a repo looks trustworthy, or review install-time and reputation risks before cloning or running code.
---

# Repo Skeptic

Use the bundled scripts from this repo instead of reconstructing the audit flow manually.
The installed skill is self-contained: the scripts and Python implementation ship inside the skill folder.

## Quick start

From the repo root:

- Text summary: `scripts/audit-repo.sh owner/repo`
- JSON output: `scripts/audit-repo-json.sh owner/repo`
- Star analysis: `scripts/star-analysis.sh owner/repo`
- Snapshot scan: `scripts/snapshot-scan.sh owner/repo`

## Workflow

1. Normalize the target repo to `owner/repo` or a GitHub URL.
2. Run `scripts/audit-repo.sh` first when the user wants an overall trust check.
3. Run `scripts/star-analysis.sh` when the user specifically wants to inspect suspicious star growth or thin-profile stargazers.
4. Run `scripts/snapshot-scan.sh` when the user specifically wants install-hook, suspicious-command, or bundled-binary evidence.
5. Review the highest-severity findings before making any trust recommendation.
6. Treat `low-risk` as "no high-signal heuristics fired", not as "safe".
7. Escalate anything involving install hooks, network-exec patterns, bundled binaries, or suspicious release assets.

## What the audit covers

- owner account age and public repo history
- repo age versus star count
- recent star clustering
- stars/issues/PR/contributor mismatch
- install-time scripts in `package.json`
- suspicious shell, network-exec, obfuscation, and bundled binaries
- executable release assets
- package registry presence checks for npm, PyPI, and crates.io

## Notes

- Requires authenticated `gh`.
- The scripts never execute target repo code.
- Prefer JSON mode when another tool or workflow needs structured output.
