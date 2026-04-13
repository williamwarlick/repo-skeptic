---
name: repo-skeptic
description: Verify GitHub repositories before trusting them. Use when the user wants to audit a GitHub repo, assess whether a repo looks trustworthy, or review install-time and reputation risks before cloning or running code.
---

# Repo Skeptic

Use the bundled scripts from this repo instead of reconstructing the audit flow manually.
The installed skill is self-contained: the scripts and Python implementation ship inside the skill folder.
For interpretation details and command selection guidance, see [REFERENCE.md](REFERENCE.md).

## Quick start

From the repo root:

- Text summary: `scripts/audit-repo.sh owner/repo`
- JSON output: `scripts/audit-repo-json.sh owner/repo`
- Star analysis: `scripts/star-analysis.sh owner/repo`
- Snapshot scan: `scripts/snapshot-scan.sh owner/repo`

## Workflow

1. Normalize the target repo to `owner/repo` or a GitHub URL.
2. Pick the smallest script that answers the user's question.
3. Use `audit-repo` by default when the user wants an overall trust check.
4. Escalate anything involving install hooks, network-exec patterns, bundled binaries, or suspicious release assets.

## Notes

- Requires authenticated `gh`.
- The scripts never execute target repo code.
- Prefer JSON mode when another tool or workflow needs structured output.
