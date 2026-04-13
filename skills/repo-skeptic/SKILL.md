---
name: repo-skeptic
description: Verify GitHub repositories before trusting them. Use when the user wants to audit a GitHub repo, assess whether a repo looks trustworthy, or review install-time and reputation risks before cloning or running code.
---

# Repo Skeptic

Use the bundled scripts from this repo instead of reconstructing the audit flow manually.

## Quick start

From the repo root:

- Text summary: `scripts/audit-repo.sh owner/repo`
- JSON output: `scripts/audit-repo-json.sh owner/repo`
- Install editable CLI into `.venv`: `scripts/bootstrap.sh`

## Workflow

1. Normalize the target repo to `owner/repo` or a GitHub URL.
2. Run the audit script first.
3. Review the highest-severity findings before making any trust recommendation.
4. Treat `low-risk` as "no high-signal heuristics fired", not as "safe".
5. Escalate anything involving install hooks, network-exec patterns, bundled binaries, or suspicious release assets.

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
