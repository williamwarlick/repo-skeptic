# Repo Skeptic Reference

## Command Matrix

- `scripts/audit-repo.sh owner/repo`
  Use for an overall trust check.
- `scripts/audit-repo-json.sh owner/repo`
  Use when another tool or workflow needs structured output.
- `scripts/star-analysis.sh owner/repo`
  Use when the main question is whether stars look organic.
- `scripts/snapshot-scan.sh owner/repo`
  Use when the main question is install-time or source-level risk.

## Result Interpretation

- `low-risk`
  No high-signal heuristics fired. This is not the same as safe.
- `needs-review`
  Some signals fired. Read the evidence before trusting or running the repo.
- `high-risk`
  Multiple strong signals fired. Raise the review bar substantially before cloning, installing, or running anything.

## Escalation Rules

Treat these as strong reasons to stop and review manually:

- install hooks in `package.json`
- network-exec patterns such as `curl | sh`
- suspicious binaries in source or releases
- severe star clustering paired with thin-profile stargazers
- very new owner accounts paired with fast star growth
- widely-trusted repos with stale commit history or a visibly narrow recent maintainer bench

## Trust Boundary

The skill only reads metadata and downloaded source snapshots. It does not execute target repo code.
