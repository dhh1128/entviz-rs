#!/usr/bin/env bash
# Configure branch protection on main for entviz-rs.
#
# Policy:
#   * Public contributors must open a PR; it cannot merge until CI passes and it
#     has 1 approving review.
#   * The maintainer (a repo admin) BYPASSES all of this and may push directly
#     to main — this is `enforce_admins: false` below.
#
# Run once (and re-run to update). Requires admin on the repo and a gh login
# with the `repo` scope:  gh auth login
#
# Adjust REQUIRED_CHECKS if you rename the CI jobs (the contexts are the job
# `name:` values in .github/workflows/ci.yml).
set -euo pipefail

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo "Configuring branch protection on ${REPO}@main ..."

gh api -X PUT "repos/${REPO}/branches/main/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["fmt + clippy + test", "coverage floor", "cargo audit", "spec-sync + Tier-A conformance"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON

echo "Done. Verify at: https://github.com/${REPO}/settings/branches"
echo "Note: 'enforce_admins=false' lets repo admins push to main directly,"
echo "      bypassing the PR + review + status-check requirements."
