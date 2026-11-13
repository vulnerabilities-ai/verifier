#!/usr/bin/env bash
# Carry over public-record lookups from a review branch that has not been merged yet.
# Called by .github/workflows/verify.yml before the lookups.
#
# Why: every run starts from main and force-pushes the review branch. Without this, a
# run started before the previous review pull request is merged would throw away that
# run's lookups (records/) and make the same requests again.
#
# Safe by construction:
#   - only records/ is taken (raw responses and their append-only manifests);
#   - only when main's records/ has not changed since the review branch was made, so
#     the review branch's records/ is main's records/ plus that run's additions;
#   - nothing happens when the branch does not exist or is already merged.
# Inputs (environment): REVIEW_BRANCH (default review/weekly), PUSH_REMOTE (default origin).
set -euo pipefail

REMOTE="${PUSH_REMOTE:-origin}"
BRANCH="${REVIEW_BRANCH:-review/weekly}"
ref="refs/remotes/${REMOTE}/${BRANCH}"

if ! git fetch -q "${REMOTE}" "+refs/heads/${BRANCH}:${ref}" 2>/dev/null; then
  echo "No branch ${BRANCH}: nothing to carry over."
  exit 0
fi
if git merge-base --is-ancestor "${ref}" HEAD; then
  echo "${BRANCH} is already merged: nothing to carry over."
  exit 0
fi
base=$(git merge-base "${ref}" HEAD)
if ! git diff --quiet "${base}" HEAD -- records; then
  echo "main's records/ changed after ${BRANCH} was made: not carried over (the lookups will be made again)."
  exit 0
fi
changed=$(git diff --name-only "${base}" "${ref}" -- records | wc -l | tr -d ' ')
if [ "${changed}" = "0" ]; then
  echo "${BRANCH} has no new records: nothing to carry over."
  exit 0
fi
git checkout -q "${ref}" -- records
echo "Carried over ${changed} record file(s) from the unmerged ${BRANCH} (commit $(git rev-parse --short "${ref}"))."
