#!/usr/bin/env bash
# Commit the weekly review to the branch review/weekly and open or update ONE
# pull request. Called by .github/workflows/verify.yml, always, even when the
# rebuild, tests or audit failed, so raw cards fetched in the run are never lost.
#
# Inputs (environment):
#   BUILD_OUTCOME   "success" or anything else. If the rebuild did not succeed,
#                   data/ and cards/*/verification.json are put back as they are
#                   on main, and only the raw card files and manifests are kept.
#   TITLE_FILE      file holding the pull request title (written by review-pr)
#   BODY_FILE       file holding the pull request description
#   REVIEW_DATE     YYYY-MM-DD, used if TITLE_FILE is missing
#   GITHUB_RUN_ID, GITHUB_REPOSITORY   as set by GitHub Actions
#   GH              the GitHub CLI command (default: gh)
#   PUSH_REMOTE     remote to push to (default: origin)
# Rule kept from before: only files under cards/ and data/ may change.
set -euo pipefail

GH="${GH:-gh}"
PUSH_REMOTE="${PUSH_REMOTE:-origin}"
BRANCH="review/weekly"

if [ "${BUILD_OUTCOME:-success}" != "success" ]; then
  echo "Rebuild did not succeed: keeping only the raw card fetch."
  git checkout -q -- data 2>/dev/null || true
  git clean -fdq -- data
  git ls-files --modified -- 'cards/*/verification.json' | xargs -r git checkout -q --
  git ls-files --others --exclude-standard -- 'cards/*/verification.json' | xargs -r rm -f
fi

outside=$(git ls-files --modified --deleted --others --exclude-standard | grep -vE '^(cards|data)/' || true)
if [ -n "${outside}" ]; then
  echo "::error::The run changed files outside cards/ and data/. Refusing to commit: ${outside}"
  exit 1
fi
deleted=$(git ls-files --deleted)
if [ -n "${deleted}" ]; then
  echo "::error::A file was deleted. Refusing to commit: ${deleted}"
  exit 1
fi

title="Weekly review ${REVIEW_DATE:-$(date -u +%Y-%m-%d)} (checks failed)"
if [ -n "${TITLE_FILE:-}" ] && [ -s "${TITLE_FILE}" ]; then
  title=$(cat "${TITLE_FILE}")
fi
body_file="${BODY_FILE:-}"
if [ -z "${body_file}" ] || [ ! -s "${body_file}" ]; then
  body_file=$(mktemp)
  printf '## Checks failed\n\nThe review description could not be written. See the run log.\n' > "${body_file}"
fi

git switch -q -C "${BRANCH}"
git add cards data
if git diff --cached --quiet; then
  echo "Nothing changed since main; no pull request needed."
  exit 0
fi
git -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -q -m "${title} (run ${GITHUB_RUN_ID:-local})"
git push -q --force "${PUSH_REMOTE}" "${BRANCH}"

existing=$(${GH} pr list --repo "${GITHUB_REPOSITORY}" --head "${BRANCH}" --state open \
  --json number --jq '.[0].number // empty')
if [ -n "${existing}" ]; then
  ${GH} pr edit "${existing}" --repo "${GITHUB_REPOSITORY}" --title "${title}" --body-file "${body_file}"
else
  ${GH} pr create --repo "${GITHUB_REPOSITORY}" --base main --head "${BRANCH}" \
    --title "${title}" --body-file "${body_file}"
fi
