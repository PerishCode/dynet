#!/usr/bin/env bash
set -euo pipefail

if [ -z "${GH_TOKEN:-}" ]; then
  echo "GH_TOKEN is required" >&2
  exit 1
fi

if [ -z "${GITHUB_REPOSITORY:-}" ] || [ -z "${GITHUB_RUN_ID:-}" ]; then
  echo "GITHUB_REPOSITORY and GITHUB_RUN_ID are required" >&2
  exit 1
fi

artifacts_url="repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/artifacts"
ids=$(gh api "$artifacts_url" --jq '.artifacts[].id')

for id in $ids; do
  gh api --method DELETE "repos/${GITHUB_REPOSITORY}/actions/artifacts/${id}" >/dev/null
done
