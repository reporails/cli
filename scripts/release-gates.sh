#!/usr/bin/env bash
# Release gates — run the structural, architecture and release checks on the
# committed HEAD, then record the commit they passed on. The pre-push hook lets
# `main` and version-branch pushes through only for that recorded commit.
#
# Usage: uv run poe release_gates

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ -n "$(git status --porcelain)" ]; then
  echo "release-gates: the working tree has uncommitted changes; commit or stash them first." >&2
  exit 1
fi

sha=$(git rev-parse HEAD)

uv run poe pylint_struct
uv run poe arch
uv run poe test_markers
bash scripts/pre-release-check.sh

if [ "$(git rev-parse HEAD)" != "$sha" ] || [ -n "$(git status --porcelain)" ]; then
  echo "release-gates: HEAD or the working tree changed during the run; nothing recorded." >&2
  exit 1
fi

echo "$sha" > "$(git rev-parse --git-common-dir)/ails-release-gates-passed"
echo "Release gates passed on ${sha:0:8}; git push will go through."
