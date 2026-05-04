#!/usr/bin/env bash
# Verify pyproject.toml and packages/npm/package.json agree on shared metadata.
# Exits non-zero on divergence; meant to gate releases via pre-release-check.sh.
#
# Compared fields: version, description, keywords, homepage, bug-tracker, repository
# Package-manager-specific fields (Documentation URL, dependencies, bin, engines)
# are skipped — see .claude/rules/config-sync.md for the full table.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYPROJECT="$ROOT/pyproject.toml"
NPM="$ROOT/packages/npm/package.json"

if [ ! -f "$PYPROJECT" ] || [ ! -f "$NPM" ]; then
  echo "ERROR: missing $PYPROJECT or $NPM" >&2
  exit 2
fi

python3 - "$PYPROJECT" "$NPM" <<'PY'
import json, re, sys, tomllib
from pathlib import Path

pyproject_path, npm_path = sys.argv[1], sys.argv[2]
pyproject = tomllib.loads(Path(pyproject_path).read_text())
npm = json.loads(Path(npm_path).read_text())

py = pyproject.get("project", {})
py_urls = {k.lower(): v for k, v in py.get("urls", {}).items()}

mismatches = []

def check(label, py_value, npm_value):
    if py_value != npm_value:
        mismatches.append(f"  {label}: pyproject={py_value!r}  npm={npm_value!r}")

check("version", py.get("version"), npm.get("version"))
check("description", py.get("description"), npm.get("description"))
check("keywords", py.get("keywords") or [], npm.get("keywords") or [])
check("homepage", py_urls.get("homepage"), npm.get("homepage"))

py_bugs = py_urls.get("bug tracker") or py_urls.get("issues")
npm_bugs = (npm.get("bugs") or {}).get("url") if isinstance(npm.get("bugs"), dict) else npm.get("bugs")
check("bug tracker", py_bugs, npm_bugs)

py_repo = py_urls.get("repository") or py_urls.get("source")
npm_repo = (npm.get("repository") or {}).get("url") if isinstance(npm.get("repository"), dict) else npm.get("repository")
# Allow git+ prefix and trailing .git on either side
def normalize_repo(u):
    if not u:
        return u
    u = re.sub(r"^git\+", "", u)
    u = re.sub(r"\.git$", "", u)
    return u
check("repository", normalize_repo(py_repo), normalize_repo(npm_repo))

if mismatches:
    print("Config sync FAILED — pyproject.toml and packages/npm/package.json diverge:")
    for m in mismatches:
        print(m)
    sys.exit(1)

# Verify the root README carries the current version in its first heading.
# packages/npm/README.md is a symlink to this file (committed under our control),
# so checking it separately would be redundant.
expected_ver = py.get("version", "")
readme_root = Path(pyproject_path).parent / "README.md"
first_heading = ""
for line in readme_root.read_text().splitlines():
    if line.startswith("#"):
        first_heading = line
        break
if f"v{expected_ver}" not in first_heading:
    print(f"README sync FAILED — README.md heading {first_heading!r} missing 'v{expected_ver}'")
    sys.exit(1)

print(f"OK — configs and README agree on shared metadata (version {expected_ver})")
PY
