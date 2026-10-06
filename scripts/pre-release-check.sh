#!/usr/bin/env bash
# Pre-release verification — mirrors the release workflow gates locally.
# Run before pushing a release branch to catch errors that would fail CI.
#
# Usage: ./scripts/pre-release-check.sh
#        Or automatically via .git/hooks/pre-push (see bottom of script)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
DIM='\033[2m'
RESET='\033[0m'

step() { echo -e "\n${GREEN}▶ $1${RESET}"; }
fail() { echo -e "${RED}✗ $1${RESET}"; exit 1; }
ok()   { echo -e "${GREEN}✓ $1${RESET}"; }

cd "$(git rev-parse --show-toplevel)"

# 1. Lint + type check
step "Ruff lint"
uv run ruff check src/ tests/ || fail "ruff check failed"
ok "Lint clean"

step "Mypy (host + win32)"
# Separate cache dirs so each platform stays warm across runs.
# Cold: ~50s combined. Warm: ~3s combined.
uv run mypy src/ || fail "mypy failed (host)"
uv run mypy --platform=win32 --cache-dir=.mypy_cache_win32 src/ || fail "mypy failed (win32) — Windows type-stub gap will break Windows CI"
ok "Types clean (host + win32)"

# 2. Unit tests
step "Unit tests"
uv run pytest tests/unit/ -q || fail "Unit tests failed"
ok "Unit tests passed"

# 3. Build wheel (directly, not via sdist)
step "Build wheel"
rm -rf dist/
uv build --wheel || fail "Wheel build failed"
ok "Wheel built: $(ls -lh dist/*.whl | awk '{print $5}')"

# 4. Verify no direct URL dependencies (PyPI rejects these)
step "Check for direct URL dependencies"
uv run python -c "
from pathlib import Path
import zipfile, re
whl = list(Path('dist').glob('*.whl'))[0]
with zipfile.ZipFile(whl) as z:
    meta = [n for n in z.namelist() if n.endswith('/METADATA')][0]
    text = z.read(meta).decode()
    directs = re.findall(r'^Requires-Dist:.*@\s*https?://.*$', text, re.MULTILINE)
    if directs:
        for d in directs:
            print(f'  BLOCKED: {d.strip()}')
        raise SystemExit('Direct URL dependencies found — PyPI will reject this wheel')
    print('  No direct URL dependencies')
" || fail "Direct URL dependency check failed"
ok "PyPI-compatible dependencies"

# 5. Verify wheel install
step "Verify wheel install"
# pyproject `requires-python` constrains the install (currently >=3.12,<3.14).
# Pick an in-range Python explicitly so this test doesn't break on dev machines
# whose default `python3` lies outside the pin (e.g. Homebrew Python 3.14).
PYTHON_FOR_TEST=""
for cand in python3.12 python3.13; do
  if command -v "$cand" >/dev/null 2>&1; then
    PYTHON_FOR_TEST="$cand"
    break
  fi
done
[ -n "$PYTHON_FOR_TEST" ] || fail "No supported Python (3.12 or 3.13) on PATH (pyproject requires-python = '>=3.12,<3.14')"
VENV=$(mktemp -d)/venv
"$PYTHON_FOR_TEST" -m venv "$VENV"
"$VENV/bin/pip" install dist/*.whl --quiet || fail "Wheel install failed"
"$VENV/bin/ails" version || fail "ails command not found"
"$VENV/bin/ails" check --help > /dev/null || fail "ails check --help failed"
ok "Wheel installs and runs (under $PYTHON_FOR_TEST)"

# 5b. Verify all expected entry points exist
step "Verify entry points"
for cmd in ails reporails-cli reporails-mcp; do
  "$VENV/bin/$cmd" --help > /dev/null 2>&1 || fail "Entry point '$cmd' not found or broken"
done
ok "All entry points present"

# 6. Lean wheel: no model files ship in it. The first run fetches the model set
#    from the default host into the user cache and checks every file against its
#    pinned checksum — the path a fresh install takes, so an unreachable host or a
#    mismatched upload fails here, before the release.
#    This step runs under its own fresh HOME, never the caller's: the caller's
#    real ~/.reporails cache is very likely already warm, which would make this
#    step a silent no-op that never actually exercises the download it promises.
step "Verify lean wheel + first-run model fetch"
MODEL_HOME=$(mktemp -d)
HOME="$MODEL_HOME" "$VENV/bin/python" -c "
import glob, zipfile
names = zipfile.ZipFile(glob.glob('dist/*.whl')[0]).namelist()
heavy = [n for n in names if n.endswith('.onnx')]
assert not heavy, f'model files in the lean wheel: {heavy}'
from reporails_cli.bundled import ensure_models_available
root = ensure_models_available()
assert root is not None, 'model download is switched off (AILS_MODEL_OFFLINE is set)'
onnx = root / 'minilm-l6-v2' / 'onnx' / 'model.onnx'
assert onnx.exists(), f'ONNX model missing after the first-run fetch: {onnx}'
print(f'  lean wheel; model set at {root}')
" || fail "lean wheel / first-run model fetch failed"
ok "Lean wheel; model set fetched and verified (fresh HOME: $MODEL_HOME)"

# 6b. Verify the fetched model set is complete: an incomplete set leaves the
# classifier inert at runtime.
step "Verify classifier model"
HOME="$MODEL_HOME" "$VENV/bin/python" -c "
from reporails_cli.core.mapper import bio_tagger as b
multislot_ok = b.multislot_available()
print(f'  classifier available: {multislot_ok}')
assert multislot_ok, 'classifier files missing from the model set'
" || fail "classifier files missing from the model set — the classifier would be inert at runtime"
ok "Classifier model present"

# 7. Verify content checks actually produce findings
#    The assertion below (client_check_count > 0) is a purely LOCAL statistic, so
#    this step never needs a remote endpoint — and must never silently reach the
#    default production host. Endpoint resolution, in order:
#      1. AILS_SERVER_URL exported by the caller  -> honoured verbatim
#      2. a local dev server answering /health    -> used, in dev mode
#      3. neither                                 -> fully offline, announced loudly
step "Verify content checks"
LOCAL_SERVER="${AILS_LOCAL_SERVER_URL:-http://localhost:8001}"
if [ -n "${AILS_SERVER_URL:-}" ]; then
  CHECK_SERVER_URL="$AILS_SERVER_URL"
  CHECK_DEV_MODE="${AILS_DEV_MODE:-}"
  echo -e "  ${DIM}endpoint: AILS_SERVER_URL from the environment${RESET}"
elif command -v curl >/dev/null 2>&1 && curl -fsS --connect-timeout 2 --max-time 5 "$LOCAL_SERVER/health" >/dev/null 2>&1; then
  CHECK_SERVER_URL="$LOCAL_SERVER"
  CHECK_DEV_MODE="true"
  echo -e "  ${DIM}endpoint: local dev server at $LOCAL_SERVER${RESET}"
else
  # An empty URL selects the hosted service, so point at a closed local
  # address: the check stays on this machine and server diagnostics fail fast.
  CHECK_SERVER_URL="http://127.0.0.1:9"
  CHECK_DEV_MODE=""
  echo -e "${RED}  ▲ NOTICE: no AILS_SERVER_URL and no local server — running OFFLINE.${RESET}"
  echo -e "${RED}    Server-side diagnostics are NOT exercised by this gate. The${RESET}"
  echo -e "${RED}    client-check assertion below still runs and still blocks the push.${RESET}"
  echo -e "${RED}    Export AILS_SERVER_URL to cover the server half as well.${RESET}"
fi
SMOKE_DIR=$(mktemp -d)
cat > "$SMOKE_DIR/CLAUDE.md" << 'FIXTURE'
# My Project

Use `npm run build` to build the project.

NEVER commit secrets or API keys.
FIXTURE
RESULT=$(HOME="$MODEL_HOME" AILS_SERVER_URL="$CHECK_SERVER_URL" AILS_DEV_MODE="$CHECK_DEV_MODE" \
  "$VENV/bin/ails" check "$SMOKE_DIR" -f json 2>/dev/null) || true
# Parse with the verification venv's own interpreter — a bare `python3` is
# whatever the host happens to ship and may not satisfy requires-python.
CLIENT=$(echo "$RESULT" | "$VENV/bin/python" -c "import sys,json; print(json.load(sys.stdin).get('stats',{}).get('client_check_count',0))")
[ "$CLIENT" -gt 0 ] || fail "Content checks not running (client_check_count=$CLIENT). A runtime dependency may be missing."
ok "Content checks producing $CLIENT findings"
rm -rf "$SMOKE_DIR"

# 8. Branch ↔ version alignment — if HEAD is a release branch named X.Y.Z,
#    pyproject.version must match. Catches "branch cut but never bumped"
#    drift before release.
step "Branch ↔ version alignment"
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
PYPROJECT_VERSION=$(grep '^version' pyproject.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
if echo "$BRANCH" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  if [ "$BRANCH" = "$PYPROJECT_VERSION" ]; then
    ok "Branch $BRANCH matches pyproject.version $PYPROJECT_VERSION"
  else
    fail "Branch $BRANCH but pyproject.version is $PYPROJECT_VERSION — bump pyproject (and packages/npm/package.json + both READMEs) to match the branch"
  fi
else
  echo -e "  ${DIM}skipped (branch '$BRANCH' is not a release branch)${RESET}"
fi

# 9. Config + README sync — pyproject.toml ↔ packages/npm/package.json + READMEs
step "Config + README sync"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if SYNC_OUT=$("$SCRIPT_DIR/check-config-sync.sh" 2>&1); then
  echo -e "$SYNC_OUT" | tail -1 | sed 's/^/  /'
  ok "Configs in sync"
else
  echo -e "$SYNC_OUT" | sed 's/^/  /'
  fail "pyproject.toml / package.json / READMEs out of sync"
fi

# Cleanup
rm -rf "$(dirname "$VENV")"
rm -rf "$MODEL_HOME"

echo -e "\n${GREEN}All pre-release checks passed.${RESET}"
