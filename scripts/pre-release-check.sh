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
VENV=$(mktemp -d)/venv
python3 -m venv "$VENV"
"$VENV/bin/pip" install dist/*.whl --quiet || fail "Wheel install failed"
"$VENV/bin/ails" version || fail "ails command not found"
"$VENV/bin/ails" check --help > /dev/null || fail "ails check --help failed"
ok "Wheel installs and runs"

# 5b. Verify all expected entry points exist
step "Verify entry points"
for cmd in ails reporails-cli reporails-mcp; do
  "$VENV/bin/$cmd" --help > /dev/null 2>&1 || fail "Entry point '$cmd' not found or broken"
done
ok "All entry points present"

# 6. Verify ONNX model bundled
step "Verify ONNX model"
"$VENV/bin/python" -c "
from reporails_cli.bundled import get_models_path
onnx = get_models_path() / 'minilm-l6-v2' / 'onnx' / 'model.onnx'
assert onnx.exists(), f'ONNX model missing: {onnx}'
print(f'  {onnx.stat().st_size / 1024 / 1024:.0f} MB')
" || fail "ONNX model not bundled in wheel"
ok "ONNX model present"

# 7. Verify content checks actually produce findings
step "Verify content checks"
SMOKE_DIR=$(mktemp -d)
cat > "$SMOKE_DIR/CLAUDE.md" << 'FIXTURE'
# My Project

Use `npm run build` to build the project.

NEVER commit secrets or API keys.
FIXTURE
RESULT=$("$VENV/bin/ails" check "$SMOKE_DIR" -f json 2>/dev/null) || true
CLIENT=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stats',{}).get('client_check_count',0))")
[ "$CLIENT" -gt 0 ] || fail "Content checks not running (client_check_count=$CLIENT). A runtime dependency may be missing."
ok "Content checks producing $CLIENT findings"
rm -rf "$SMOKE_DIR"

# Cleanup
rm -rf "$(dirname "$VENV")"

echo -e "\n${GREEN}All pre-release checks passed.${RESET}"
