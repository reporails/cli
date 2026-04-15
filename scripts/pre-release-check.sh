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

step "Mypy"
uv run mypy src/ || fail "mypy failed"
ok "Types clean"

# 2. Unit tests
step "Unit tests"
uv run pytest tests/unit/ -q || fail "Unit tests failed"
ok "Unit tests passed"

# 3. Build wheel (directly, not via sdist)
step "Build wheel"
rm -rf dist/
uv build --wheel || fail "Wheel build failed"
ok "Wheel built: $(ls -lh dist/*.whl | awk '{print $5}')"

# 4. Twine metadata check
step "Twine metadata check"
uv run --with "twine>=5,<6" twine check dist/* || fail "Twine check failed"
ok "PyPI metadata valid"

# 5. Verify wheel install
step "Verify wheel install"
VENV=$(mktemp -d)/venv
python3 -m venv "$VENV"
"$VENV/bin/pip" install dist/*.whl --quiet || fail "Wheel install failed"
"$VENV/bin/ails" version || fail "ails command not found"
"$VENV/bin/ails" check --help > /dev/null || fail "ails check --help failed"
ok "Wheel installs and runs"

# 6. Verify ONNX model bundled
step "Verify ONNX model"
"$VENV/bin/python" -c "
from reporails_cli.bundled import get_models_path
onnx = get_models_path() / 'minilm-l6-v2' / 'onnx' / 'model.onnx'
assert onnx.exists(), f'ONNX model missing: {onnx}'
print(f'  {onnx.stat().st_size / 1024 / 1024:.0f} MB')
" || fail "ONNX model not bundled in wheel"
ok "ONNX model present"

# Cleanup
rm -rf "$(dirname "$VENV")"

echo -e "\n${GREEN}All pre-release checks passed.${RESET}"
