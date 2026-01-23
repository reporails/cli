#!/usr/bin/env bash
# Link .md rule files from framework repo to CLI checks/
# Usage: ./scripts/link-rules.sh [framework-path]
#
# Creates symlinks: checks/{category}/{rule}.md → framework/rules/{category}/{rule}.md
# The .md files are gitignored in CLI, so symlinks won't be tracked.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_ROOT="$(dirname "$SCRIPT_DIR")"
CHECKS_DIR="$CLI_ROOT/checks"

# Default framework path (sibling directory)
FRAMEWORK_PATH="${1:-$CLI_ROOT/../framework}"
RULES_DIR="$FRAMEWORK_PATH/rules"

# Validate paths
if [[ ! -d "$RULES_DIR" ]]; then
    echo "Error: Framework rules directory not found: $RULES_DIR"
    echo "Usage: $0 [path-to-framework]"
    exit 1
fi

if [[ ! -d "$CHECKS_DIR" ]]; then
    echo "Error: CLI checks directory not found: $CHECKS_DIR"
    exit 1
fi

echo "Linking rules from: $RULES_DIR"
echo "              to: $CHECKS_DIR"
echo

linked=0

# Find all .md files in framework rules
find "$RULES_DIR" -name "*.md" -type f -print0 | while IFS= read -r -d '' md_file; do
    # Get relative path from rules dir (e.g., structure/S1-size-limits.md)
    relative="${md_file#$RULES_DIR/}"

    # Target symlink location in checks/
    target="$CHECKS_DIR/$relative"
    target_dir="$(dirname "$target")"

    # Ensure target directory exists
    mkdir -p "$target_dir"

    # Remove existing file/symlink if present
    if [[ -e "$target" || -L "$target" ]]; then
        rm "$target"
    fi

    # Create relative symlink
    # Calculate relative path from target dir to source file
    rel_source="$(realpath --relative-to="$target_dir" "$md_file")"
    ln -s "$rel_source" "$target"

    echo "  Linked: $relative"
done

# Also link capability-levels.md (lives at framework root)
CAP_LEVELS_SRC="$FRAMEWORK_PATH/capability-levels.md"
CAP_LEVELS_DEST="$CLI_ROOT/docs/capability-levels.md"

if [[ -f "$CAP_LEVELS_SRC" ]]; then
    rm -f "$CAP_LEVELS_DEST"
    rel_source="$(realpath --relative-to="$CLI_ROOT/docs" "$CAP_LEVELS_SRC")"
    ln -s "$rel_source" "$CAP_LEVELS_DEST"
    echo "  Linked: docs/capability-levels.md"
fi

echo
echo "Done. Symlinks created for all framework docs."
