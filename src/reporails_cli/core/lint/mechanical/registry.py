"""Registry mapping a mechanical check's name to the function that runs it."""

from __future__ import annotations

from typing import Any

from reporails_cli.core.lint.mechanical.checks import (
    byte_size,
    directory_contains,
    directory_exists,
    file_count,
    file_exists,
    frontmatter_key,
    git_tracked,
    line_count,
)
from reporails_cli.core.lint.mechanical.checks_absent import content_absent, file_absent
from reporails_cli.core.lint.mechanical.checks_advanced import (
    aggregate_byte_size,
    count_at_least,
    count_at_most,
    directory_file_types,
    extract_imports,
    filename_matches_pattern,
    frontmatter_extra_keys,
    frontmatter_matches_dirname,
    frontmatter_present,
    frontmatter_valid_glob,
    frontmatter_valid_yaml,
    import_depth,
    path_resolves,
    skill_entrypoint_present,
    valid_markdown,
)
from reporails_cli.core.lint.mechanical.checks_links import (
    check_import_targets_exist,
    check_markdown_link_targets_exist,
    extract_markdown_links,
)
from reporails_cli.core.lint.mechanical.hook_handlers import hook_handlers

# Registry of mechanical checks
MECHANICAL_CHECKS: dict[str, Any] = {
    "file_exists": file_exists,
    "directory_exists": directory_exists,
    "directory_contains": directory_contains,
    "git_tracked": git_tracked,
    "frontmatter_key": frontmatter_key,
    "frontmatter_present": frontmatter_present,
    "frontmatter_valid_yaml": frontmatter_valid_yaml,
    "valid_markdown": valid_markdown,
    "file_count": file_count,
    "line_count": line_count,
    "byte_size": byte_size,
    "path_resolves": path_resolves,
    "extract_imports": extract_imports,
    "aggregate_byte_size": aggregate_byte_size,
    "import_depth": import_depth,
    "directory_file_types": directory_file_types,
    "frontmatter_valid_glob": frontmatter_valid_glob,
    "content_absent": content_absent,
    "count_at_most": count_at_most,
    "count_at_least": count_at_least,
    "check_import_targets_exist": check_import_targets_exist,
    "extract_markdown_links": extract_markdown_links,
    "check_markdown_link_targets_exist": check_markdown_link_targets_exist,
    "file_absent": file_absent,
    "filename_matches_pattern": filename_matches_pattern,
    "frontmatter_extra_keys": frontmatter_extra_keys,
    "frontmatter_matches_dirname": frontmatter_matches_dirname,
    "skill_entrypoint_present": skill_entrypoint_present,
    "hook_handlers": hook_handlers,
    # Aliases for signal catalog naming
    "glob_match": file_exists,
    "max_line_count": line_count,
    "glob_count": file_count,
    # Aliases for rule frontmatter name → check mapping
    "file_tracked": git_tracked,
    "memory_dir_exists": directory_exists,
    "total_size_check": aggregate_byte_size,
}
