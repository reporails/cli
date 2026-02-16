"""Init command - downloads rules framework.

Core logic has been split into:
- download.py: Download and install rules, recommended packages
- updater.py: Update rules and recommended to latest/specific versions

This module keeps run_init() and re-exports all public names for backward
compatibility (existing imports and mock patches targeting
``reporails_cli.core.init.*`` continue to work).
"""

from __future__ import annotations

from pathlib import Path

import httpx as httpx

from reporails_cli.core.bootstrap import (
    get_installed_version as get_installed_version,
)
from reporails_cli.core.bootstrap import (
    get_recommended_package_path as get_recommended_package_path,
)
from reporails_cli.core.bootstrap import (
    get_reporails_home as get_reporails_home,
)
from reporails_cli.core.download import (
    RECOMMENDED_API_URL as RECOMMENDED_API_URL,
)
from reporails_cli.core.download import (
    RECOMMENDED_REPO as RECOMMENDED_REPO,
)
from reporails_cli.core.download import (
    RECOMMENDED_VERSION as RECOMMENDED_VERSION,
)
from reporails_cli.core.download import (
    RULES_API_URL as RULES_API_URL,
)
from reporails_cli.core.download import (
    RULES_TARBALL_URL as RULES_TARBALL_URL,
)
from reporails_cli.core.download import (
    RULES_VERSION as RULES_VERSION,
)
from reporails_cli.core.download import (
    copy_bundled_yml_files as copy_bundled_yml_files,
)
from reporails_cli.core.download import (
    copy_local_framework as copy_local_framework,
)
from reporails_cli.core.download import (
    download_from_github as download_from_github,
)
from reporails_cli.core.download import (
    download_recommended as download_recommended,
)
from reporails_cli.core.download import (
    download_rules as download_rules,
)
from reporails_cli.core.download import (
    download_rules_tarball as download_rules_tarball,
)
from reporails_cli.core.download import (
    get_bundled_checks_path as get_bundled_checks_path,
)
from reporails_cli.core.download import (
    is_recommended_installed as is_recommended_installed,
)
from reporails_cli.core.download import (
    sync_rules_to_local as sync_rules_to_local,
)
from reporails_cli.core.download import (
    write_version_file as write_version_file,
)
from reporails_cli.core.updater import (
    REQUIRED_SCHEMAS as REQUIRED_SCHEMAS,
)
from reporails_cli.core.updater import (
    IncompatibleSchemaError as IncompatibleSchemaError,
)
from reporails_cli.core.updater import (
    UpdateResult as UpdateResult,
)
from reporails_cli.core.updater import (
    check_manifest_compatibility as check_manifest_compatibility,
)
from reporails_cli.core.updater import (
    download_rules_version as download_rules_version,
)
from reporails_cli.core.updater import (
    get_latest_recommended_version as get_latest_recommended_version,
)
from reporails_cli.core.updater import (
    get_latest_version as get_latest_version,
)
from reporails_cli.core.updater import (
    update_recommended as update_recommended,
)
from reporails_cli.core.updater import (
    update_rules as update_rules,
)


def run_init() -> dict[str, str | int | Path]:
    """Run global initialization.

    Setup rules at ~/.reporails/rules/ (from local framework or GitHub).

    Returns dict with status info.
    """
    results: dict[str, str | int | Path] = {}

    # Setup rules (check local framework_path first, then GitHub)
    rules_path, rule_count = download_rules()
    results["rules_path"] = rules_path
    results["rule_count"] = rule_count

    # Write version file
    write_version_file(RULES_VERSION)
    results["rules_version"] = RULES_VERSION

    return results
