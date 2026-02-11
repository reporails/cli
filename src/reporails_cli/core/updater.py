"""Update rules and recommended packages to latest or specific versions."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from reporails_cli.core.bootstrap import (
    get_installed_recommended_version,
    get_installed_version,
    get_reporails_home,
)
from reporails_cli.core.download import (
    RECOMMENDED_API_URL,
    RULES_API_URL,
    RULES_TARBALL_URL,
    _safe_extractall,
    _validate_rules_structure,
    copy_bundled_yml_files,
    download_recommended,
    write_version_file,
)

# Schema versions this CLI can consume (match on major.minor, ignore patch).
# Only schemas the CLI reads directly -- others are ignored.
REQUIRED_SCHEMAS: dict[str, str] = {
    "rule": "0.1",
    "levels": "0.1",
    "agent": "0.1",
}


class IncompatibleSchemaError(RuntimeError):
    """Raised when downloaded rules require a newer CLI version."""


def check_manifest_compatibility(rules_path: Path) -> None:
    """Verify manifest.yml schema versions against CLI requirements."""
    import yaml

    manifest_path = rules_path / "manifest.yml"
    if not manifest_path.exists():
        return

    content = manifest_path.read_text(encoding="utf-8")
    manifest = yaml.safe_load(content) or {}
    schemas = manifest.get("schemas", {})

    incompatible = []
    for schema_name, required_prefix in REQUIRED_SCHEMAS.items():
        actual = schemas.get(schema_name)
        if actual is None:
            continue
        actual_prefix = ".".join(actual.split(".")[:2])
        if actual_prefix != required_prefix:
            incompatible.append(f"  {schema_name}: requires {required_prefix}.x, got {actual}")

    if incompatible:
        details = "\n".join(incompatible)
        raise IncompatibleSchemaError(
            f"Rules require schema versions this CLI doesn't support:\n{details}\nUpgrade the CLI to use these rules."
        )


@dataclass
class UpdateResult:
    """Result of an update operation."""

    previous_version: str | None
    new_version: str
    updated: bool
    rule_count: int
    message: str


def download_rules_version(version: str) -> tuple[Path, int]:
    """Download rules for a specific version with staging + schema check."""
    import tarfile

    rules_path = get_reporails_home() / "rules"
    url = RULES_TARBALL_URL.format(version=version)

    with TemporaryDirectory() as tmpdir:
        staging_path = Path(tmpdir) / "rules"
        staging_path.mkdir()

        yml_count = copy_bundled_yml_files(staging_path)

        tarball_path = Path(tmpdir) / "rules.tar.gz"
        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            response = client.get(url)
            response.raise_for_status()
            tarball_path.write_bytes(response.content)

        with tarfile.open(tarball_path, "r:gz") as tar:
            _safe_extractall(tar, staging_path)

        _validate_rules_structure(staging_path)
        check_manifest_compatibility(staging_path)

        # Atomic-ish swap: rename old out, move new in, then remove old
        old_backup = rules_path.with_suffix(".old")
        if old_backup.exists():
            shutil.rmtree(old_backup)
        if rules_path.exists():
            rules_path.rename(old_backup)
        try:
            shutil.move(str(staging_path), str(rules_path))
        except Exception:
            # Restore old rules on failure
            if old_backup.exists():
                old_backup.rename(rules_path)
            raise
        if old_backup.exists():
            shutil.rmtree(old_backup)

        tarball_count = sum(1 for _ in rules_path.rglob("*") if _.is_file())

    write_version_file(version)
    return rules_path, yml_count + tarball_count


def get_latest_version() -> str | None:
    """Fetch the latest rules release version from GitHub API."""
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(RULES_API_URL)
            response.raise_for_status()
            data: dict[str, object] = response.json()
            tag_name = data.get("tag_name")
            return str(tag_name).removeprefix("v") if tag_name else None
    except (httpx.HTTPError, KeyError):
        return None


def get_latest_recommended_version() -> str | None:
    """Fetch the latest recommended release version from GitHub API."""
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(RECOMMENDED_API_URL)
            response.raise_for_status()
            data: dict[str, object] = response.json()
            tag_name = data.get("tag_name")
            return str(tag_name).removeprefix("v") if tag_name else None
    except (httpx.HTTPError, KeyError):
        return None


def update_rules(version: str | None = None, force: bool = False) -> UpdateResult:
    """Update rules to specified version or latest."""
    if version:
        target_version = version.removeprefix("v")
    else:
        latest = get_latest_version()
        if not latest:
            return UpdateResult(
                previous_version=get_installed_version(),
                new_version="unknown",
                updated=False,
                rule_count=0,
                message="Failed to fetch latest version from GitHub.",
            )
        target_version = latest

    current_version = get_installed_version()

    if current_version == target_version and not force:
        return UpdateResult(
            previous_version=current_version,
            new_version=target_version,
            updated=False,
            rule_count=0,
            message=f"Already at version {target_version}.",
        )

    try:
        _rules_path, rule_count = download_rules_version(target_version)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return UpdateResult(
                previous_version=current_version,
                new_version=target_version,
                updated=False,
                rule_count=0,
                message=f"Version {target_version} not found.",
            )
        raise
    except IncompatibleSchemaError as e:
        return UpdateResult(
            previous_version=current_version,
            new_version=target_version,
            updated=False,
            rule_count=0,
            message=str(e),
        )

    return UpdateResult(
        previous_version=current_version,
        new_version=target_version,
        updated=True,
        rule_count=rule_count,
        message=f"Updated from {current_version or 'none'} to {target_version}.",
    )


def update_recommended(version: str | None = None, force: bool = False) -> UpdateResult:
    """Update recommended package to specified version or latest."""
    if version:
        target_version = version.removeprefix("v")
    else:
        latest = get_latest_recommended_version()
        if not latest:
            return UpdateResult(
                previous_version=get_installed_recommended_version(),
                new_version="unknown",
                updated=False,
                rule_count=0,
                message="Failed to fetch latest recommended version from GitHub.",
            )
        target_version = latest

    current_version = get_installed_recommended_version()

    if current_version == target_version and not force:
        return UpdateResult(
            previous_version=current_version,
            new_version=target_version,
            updated=False,
            rule_count=0,
            message=f"Recommended already at version {target_version}.",
        )

    try:
        pkg_path = download_recommended(version=target_version)
        rule_count = sum(1 for _ in pkg_path.rglob("*") if _.is_file())
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return UpdateResult(
                previous_version=current_version,
                new_version=target_version,
                updated=False,
                rule_count=0,
                message=f"Recommended version {target_version} not found.",
            )
        raise

    return UpdateResult(
        previous_version=current_version,
        new_version=target_version,
        updated=True,
        rule_count=rule_count,
        message=f"Recommended updated from {current_version or 'none'} to {target_version}.",
    )
