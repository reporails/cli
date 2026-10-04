"""A fault a user can cause is logged with its path and cause, not swallowed silently."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from reporails_cli.core.classify import file_tags
from reporails_cli.core.discovery import agent_discovery
from reporails_cli.core.discovery.features import _count_components
from reporails_cli.core.mapper import inspect as mapper_inspect


@pytest.fixture
def broken_rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A bundled-rules folder holding one agent config that is not valid YAML."""
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "config.yml").write_text("file_types: [unclosed\n  - : :\n", encoding="utf-8")
    monkeypatch.setattr("reporails_cli.core.platform.config.bundled.get_bundled_rules_path", lambda: tmp_path)
    cached = (agent_discovery.root_markers, file_tags._memory_surface_dirs, file_tags._config_surface_patterns)
    for fn in cached:
        fn.cache_clear()
    yield tmp_path
    for fn in cached:
        fn.cache_clear()


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_root_markers_warns_about_an_unreadable_agent_config(broken_rules_dir: Path, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger=agent_discovery.logger.name):
        assert agent_discovery.root_markers() == ()
    assert str(broken_rules_dir / "broken" / "config.yml") in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_memory_surface_dirs_warns_about_an_unreadable_agent_config(broken_rules_dir: Path, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger=file_tags.logger.name):
        file_tags._memory_surface_dirs()
    assert str(broken_rules_dir / "broken" / "config.yml") in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_config_surface_patterns_warns_about_an_unreadable_agent_config(broken_rules_dir: Path, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger=file_tags.logger.name):
        file_tags._config_surface_patterns()
    assert str(broken_rules_dir / "broken" / "config.yml") in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_count_components_warns_when_backbone_is_not_yaml(tmp_path: Path, caplog) -> None:
    backbone = tmp_path / "backbone.yml"
    backbone.write_text("components: [unclosed\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert _count_components(backbone) == 0
    assert str(backbone) in caplog.text
    assert "line 2" in caplog.text
    assert len(caplog.records) == 1
    assert "\n" not in caplog.records[0].getMessage()


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_count_components_of_a_list_backbone_is_zero(tmp_path: Path) -> None:
    backbone = tmp_path / "backbone.yml"
    backbone.write_text("- a\n- b\n", encoding="utf-8")
    assert _count_components(backbone) == 0


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_unreadable_tokenizer_file_is_warned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    from reporails_cli.core.mapper import parse

    models = tmp_path / "minilm-l6-v2"
    models.mkdir()
    (models / "tokenizer.json").write_text("not json", encoding="utf-8")
    monkeypatch.setattr("reporails_cli.bundled.get_models_path", lambda: tmp_path)
    parse._subword_tokenizer.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger=parse.logger.name):
            assert parse._subword_tokenizer() is None
    finally:
        parse._subword_tokenizer.cache_clear()
    assert "tokenizer.json" in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_a_fault_while_reading_credentials_is_not_hidden_by_error_rendering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reporails_cli.formatters.text import funnel_cta

    def boom() -> bool:
        raise RuntimeError("credential store exploded")

    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", boom)
    with pytest.raises(RuntimeError, match="credential store exploded"):
        funnel_cta._has_key()


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_a_project_config_that_is_not_utf8_is_warned_and_defaults_apply(tmp_path: Path, caplog) -> None:
    from reporails_cli.core.classify import _apply_project_overrides
    from reporails_cli.core.platform.config.config import get_project_config

    (tmp_path / ".ails").mkdir()
    config = tmp_path / ".ails" / "config.yml"
    config.write_bytes(b"exclude_dirs: [\xff\xfe]\n")
    with caplog.at_level(logging.WARNING):
        assert get_project_config(tmp_path).exclude_dirs == []
        assert _apply_project_overrides([], "claude", tmp_path) == []
    assert str(config) in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_a_global_config_that_is_not_utf8_is_warned_and_defaults_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    from reporails_cli.core.platform.config.config import get_global_config

    config = tmp_path / "config.yml"
    config.write_bytes(b"tier: \xff\xfe\n")
    monkeypatch.setattr("reporails_cli.core.platform.config.bootstrap.get_global_config_path", lambda: config)
    with caplog.at_level(logging.WARNING):
        assert get_global_config().tier == ""
    assert str(config) in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_a_globs_value_starting_with_a_star_is_read(tmp_path: Path) -> None:
    rule = tmp_path / "r.mdc"
    rule.write_text("---\ndescription: Style\nglobs: *.tsx\n---\nbody\n", encoding="utf-8")
    assert mapper_inspect._parse_frontmatter_globs(rule, "globs") == ("*.tsx",)


def _broken_rule(tmp_path: Path):
    from reporails_cli.core.platform.dto.models import ClassifiedFile

    rule = tmp_path / "r.md"
    rule.write_text("---\nname: ok\npaths: [unclosed\n  - : :\n---\nbody\n", encoding="utf-8")
    return [ClassifiedFile(path=rule, file_type="rule")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_key_and_extra_key_checks_leave_a_block_that_is_not_yaml_to_the_yaml_check(tmp_path: Path) -> None:
    from reporails_cli.core.lint.mechanical.checks import frontmatter_key
    from reporails_cli.core.lint.mechanical.checks_advanced import frontmatter_extra_keys, frontmatter_valid_yaml

    files = _broken_rule(tmp_path)
    assert frontmatter_key(tmp_path, {"key": "paths"}, files).passed
    assert frontmatter_extra_keys(tmp_path, {"allowed": ["paths"]}, files).passed
    result = frontmatter_valid_yaml(tmp_path, {}, files)
    assert result.passed is False
    assert result.occurrences is not None and result.occurrences[0][0] == "r.md:4"


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_a_project_config_that_is_not_yaml_is_reported_once_in_one_line(tmp_path: Path, caplog) -> None:
    from reporails_cli.core.platform.config.config import get_project_config
    from reporails_cli.core.platform.utils.utils import clear_yaml_cache

    clear_yaml_cache()
    (tmp_path / ".ails").mkdir()
    config = tmp_path / ".ails" / "config.yml"
    config.write_text("exclude_dirs: [unclosed\n  x: : y\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            get_project_config(tmp_path)
    clear_yaml_cache()
    assert len(caplog.records) == 1
    assert str(config) in caplog.text
    assert "\n" not in caplog.records[0].getMessage()


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_load_yaml_file_rereads_an_edited_file(tmp_path: Path) -> None:
    from reporails_cli.core.platform.utils.utils import clear_yaml_cache, load_yaml_file

    clear_yaml_cache()
    f = tmp_path / "c.yml"
    f.write_text("a: 1\n", encoding="utf-8")
    assert load_yaml_file(f) == {"a": 1}
    f.write_text("a: 22\n", encoding="utf-8")
    assert load_yaml_file(f) == {"a": 22}
