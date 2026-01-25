"""Template loader for CLI output.

Loads and renders text templates for consistent CLI display.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Any


@lru_cache
def load_template(name: str) -> str:
    """Load template file by name.

    Args:
        name: Template filename (e.g., "cli_box.txt")

    Returns:
        Template content as string

    Raises:
        FileNotFoundError: If template doesn't exist
    """
    try:
        return files("reporails_cli.templates").joinpath(name).read_text()
    except FileNotFoundError:
        raise FileNotFoundError(f"Template not found: {name}") from None


def render(template_name: str, **kwargs: Any) -> str:
    """Load and render a template with given variables.

    Args:
        template_name: Template filename
        **kwargs: Variables to substitute

    Returns:
        Rendered template string

    Raises:
        KeyError: If required variable is missing
    """
    template = load_template(template_name)
    try:
        return template.format(**kwargs)
    except KeyError as e:
        raise KeyError(f"Missing template variable {e} in {template_name}") from None


def render_conditional(template_name: str, condition: bool, **kwargs: Any) -> str:
    """Render template only if condition is true.

    Args:
        template_name: Template filename
        condition: Whether to render
        **kwargs: Variables to substitute

    Returns:
        Rendered template or empty string
    """
    if not condition:
        return ""
    return render(template_name, **kwargs)
