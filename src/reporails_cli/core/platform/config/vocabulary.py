"""Loader for the bundled capability keyword vocabulary.

Lives in the platform layer so both ``core/classify`` (the classifier's
capability resolver) and ``core/platform/adapters`` (the read-side rule query)
read one source instead of hand-keeping a mirror. Reads
``bundled/lexicon/capabilities.yml`` via the cached ``load_yaml_file`` helper
and shape-validates it against ``CapabilityVocabulary``.
"""

from __future__ import annotations

from functools import lru_cache

from reporails_cli.bundled import get_lexicon_path
from reporails_cli.core.platform.dto.lexicon import CapabilityVocabulary
from reporails_cli.core.platform.utils.utils import load_yaml_file

_CAPABILITIES_FILE = "capabilities.yml"


@lru_cache(maxsize=1)
def load_capability_vocabulary() -> CapabilityVocabulary:
    """The bundled capability vocabulary, read and validated once per process."""
    return CapabilityVocabulary.model_validate(load_yaml_file(get_lexicon_path() / _CAPABILITIES_FILE))
