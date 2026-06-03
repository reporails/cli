"""Charge-classifier regression fixtures for the parenthetical-derail class.

A long multi-clause parenthetical between the lead verb and the rest of the
clause makes spaCy pick an interior word as ROOT and demote the lead verb to
``nsubj``. The position-0 nsubj rescue now covers ambiguous lead verbs when
ROOT lands inside a parenthetical. These cases need the spaCy parse, so they
run only when the bundled model is available (principles §5: no ML in unit
tests).
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.classify import classify_charge
from reporails_cli.core.mapper.models import get_models

requires_model = pytest.mark.skipif(
    get_models().nlp is None,
    reason="Bundled spaCy model not available",
)


@pytest.mark.integration
@pytest.mark.subsys_classify
@requires_model
@pytest.mark.parametrize(
    ("text", "expected_cv"),
    [
        # Target — the reference-the-interface headline directive (cleaned).
        # spaCy roots on "declared" inside the parenthetical; "Reference" is
        # demoted to nsubj and is an ambiguous lead verb.
        (
            "Reference an artifact by its invocable interface (slash-commands, "
            "like /doku, CLI invocation, like doku, declared name, like Entity "
            "or Harness) when one exists;",
            1,
        ),
        # Held-out — a different directive of the same class, not authored for
        # the literal target string. Verified NEUTRAL before the fix.
        (
            "Reference each dependency by its pinned name (ranges, like caret, "
            "exact pins, like 1.2.3, declared peers, like react) when one is "
            "published.",
            1,
        ),
        # Held-out, non-`reference` ambiguous verb — the derail class is not
        # narrow; several ambiguous lead verbs reproduce it. Also NEUTRAL
        # before the fix.
        (
            "Format each record by its pinned name (ranges, like caret, exact "
            "pins, like 1.2.3, declared peers, like react) when one is "
            "published.",
            1,
        ),
        # Control — genuine declarative whose ROOT sits outside any
        # parenthetical; must stay NEUTRAL.
        ("Reference materials cover the protocol, the appendix, and the errata.", 0),
        # Control — a parenthetical aside in a declarative; ROOT is outside the
        # parens, so the in-paren guard does not fire.
        ("Test data (gathered over years, sampled monthly) showed a clear trend.", 0),
    ],
)
def test_parenthetical_derail_charge(text: str, expected_cv: int) -> None:
    _charge, charge_value, _modality, _trace, _sc = classify_charge(text)
    assert charge_value == expected_cv
