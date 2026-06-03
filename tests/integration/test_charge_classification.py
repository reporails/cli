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


@pytest.mark.integration
@pytest.mark.subsys_classify
@requires_model
@pytest.mark.parametrize(
    ("text", "expected_cv"),
    [
        # POSITIVES — sentence-initial POS-ambiguous lead token governing a
        # determiner-led object NP, no subject → IMPERATIVE, even when the lead
        # word is absent from the verb lexicon ("pin"/"lock" are missing; the
        # frame, not a lexicon entry, charges them).
        (
            "Pin every dependency to an exact version (use == in "
            "requirements.txt, never a floating range) before you open the PR.",
            1,
        ),
        (
            "Lock every dependency to a fixed point (avoid floating ranges, prefer exact pins) before you publish.",
            1,
        ),
        (
            "Cache the rendered response (keyed by the normalized request path, "
            "not the raw URL, never the session id) on every read.",
            1,
        ),
        (
            "Log the correlation id (the X-Request-ID header, falling back to "
            "the span id, never the raw user token) on every error path.",
            1,
        ),
        # NEGATIVES — the same lead words as the SUBJECT of a finite main verb;
        # ROOT is the finite verb, the lead token is its compound/subject, so
        # the frame does not fire and the atom stays declarative.
        (
            "Lock contention dominates the latency budget (especially under the "
            "new scheduler, worse on hot paths) during peak load.",
            0,
        ),
        (
            "Cache misses are the main cost (after the recent refactor, across read and write paths) in this service.",
            0,
        ),
        # NO REGRESSION — a lexicon verb whose parenthetical derails the parse
        # still charges via the nsubj rescue.
        (
            "Validate the payload against its schema (reject unknown fields, "
            "require all mandatory keys) before you accept it.",
            1,
        ),
    ],
)
def test_determiner_object_frame_charge(text: str, expected_cv: int) -> None:
    _charge, charge_value, _modality, _trace, _sc = classify_charge(text)
    assert charge_value == expected_cv
