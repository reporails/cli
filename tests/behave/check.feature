Feature: `ails check` scores and validates instruction files end-to-end
  `ails check` is the artifact a user (and the CI harness) actually invokes. These
  scenarios drive the REAL `ails` console script via subprocess against a real
  project on disk — the composed discovery → map → classify → score pipeline, exit
  code derivation, and both the text and JSON formatters.

  Each scenario is a SEAM or a GUARD, never a shape assertion: it reddens the
  moment the behavior it demonstrates breaks.

  @e2e
  Scenario: The --strict flag turns findings into a non-zero CI gate
    Given a git project whose CLAUDE.md has error findings
    When I run "ails check"
    Then the check exits 0
    When I run "ails check --strict"
    Then the check exits non-zero

  @e2e @regression
  Scenario: Every JSON finding carries the finding-tuple contract
    Given a git project whose CLAUDE.md has error findings
    When I run "ails check --format json"
    Then the check exits 0
    And every finding carries the keys line, severity, rule, category, message
    And no finding carries a leverage key

  @e2e @regression
  Scenario: Scoring is deterministic across runs and reacts to persisted edits
    Given a git project whose CLAUDE.md has error findings
    When I run "ails check --format json"
    And I run "ails check --format json"
    Then the last two runs report identical findings
    When the CLAUDE.md is rewritten to a richer instruction set
    And I run "ails check --format json"
    Then the findings differ from the first run
