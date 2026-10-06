Feature: `ails check` renders findings through the github and text formatters
  A finding is only useful once a formatter renders it. These scenarios drive the
  REAL console script via subprocess and assert on the rendered surface of the two
  human/CI formatters `--format json` never exercises: the GitHub Actions workflow
  commands (`::error` / `::warning`) that annotate a PR, and the default text
  scorecard a user reads in their terminal.

  Each scenario is a GUARD: it reddens the moment its formatter stops emitting the
  shape CI (or the user) depends on.

  @e2e
  Scenario: The github formatter emits GitHub Actions workflow commands
    Given a git project whose CLAUDE.md has error findings
    When I run "ails check --format github"
    Then the check exits 0
    And the output emits GitHub Actions workflow commands

  @e2e
  Scenario: The default text formatter renders the level and a finding count
    Given a git project whose CLAUDE.md has error findings
    When I run "ails check"
    Then the check exits 0
    And the text output shows the level and a finding count
