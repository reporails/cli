Feature: A rule another rule supersedes reports nothing of its own
  `ails check` runs only each rule's own checks, so a check inherited from a superseded
  rule does not report under the rule that replaced it.

  @e2e @regression
  Scenario: A settings file without hooks is not reported by a rule the run superseded
    Given a git project with CLAUDE.md, AGENTS.md and a ".claude/settings.json" with no hooks
    When I run "ails check --offline -f json"
    Then the json reports no finding for "CORE:S:0027"
    And the json findings per file are the set the run reported before checks were read from parsed rules
