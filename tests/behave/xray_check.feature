Feature: The x-ray page checks a rule file written while it is open

  @e2e
  Scenario: A rule file added after the page's first check is checked by the page's next check call
    Given a project with a recorded Claude Code session
    And the project's instruction file reads "Run `pytest tests/ -v` before every commit."
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    When the page is asked to check "CLAUDE.md"
    And the file ".claude/rules/new.md" is written and loaded by the session, reading "maybe you could possibly consider perhaps running tests sometimes"
    And the page is asked to check ".claude/rules/new.md"
    Then the page's findings for ".claude/rules/new.md" are not empty
    And they are the rule and line pairs "ails check .claude/rules/new.md --offline --format json" reports for it
