Feature: `ails check` flags a healed file that has slipped since the heal
  After a heal keeps a file, a later plain `ails check` says which healed file now
  scores lower or has its findings back; a file that held up stays quiet, and a
  project nobody healed shows nothing. The scenarios drive the REAL `ails` binary
  offline, so the comparison is on findings.

  @e2e
  Scenario: A healed file whose findings came back is named in the text and the JSON output
    Given a git project with two files that have findings
    And a heal record that holds "CLAUDE.md" with no findings and ".claude/rules/style.md" as the run finds it
    When I run "ails check --offline"
    Then the output has one "Since the last heal:" line, for "CLAUDE.md", naming its findings back
    When I run "ails check --offline --format json"
    Then the JSON "heal_regressions" names only "CLAUDE.md" with the rules that grew

  @e2e
  Scenario: A project with no heal record shows nothing
    Given a git project with two files that have findings
    When I run "ails check --offline"
    Then the output has no "Since the last heal:" line
    When I run "ails check --offline --format json"
    Then the JSON "heal_regressions" is empty
