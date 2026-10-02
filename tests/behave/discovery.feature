Feature: `ails check` discovers, classifies, and ranks instruction surfaces
  Discovery, classification, and level derivation are the composed front of the
  pipeline: `ails` walks a real project, decides which files are instruction
  surfaces, sorts each into its capability surface, and derives an ordinal level
  from the breadth it found. These scenarios drive the REAL console script via
  subprocess against a real project on disk.

  Each scenario is a SEAM or a GUARD: it reddens the moment discovery drops a
  file, classification mislabels a surface, or the level walk stops responding.

  @e2e
  Scenario: Discovery finds every instruction surface and classifies each
    Given a git project with a CLAUDE.md, a rules file, and an agent file
    When I run "ails check --format json"
    Then the check exits 0
    And the json files map contains CLAUDE.md, the rules file, and the agent file
    And the json surfaces classify them as Main, Rules, and Agents

  @e2e
  Scenario: Project level rises as instruction surfaces broaden
    Given a git project with a lone CLAUDE.md
    When I run "ails check --format json"
    And I record the json level
    When I add a rules surface and an agent surface
    And I run "ails check --format json"
    And I record the json level
    Then each recorded level ranks at or above the previous
    And the last recorded level ranks above the first

  @e2e
  Scenario: An empty project exits cleanly with a no-instruction-files message
    Given a git project with no instruction files
    When I run "ails check"
    Then the check exits 0
    And the output reports no instruction files
    And neither stream contains a Python traceback
