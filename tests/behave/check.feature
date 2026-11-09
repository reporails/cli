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

  @e2e @regression
  Scenario: A folder inside a git repository is not reported as untracked
    Given a git project with a "sub/CLAUDE.md" and no ".git" in "sub"
    When I run "ails check" on the project's "sub" folder from outside the project
    Then the check exits 0
    And the run reports no "CORE:G:0001" finding

  @e2e @regression
  Scenario: A folder with no git repository above it is reported as untracked
    Given a project folder with a CLAUDE.md and no git repository above it
    When I run "ails check --format json"
    Then the check exits 0
    And the run reports a "CORE:G:0001" finding

  @e2e @regression
  Scenario: A file inside the folder the command runs in keeps that folder as the project root
    Given a git project whose "sub/CLAUDE.md" has findings that the project config disables
    When I run "ails check sub/CLAUDE.md --format json"
    Then the check exits 0
    And that file carries none of the disabled rules

  @e2e @regression
  Scenario: A file in another project folder roots at its own folder
    Given a git project "proj" elsewhere with a CLAUDE.md and a "docs/CLAUDE.md"
    When I run "ails check" on "proj/CLAUDE.md" from the folder beside it
    Then the check exits 0
    And the json files map contains only "CLAUDE.md"
    When I run "ails check" on "proj/docs/CLAUDE.md" from the folder beside it
    Then the json files map contains only "CLAUDE.md"

  @e2e @regression
  Scenario: A rule file checked from outside its project says it is not listed there
    Given a git project "proj" elsewhere with a ".claude/rules/x.md" rule file
    When I run "ails check" on "proj/.claude/rules/x.md" from the folder beside it
    Then the check exits 0
    And the notice names "proj/.claude/rules/x.md" and says to run ails check in the project's folder

  @e2e @regression
  Scenario: A folder inside ~/.claude checks only that folder
    Given a home agent folder with a CLAUDE.md and a "skills/demo/SKILL.md"
    When I run "ails check" on the home "skills" folder from a project folder
    Then the check exits 0
    And the json files map contains only "skills/demo/SKILL.md"

  @e2e @regression
  Scenario: A rule file linked from outside its project is checked within that project
    Given a git project whose ".claude/rules/style.md" links to a file outside it
    When I run "ails check" on the linked file from the project folder
    Then the check exits 0
    And the run checked ".claude/rules/style.md" relative to its project root
    And the output does not say the file is not an instruction file

  @e2e @regression
  Scenario: A dotfiles-linked file under ~/.claude keeps its user-level root
    Given a home rule file that links to a dotfiles folder
    When I run "ails check" on the linked home rule file from a project folder
    Then the check exits 0
    And the run checked "rules/style.md" relative to its project root
    And the output does not say the file is not an instruction file

  @e2e @regression
  Scenario: No target inside a ~/.claude folder checks that folder like a dot does
    Given a home agent folder with a CLAUDE.md and a "skills/demo/SKILL.md"
    When I run "ails check" with no target from the home "skills" folder
    Then the check exits 0
    And the json files map contains only "skills/demo/SKILL.md"

  @e2e @regression
  Scenario: A file in the folder the command runs in is not told to move
    Given a git project with a "docs/guide.md" that is not an instruction file
    When I run "ails check docs/guide.md"
    Then the notice says "docs/guide.md" is not an instruction file of this project, with no advice to move
