Feature: `ails check` reports the targets it did not check, and names what it was given
  Named targets that nothing was checked for are reported by name in every format.

  @e2e @regression
  Scenario: A folder whose markdown a setting leaves out is reported as excluded
    Given a git project that sets exclude_dirs to "prompts", a folder holding "review.md"
    When I run "ails check" on the named target "prompts" as json
    Then the json not_evaluated lists "prompts" with the reason "excluded"
    When I run "ails check" on the named target "prompts" as text
    Then the output says the markdown of "prompts" is left out by exclude_dirs

  @e2e @regression
  Scenario: A named imported file keeps the class and loading of its importer
    Given a git project whose CLAUDE.md imports "docs/extra.md" under generic_scanning
    Then the text run of "docs/extra.md" shows it as Imported and not as an unlisted file

  @e2e @regression
  Scenario: A target nothing was checked for is reported in the github format
    Given a git project with an "assets" folder holding only an image
    When I run "ails check" on the named target "assets" as github
    Then the output names "assets" as not checked
    Given a git copilot project with a "prompts" folder
    When I run "ails check" with agent "copilot" on the named target "@nosuchthing" as github
    Then the output names "@nosuchthing" as not checked

  @e2e @regression
  Scenario: A file named with an upper-case extension is not a markdown file
    Given a git project with a "prompts/Up.MD" file
    When I run "ails check" on the named target "prompts/Up.MD" as json
    Then the json not_evaluated lists "prompts/Up.MD" with the reason "not_markdown"

  @e2e @regression
  Scenario: A capability with no files is reported by name
    Given a git copilot project with no skill files
    When I run "ails check" on the named target "skills" as json
    Then the json not_evaluated lists "skills" with the reason "no_files"
    When I run "ails check" on the named target "skills" as text
    Then the output names "skills" as not checked
    And the output does not ask to create an instruction file

  @e2e @regression
  Scenario: A folder linked to a folder outside the project is checked for the markdown it holds
    Given a git project whose "linked" folder links to a folder outside it that holds "notes.md"
    When I run "ails check" on the named target "linked" as json
    Then the json checks a file named "notes.md" and lists "linked" as not checked for no reason

  @e2e @regression
  Scenario: A capability the agent lacks is listed as not checked and the run exits 2
    Given a git copilot project with a "prompts" folder
    When I run "ails check" with agent "copilot" on the named target "@skils" as json
    Then the json not_evaluated lists "@skils" with the reason "unknown_capability"
    And the exit code is 2

  @e2e @regression
  Scenario: A file and a folder named together are both checked
    Given a git project with a "docs" folder holding "guide.md"
    When I run "ails check" on the named targets "CLAUDE.md" and "docs" as json
    Then the json files map contains "docs/guide.md"


  @e2e @regression
  Scenario: A settings file of another project is listed as that project's file
    Given a project "proj" elsewhere with a ".claude/settings.json" and a folder outside it
    When I run "ails check" on that settings file as json
    Then the json not_evaluated lists that settings file with the reason "other_project"
    When I run "ails check" on that settings file as text
    Then the output says to run ails check in that project's folder

  @e2e @regression
  Scenario: A user-level settings file is checked
    Given a git project and a user-level "~/.claude/settings.json" beside a user CLAUDE.md
    When I run "ails check" on that settings file as json
    Then the json checks "settings.json" and lists nothing as not checked

  @e2e @regression
  Scenario: An empty project named from another folder gets the usual empty-run result
    Given an empty git project "emptyproj" and a git project beside it to run from
    When I run "ails check" on the empty project by its path as text
    Then the output says no instruction files were found and asks to create an AGENTS.md
    And the output lists no target as not checked
    When I run "ails check" on the empty project by its path as json
    Then the json not_evaluated is empty

  @e2e @regression
  Scenario: A folder with no markdown in a project with no instruction file keeps the usual result and is listed
    Given an empty git project with a "docs" folder holding only "readme.txt"
    When I run "ails check" on the named target "docs" as text
    Then the output says no instruction files were found and asks to create an AGENTS.md
    And the output names "docs" as not checked
    When I run "ails check" on the named target "docs" as json
    Then the json not_evaluated lists "docs" with the reason "no_markdown"
