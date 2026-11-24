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
