Feature: The x-ray Hooks group shows which declared hooks never fire and why

  @e2e @page @browser
  Scenario: A declared hook whose script is not executable reads as never fired, with the fix in its details
    Given a project with a recorded Claude Code session
    And the project's settings declare a hook whose script ran and a hook whose script is not executable
    And the session recorded the first hook running
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the Hooks group header reads fired of declared with "1 cannot fire" and stays closed until opened
    And the broken hook's row reads "never fired · not executable" and the fired hook's row reads its count and last time
    And the broken hook's details open on a Health section naming the event, the matcher and "chmod +x" for its script
    And the Sources table says the same phrase in the In context column and the page added no tab

  @e2e @page @browser
  Scenario: A hook that fired in an earlier session says so instead of never fired
    Given a project with a recorded Claude Code session
    And the project's settings declare a hook whose script ran and a hook whose script is not executable
    And the session recorded the first hook running
    And an earlier session of the project recorded the second hook running
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the second hook's row names the earlier session and its time and does not read never fired

  @e2e @page @browser
  Scenario: The page makes no call to any server beside the one serving it
    Given a project with a recorded Claude Code session
    And the project's settings declare a hook whose script ran and a hook whose script is not executable
    And the session recorded the first hook running
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And every request the page made went to the address that served it
