Feature: Any session of a project opens in x-ray without typing an id, from a terminal or from inside an agent

  @e2e
  Scenario: A running page lists the project's sessions and serves an older one without a restart
    Given a project with two recorded Claude Code sessions, the older one written first
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page lists both sessions with start time, length and subagent count
    And the older session's view is served by the same running page process

  @e2e @browser
  Scenario: Picking the older session in the page header shows it with no id typed
    Given a project with two recorded Claude Code sessions, the older one written first
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And picking the older session in the header shows that session on the page

  @e2e @windows_unverified
  Scenario: The MCP xray tool returns the page address at once and a second call reuses the page
    Given a project with two recorded Claude Code sessions, the older one written first
    When the MCP server's xray tool is called twice one after the other
    Then the first call answered with an address well inside the page start limit
    And the address's page answers as the x-ray page
    And the second call returned the same port marked reused

  @e2e
  Scenario: Two MCP xray calls at the same moment get the same page
    Given a project with two recorded Claude Code sessions, the older one written first
    When the MCP server's xray tool is called twice at the same moment
    Then both calls returned the same port

  @e2e
  Scenario: A session named by the agent's environment opens even though a newer session exists
    Given a project with two recorded Claude Code sessions, the older one written first
    When "ails xray --current --background --no-open" is run in the project as the agent of the older session
    Then the printed address names the older session
    And the page at that address shows the older session as the current one

  @e2e
  Scenario: Without the agent's session variable the newest session opens and says so
    Given a project with two recorded Claude Code sessions, the older one written first
    When "ails xray --current --background --no-open" is run in the project by an agent that does not say its session
    Then the printed address names the newest session and says the agent did not say which session it is
    And the page at that address shows the newest session marked as not known to be the agent's own

  @e2e
  Scenario: Run in a project subfolder as the agent of the older session, the page opens that session
    Given a project with two recorded Claude Code sessions, the older one written first
    When "ails xray --current --background --no-open" is run in a project subfolder as the agent of the older session
    Then the printed address names the older session
    And the page at that address shows the older session as the current one

  @e2e
  Scenario: A folder with no recorded session is refused naming the folder
    Given a folder with no recorded Claude Code session
    When "ails xray --no-open" is run in that folder
    Then it exits 2 naming the folder and where Claude Code was started

  @e2e
  Scenario: A page started in the background stops by itself once no request has come for its idle window
    Given a project with two recorded Claude Code sessions, the older one written first
    When "ails xray --current --background --no-open" is run in the project with a 2 second idle window
    Then the printed address answers as the x-ray page
    And within 15 seconds the page no longer answers and the project has no page record

  @e2e
  Scenario: The page starts even when the project holds modules named like the page's own dependencies
    Given a project with two recorded Claude Code sessions, the older one written first
    And the project root holds "typer.py" and "httpx.py" that print a marker and exit non-zero
    When "ails xray --current --background --no-open" is run in the project by an agent that does not say its session
    Then the printed address answers as the x-ray page
    And the project's marker was never printed

  @e2e
  Scenario: A page left running across a change of ails refuses its old view and a new start opens a fresh page
    Given a project with two recorded Claude Code sessions, the older one written first
    And a throwaway copy of the ails code
    When "ails xray --no-open" is started from the copy in the project
    Then the page serves the session view
    When a file of the copy changes
    Then within 15 seconds the page's session view is refused as old, telling the user to run ails xray again
    And "ails xray --current --background --no-open" run in the project opens a different page serving the view

  @e2e
  Scenario: A page started from a terminal is reused by an agent that knows its session and shows it as the current one
    Given a project with two recorded Claude Code sessions, the older one written first
    When "ails xray --current --no-open" is left running in the project with the session variable unset
    And the MCP server's xray tool is called by the agent of the newest session
    Then the returned address is on the running page's port
    And the page at the returned address shows the newest session as the current one
