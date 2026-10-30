Feature: ails xray serves a session's context window on the loopback address through the real binary

  @e2e
  Scenario: The page and its session view load, and a call without the launch token is refused
    Given a project with a recorded Claude Code session
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page carries a launch token and the session view with that token has turns
    And the session view without the token is refused with 403

  @e2e @browser
  Scenario: The page opened in a real browser draws the session's context window
    Given a project with a recorded Claude Code session
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And headless Chrome rendering the page shows the context window map, not a server error

  @e2e
  Scenario: A project with no recorded session is refused
    Given a project with no recorded Claude Code session
    When "ails xray --no-open" is run in the project
    Then it exits 2 saying no Claude Code session was found
