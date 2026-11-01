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
    And headless Chrome rendering the page shows the context window chart, not a server error

  @e2e @browser
  Scenario: The page draws each turn's replies as chart points and labels each turn
    Given a project with a recorded Claude Code session
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the drawn main-session points of each turn equal that turn's series in the view
    And each turn is labelled with its number and its reply count
    And no two chart labels overlap at 925 and at 1440 pixels

  @e2e @browser
  Scenario: At 925 pixels the chart fits the first screen and the artifact list sits beside the information display
    Given a project with a recorded Claude Code session
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And at 925 pixels the chart ends inside the first 1000 pixels and the artifact list is left of the information display

  @e2e @browser
  Scenario: A memory file that was not loaded can be selected and its text shows
    Given a project with a recorded Claude Code session
    And the project's memory folder holds an unlinked topic file reading "unlinked memory text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And selecting the not-loaded memory file shows "unlinked memory text"

  @e2e @browser
  Scenario: A prompt line shows no text until it is clicked
    Given a project with a recorded Claude Code session
    And the session's first prompt was typed and reads "typed prompt text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the prompt line shows no text and asks for none until it is clicked, then shows what the prompt route returns

  @e2e @browser
  Scenario: A file's text shown on the page follows the file when the session moves on
    Given a project with a recorded Claude Code session
    And the project's instruction file reads "first text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page shows "first text" for the file, then "second text" once the file and the session change

  @e2e @browser
  Scenario: Markup in a file name and in a prompt shows as text and builds no element
    Given a project with a recorded Claude Code session
    And the project's memory folder holds an unlinked note named "<img src=x onerror=window.__pwned=1>.md" reading "<b>bold</b>"
    And the session's first prompt was typed and reads "<b>bold</b> <img src=x onerror=window.__pwned=1>"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the markup in the file name, the file and the prompt shows literally and no element or handler was injected
    And the page's scripts write to no HTML sink

  @e2e @browser
  Scenario: A checked file's finding rows show each finding's own message
    Given a project with a recorded Claude Code session
    And the project's instruction file reads "Be careful and try to write good code when possible."
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And checking the instruction file lists each finding with the message the check route returns

  @e2e @browser
  Scenario: A session with two compactions draws two bands, the first ending where the second compaction starts
    Given a project with a recorded Claude Code session that compacted twice
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page draws a band and a line for each of the two compactions and the first band ends at the second line

  @e2e @browser
  Scenario: The page shows the view's peak, turn starts and prompt numbers instead of working them out
    Given a project with a recorded Claude Code session
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the header peak, each turn's start, its prompt numbers and its Stop count are the view's own values

  @e2e
  Scenario: A project with no recorded session is refused
    Given a project with no recorded Claude Code session
    When "ails xray --no-open" is run in the project
    Then it exits 2 saying no Claude Code session was found
