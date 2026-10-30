Feature: Agent hook events are recorded and read back through the real binary

  @e2e
  Scenario: A whole Claude Code session is recorded in order and read back
    Given the recorded Claude Code session payloads
    When every payload is piped into "ails hook --agent claude" in order
    Then every hook call exited 0 with nothing on stdout
    And "ails events" returns the session's records in order with the right kinds and tool-use ids
    And "ails events --after 10" returns the last 5 records and "next" is 15

  @e2e
  Scenario: Garbage on stdin never fails the hook and is recorded as a refusal
    Given the recorded Claude Code session payloads
    When the text "this is not json" is piped into "ails hook"
    Then every hook call exited 0 with nothing on stdout
    And "ails events" for the session "unknown" shows a refusal record

  @e2e
  Scenario: An unwritable store never fails the hook
    Given the recorded Claude Code session payloads
    And the event store location is a regular file
    When every payload is piped into "ails hook --agent claude" in order
    Then every hook call exited 0 with nothing on stdout

  @e2e
  Scenario: A negative offset is refused
    Given the recorded Claude Code session payloads
    When "ails events --after -1" is run for the session
    Then the command exited 2 with no JSON on stdout
