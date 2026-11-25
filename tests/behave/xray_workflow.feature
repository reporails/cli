Feature: A Claude Code session with a Workflow run shows a workflow node on the x-ray canvas

  @page @browser
  Scenario: A Workflow run is one node naming the workflow, its phases, status, agents and tokens, with its agents under their phases
    Given a project with a recorded Claude Code session that ran a Workflow of two phases
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the view holds the workflow with its name, status, two agents, token total and one agent under each of its two phases
    And the canvas draws the workflow node with those facts and opening it lists each phase with its agent
    And each agent of the run hands back the output the run accepted, and its hand-back text is that output

  Scenario: The agent a stopped Workflow run left without an accepted output reads stopped
    Given a project with a recorded Claude Code session that ran a Workflow of two phases
    And the run was stopped before it accepted the second agent's output
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the first agent hands back the output the run accepted and the second reads stopped

  @page @browser
  Scenario: Only the Workflow run whose record has the wrong shape shows as not readable and the page still loads
    Given a project with a recorded Claude Code session that ran a Workflow of two phases
    And the session holds a second well-formed Workflow run record and the first run's record holds a status that is not text
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the view holds the second run as a readable node and the first as not readable with the reason, and the canvas still draws both nodes

  @page @browser
  Scenario: A Workflow run record cut off mid-write shows as not readable instead of running
    Given a project with a recorded Claude Code session that ran a Workflow of two phases
    And the session holds a second well-formed Workflow run record and the first run's record is cut off mid-write
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the view holds the second run as a readable node and the first as not readable with the reason, and the canvas still draws both nodes
