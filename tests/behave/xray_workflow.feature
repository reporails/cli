Feature: A Claude Code session with a Workflow run shows a workflow node on the x-ray canvas

  @page @browser
  Scenario: A Workflow run is one node naming the workflow, its phases, status, agents and tokens, with its agents under their phases
    Given a project with a recorded Claude Code session that ran a Workflow of two phases
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the view holds the workflow with its name, status, two agents, token total and one agent under each of its two phases
    And the canvas draws the workflow node with those facts and opening it lists each phase with its agent

  @page @browser
  Scenario: Only the Workflow run whose record has the wrong shape shows as not readable and the page still loads
    Given a project with a recorded Claude Code session that ran a Workflow of two phases
    And the session holds a second well-formed Workflow run record and the first run's record holds a status that is not text
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the view holds the second run as a readable node and the first as not readable with the reason, and the canvas still draws both nodes
