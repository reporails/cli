Feature: Every `ails check` run holds the same properties in every output format
  A defect that lived in the composed run (a rule left on after it was disabled, a total
  that no longer equals its parts, a format that dropped a finding, an exit code that
  ignored the findings) is not one expected output for one fixture. These scenarios drive
  the REAL `ails` binary and the REAL MCP server over a fixture set, in text, JSON,
  `github` and MCP, and check four properties on every run:

    - a disabled rule appears in no output;
    - the total equals m_probe + client + server;
    - text, JSON, `github` and MCP carry one finding set for the same run;
    - the exit code matches the findings and the run state.

  The offline examples run in every `behave`. The `@api` examples run against the local dev
  api (`AILS_LOCAL_API_URL`, default http://localhost:8001) and skip LOUDLY when it does not
  answer; they never pass without having reached it.

  @property @e2e @regression
  Scenario Outline: One run of <fixture> carries one finding set, a total that adds up, and an honest exit code
    Given the fixture project "<fixture>"
    When I run every output format
    Then text, JSON, GitHub and MCP carry one finding set
    And the total equals m_probe plus client plus server in JSON and MCP
    And every command-line format exits as its findings say

    @offline
    Examples:
      | fixture       |
      | claude_only   |
      | multi_agent   |
      | settings_json |
      | directives    |

    @api
    Examples:
      | fixture     |
      | claude_only |
      | directives  |

  @property @e2e @regression
  Scenario Outline: A disabled rule appears in no output of <fixture>
    Given the fixture project "<fixture>"
    When I disable every rule the run reports
    And I run every output format
    Then no output names a disabled rule
    And the total equals m_probe plus client plus server in JSON and MCP
    And every command-line format exits as its findings say

    @offline
    Examples:
      | fixture       |
      | claude_only   |
      | multi_agent   |
      | settings_json |
      | directives    |

    @api
    Examples:
      | fixture     |
      | claude_only |
      | directives  |

  @property @e2e @regression
  Scenario: A config that cannot be read stops every format
    Given the fixture project "directives"
    And a project config that cannot be read
    When I run every output format
    Then every command-line format exits 2 and reports no finding
    And MCP replies config_unreadable
