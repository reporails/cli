Feature: The server is asked for a verdict before any local work starts
  `ails check`, the MCP `validate` tool and the x-ray launch check first ask the service whether it
  serves this caller. A refusal ends the run at once: nothing is discovered, no model is fetched and
  no diagnosis is requested. `--offline` (or `AILS_OFFLINE=1`) runs the local checks with no network
  call. Every scenario drives the REAL `ails` against a local service stand-in on an ephemeral port,
  with a home directory of its own.

  @e2e @regression
  Scenario: A refused anonymous caller is told how to sign up, before any file is read or model fetched
    Given a service that refuses an anonymous caller for the hourly limit
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the run exits 1
    And the output says "ails login"
    And the output says "free API key"
    And the service was asked only for the handshake
    And no model was fetched and no file was discovered

  @e2e @regression
  Scenario: A refused out-of-date version is told to update
    Given a service that refuses an out-of-date version
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the run exits 1
    And the output says "ails update"
    And the service was asked only for the handshake

  @e2e @regression
  Scenario: A refusal reaches the json and github formats
    Given a service that refuses an anonymous caller for the hourly limit
    And a git project with a lone CLAUDE.md
    When I invoke "ails check -f json" against the service
    Then the run exits 1
    And the stdout is a json error "server_refused" saying "ails login"
    When I invoke "ails check -f github" against the service
    Then the run exits 1
    And the stdout is one "::error::" line saying "ails login"

  @e2e @regression
  Scenario: A rejected credential is told to sign in again
    Given a service that rejects the credential
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the run exits 1
    And the output says "ails login"
    And the output says "AILS_API_KEY"
    And the service was asked only for the handshake

  @e2e @regression
  Scenario: A credential rejected right after sign-in does not stop the run
    Given a service that rejects the credential saved a moment ago
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the run exits 0
    And the service was asked for the handshake and the run went on to its local result

  @e2e @regression
  Scenario: A mistyped path is reported before the service is asked
    Given a service that accepts the caller
    And a git project with a lone CLAUDE.md
    When I invoke "ails check ./does-not-exist" against the service
    Then the run exits 2
    And the output says "Path not found"
    And the service was asked nothing

  @e2e @regression
  Scenario: An unreachable service names the offline option
    Given no service is listening
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the run exits 1
    And the output says "--offline"
    And the output says "AILS_OFFLINE=1"
    And no model was fetched and no file was discovered

  @e2e @regression
  Scenario Outline: Local checks run with no network call when offline is asked for
    Given a service that refuses an anonymous caller for the hourly limit
    And a git project with a lone CLAUDE.md
    When I invoke "<command>" against the service
    Then the run exits 0
    And the output says "Server analysis did not run"
    And the service was asked nothing

    Examples:
      | command                  |
      | ails check --offline     |
      | ails check --offline -f json |

  @e2e @regression
  Scenario: AILS_OFFLINE=1 is the same as --offline
    Given a service that refuses an anonymous caller for the hourly limit
    And a git project with a lone CLAUDE.md
    When with AILS_OFFLINE set to "1" I invoke "ails check" against the service
    Then the run exits 0
    And the output says "Server analysis did not run"
    And the service was asked nothing

  @e2e @regression
  Scenario: A service without the handshake route does not stop the run
    Given a service that answers the handshake with HTTP 404
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the run exits 0
    And the service was asked for the handshake and the run went on to its local result

  @e2e @regression
  Scenario: An edge that answers the handshake with HTTP 403 does not stop the run
    Given a service that answers the handshake with HTTP 403
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the run exits 0
    And the service was asked for the handshake and the run went on to its local result

  @e2e @regression
  Scenario: The check tells the service which surface asks
    Given a service that accepts the caller
    And a git project with a lone CLAUDE.md
    When I invoke "ails check" against the service
    Then the service saw the surface "cli"

  @e2e @regression
  Scenario: A check in a CI system says so
    Given a service that accepts the caller
    And a git project with a lone CLAUDE.md
    When with CI set to "true" I invoke "ails check" against the service
    Then the service saw the surface "ci"

  @e2e @regression
  Scenario: The MCP validate tool tells the service its surface and stops on a refusal
    Given a service that refuses an anonymous caller for the hourly limit
    And a git project with a lone CLAUDE.md
    When the MCP validate tool runs against the service
    Then the MCP reply is the error "server_refused" saying "ails login"
    And the service saw the surface "mcp"
    And the service was asked only for the handshake

  @e2e @regression
  Scenario Outline: A command that makes no check never asks the service for a verdict
    Given a service that refuses an anonymous caller for the hourly limit
    When I invoke "<command>" against the service
    Then the service saw no handshake

    Examples:
      | command                              |
      | ails version                         |
      | ails explain CORE:S:0007             |
      | ails rules list                      |
      | ails config get default_agent        |
      | ails login --help                    |
      | ails install --help                  |
      | ails update --help                   |
