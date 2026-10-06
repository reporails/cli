Feature: `ails login` signs a machine in through the browser
  `ails login` is the command a user runs to connect this machine to their account.
  The scenario drives the REAL `ails` console script against a small local website
  stand-in: it starts a sign-in, answers "still pending" once, then approves. The
  home directory is a temp dir, so the stored sign-in is read back from the file the
  binary wrote.

  @e2e
  Scenario: Signing in waits for the browser approval and stores the sign-in
    Given a website that approves the sign-in after one pending answer
    When I run "ails login" against that website
    Then the login exits 0
    And the login output says "Signed in as @octo (Pro)"
    And the login output shows the code "ABCD-EFGH"
    And the stored sign-in holds the issued token for "octo"
    And the website was asked twice for the token

  @e2e
  Scenario: Logging out revokes the sign-in and removes the stored file
    Given a website that approves the sign-in after one pending answer
    When I run "ails login" against that website
    And I run "ails logout" against that website
    Then the login exits 0
    And the login output says "Logged out on this machine."
    And the website revoked the issued token
    And no sign-in is stored
