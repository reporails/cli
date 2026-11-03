Feature: The Tool calls and Sources tables list every call and source, agree with the inspector and stay light

  @page @browser
  Scenario: The Tool calls summary and scope filters count the view's calls
    Given the bundled page is served over the "view_sample" fixture view
    Then the Tool calls tab counts match the view for every scope and the failed-only filter

  @page @browser
  Scenario: With one agent and one tool the table lists the inspector's counts
    Given the bundled page is served over the "view_sample" fixture view
    Then for every agent and tool the Tool calls table with that scope and tool has the inspector's calls and failures

  @page @browser
  Scenario: A call row opens its input and result in the side panel
    Given the bundled page is served over the "view_sample" fixture view
    Then a click on a call row fills the side panel with the call's input and result from the server

  @page @browser
  Scenario: A shell call's summary shows its command, asked for the drawn rows only
    Given the bundled page is served over the "view_sample" fixture view
    Then a shell call's row shows its command and no more commands are requested than rows are drawn

  @page @browser
  Scenario: A call still running is asked for once however many views arrive, and again when its result lands
    Given the server has not recorded the call's result yet
    And the bundled page is served over the "view_sample" fixture view
    Then a running call's command is requested once across view versions and once more after its result lands

  @page @browser
  Scenario: Thousands of calls request commands for the drawn rows only
    Given the bundled page is served over a view holding 2400 calls
    Then no more commands are requested than rows are drawn

  @page @browser
  Scenario: Thousands of calls keep a few rows in the page and scrolling shows later ones
    Given the bundled page is served over a view holding 2400 calls
    Then fewer than 200 rows are in the page and scrolling the table shows the last call

  @page @browser
  Scenario: The Sources table lists every source and the built-in items
    Given the bundled page is served over the "view_sample" fixture view
    Then the Sources table lists every source and every built-in item

  @page @browser
  Scenario: The Sources table prints finding counts and hidden built-in items as they are
    Given the bundled page is served over the "view_sample" fixture view
    Then the Sources table prints each count of findings, a dash for none, and "not visible" for a built-in item the transcript hides

  @page @browser
  Scenario: A call's details list the instruction files by the vocabulary's flag
    Given the bundled page is served over the "view_sample" fixture view
    Then a call's details list the files of the kinds the view flags as instructions
    Given the bundled page is served over the "view_sample" fixture view changed so only memory files count as instructions
    Then a call's details list the files of the kinds the view flags as instructions

  @page @browser
  Scenario: The scope button names its agent with an ellipsis for a long name
    Given the bundled page is served over the "view_fxpage" fixture view
    Then the scope button of a long agent name is cut with an ellipsis and carries the full name

  @page @browser
  Scenario: Show all closes when a filter changes
    Given the bundled page is served over a view holding 2400 calls
    Then "Show all" closes when a filter changes

  @page @browser
  Scenario: A call opened before its result landed shows the result after the next view
    Given the server has not recorded the call's result yet
    And the bundled page is served over the "view_sample" fixture view
    Then a call opened before its result landed shows the result after the view changes

  @page @browser
  Scenario: Only shell calls ask for a command and a shell row's tooltip shows it
    Given the bundled page is served over the "view_sample" fixture view
    Then a non-shell call row sends no command request and a shell call row's tooltip shows its command

  @page @browser
  Scenario: A refused command request is not asked again on the next view versions
    Given the server refuses the call route
    And the bundled page is served over the "view_sample" fixture view
    Then a call whose command request was refused is requested once across view versions

  @page @browser
  Scenario: Many command texts arriving together cause one redraw per frame
    Given the bundled page is served over a view holding 2400 calls
    Then many command texts arriving together are drawn in a few frames, not once per text
