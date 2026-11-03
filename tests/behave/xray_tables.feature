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
  Scenario: Thousands of calls keep a few rows in the page and scrolling shows later ones
    Given the bundled page is served over a view holding 2400 calls
    Then fewer than 200 rows are in the page and scrolling the table shows the last call

  @page @browser
  Scenario: The Sources table lists every source and the built-in items
    Given the bundled page is served over the "view_sample" fixture view
    Then the Sources table lists every source and every built-in item
