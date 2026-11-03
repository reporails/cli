Feature: The x-ray Sources panel and right column list everything and describe one agent

  @page @browser
  Scenario: Hiding a kind on the graph leaves the Sources list as it was
    Given the bundled page is served over the "view_panels" fixture view
    Then turning an eye off changes only the graph, never the Sources groups or their item counts

  @page @browser
  Scenario: Group headers show one usage figure and rows show a name and three facts
    Given the bundled page is served over the "view_panels" fixture view
    Then headers carry one used of total figure and a findings line only with findings, and rows say their facts

  @page @browser
  Scenario: The right column shows one agent and its context adds up
    Given the bundled page is served over the "view_panels" fixture view
    Then the right column shows the main agent, then a selected subagent, and the context rows add up

  @page @browser
  Scenario: A source and the peak context open their details
    Given the bundled page is served over the "view_panels" fixture view
    Then a source opens its text from the file route and the peak legend adds up to the whole
