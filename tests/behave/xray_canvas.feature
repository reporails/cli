Feature: The x-ray graph draws agents right of the spine, what entered context left of it and hooks on it

  @page @browser
  Scenario: Agents sit right of the spine, one source node per source on the left, hooks on the spine
    Given the bundled page is served over the "view_sample" fixture view
    Then every agent card is right of the spine, every source node left of it, each source has one node at its first load and no legend is drawn

  @page @browser
  Scenario: An MCP server is one node with a round trip to every cluster of its calls
    Given the bundled page is served over the "view_sample" fixture view
    Then each MCP server is one node with as many round-trip edges as call clusters and its call count

  @page @browser
  Scenario: Hook firings stay on the spine and the side track is one path per tracked category
    Given the bundled page is served over the "view_p4" fixture view
    Then hook loads and stretches are stations on the spine and the side track draws one path per tracked category

  @page @browser
  Scenario: Hiding the agent kind removes every subagent card, group and arch and keeps the rest
    Given the bundled page is served over the "view_p1" fixture view
    Then hiding the agent kind leaves no subagent card, group or arch and the main agent, spine and source nodes stay

  @page @browser
  Scenario: A collapsed group holding the selected agent names it
    Given the bundled page is served over the "view_p1" fixture view
    Then a collapsed group holding the selected agent shows a solid border and its name instead of in parallel

  @page @browser
  Scenario: The jump rail marks fan-outs, failures and the end, and a click scrolls the graph there
    Given the bundled page is served over the "view_p1" fixture view
    Then the rail holds one marker per fan-out group and failure run plus the end and clicking the end marker scrolls the graph to it

  @page @browser
  Scenario: The vocabulary's spine flag decides which loads are stations on the spine
    Given the bundled page is served over the "view_sample" fixture view changed so memory loads stay on the spine and hook loads do not
    Then only the memory loads and the hook firings are stations on the spine

  @page @browser
  Scenario: The link to Tool calls opens the agent on screen
    Given the bundled page is served over the "view_sample" fixture view
    Then the link to Tool calls opens it for the agent on screen only
