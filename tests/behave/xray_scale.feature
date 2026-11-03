Feature: The x-ray page keeps drawing and scrolling smoothly at the design scale

  An 8 hour session with 5,000 tool calls, 60 subagents four levels deep, 30 MCP servers and bursts of 12 subagents.

  @page @browser
  Scenario: The Graph tab draws at once, holds no element per call and scrolls at 30 fps or better
    Given the bundled page is served over a synthetic view at the design scale
    Then the Graph tab draws within 4000 ms, keeps every layer under 400 elements and scrolls at 30 fps or better

  @page @browser
  Scenario: The Tool calls and Sources tabs keep a few rows in the page and scroll at 30 fps or better
    Given the bundled page is served over a synthetic view at the design scale
    Then the Tool calls table lists all 5000 calls with fewer than 200 rows in the page and the tables scroll at 30 fps or better

  @page @browser
  Scenario: At 1280 px the page and the graph do not scroll sideways and no cards overlap
    Given the bundled page is served over a synthetic view at the design scale
    Then at 1280 px there is no horizontal scroll and no two cards overlap
