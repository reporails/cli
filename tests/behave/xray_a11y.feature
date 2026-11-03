Feature: The x-ray page works by keyboard, keeps its focus, and stays readable to every user

  @page @browser
  Scenario: Focus stays on a canvas source node through hover and focus redraws
    Given the bundled page is served over the "view_sample" fixture view
    Then tabbing onto a canvas source node keeps focus on it after the canvas redraws for hover and focus

  @page @browser
  Scenario: Pressing Enter on an eye toggle or a group header keeps focus on it
    Given the bundled page is served over the "view_sample" fixture view
    Then Enter on an eye toggle and on a group header keeps focus on that control

  @page @browser
  Scenario: Details opened from a canvas node make the canvas inert and give focus back to that node
    Given the bundled page is served over the "view_sample" fixture view
    Then Enter on a canvas source node opens details with one click, the canvas is inert, and Escape returns focus to that node

  @page @browser
  Scenario: Space selects an agent card whose name carries its summary
    Given the bundled page is served over the "view_sample" fixture view
    Then Space on an agent card selects it and its accessible name carries its slot summary

  @page @browser
  Scenario: The Tool calls table is a grid the arrow keys walk
    Given the bundled page is served over the "view_sample" fixture view
    Then the Tool calls table is a grid with row counts and indexes, arrow keys walk its rows across window swaps, and its summary is written only on change

  @page @browser
  Scenario: Every visible text keeps 4.5 to 1 contrast on chips and on dimmed cards and nodes
    Given the bundled page is served over the "view_sample" fixture view
    Then no visible text on the Graph, Tool calls and Sources tabs falls under 4.5 to 1 contrast in plain, selected and dimmed states

  @page @browser
  Scenario: Control borders and the selected indicator reach 3 to 1
    Given the bundled page is served over the "view_sample" fixture view
    Then segment and session switcher borders and the selected tab and segment indicators reach 3 to 1

  @page @browser
  Scenario: At 580 pixels of graph column the canvas text still renders at 10.5 pixels
    Given the bundled page is served over the "view_sample" fixture view
    Then at a 580 pixel graph column every canvas text renders at least 10.5 pixels

  @page @browser
  Scenario: Rail markers and station dots have a 24 pixel hit area
    Given the bundled page is served over the "view_sample" fixture view
    Then every rail marker and station dot measures at least 24 pixels each way

  @page @browser
  Scenario: At 700 pixels the page is one column and does not scroll sideways
    Given the bundled page is served over the "view_sample" fixture view
    Then at 700 pixels the page has one column and no sideways scroll

  @page @browser
  Scenario: Focus on a source whose id holds a line break survives a redraw
    Given the bundled page is served over the "view_sample" fixture view changed so a source id holds a line break
    Then focus on a canvas source node whose id holds a line break survives the redraw
