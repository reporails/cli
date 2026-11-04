Feature: The x-ray page's shell keeps its tabs, hint bar, details frame and layout steady and readable

  @page @browser
  Scenario: A session with no subagents and one with subagents both open on Graph
    Given the bundled page is served over the "view_solo" fixture view
    Then the page opens on the Graph tab with each tab's count from the view
    Given the bundled page is served over the "view_sample" fixture view
    Then the page opens on the Graph tab with each tab's count from the view

  @page @browser
  Scenario: Double-clicking a card does not drill in and clicking it selects it
    Given the bundled page is served over the "view_sample" fixture view
    Then a double-click on a card leaves the page at its level and a click selects the card

  @page @browser
  Scenario: Hovering or focusing a source moves nothing on the page
    Given the bundled page is served over the "view_sample" fixture view
    Then hover and keyboard focus on a source highlight it, move no element and keep the hint bar's height

  @page @browser
  Scenario: A source opens details over the canvas only, and Escape closes them in order
    Given the bundled page is served over the "view_sample" fixture view
    Then a click on a source opens a dialog inside the canvas column with focus on its close button, and Escape closes it, returns focus to the source, and a second Escape clears the selection

  @page @browser
  Scenario: On the other tabs details fill a side panel
    Given the bundled page is served over the "view_sample" fixture view
    Then a click on a source on the Tool calls tab fills the side panel with no overlay, and Escape closes it

  @page @browser
  Scenario: The Tool calls tab opens full width with its bar on one line
    Given the bundled page is served over the "view_sample" fixture view
    Then the Tool calls tab has no right pane and its bar does not wrap at 1280 pixels

  @page @browser
  Scenario: A call opens beside a narrowed table and Escape gives the width back
    Given the bundled page is served over the "view_sample" fixture view
    Then a click on a call narrows the table to its identifying columns and opens the details beside it, and Escape restores the full width

  @page @browser
  Scenario: A source opens beside a narrowed Sources table
    Given the bundled page is served over the "view_sample" fixture view
    Then the Sources tab has no right pane, a click on a source narrows it and opens the details beside it, and Escape restores the full width

  @page @browser
  Scenario: The strip draws every call full height and a click on a mark opens its call
    Given the bundled page is served over the "view_sample" fixture view
    Then the strip spans the table at the canvas's pixel width with full-height marks, and a click on a mark opens its call while a click on a gap opens nothing

  @page @browser
  Scenario: A viewport resize redraws the strip and Escape returns focus to the opened call's row
    Given the bundled page is served over the "view_sample" fixture view
    Then after the viewport narrows the strip is redrawn at the new width, a click opens the right call and Escape focuses its row

  @page @browser
  Scenario: On a narrow screen the open details sit under the table
    Given the bundled page is served over the "view_sample" fixture view
    Then on a screen of 1000 pixels the open details sit under the table in one column, and at 700 pixels nothing scrolls sideways

  @page @browser
  Scenario: The filter bar shows the most-called tools, a menu holds the rest and open details collapse it
    Given the bundled page is served over the "view_sample" fixture view changed so its calls used fourteen tools
    Then no element of the filter bar scrolls sideways, the plus menu filters by a tool without a button and open details collapse the bar to one button

  @page @browser
  Scenario: At 1280 pixels nothing scrolls sideways and the graph scales to its column
    Given the bundled page is served over the "view_sample" fixture view
    Then at 1280 pixels the page and the graph column do not scroll sideways and the graph is scaled down

  @page @browser
  Scenario: No text is smaller than 10.5 pixels or below 4.5 to 1 contrast
    Given the bundled page is served over the "view_sample" fixture view
    Then every visible text on the Graph tab, with details open, and on the Tool calls tab is at least 10.5 pixels with 4.5 to 1 contrast

  @page @browser
  Scenario: A solo session's agent summary stays on the Graph tab, and the table tabs have no scope buttons and no hint bar
    Given the bundled page is served over the "view_solo" fixture view
    Then the Graph tab shows the agent summary, the Tool calls and Sources tabs show none, no scope buttons and a hint bar only on the Graph tab

  @page @browser
  Scenario: A session without subagents opens on Graph, and so does the session picked in the header
    Given the bundled page is served over the "view_solo" fixture view
    Then the page opens on the Graph tab and the session picked in the header opens on it too
