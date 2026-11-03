Feature: The x-ray page's shell keeps its tabs, hint bar, details frame and layout steady and readable

  @page @browser
  Scenario: A session with no subagents opens on Tool calls, one with subagents on Graph
    Given the bundled page is served over the "view_solo" fixture view
    Then the page opens on the Tool calls tab with each tab's count from the view and no toolbar
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
  Scenario: At 1280 pixels nothing scrolls sideways and the graph scales to its column
    Given the bundled page is served over the "view_sample" fixture view
    Then at 1280 pixels the page and the graph column do not scroll sideways and the graph is scaled down

  @page @browser
  Scenario: No text is smaller than 10.5 pixels or below 4.5 to 1 contrast
    Given the bundled page is served over the "view_sample" fixture view
    Then every visible text on the Graph tab, with details open, and on the Tool calls tab is at least 10.5 pixels with 4.5 to 1 contrast
