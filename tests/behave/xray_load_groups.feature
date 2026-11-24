Feature: Instruction loads one hook caused draw as one group card on the x-ray canvas

  @page @browser
  Scenario: A hook that forces a run of instruction loads is one card naming the hook, its files and its tokens
    Given a project whose session had a hook fire and four instruction loads follow within seconds, one file loaded three times
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the view holds one group naming the hook with four loads of two files, the repeated file counted three times, and the station keeps none of those loads
    And the canvas draws one group card for the hook with its file count and tokens and opening it lists the loads with the repeated file once as times three
    And the same session where the hook fired silently names no hook and holds the same context and the same instruction-load tokens

  @page @browser
  Scenario: A folded segment's compaction stripe keeps its one line of text inside the stripe at 1280 and 1920 pixels
    Given the bundled page is served over the "view_folds" fixture view
    Then every compaction stripe's text ends inside its stripe at 1280 and at 1920 pixels

  @page @browser
  Scenario: Files a hook's group reloads after a compaction count as reloaded and stay drawn with the Hooks layer off
    Given the bundled page is served over a view where a hook's group of loads reloads the root files just after the compaction
    Then the group's card sits below the compaction stripe, the compaction lists as not loaded again only the file with no load, and the card stays with the Hooks layer off
