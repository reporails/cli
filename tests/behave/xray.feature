Feature: ails xray serves a session's context window on the loopback address through the real binary

  @e2e
  Scenario: The page and its session view load, and a call without the launch token is refused
    Given a project with a recorded Claude Code session
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page carries a launch token and the session view with that token holds the main agent
    And the session view without the token is refused with 403

  @e2e @browser
  Scenario: A memory file that was not loaded can be opened and its text shows
    Given a project with a recorded Claude Code session
    And the project's memory folder holds an unlinked topic file reading "unlinked memory text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And opening the not-loaded memory file shows "unlinked memory text"

  @e2e @browser
  Scenario: A prompt line shows no text until it is clicked
    Given a project with a recorded Claude Code session
    And the session's first prompt was typed and reads "typed prompt text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the prompt line shows no text and asks for none until it is clicked, then shows what the prompt route returns

  @e2e @browser
  Scenario: A file's text shown on the page follows the file when the session moves on
    Given a project with a recorded Claude Code session
    And the project's instruction file reads "first text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page shows "first text" for the file, then "second text" once the file and the session change

  @e2e @browser
  Scenario: Markup in a file name and in a prompt shows as text and builds no element
    Given a project with a recorded Claude Code session
    And the project's memory folder holds an unlinked note named "<img src=x onerror=window.__pwned=1>.md" reading "<b>bold</b>"
    And the session's first prompt was typed and reads "<b>bold</b> <img src=x onerror=window.__pwned=1>"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the markup in the file name, the file and the prompt shows literally and no element or handler was injected
    And the page's scripts write to no HTML sink

  @e2e @browser
  Scenario: A checked file's finding rows show each finding's own message
    Given a project with a recorded Claude Code session
    And the project's instruction file reads "Be careful and try to write good code when possible."
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And checking the instruction file lists each finding with the message the check route returns

  @e2e @browser
  Scenario: A session with two compactions marks both on the main agent's spine
    Given a project with a recorded Claude Code session that compacted twice
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page draws a compaction marker for each of the two compactions with the sizes the view holds

  @e2e
  Scenario: A project with no recorded session is refused
    Given a project with no recorded Claude Code session
    When "ails xray --no-open" is run in the project
    Then it exits 2 saying no Claude Code session was found

  @page @browser
  Scenario: No two cards overlap and the subagents stacked in time say how many more run
    Given the bundled page is served over the "view_sample" fixture view
    Then no two cards overlap at 1440 and at 925 pixels, and the subagents stacked in time say how many more run

  @page @browser
  Scenario: Drilling in three levels shows the collapsed breadcrumb and the direct parent's strip
    Given the bundled page is served over the "view_sample" fixture view
    Then drilling in three levels shows the collapsed breadcrumb and the parent strip of the direct parent

  @page @browser
  Scenario: Focusing a source rings who had it, and a never-loaded source says so
    Given the bundled page is served over the "view_sample" fixture view
    Then focusing a source rings exactly the nodes that had it and dims the rest, and a never-loaded source says so

  @page @browser
  Scenario: Toggling a layer removes its chips, section and stations together
    Given the bundled page is served over the "view_sample" fixture view
    Then toggling a layer removes that kind's slot chips, Sources section and stations at once

  @page @browser
  Scenario: An adapter that declares fewer source kinds gets no empty slot, toggle or section
    Given the bundled page is served over the "view_stub_adapter" fixture view
    Then the page draws no slot, toggle, section or station for a source kind the adapter omits

  @page @browser
  Scenario: A compaction, a stopped subagent and a never-loaded source render as specified
    Given the bundled page is served over the "view_sample" fixture view
    Then a compaction marker, a stopped subagent and a never-loaded source each render as specified

  @page @browser
  Scenario: A findings pill and a source row open the file's findings
    Given the bundled page is served over the "view_sample" fixture view
    Then a findings pill opens the file's findings at its hash and a source row links to its file

  @page @browser
  Scenario: The page prints the view's own words and numbers
    Given the bundled page is served over the "view_sample" fixture view
    Then the page shows the view's own model, window, unknown facts, trigger words, notes, ratio and subagent counts

  @page @browser
  Scenario: A kind reported absent and an untyped node
    Given the bundled page is served over the "view_stub_adapter" fixture view
    Then a kind the view reports absent says so from its fact, and an untyped node adds no filter button but still shows

  @page @browser
  Scenario: A file opened during another file's check is still checked
    Given the bundled page is served over the "view_sample" fixture view
    Then a file opened while another file's check runs is checked once that check ends

  @page @browser
  Scenario: A failing command's text is fetched once as the view keeps changing
    Given the served view carries a new version on every poll
    And the bundled page is served over the "view_sample" fixture view
    Then each failing command's text is fetched once however many times the view changes

  @page @browser
  Scenario: A node of a second kind is drawn by its own renderer with no canvas change
    Given the bundled page is served over the "view_stub_kind" fixture view
    Then the stub kind's cards are drawn by a stub renderer only the test serves, with no change to the canvas
