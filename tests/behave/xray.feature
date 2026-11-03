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
  Scenario: No two cards overlap and no running count is drawn
    Given the bundled page is served over the "view_sample" fixture view
    Then no two cards overlap at 1440 and at 925 pixels and no "+N running" text is drawn

  @page @browser
  Scenario: No card is displaced from its launch time when agents fan out
    Given the bundled page is served over the "view_p1" fixture view
    Then at 1440 and at 925 pixels no card overlaps another and every card sits 18 pixels above its launch on the spine

  @page @browser
  Scenario: A burst of parallel subagents is one group card that expands into rows of two and collapses again
    Given the bundled page is served over the "view_p1" fixture view
    Then the bursts are collapsed group cards, a click expands one into rows of two members and a second click collapses it

  @page @browser
  Scenario: A selected member opens its group, and an explicit choice wins
    Given the bundled page is served over the "view_p1" fixture view
    Then selecting a member of a collapsed group shows its group expanded until the user collapses it

  @page @browser
  Scenario: A stretched time scale is marked and its ticks keep their distance
    Given the bundled page is served over the "view_p1" fixture view
    Then a stretched segment shows a violet bar with its tooltip and the note, and no two ticks sit closer than 18 pixels

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
    Then toggling a layer removes that kind's slot chips, Sources section and source nodes at once

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
  Scenario: The inspector's Context at peak, Cost and Not passed down panes are compact until opened
    Given the bundled page is served over the "view_sample" fixture view
    Then the inspector's panes start compact, open independently, stay open across agents, and print every estimate with a tilde

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

  @page @browser
  Scenario: The Sources panel groups its sources by kind, collapsed except the first, with show more and focus-opens-group
    Given the bundled page is served over the "view_p3" fixture view
    Then the Sources groups follow the adapter order with only the first open, expand and collapse all work, a long group shows four with a show-more, and focusing a source opens its group

  @page @browser
  Scenario: Agent definitions list their launch counts, light their subagents and carry the A chip
    Given the bundled page is served over the "view_p3" fixture view
    Then a launched agent source lights exactly its subagents, a never-launched one lights nothing, the group ends with the adapter note, the A chip is filled or outlined by count and the Sources panel has a layer toggle per adapter kind

  @page @browser
  Scenario: A source row shows its estimated cost
    Given the bundled page is served over the "view_sample" fixture view
    Then an instructions source row shows its cost as an estimate and a source without one shows none

  @page @browser
  Scenario: The spine's width follows the exact context and its bands follow the composition
    Given the bundled page is served over the "view_sample" fixture view
    Then the spine is about 18 pixels wide each side at the peak reply, narrower at the first, its bands fill it in the adapter's order and no legend is drawn

  @page @browser
  Scenario: A hook stretch is one pill and stations within 14 pixels merge into one
    Given the bundled page is served over the "view_p4" fixture view
    Then a hook stretch draws one pill with its count, and three close hook loads draw one pill naming all three

  @page @browser
  Scenario: Handoff pills show only for the selected agent
    Given the bundled page is served over the "view_sample" fixture view
    Then no handoff pill exists until an agent is selected, then its two show

  @page @browser
  Scenario: A long task name wraps to two lines, with no type label and its full text in the tooltip
    Given the bundled page is served over the "view_p4" fixture view
    Then a long card title wraps to two lines, the subtitle has no type label and the title attribute holds the full name

  @page @browser
  Scenario: A card launched early and an expanded fan-out box stay clear of the top card
    Given the bundled page is served over the "view_fxpage" fixture view
    Then a subagent launched at the start and an expanded fan-out box sit below the top card and touch no card

  @page @browser
  Scenario: No station pill covers a card
    Given the bundled page is served over the "view_fxpage" fixture view
    Then no station pill overlaps a card at 1440 and at 925 pixels

  @page @browser
  Scenario: A group card keeps every line inside its border
    Given the bundled page is served over the "view_p1" fixture view
    Then every group card line and its expand label sit inside the card at 1440 and at 925 pixels

  @page @browser
  Scenario: Going up from a group member opens its group
    Given the bundled page is served over the "view_p4" fixture view
    Then going up a level from a member of a collapsed group selects the member and shows its group expanded

  @page @browser
  Scenario: Every printed token estimate carries a tilde and says it is estimated
    Given the bundled page is served over the "view_sample" fixture view
    Then a source row, the focus banner and a load station's tooltip print their token counts with a tilde and the word estimated

  @page @browser
  Scenario: Unpriced replies with no model named say so
    Given the bundled page is served over the "view_fxpage" fixture view
    Then the cost pane says replies were not priced because no model was named, and lists the models when there are some

  @page @browser
  Scenario: The session switcher lists the project's sessions and marks the current one
    Given the bundled page is served over the "view_sample" fixture view
    Then the switcher lists the stub's sessions with start time, length and subagent count and marks the current one

  @page @browser
  Scenario: A session's first prompt is fetched only when its toggle is clicked
    Given the bundled page is served over the "view_sample" fixture view
    Then no first prompt is requested until an entry's toggle is clicked, and then its text shows as text

  @page @browser
  Scenario: Picking a session reloads the page with it and every session route carries it
    Given the bundled page is served over the "view_sample" fixture view
    Then picking another entry reloads the page with that session and every session route it then calls carries it

  @page @browser
  Scenario: A view whose session was not named says the newest session is shown
    Given the served view says it picked "current_unknown"
    And the bundled page is served over the "view_sample" fixture view
    Then a notice names the view's adapter tool as the agent that did not say which session it is

  @page @browser
  Scenario: A view whose newest session was picked shows no notice
    Given the served view says it picked "newest"
    And the bundled page is served over the "view_sample" fixture view
    Then no session notice is shown
