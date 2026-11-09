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

  @e2e @browser @windows_unverified
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

  @e2e @browser
  Scenario: The compaction marker's summary control opens the summary in the inspector
    Given a project with a recorded Claude Code session that compacted twice
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And clicking the first compaction marker's summary control opens that summary in the main agent's inspector

  @e2e @browser
  Scenario: Each compaction shows its summary text verbatim with its size in tokens
    Given a project with a recorded Claude Code session that compacted twice
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page shows the manual and the automatic compaction's summary text verbatim with its size beside it

  @e2e
  Scenario: A compaction summary is served on request and reaches no event record
    Given a project with a recorded Claude Code session that compacted twice
    When "ails xray --no-open" is started in the project
    And the session's PostCompact hook payload carrying the summary text is piped into "ails hook"
    Then the printed address is on 127.0.0.1
    And the summary route returns the summary text, and the view, the event log and "ails events" hold none of it

  @e2e
  Scenario: A hook's details show its command, its settings file and its firings, and its output only on request
    Given a project with a recorded Claude Code session
    And the project's settings declare a PreToolUse hook running "echo guard"
    And the session recorded that hook running with some output
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the hook's details name its command, its settings file and the firing's decision, exit code and output size
    And the session view holds no output text and the hook output route returns it only when asked

  @e2e
  Scenario: The MCP group lists a plugin's server with its plugin and state, and a server only its tools name
    Given a project with a recorded Claude Code session
    And an enabled plugin named "reporails" declares an MCP server of the same name that the user turned off here
    And the session listed one tool of an MCP server named "toolsonly" that no file declares
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the MCP group lists "reporails" as that plugin's server turned off in this project
    And the MCP group lists "toolsonly" as connected with one tool and no plugin

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
  Scenario: The inspector's Peak context and Est. cost tiles open their details
    Given the bundled page is served over the "view_sample" fixture view
    Then the inspector tiles open the peak and cost details, and every estimate has a tilde

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
    Then a launched agent source lights exactly its subagents, a never-launched one lights nothing, the A chip is filled or outlined by count and the Sources panel has an eye per adapter kind

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
    Then the cost details say replies were not priced because no model was named, and list the models if any

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

  @e2e @browser
  Scenario: An agent's In context list is the measured request when Claude Code recorded it
    Given a project with a session whose Claude Code recorded each request it made, with a subagent
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's In context rows are measured, add up to its peak reply and name the system prompt and tools
    And the subagent's In context rows add up to the peak reply of its own file
    And each agent's system, tool definition and tool call rows are the shares of its request's own characters
    And the page's In context list for each agent shows no remainder text and no asterisk

  @e2e @browser
  Scenario: A picture in a tool result is counted at its own token cost, not spread over the measured shares
    Given a project with a session whose peak request carries a picture inside a tool result, with a subagent
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's In context rows are measured, add up to its peak reply and name the system prompt and tools
    And each agent's system, tool definition and tool call rows are the shares of its request's own characters
    And the main agent's tool calls and results row holds the picture's tokens and its measure names them

  @e2e
  Scenario: A reply whose request is not recorded yet takes the system prompt and tools of the request before it
    Given a project with a session whose main agent's newest reply has no recorded request yet
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's System prompt and tools show the sizes of its earlier request, not the reply's remainder

  @e2e @browser
  Scenario: A measured row opens its own agent's figure and request
    Given a project with a session whose Claude Code recorded each request it made, with a subagent
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And each agent's measured System prompt row opens that agent's own figure and request

  @e2e @browser
  Scenario: A built-in agent type shows the system prompt and tools its launch recorded
    Given a project with a session whose Claude Code recorded each request it made, with a subagent
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the general-purpose agent type's details show its recorded system prompt and its tools with launch counts
    And the system prompt route returns that text only for a type the session launched

  @e2e @browser
  Scenario: The main agent's System prompt details show the text its recorded request was sent with
    Given a project with a session whose Claude Code recorded each request it made, with a subagent
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's System prompt details show the system prompt text of its recorded request

  @e2e @browser
  Scenario: The main agent's System prompt details name the latest of several system prompts
    Given a project with a session whose main requests were sent with two different system prompts
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's System prompt details say there were two and show the latest

  @e2e @browser
  Scenario: Requests that differ only in their tools do not make the system prompt look different
    Given a project with a session whose main requests were sent with the same system prompt and different tools
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's System prompt details show the text without saying the system prompts differed

  @e2e
  Scenario: A session with no recorded request has no main system prompt text
    Given a project with a session from an older Claude Code that did not record its requests, with a subagent
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's System prompt route refuses when the session recorded no request

  @e2e @browser
  Scenario: A built-in agent type shows how its launch was configured
    Given a project with a session whose subagent was launched with a model and a config
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the general-purpose agent type's details show its launch settings

  @e2e @browser
  Scenario: A session from an older Claude Code shows the estimated split, labelled as an estimate
    Given a project with a session from an older Claude Code that did not record its requests, with a subagent
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the main agent's In context list is not measured, keeps its remainder row and says it is an estimate
    And the page shows the estimate note and a remainder row in the main agent's In context list

  @e2e @browser
  Scenario: A loaded file the project's config leaves out still shows its text
    Given a project whose instruction file sits under a symlinked folder that its config leaves out and the session loaded
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the page shows that file's text and offers no check or fix for it

  @e2e @browser
  Scenario: A loaded file inside an excluded folder shows its text and its buttons name the exclusion
    Given a project with a recorded Claude Code session
    And the project's config excludes the folder "sub", which holds the loaded instruction file reading "sub scoped text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And "sub/CLAUDE.md" shows its text "sub scoped text" and its check and fix buttons name exclude_dirs "sub" in ".ails/config.yml"

  @e2e @browser
  Scenario: A session that grows redraws no panel whose content did not change
    Given a project with a recorded Claude Code session
    And the project's instruction file reads "steady text"
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And with the details of "CLAUDE.md" open on each tab, a session that grows redraws no panel whose content is unchanged

  @e2e
  Scenario: A compaction lists each instruction file loaded before it as kept, reloaded or unknown
    Given a project with a session that compacted after loading three instruction files, recording requests
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the compaction lists the root file reloaded, the file read again kept and the other nested file unknown
    And the chart's instruction files keep the unsettled file's tokens after the compaction

  @e2e
  Scenario: A compaction in a session that recorded no requests cannot settle its nested files
    Given an older Claude Code session that compacted after loading three instruction files
    When "ails xray --no-open" is started in the project
    Then the printed address is on 127.0.0.1
    And the compaction lists each nested file as unknown and the root file as reloaded
    And the chart's instruction files after the compaction still hold each nested file
