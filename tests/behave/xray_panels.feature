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

  @page @browser
  Scenario: The main agent's cost shows the whole session
    Given the bundled page is served over the "view_sample" fixture view
    Then the main agent's cost tile and details list the session total, the subagents' share and the costliest subagents

  @page @browser
  Scenario: Details word their numbers as they are measured
    Given the bundled page is served over the "view_sample" fixture view changed so the first subagent loaded CLAUDE.md late
    Then the details word the cache figures, the work size, the load time and the exact total as the numbers mean

  @page @browser
  Scenario: Estimates that overshoot the exact total say so
    Given the bundled page is served over the "view_sample" fixture view changed so the main agent's estimates overshoot
    Then the peak details say the estimates overshoot and no percentage passes 100

  @page @browser
  Scenario: Memory the transcript did not record is not called never loaded
    Given the bundled page is served over the "view_sample" fixture view changed so its memory was not recorded
    Then the Sources table says the memory files were not recorded in this session, not that they were never loaded
    And the subagent's Output line says its hand-back size is not known and shows no ratio

  @page @browser
  Scenario: Unpriced replies are counted as replies
    Given the bundled page is served over the "view_fxpage" fixture view
    Then the session cost details count the replies that could not be priced as replies

  @page @browser
  Scenario: A Sources row highlights on hover while its kind's eye is off
    Given the bundled page is served over the "view_sample" fixture view
    Then hovering a Sources row of a kind whose eye is off still highlights that row

  @page @browser
  Scenario: A subagent with no replies never reads 0 of work
    Given the bundled page is served over the "view_sample" fixture view changed so the first subagent has no replies
    Then the subagent's Output line says the size of its work is not known and never reads 0 of work
