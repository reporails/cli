Feature: The x-ray page's first open shows a loading skeleton of its layout, and gives it up for content or a notice

  @page @browser
  Scenario: Until the first view lands the page shows the graph layout as a skeleton, then the real graph
    Given the bundled page is served over the "view_sample" fixture view
    Then with the first view held back the first paint is the graph layout as a skeleton, and once it lands no skeleton remains and the top card is drawn

  @page @browser
  Scenario: A server that answers 409 leaves the notice and no skeleton
    Given the bundled page is served over the "view_sample" fixture view
    Then a view answered with 409 shows the notice text and no skeleton

  @page @browser
  Scenario: A server that does not answer leaves the notice and no skeleton
    Given the bundled page is served over the "view_sample" fixture view
    Then a view that is never answered shows the notice text and no skeleton

  @page @browser
  Scenario: Reduced motion stops the skeleton's shimmer
    Given the bundled page is served over the "view_sample" fixture view
    Then under reduced motion the skeleton has no running animation
