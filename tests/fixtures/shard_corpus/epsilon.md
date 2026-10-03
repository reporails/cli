# Epsilon Docs Site

A static documentation site built from Markdown sources.

## Commands

- `bundle install` — Install Ruby dependencies
- `bundle exec jekyll serve` — Serve the site locally
- `bundle exec jekyll build` — Build the static site

## Architecture

Pages live under `docs/`, layouts under `_layouts/`, and shared includes under
`_includes/`.

## Constraints

- NEVER hardcode an absolute URL in a page template
- ALWAYS run the link checker before publishing
- MUST keep the navigation config in sync with the pages directory
- Avoid embedding large images without a compressed variant
