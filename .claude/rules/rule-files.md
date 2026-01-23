---
paths: ["checks/**"]
---

# Rule File Structure

## File Naming

- `checks/{category}/{id}-{slug}.md` — rule definition (gitignored)
- `checks/{category}/{id}-{slug}.yml` — OpenGrep patterns (tracked)

## Writing .yml Files

- ALL rules get a `.yml` file regardless of type
- Use the `detection` field from `.md` frontmatter as guidance
- NEVER embed OpenGrep YAML inside `.md` files