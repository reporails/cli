---
id: CORE:S:0018
slug: skill-directory-kebab-case
title: Skill Directory Kebab Case
category: structure
type: deterministic
severity: medium
backed_by: []
match: {type: skill}
source: https://code.claude.com/docs/en/skills
---
# Skill Directory Kebab Case

Skill files must declare a `name:` field in frontmatter using kebab-case format (lowercase letters and digits separated by hyphens). Consistent naming prevents path resolution errors across platforms.

## Antipatterns

- Using underscores in the skill name (`name: my_skill`). The pattern requires hyphens, not underscores.
- Using camelCase or PascalCase (`name: mySkill`). The pattern requires all-lowercase characters.
- Omitting the `name:` field entirely. The check expects a `name:` key-value pair matching the kebab-case pattern.
- Starting the name with a digit (`name: 2-deploy`). The pattern requires the name to start with a lowercase letter.

## Pass / Fail

### Pass

~~~~markdown
---
name: deploy-staging
---
# Deploy Staging

Push to the staging environment.
~~~~

### Fail

~~~~markdown
---
name: Deploy_Staging
---
# Deploy Staging

Push to the staging environment.
~~~~

## Limitations

Checks that the skill name field uses kebab-case format. Does not validate whether the name describes the skill's purpose.
