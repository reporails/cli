---
id: CLAUDE:S:0010
slug: import-depth-within-limit
title: "Import Depth Within Limit"
category: structure
type: mechanical
severity: medium
match: {type: main}
---

# Import Depth Within Limit

Import chains should not exceed 3 levels deep. Deep import hierarchies increase context loading time and create fragile dependency chains.

## Limitations

Counts import depth from the root instruction file. Does not evaluate whether deep imports are justified by project complexity.
