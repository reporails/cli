---
id: CORE:C:0058
slug: one-instruction-per-sentence
title: "One Instruction Per Sentence"
category: coherence
type: deterministic
execution: local
severity: medium
match: {}
---

# One Instruction Per Sentence

Give each instruction its own sentence. Instructions packed into one sentence compete, and some of them are not followed; the last one tends to win. The joining punctuation does not change that, because a comma, a semicolon, a dash, "and" or "then" packs instructions the same way. A period or a list item of its own is what separates them. When two instructions must share a sentence, put the one that must win last.

After a split, each sentence has to stand on its own. Repeat the subject or object the instructions shared, so no sentence depends on its neighbour for what it acts on. Keep a directive together with the bound that limits it: "Fix the failing test — ask, don't refactor" keeps "ask, don't refactor" with its directive, or each half names its object ("Ask before refactoring the module. Do not refactor the module on your own."). Never leave a lead-in such as "You are a reviewer: you read the diff" holding only the first item of its list; keep the lead-in with every item it introduces, or give each item a sentence that names its own subject.

## Antipatterns

- **Comma-spliced commands**: "Install dependencies with `uv sync`, run `uv run pytest`, and commit the lockfile." Three instructions share one sentence, and the earlier ones are the likeliest to be dropped. The diagnostic reports the sentence with the number of instructions it holds and names each one.
- **A prohibition packed with its alternative**: "Do not edit generated files; run `make gen` to regenerate them." The semicolon joins the two as tightly as a comma does. Give the command and the prohibition a sentence each, with the command first.
- **Commands joined by "and"**: "Update `CHANGELOG.md` and push the release tag." A bare "and" or "then" between two commands packs them into one sentence. An "and" between two objects of one command ("Run the linter and the formatter.") is one instruction and passes.
- **A list step that packs several actions**: the step "Pull the latest `main`, install dependencies with `uv sync`, then run `uv run pytest`." Each list item is read as a sentence like any other. Give each action its own step.
- **A split that strands a fragment**: "Run the linter. And the formatter." or "Fix the failing test. Don't refactor." Each sentence has to name its own object and keep its limiting bound, so the second half is read with what it acts on.

## Pass / Fail

### Pass

~~~~markdown
Install dependencies with `uv sync` after every pull.
Run `uv run pytest` before every commit.
Commit the updated lockfile together with your change.
Run `make gen` to regenerate files under `gen/`.
*Do not edit files under `gen/` by hand.*
Update `CHANGELOG.md` before every release.
Push the release tag to `origin` after the changelog.

1. Pull the latest `main` into your branch.
2. Install dependencies with `uv sync` from the repository root.
3. Run `uv run pytest` on the updated branch.
~~~~

### Fail

~~~~markdown
Install dependencies with `uv sync`, run `uv run pytest`, and commit the lockfile.
Do not edit generated files; run `make gen` to regenerate them.
Update `CHANGELOG.md` and push the release tag.

1. Pull the latest `main`, install dependencies with `uv sync`, then run `uv run pytest`.
~~~~

## Limitations

Reports each sentence of running text (prose, list items, numbered steps, blockquotes and table rows) that is read as two or more instructions, once, on the sentence's first line, with the count and the instructions. Each instruction is read on its own, so a packed sentence scores like the same instructions written as separate sentences. A prose sentence wrapped across lines is reported whole, while each of its lines is scored on its own, so an instruction that runs from the end of one line onto the next is scored in two parts. Headings and code blocks are not read, and neither is a sentence that gives no instruction at all. A part that is read as a statement rather than an instruction is not counted. A part of a sentence counts as an instruction when it opens with a prohibition ("do not", "don't", "never", "avoid") or with a verb telling the reader what to do. A word that can also be a noun, such as `format`, `test` or `build`, counts only with its object after it ("test it", "build the image"). A comma inside parentheses, quotes or a code span belongs to an aside, an example or a command, and does not split the sentence. Verbs listed after "to" ("Use `uv` to install packages, add dependencies, and run scripts.") say what one instruction is for and count once, until a semicolon, a "then" or a prohibition starts the next instruction. A lone word in a list ("grep, find and sed") is not a command. The items a prohibition lists before an "or" ("Do not commit secrets, push credentials, or share tokens.") are what it forbids, one instruction; a directive after a prohibition is its own instruction unless it reads like one of those items ("never edit it, run `make gen` or `make all`"). A lead label (`Note:`, `**Rule:**`) or a task checkbox (`[ ]`) is not a command and is left out of the named instructions. A condition written before a command ("…; when the build fails, run it again") belongs to the instruction it leads into. The last item of a list joined by "and" ("Preserve `id`, `slug`, and coordinate fields") is part of the list, not an instruction of its own. What a "See" pointer names runs to the next comma, semicolon or dash ("See the build and deploy guide."), and is not an instruction. A part that opens with a code span ("`make build` — Build the service") names a command rather than giving one.

A command led by a subject or a modal ("you must lint the code") is not counted, and neither is a command whose verb is outside the rule's vocabulary. A packed sentence with only one recognisable command is therefore not reported. Putting the instruction that must win last does not clear the finding.

Instruction Elaboration (`CORE:E:0004`) asks for the fragments of one instruction to fold into one sentence. The two rules agree: one instruction takes one sentence, and two instructions take two.
