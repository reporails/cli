---
id: CORE:G:0010
slug: no-hidden-unicode
title: No Hidden Unicode
category: governance
type: deterministic
enforcement_required: true
enforcement_mechanism: ci
severity: high
backed_by: [advanced-context-engineering, spec-writing-for-agents]
match: {format: [freeform, frontmatter, schema_validated]}
---

# No Hidden Unicode

Instruction files must not contain invisible characters. A human reviewer sees plain text while the agent still reads the hidden characters, so an instruction can be planted in a file that looks harmless.

The check reports every line that holds one, in prose and in code blocks, in the file you wrote and in any file it imports with `@path` (the finding names the imported file and its line). It reports:

- Unicode Tag characters (U+E0000 to U+E007F), which spell out invisible ASCII text
- direction controls that reorder how text is displayed (U+202A to U+202E, U+2066 to U+2069, U+200E, U+200F, U+061C)
- zero-width characters (U+200B, U+200C, U+200D, U+2060, U+180E) and invisible operators (U+2061 to U+2064)
- the combining grapheme joiner (U+034F) and deprecated format controls (U+206A to U+206F)
- a byte order mark (U+FEFF) in the middle of a file

These normal uses are not reported:

- a zero-width joiner between two emoji, as in a family emoji, including a skin-tone modifier before the joiner
- the tag characters of an emoji flag sequence such as the England flag (a black flag, tag letters, then the cancel tag U+E007F)
- a zero-width non-joiner or joiner between letters or marks of Arabic-script and Indic scripts, as in Persian and Devanagari text

## Antipatterns

- Pasting text copied from a web page or a chat window -- it can carry zero-width spaces or tag characters that stay invisible in the editor.
- Accepting an instruction-file change that shows no visible difference -- a hidden instruction can sit in a line that reads as ordinary prose.
- Leaving a zero-width space inside a word or a command -- the line looks right but the agent reads different text.

## Pass / Fail

### Pass

~~~~markdown
## Style

Use plain ASCII punctuation in commands.
Family emoji such as 👨‍👩‍👧 and 👩🏽‍💻 are fine.
Persian می‌خواهم and Devanagari क्‍ष are fine.
~~~~

### Fail

~~~~markdown
## Style

Run the tests before committing.<U+E0049><U+E0067><U+E006E><U+E006F><U+E0072><U+E0065> (hidden tag characters)
Run the te<U+200B>sts (zero-width space inside a word)
~~~~

## Limitations

Reports only the listed characters; other invisible or look-alike characters (for example homoglyph letters) are not reported. A byte order mark at the very start of a file, or at the start of a file it imports with `@path`, is a normal encoding marker and is not reported; only one in the middle of a file is. A zero-width joiner is left alone only when an emoji sits directly on both sides (a skin-tone modifier and variation selector may sit before it), or when letters or marks of Arabic-script or Indic scripts sit on both sides; a zero-width non-joiner only in the script case. Tag characters are left alone only inside a complete emoji flag sequence; anywhere else, and in an unterminated sequence, they are reported. Scripts beyond Arabic and the listed Indic scripts (Devanagari, Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam, Sinhala) are not given the joiner carve-out.
