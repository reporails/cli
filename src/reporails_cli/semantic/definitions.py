"""Semantic rule definitions for LLM judgment.
from __future__ import annotations
These rules cannot be evaluated with pattern matching alone.
They require the host LLM to make a judgment call based on
the content and context of the CLAUDE.md file.
"""

from typing import Any

# Semantic rule definitions
# Each definition contains:
# - question: The evaluation question for the LLM
# - criteria: Specific criteria for evaluation
# - examples: Good and bad examples
# - choices: Valid response options
# - pass_value: The choice that indicates passing
# - severity: Violation severity if failed
# - points_if_fail: Point deduction if failed

SEMANTIC_DEFINITIONS: dict[str, dict[str, Any]] = {
    "C8": {
        "question": "Does the CLAUDE.md file clearly communicate the project's philosophy and design principles in a way that guides AI behavior?",
        "criteria": {
            "clarity": "Philosophy statements are clear and unambiguous",
            "actionability": "Principles translate into concrete guidance",
            "consistency": "Philosophy aligns with other instructions",
            "relevance": "Philosophy is specific to this project, not generic",
        },
        "examples": {
            "good": [
                "We prioritize readability over cleverness. Always prefer explicit code.",
                "This is a financial system: security > features > performance.",
                "Follow the rule of three: don't abstract until you have three examples.",
            ],
            "bad": [
                "Write good code.",
                "Follow best practices.",
                "Be careful with the code.",
            ],
        },
        "choices": ["clear_philosophy", "vague_philosophy", "no_philosophy"],
        "pass_value": "clear_philosophy",
        "severity": "high",
        "points_if_fail": -15,
    },
    "E2": {
        "question": "Does the CLAUDE.md file define a clear session start ritual or onboarding process for AI assistants?",
        "criteria": {
            "explicit_steps": "Lists specific steps to take at session start",
            "context_loading": "Guides which files/context to load first",
            "verification": "Includes a way to verify understanding",
            "efficiency": "Ritual is concise and not wasteful",
        },
        "examples": {
            "good": [
                "Session start: 1) Read src/index.ts 2) Check current branch 3) Review open TODOs",
                "Before starting: run `npm test` to verify environment, then check package.json for task context",
            ],
            "bad": [
                "Start by reading the code.",
                "Make sure you understand the project.",
            ],
        },
        "choices": ["has_ritual", "partial_ritual", "no_ritual"],
        "pass_value": "has_ritual",
        "severity": "medium",
        "points_if_fail": -10,
    },
    "G3": {
        "question": "Are there any conflicting or contradictory instructions in the CLAUDE.md file?",
        "criteria": {
            "consistency": "All instructions point in the same direction",
            "no_contradictions": "No instruction negates another",
            "clear_priority": "When trade-offs exist, priority is stated",
        },
        "examples": {
            "good": [
                "Always write tests (unit tests preferred, integration tests for API endpoints)",
                "Security > performance > features (in that priority order)",
            ],
            "bad": [
                "Write comprehensive tests"
                + " ... "
                + "Keep changes minimal, skip tests for small fixes",
                "Use TypeScript strict mode" + " ... " + "any is acceptable for quick prototypes",
            ],
        },
        "choices": ["no_conflicts", "minor_conflicts", "major_conflicts"],
        "pass_value": "no_conflicts",
        "severity": "critical",
        "points_if_fail": -25,
    },
    "C2": {
        "question": "Are the commands and examples in CLAUDE.md clear enough to be executed without clarification?",
        "criteria": {
            "complete": "Commands include all required arguments",
            "context": "Commands include necessary context (directory, env vars)",
            "copy_paste": "Commands can be copy-pasted and run",
        },
        "examples": {
            "good": [
                "Run tests: `npm test` (from project root)",
                "Build: `docker build -t myapp:dev .` (requires Docker 20+)",
            ],
            "bad": [
                "Run the tests",
                "Build with docker",
                "Use the usual commands",
            ],
        },
        "choices": ["clear_commands", "partial_commands", "unclear_commands"],
        "pass_value": "clear_commands",
        "severity": "medium",
        "points_if_fail": -10,
    },
    "S3": {
        "question": "Are the code examples in CLAUDE.md still valid and consistent with the current codebase?",
        "criteria": {
            "exists": "Referenced files and functions exist",
            "current": "Examples reflect current API/syntax",
            "accurate": "Example behavior matches actual behavior",
        },
        "examples": {
            "good": [
                "Examples reference actual functions in the codebase",
                "Code snippets use current API signatures",
            ],
            "bad": [
                "References to deleted files",
                "Examples using deprecated APIs",
                "Function signatures that don't match reality",
            ],
        },
        "choices": ["examples_valid", "some_outdated", "examples_stale"],
        "pass_value": "examples_valid",
        "severity": "medium",
        "points_if_fail": -10,
    },
    "M1": {
        "question": "Does the CLAUDE.md file contain references to external resources (docs, APIs) that appear current and accessible?",
        "criteria": {
            "links_valid": "External links are well-formed",
            "version_aligned": "Referenced versions match dependencies",
            "not_deprecated": "No references to deprecated resources",
        },
        "examples": {
            "good": [
                "React docs: https://react.dev/reference/react",
                "Using Express 4.x patterns (matches package.json)",
            ],
            "bad": [
                "See legacy docs at [broken link]",
                "Follow React 16 patterns (but using React 18)",
            ],
        },
        "choices": ["references_current", "some_outdated", "references_stale"],
        "pass_value": "references_current",
        "severity": "low",
        "points_if_fail": -5,
    },
}


def get_semantic_definition(rule_id: str) -> dict[str, Any] | None:
    """
    Get semantic definition for a rule.

    Args:
        rule_id: Rule identifier (e.g., "C8")

    Returns:
        Definition dict or None if not a semantic rule
    """
    return SEMANTIC_DEFINITIONS.get(rule_id)


def get_all_semantic_rule_ids() -> list[str]:
    """
    Get all semantic rule IDs.

    Returns:
        List of semantic rule IDs
    """
    return list(SEMANTIC_DEFINITIONS.keys())
