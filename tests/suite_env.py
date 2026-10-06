"""The environment the test suites run in, owned in one place for pytest and behave.

No ambient `AILS_*` setting and no CI marker reaches a test: a developer's sign-in, plan or
server address must never decide a result, and a run must never talk to a real server. The suite
defaults are the only `AILS_*` values left; a test that needs another sets its own.
"""

from __future__ import annotations

from collections.abc import Mapping

CI_ENV_VARS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI")  # mirrors helpers._is_ci

# Tests never download the model set, and never reach a hosted service: a closed local port
# fails fast, so a check runs its offline path.
SUITE_DEFAULTS = {"AILS_MODEL_OFFLINE": "1", "AILS_SERVER_URL": "http://127.0.0.1:9"}


def suite_env(base: Mapping[str, str], *, drop_ci: bool = True) -> dict[str, str]:
    """`base` without any `AILS_*` key (and without CI markers unless `drop_ci` is off), plus the suite defaults."""
    drop = ("AILS_",)
    kept = {
        k: v for k, v in base.items() if not k.upper().startswith(drop) and not (drop_ci and k.upper() in CI_ENV_VARS)
    }
    return {**kept, **SUITE_DEFAULTS}
