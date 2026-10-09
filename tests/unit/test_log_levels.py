"""Logger levels held for a block come back afterwards."""

import logging

import pytest

from reporails_cli.core.platform.observability.log_levels import quiet_loggers


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_quiet_loggers_hold_the_level_inside_and_restore_it_after() -> None:
    log = logging.getLogger("reporails_cli.test_quiet_probe")
    log.setLevel(logging.INFO)
    with quiet_loggers(("reporails_cli.test_quiet_probe",)):
        assert log.level == logging.ERROR
    assert log.level == logging.INFO


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_quiet_loggers_restore_the_level_when_the_block_raises() -> None:
    log = logging.getLogger("reporails_cli.test_quiet_probe")
    log.setLevel(logging.DEBUG)
    with pytest.raises(RuntimeError), quiet_loggers(("reporails_cli.test_quiet_probe",)):
        raise RuntimeError
    assert log.level == logging.DEBUG
