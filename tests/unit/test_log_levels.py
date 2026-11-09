"""Logger levels held for a block come back; the logging setup and run timing behave in a long-lived process."""

import logging
import time
from collections.abc import Iterator

import pytest

from reporails_cli.core.platform.observability import stage_timer
from reporails_cli.core.platform.observability.log_levels import configure_logging, quiet_loggers
from reporails_cli.core.platform.observability.stage_timer import StageTimer


@pytest.fixture
def package_logger(monkeypatch: pytest.MonkeyPatch) -> Iterator[logging.Logger]:
    """The `reporails_cli` logger with no handler of its own, restored afterwards."""
    log = logging.getLogger("reporails_cli")
    timer = logging.getLogger(stage_timer.__name__)
    saved = (list(log.handlers), log.level, log.propagate, timer.level)
    log.handlers = []
    yield log
    log.handlers, log.level, log.propagate, timer.level = saved


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_configure_logging_twice_adds_one_handler_that_prints_message_and_traceback(
    package_logger: logging.Logger, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    configure_logging()
    configure_logging()
    assert len(package_logger.handlers) == 1
    try:
        raise ValueError("boom-marker")
    except ValueError:
        logging.getLogger("reporails_cli.probe").warning("it failed", exc_info=True)
    err = capsys.readouterr().err
    assert "it failed" in err
    assert "Traceback" in err and "boom-marker" in err


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_configure_logging_adds_no_handler_when_the_root_logger_has_one(
    package_logger: logging.Logger, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(logging.getLogger(), "handlers", [logging.NullHandler()])
    configure_logging()
    assert package_logger.handlers == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_run_measures_marks_from_its_own_start_and_drops_the_previous_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_STAGE_TIMING", "1")
    timer = StageTimer()
    timer.reset()
    time.sleep(0.2)
    with timer.run("first"):
        timer.mark("load")
    load = next(r for r in timer.records if r.stage == "load")
    assert load.ms < 100
    with timer.run("second"):
        pass
    assert [r.stage for r in timer.records] == ["second"]


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


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_stage_timing_only_prints_stage_timing_records_and_drops_every_other(
    package_logger: logging.Logger, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    monkeypatch.setenv("AILS_STAGE_TIMING", "1")
    configure_logging(stage_timing_only=True)
    logging.getLogger("reporails_cli.probe").warning("warning-marker")
    logging.getLogger(stage_timer.__name__).info("timing-marker")
    err = capsys.readouterr().err
    assert "timing-marker" in err
    assert "warning-marker" not in err
