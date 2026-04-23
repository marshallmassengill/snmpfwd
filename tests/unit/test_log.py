"""Handler-wiring behavior of snmpfwd.log.setLogger.

The CLI lets `--logging-method` be given more than once; the contract
is that force=True clears existing handlers (for the first call) and
force=False appends (for every subsequent call). These tests pin that
behavior down without spinning up the real process."""
from __future__ import annotations

import logging

import pytest

from snmpfwd import log
from snmpfwd.error import SnmpfwdError


def _fresh_logger_name(request) -> str:
    # Each test gets its own program-id so handler state doesn't leak
    # between tests (the logging module's registry is process-global).
    return 'snmpfwd-test-' + request.node.name


def test_setLogger_force_attaches_single_handler(request):
    progId = _fresh_logger_name(request)
    log.setLogger(progId, 'null', force=True)
    logger = logging.getLogger(progId)
    # Only the null-method handler remains.
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.NullHandler)


def test_setLogger_default_appends(request):
    progId = _fresh_logger_name(request)
    log.setLogger(progId, 'null', force=True)
    log.setLogger(progId, 'stderr')  # default force=False
    logger = logging.getLogger(progId)
    assert len(logger.handlers) == 2
    kinds = {type(h).__name__ for h in logger.handlers}
    assert 'NullHandler' in kinds
    assert 'StreamHandler' in kinds


def test_setLogger_force_clears_prior_handlers(request):
    progId = _fresh_logger_name(request)
    log.setLogger(progId, 'stderr', force=True)
    log.setLogger(progId, 'stdout')  # appends
    assert len(logging.getLogger(progId).handlers) == 2

    log.setLogger(progId, 'null', force=True)  # should reset to just null
    logger = logging.getLogger(progId)
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.NullHandler)


def test_setLogger_rejects_unknown_method(request):
    progId = _fresh_logger_name(request)
    with pytest.raises(SnmpfwdError):
        log.setLogger(progId, 'nonesuch-sink', force=True)


def test_setLogger_missing_method_raises(request):
    progId = _fresh_logger_name(request)
    with pytest.raises(SnmpfwdError):
        log.setLogger(progId)  # no method name at all


def test_two_sinks_both_receive_records(request):
    progId = _fresh_logger_name(request)
    # Start from a clean slate, then attach two memory-backed sinks
    # alongside one another by appending handlers directly — avoids
    # depending on stderr/stdout or file I/O in the test.
    log.setLogger(progId, 'null', force=True)
    logger = logging.getLogger(progId)
    # Remove the null sink that the setup left behind so we see only
    # the records that reach the memory handlers we append next.
    for h in list(logger.handlers):
        logger.removeHandler(h)

    class _Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []
        def emit(self, record):
            self.records.append(record.getMessage())

    a, b = _Capture(), _Capture()
    logger.addHandler(a)
    logger.addHandler(b)

    # Drive through the public module-level `info()` which writes to
    # whatever logger `setLogger` bound internally. Rebind by calling
    # setLogger once more with force=True — but that clears our two
    # handlers. So reach through the module-private binding instead,
    # which is what the public API ultimately targets.
    log._logger = logger
    log.info('hello')

    assert any('hello' in r for r in a.records)
    assert any('hello' in r for r in b.records)
