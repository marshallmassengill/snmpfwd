"""Runtime counters — drive known activity through the proxy and look
for the expected counter names + values in the log dump."""
from __future__ import annotations

import time

import pytest

from .helpers import SnmpCliError, snmp_get


SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def _wait_for_log_match(path, needle: str, deadline_s: float = 8.0) -> str:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace")
        if needle in text:
            return text
        time.sleep(0.1)
    return path.read_text(errors="replace")


def test_trunk_connections_up_appears_in_server_log(snmpfwd_proxy):
    """Trunk came up during fixture setup → the metrics timer reports
    trunk.connections_up=1 within one interval (2s in tests)."""
    log = _wait_for_log_match(
        snmpfwd_proxy.server_log, 'trunk.connections_up=',
    )
    assert 'trunk.connections_up=' in log, (
        'server log never reported trunk.connections_up counter:\n'
        + log[-3000:]
    )


def test_auth_failure_increments_counter(snmpfwd_proxy):
    """A wrong-community request trips server.auth_failures, visible
    in the next counter dump."""
    # Drive one auth failure. Wait out its per-query timeout.
    with pytest.raises(SnmpCliError):
        snmp_get(
            target=snmpfwd_proxy.listen_address,
            community="wrong-community",
            oids=[SYS_DESCR],
            timeout_secs=1.0,
            retries=0,
        )

    log = _wait_for_log_match(
        snmpfwd_proxy.server_log, 'server.auth_failures=',
    )
    assert 'server.auth_failures=' in log, (
        'server log never reported server.auth_failures counter:\n'
        + log[-3000:]
    )


def test_requests_forwarded_counter(snmpfwd_proxy):
    """A successful GET increments server.requests_forwarded on the
    server side."""
    snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    log = _wait_for_log_match(
        snmpfwd_proxy.server_log, 'server.requests_forwarded=',
    )
    assert 'server.requests_forwarded=' in log
