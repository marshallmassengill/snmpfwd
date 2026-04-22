"""SIGHUP-triggered config reload. Verifies that rewriting the server's
config file and sending SIGHUP makes the running proxy adopt the new
routing without dropping or leaking in-flight state."""
from __future__ import annotations

import os
import signal
import time

import pytest

from .helpers import SnmpCliError, snmp_get


SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def _wait_for_log(path, needle: str, deadline_s: float = 5.0) -> bool:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace")
        if needle in text:
            return True
        time.sleep(0.1)
    return False


def test_sighup_reloads_server_routing(snmpfwd_proxy):
    """Rewrite the server config to use an impossible snmp-pdu-type-pattern
    and SIGHUP the server. Subsequent requests should be dropped (their
    content-id classifier now returns None, so no route matches)."""
    # Sanity check: a GET works with the initial config.
    vbs = snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1

    # Rewrite the server config so the content classifier refuses to
    # match any PDU type. Everything else stays the same.
    original = snmpfwd_proxy.server_config_path.read_text()
    modified = original.replace(
        'snmp-pdu-type-pattern: .*?',
        'snmp-pdu-type-pattern: NEVERMATCH',
    )
    assert modified != original, "the test config template is missing the expected pattern"
    snmpfwd_proxy.server_config_path.write_text(modified)

    # SIGHUP the running snmpfwd-server.
    os.kill(snmpfwd_proxy.server_pid, signal.SIGHUP)

    assert _wait_for_log(
        snmpfwd_proxy.server_log,
        'configuration routing reloaded',
    ), "server log never reported a successful reload\n--- log tail ---\n" + \
        snmpfwd_proxy.server_log.read_text()[-2000:]

    # After reload the classifier returns no route — GET times out.
    with pytest.raises(SnmpCliError) as excinfo:
        snmp_get(
            target=snmpfwd_proxy.listen_address,
            community=snmpfwd_proxy.listen_community,
            oids=[SYS_DESCR],
            timeout_secs=2.0,
            retries=0,
        )
    assert "Timeout" in excinfo.value.stdout + excinfo.value.stderr

    # Server log records the "no route configured" drop decision.
    log = snmpfwd_proxy.server_log.read_text(errors="replace")
    assert 'no route configured' in log


def test_sighup_invalid_config_keeps_old_routing(snmpfwd_proxy):
    """If the new config fails to parse/validate, the reload callback
    logs the error and the running proxy keeps serving with its
    previous routing."""
    # Sanity check.
    snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )

    # Rewrite the config with an invalid content-id regex so re-parse fails.
    snmpfwd_proxy.server_config_path.write_text('this is not valid snmpfwd config\n')
    os.kill(snmpfwd_proxy.server_pid, signal.SIGHUP)

    assert _wait_for_log(
        snmpfwd_proxy.server_log,
        'configuration reload failed',
    ), "server log never reported a reload failure"

    # Old routing still works — a GET still succeeds.
    vbs = snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1
