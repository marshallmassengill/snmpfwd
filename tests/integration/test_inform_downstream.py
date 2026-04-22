"""Phase 3B: the proxy acks an INFORM only after the downstream acks it.

test_inform.py covers the happy path (downstream up). This module
covers the no-ack-on-failure path: if the downstream is unreachable,
the proxy must NOT ack the original sender — RFC-strict INFORM
semantic for a proxy — so the sender can retry or time out."""
from __future__ import annotations

import time

import pytest

from .helpers import SnmpCliError, snmp_inform


TRAP_OID = "1.3.6.1.4.1.99999.3"
MARKER_OID = "1.3.6.1.4.1.99999.3.1"
MARKER_VALUE = "INTEGRATION-TEST-INFORM-DOWNSTREAM-UNREACHABLE"


def test_inform_no_ack_when_downstream_unreachable(snmpfwd_trap_proxy_dead_backend):
    """With the downstream port empty (nothing listening), the client
    times out trying to INFORM it and reports that over the trunk; the
    server logs "NOT responding" and skips the ack. snmpinform on the
    original sender side sees a timeout (non-zero exit) — proof that
    the proxy did not ack prematurely."""
    # snmp-peer-timeout in the trap-forwarding client config is 500 (5s)
    # with no retries. snmpinform waits slightly longer so it sees the
    # definitive no-ack rather than racing the client's internal
    # timeout.
    with pytest.raises(SnmpCliError) as excinfo:
        snmp_inform(
            target=snmpfwd_trap_proxy_dead_backend.listen_address,
            community=snmpfwd_trap_proxy_dead_backend.listen_community,
            trap_oid=TRAP_OID,
            varbinds=[(MARKER_OID, "s", MARKER_VALUE)],
            timeout_secs=7.0,
            retries=0,
        )
    assert "Timeout" in excinfo.value.stdout + excinfo.value.stderr

    # Server should have logged the "NOT responding" decision.
    time.sleep(0.2)  # small grace for log flush
    server_log = snmpfwd_trap_proxy_dead_backend.server_log.read_text(
        errors="replace"
    )
    assert "NOT responding" in server_log, (
        "server log didn't record the skipped-ack decision:\n"
        + server_log[-4000:]
    )
