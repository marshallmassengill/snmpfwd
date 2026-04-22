"""INFORM forwarding. Confirms that the proxy:

  (a) acks the original INFORM sender immediately (proof: snmpinform
      exits 0 rather than timing out), and
  (b) still forwards the notification downstream to the configured
      trap receiver (snmptrapd logs the payload).

The proxy's ack is "best-effort": it means "I received this INFORM
and will try to forward it". End-to-end confirmation where the proxy
only ack's after the downstream has ack'd is a separate design
(Phase 3B) — see docs/PORTING-NOTES.md.
"""
from __future__ import annotations

import time

from .helpers import SnmpCliError, snmp_inform
import pytest


TRAP_OID = "1.3.6.1.4.1.99999.2"
MARKER_OID = "1.3.6.1.4.1.99999.2.1"
MARKER_VALUE = "INTEGRATION-TEST-INFORM-PAYLOAD"


def _wait_for_log(log_path, needle: str, deadline_s: float = 5.0) -> str:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        text = log_path.read_text(errors="replace")
        if needle in text:
            return text
        time.sleep(0.1)
    return log_path.read_text(errors="replace")


def test_inform_is_acked_by_proxy(snmpfwd_trap_proxy):
    """snmpinform exits 0 only if the receiver (here: the proxy) sent a
    Response ack back. Before Phase 3A this would fail with a timeout
    because snmpfwd's NotificationReceiver override never responded to
    confirmed-class PDUs."""
    # If the proxy fails to ack, snmpinform returns non-zero after its
    # timeout elapses. If this line raises, the proxy is not acking.
    snmp_inform(
        target=snmpfwd_trap_proxy.listen_address,
        community=snmpfwd_trap_proxy.listen_community,
        trap_oid=TRAP_OID,
        varbinds=[(MARKER_OID, "s", MARKER_VALUE)],
    )


def test_inform_forwards_to_backend(snmpfwd_trap_proxy):
    """The INFORM's payload still reaches the downstream trap receiver
    alongside the immediate ack sent back to the original sender."""
    snmp_inform(
        target=snmpfwd_trap_proxy.listen_address,
        community=snmpfwd_trap_proxy.listen_community,
        trap_oid=TRAP_OID,
        varbinds=[(MARKER_OID, "s", MARKER_VALUE)],
    )

    log = _wait_for_log(snmpfwd_trap_proxy.backend.log_path, MARKER_VALUE)
    assert MARKER_VALUE in log, (
        "INFORM payload did not reach snmptrapd; log tail:\n" + log[-4000:]
    )
    # The enterprise OID prefix survives the hop (could render as
    # `iso.3.6.1.4.1.99999.2` or `enterprises.99999.2`).
    assert "99999.2" in log


def test_inform_server_log_shows_forwarding(snmpfwd_trap_proxy):
    """snmpfwd-server's debug log records an INFORM being handled
    (as opposed to a TRAP — different PDU type in the log line)."""
    snmp_inform(
        target=snmpfwd_trap_proxy.listen_address,
        community=snmpfwd_trap_proxy.listen_community,
        trap_oid=TRAP_OID,
        varbinds=[(MARKER_OID, "s", MARKER_VALUE)],
    )

    # Give the proxy a moment to flush debug output.
    time.sleep(0.5)
    server_log = snmpfwd_trap_proxy.server_log.read_text(errors="replace")
    assert "InformRequest" in server_log or "INFORM" in server_log, (
        "server log didn't show InformRequest handling:\n" + server_log[-4000:]
    )
