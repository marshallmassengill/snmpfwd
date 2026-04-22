"""
Trap forwarding scenarios. Validates the notification-receiver path in
snmpfwd-server (which overrides `processPdu` on pysnmp's NotificationReceiver)
and the notification-originator path in snmpfwd-client — a flow distinct
from the command-forwarding code paths tested in test_smoke / test_commands.

Flagged as high regression risk during the pysnmp-lextudio port because the
`processPdu` / `process_pdu` rename has no backward-compatibility alias on
the modern pysnmp.
"""
from __future__ import annotations

import time

from .helpers import snmp_trap

TRAP_OID = "1.3.6.1.4.1.99999.1"
MARKER_OID = "1.3.6.1.4.1.99999.1.1"
MARKER_VALUE = "INTEGRATION-TEST-TRAP-PAYLOAD"


def _wait_for_trap(log_path, needle: str, deadline_s: float = 5.0) -> str:
    """Poll snmptrapd's trap log until the trap arrives. Returns the log text."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        text = log_path.read_text(errors="replace")
        if needle in text:
            return text
        time.sleep(0.1)
    return log_path.read_text(errors="replace")


def test_trapv2_forwards_to_backend(snmpfwd_trap_proxy):
    """snmptrap → snmpfwd-server (trap receiver) → trunk → snmpfwd-client
    (trap originator) → snmptrapd (backend) → logs the trap we sent."""
    snmp_trap(
        target=snmpfwd_trap_proxy.listen_address,
        community=snmpfwd_trap_proxy.listen_community,
        trap_oid=TRAP_OID,
        varbinds=[(MARKER_OID, "s", MARKER_VALUE)],
    )

    log = _wait_for_trap(snmpfwd_trap_proxy.backend.log_path, MARKER_VALUE)
    assert MARKER_VALUE in log, (
        "trap payload did not reach snmptrapd; log tail:\n" + log[-4000:]
    )
    # The enterprise OID arrives as `iso.3.6.1.4.1.99999.1` (iso = .1 prefix
    # in net-snmp's textual form), `1.3.6.1.4.1.99999.1`, or translated to
    # `enterprises.99999.1`. Match the suffix to stay renderer-agnostic.
    assert "99999.1" in log, (
        "trap-oid not in snmptrapd log:\n" + log[-4000:]
    )


def test_trapv2_server_logs_forwarding(snmpfwd_trap_proxy):
    """snmpfwd-server's debug log records the inbound trap being forwarded
    over the trunk. Confirms the notification-receiver code path ran."""
    snmp_trap(
        target=snmpfwd_trap_proxy.listen_address,
        community=snmpfwd_trap_proxy.listen_community,
        trap_oid=TRAP_OID,
        varbinds=[(MARKER_OID, "s", MARKER_VALUE)],
    )

    # Give the proxy a moment to write the debug line.
    time.sleep(0.5)
    server_log = snmpfwd_trap_proxy.server_log.read_text(errors="replace")
    assert "SNMPv2Trap" in server_log or "TRAPv2" in server_log, (
        "expected trap PDU handling in server log:\n" + server_log[-4000:]
    )
