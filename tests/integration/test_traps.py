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

import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator

import pytest

from .helpers import (
    free_tcp_port,
    free_udp_port,
    log_contains,
    snmp_trap,
    spawn_supervised,
    tcp_port_open,
)
from .templates import render_client_trap_conf

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


# ---------------------------------------------------------------------------
# TRAPv1 forwarding
#
# SNMPv1 traps use a distinct PDU type that snmpfwd-server translates to
# SNMPv2 via `rfc2576.v1_to_v2` before forwarding over the trunk. The v2c
# client then delivers it as an SNMPv2Trap to the downstream snmptrapd,
# which logs it as an `iso.*` enterprise trap. Testing end-to-end catches
# the translation-observer and PDU-shape changes that were the biggest
# regression risks in the pysnmp-lextudio port.


# Server config with BOTH v1 and v2c creds so the same snmpfwd instance
# accepts either trap version on the listener. Reuses the v2c
# trap-forwarding server template layout but adds a v1 credentials
# group whose `snmp-security-model: 1` tells pysnmp to accept v1
# messages.
SERVER_TRAP_V1_AND_V2_CONF = """\
config-version: 2
program-name: snmpfwd-server

snmp-credentials-group-v1 {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address: 127.0.0.1:{snmp_listen_port}

  snmp-engine-id: {snmp_engine_id}

  snmp-community-name: {listen_community}
  snmp-security-name: {listen_community}-v1
  snmp-security-model: 1
  snmp-security-level: 1

  snmp-credentials-id: creds-v1
}}

snmp-credentials-group-v2 {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address: 127.0.0.1:{snmp_listen_port}

  snmp-engine-id: {snmp_engine_id}

  snmp-community-name: {listen_community}
  snmp-security-name: {listen_community}-v2
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-credentials-id: creds-v2
}}

context-group {{
  snmp-context-engine-id-pattern: .*?
  snmp-context-name-pattern: .*?

  snmp-context-id: any-context
}}

content-group {{
  snmp-pdu-type-pattern: (TRAPv1|TRAPv2|INFORM)
  snmp-pdu-oid-prefix-pattern-list: .*?

  snmp-content-id: trap-content
}}

peers-group {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address-pattern-list: .*?
  snmp-peer-address-pattern-list: .*?

  snmp-peer-id: 100
}}

trunking-group {{
  trunk-bind-address: 127.0.0.1
  trunk-peer-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: client

  trunk-id: trunk-1
}}

routing-map {{
  matching-snmp-context-id-list: any-context
  matching-snmp-content-id-list: trap-content
  matching-snmp-peer-id-list: 100

  v1-route {{
    matching-snmp-credentials-id-list: creds-v1
    using-trunk-id-list: trunk-1
  }}

  v2-route {{
    matching-snmp-credentials-id-list: creds-v2
    using-trunk-id-list: trunk-1
  }}
}}
"""


def _resolve_bin(name: str) -> str:
    override = os.environ.get("SNMPFWD_VENV")
    if override:
        candidate = Path(override) / "bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.is_file() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)
    found = shutil.which(name)
    if found:
        return found
    pytest.skip(f"{name} not locatable")


@pytest.fixture
def snmpfwd_trap_proxy_v1(tmp_path: Path, snmptrapd_backend):
    """Spawn a trap-forwarding snmpfwd pair whose server accepts BOTH
    SNMPv1 and SNMPv2c traps. Used to exercise the server's v1→v2
    PDU translation path."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    listen_community = "public"
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"

    server_conf = tmp_path / "server.conf"
    client_conf = tmp_path / "client.conf"
    server_conf.write_text(SERVER_TRAP_V1_AND_V2_CONF.format(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        listen_community=listen_community,
        trunk_port=trunk_port,
    ))
    client_conf.write_text(render_client_trap_conf(
        snmp_engine_id=engine_id,
        backend_community=snmptrapd_backend.community,
        backend_port=snmptrapd_backend.port,
        trunk_port=trunk_port,
    ))

    server_log = tmp_path / "snmpfwd-server.log"
    client_log = tmp_path / "snmpfwd-client.log"

    client_proc = spawn_supervised(
        name="snmpfwd-client",
        cmd=[
            _resolve_bin("snmpfwd-client"),
            f"--config-file={client_conf}",
            f"--logging-method=file:{client_log}",
            "--log-level=debug",
        ],
        log_path=tmp_path / "snmpfwd-client.stdouterr.log",
        ready=lambda: tcp_port_open("127.0.0.1", trunk_port),
        ready_timeout=15.0,
    )
    server_proc = None
    try:
        server_proc = spawn_supervised(
            name="snmpfwd-server",
            cmd=[
                _resolve_bin("snmpfwd-server"),
                f"--config-file={server_conf}",
                f"--logging-method=file:{server_log}",
                "--log-level=debug",
            ],
            log_path=tmp_path / "snmpfwd-server.stdouterr.log",
            ready=lambda: log_contains(server_log, "client is now connected"),
            ready_timeout=15.0,
        )
        yield {
            "listen_address": f"127.0.0.1:{listen_port}",
            "listen_community": listen_community,
            "snmptrapd_log": snmptrapd_backend.log_path,
            "server_log": server_log,
        }
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


def test_trapv1_forwards_via_translation(snmpfwd_trap_proxy_v1):
    """snmptrap -v1 → snmpfwd-server (v1 receiver, v1→v2 translator) →
    trunk → snmpfwd-client (v2c originator) → snmptrapd. Tests the
    `rfc2576.v1_to_v2` translation path that has no v2 equivalent on
    the modern pysnmp."""
    stack = snmpfwd_trap_proxy_v1

    # SNMPv1 trap positional args are DIFFERENT from v2c: enterprise
    # OID, agent-addr, generic-trap, specific-trap, uptime, then
    # varbinds. See snmptrap(1).
    result = subprocess.run(
        [
            "snmptrap", "-v1", "-c", stack["listen_community"],
            stack["listen_address"],
            "1.3.6.1.4.1.99999",   # enterprise OID
            "127.0.0.1",            # agent-addr
            "6",                    # generic-trap: enterpriseSpecific
            "42",                   # specific-trap
            "",                     # uptime (empty -> snmptrap uses 0)
            MARKER_OID, "s", MARKER_VALUE,
        ],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, (
        f"snmptrap -v1 failed rc={result.returncode} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}\n"
        f"server log:\n{stack['server_log'].read_text(errors='replace')[-2000:]}"
    )

    log = _wait_for_trap(stack["snmptrapd_log"], MARKER_VALUE)
    assert MARKER_VALUE in log, (
        "v1-trap payload never reached snmptrapd after proxy translation:\n"
        + log[-4000:]
    )
    # After server-side v1→v2 translation, the trap OID on the wire
    # to snmptrapd is the v1-to-v2-mapped form (RFC 2576 §3.1). The
    # enterprise OID we supplied (1.3.6.1.4.1.99999) shows up in the
    # trap's enterprise varbind either way.
    assert "99999" in log, (
        "v1 trap enterprise OID missing from snmptrapd log:\n" + log[-4000:]
    )
