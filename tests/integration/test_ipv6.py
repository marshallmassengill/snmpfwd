"""IPv6 transport end-to-end.

snmpfwd's endpoint-parser tests cover the `[fe80::1]` address literal
but never exercised pysnmp's UDP-over-IPv6 carrier in a running
daemon. This test drives one snmpget through a proxy whose
agent-facing and backend-facing sockets are both on `[::1]` (and use
the `1.3.6.1.2.1.100.1.2.*` transport-domain subtree that snmpfwd's
config language reserves for IPv6 endpoints). The trunk itself stays
on IPv4 loopback — it's unrelated to the SNMP transport.
"""
from __future__ import annotations

import dataclasses
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest

from .helpers import (
    free_tcp_port,
    free_udp_port,
    log_contains,
    require_cli,
    snmp_get,
    spawn_supervised,
    tcp_port_open,
)


SYS_DESCR = "1.3.6.1.2.1.1.1.0"


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


# ---------------------------------------------------------------------------
# Fixtures


@dataclasses.dataclass
class SnmpdV6Backend:
    address: str     # "[::1]:<port>" — the full target string snmpget accepts
    port: int
    community: str


@pytest.fixture
def snmpd_v6_backend(tmp_path: Path) -> Iterator[SnmpdV6Backend]:
    """snmpd bound to `[::1]:<port>` so we're exercising the IPv6
    socket path rather than the dual-stack-default-to-v4 shortcut."""
    snmpd = require_cli("snmpd")
    port = free_udp_port()
    conf_path = tmp_path / "snmpd.conf"
    # net-snmp's `rocommunity` directive only covers IPv4; the IPv6
    # counterpart is `rocommunity6`. Passing `rocommunity public ::1`
    # looks like it ought to work but snmpd silently drops every v6
    # request — receives the packet, never responds.
    conf_path.write_text(
        "rocommunity6 public ::1\n"
        'syslocation "ipv6-test-lab"\n'
        'syscontact "ipv6-test@localhost"\n'
        "sysServices 72\n"
    )
    log_path = tmp_path / "snmpd.log"
    cmd = [
        snmpd, "-f", "-Lo",
        "-C", "-c", str(conf_path),
        "--rwcommunity=",
        "--noPersistentSave=true",
        "--noPersistentLoad=true",
        f"udp6:[::1]:{port}",
    ]
    proc = spawn_supervised(
        name="snmpd-v6", cmd=cmd, log_path=log_path,
        ready=lambda: log_contains(log_path, "NET-SNMP version"),
        ready_timeout=10.0,
    )
    try:
        yield SnmpdV6Backend(
            address=f"[::1]:{port}", port=port, community="public",
        )
    finally:
        proc.terminate()


@dataclasses.dataclass
class SnmpfwdV6Proxy:
    backend: SnmpdV6Backend
    listen_address: str   # "[::1]:<port>"
    listen_port: int
    listen_community: str
    server_log: Path
    client_log: Path


@pytest.fixture
def snmpfwd_proxy_v6(
    tmp_path: Path, snmpd_v6_backend: SnmpdV6Backend,
) -> Iterator[SnmpfwdV6Proxy]:
    """snmpfwd-server listens on `[::1]`, snmpfwd-client talks to
    snmpd on `[::1]`. Trunk stays on 127.0.0.1 — it's a separate
    transport from the SNMP ones and irrelevant to the address-family
    being tested."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    listen_community = "public"
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"
    # 1.3.6.1.2.1.100.1.2 is pysnmp's UDP-over-IPv6 transport domain
    # root; adding .200 gives a per-endpoint identifier that doesn't
    # collide with other tests.
    v6_domain = "1.3.6.1.2.1.100.1.2.200"

    server_conf = tmp_path / "server.conf"
    server_conf.write_text(
        f"""\
config-version: 2
program-name: snmpfwd-server

snmp-credentials-group {{
  snmp-transport-domain: {v6_domain}
  snmp-bind-address: [::1]:{listen_port}

  snmp-engine-id: {engine_id}

  snmp-community-name: {listen_community}
  snmp-security-name: {listen_community}
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-credentials-id: creds-1
}}

context-group {{
  snmp-context-engine-id-pattern: .*?
  snmp-context-name-pattern: .*?

  snmp-context-id: any-context
}}

content-group {{
  snmp-pdu-type-pattern: .*?
  snmp-pdu-oid-prefix-pattern-list: .*?

  snmp-content-id: any-content
}}

peers-group {{
  snmp-transport-domain: {v6_domain}
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
  matching-snmp-content-id-list: any-content
  matching-snmp-credentials-id-list: creds-1
  matching-snmp-peer-id-list: 100

  using-trunk-id-list: trunk-1
}}
"""
    )

    client_conf = tmp_path / "client.conf"
    client_conf.write_text(
        f"""\
config-version: 2
program-name: snmpfwd-client

peers-group {{
  snmp-engine-id: {engine_id}

  snmp-transport-domain: {v6_domain}
  snmp-bind-address: [::0]:0

  snmp-peer-timeout: 500
  snmp-peer-retries: 0

  snmp-community-name: {snmpd_v6_backend.community}
  snmp-security-name: backend
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-peer-address: [::1]:{snmpd_v6_backend.port}
  snmp-peer-id: backend-1
}}

trunking-group {{
  trunk-bind-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: server

  trunk-id: <discover>
}}

server-snmp-entity-info-group {{
  server-snmp-bind-address-pattern: .*?
  server-snmp-context-name-pattern: .*?

  server-snmp-pdu-type-pattern: .*?
  server-snmp-oid-prefix-pattern: .*?

  server-snmp-engine-id-pattern: .*?
  server-snmp-context-engine-id-pattern: .*?

  server-snmp-transport-domain-pattern: .*?
  server-snmp-peer-address-pattern: .*?

  server-snmp-security-level-pattern: .*?
  server-snmp-security-name-pattern: .*?
  server-snmp-security-model-pattern: .*?

  server-snmp-entity-id: any-manager
}}

server-classification-group {{
  server-snmp-context-id-pattern: .*?
  server-snmp-content-id-pattern: .*?
  server-snmp-peer-id-pattern: .*?
  server-snmp-credentials-id-pattern: .*?

  server-classification-id: pass-through
}}

routing-map {{
  matching-trunk-id-list: trunk-1
  matching-server-snmp-entity-id-list: any-manager
  matching-server-classification-id-list: pass-through

  using-snmp-peer-id-list: backend-1
}}
"""
    )

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
        yield SnmpfwdV6Proxy(
            backend=snmpd_v6_backend,
            listen_address=f"[::1]:{listen_port}",
            listen_port=listen_port,
            listen_community=listen_community,
            server_log=server_log,
            client_log=client_log,
        )
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


# ---------------------------------------------------------------------------
# Test


def test_ipv6_get_roundtrips(snmpfwd_proxy_v6: SnmpfwdV6Proxy):
    """snmpget over IPv6 to the proxy must round-trip to the v6-bound
    backend snmpd and return the sysDescr string."""
    vbs = snmp_get(
        target=f"udp6:{snmpfwd_proxy_v6.listen_address}",
        community=snmpfwd_proxy_v6.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1, vbs
    assert vbs[0].type_name == "STRING", vbs[0]
    assert vbs[0].value.strip(), f"sysDescr was empty: {vbs[0]!r}"
