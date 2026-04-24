"""Protocol-version translation across the proxy.

snmpfwd's headline use case is a gateway that lets managers speaking
one SNMP version reach agents speaking another. Every other
integration test uses the same version on both sides. These tests
drive the cross-version cases:

- v2c-in, v3-out: a v2c-capable manager polling a v3-only backend,
  with the proxy doing SNMP version translation + USM re-encryption.
- v3-in, v2c-out: modern manager authenticating with USM against the
  proxy, with the proxy forwarding unauthenticated v2c to a legacy
  agent on the trusted side.

Both require pysnmp to decode the PDU on one side, carry it across
the trunk in a version-agnostic wire form, and re-encode with a
different SNMP version on the other side.
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
from .templates import (
    render_client_conf,
    render_client_v3_conf,
    render_server_conf,
    render_server_v3_conf,
    render_snmpd_v3_conf,
)


SYS_DESCR = "1.3.6.1.2.1.1.1.0"

BACKEND_V3_USER = "backend-user"
BACKEND_V3_AUTH = "backauthpass-xlate"
BACKEND_V3_PRIV = "backprivpass-xlate"

MANAGER_V3_USER = "mgr-user"
MANAGER_V3_AUTH = "mgrauthpass-xlate"
MANAGER_V3_PRIV = "mgrprivpass-xlate"


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
class _SnmpdV3:
    port: int
    user: str
    auth: str
    priv: str


@pytest.fixture
def snmpd_v3(tmp_path: Path) -> Iterator[_SnmpdV3]:
    """snmpd configured as SNMPv3-only with SHA auth + AES priv."""
    snmpd = require_cli("snmpd")
    port = free_udp_port()
    conf = tmp_path / "snmpd-v3.conf"
    conf.write_text(render_snmpd_v3_conf(
        v3_user=BACKEND_V3_USER,
        sys_location="xlate-v3-lab",
        sys_contact="xlate-v3@localhost",
    ))
    log = tmp_path / "snmpd-v3.log"
    proc = spawn_supervised(
        name="snmpd-v3",
        cmd=[
            snmpd, "-f", "-Lo",
            "-C", "-c", str(conf),
            f"--createUser={BACKEND_V3_USER} SHA {BACKEND_V3_AUTH} "
            f"AES {BACKEND_V3_PRIV}",
            "--rwcommunity=",
            "--noPersistentSave=true",
            "--noPersistentLoad=true",
            f"udp:127.0.0.1:{port}",
        ],
        log_path=log,
        ready=lambda: log_contains(log, "NET-SNMP version"),
        ready_timeout=10.0,
    )
    try:
        yield _SnmpdV3(port=port, user=BACKEND_V3_USER,
                       auth=BACKEND_V3_AUTH, priv=BACKEND_V3_PRIV)
    finally:
        proc.terminate()


@dataclasses.dataclass
class _Proxy:
    listen_address: str
    listen_community: str
    server_log: Path
    client_log: Path


def _spawn_proxy_pair(
    tmp_path: Path, server_conf: str, client_conf: str,
) -> Iterator[_Proxy]:
    """Boot snmpfwd-server + snmpfwd-client with the given rendered
    config strings. Both wait for "client is now connected" on the
    server log before yielding, matching the other integration
    fixtures."""
    # The listen address / community are dug out of the server config
    # so the caller doesn't have to pass them separately.
    listen_addr = None
    listen_community = "public"
    for line in server_conf.splitlines():
        if "snmp-bind-address:" in line:
            listen_addr = line.split(":", 1)[1].strip()
            break
    trunk_port_line = next(
        l for l in client_conf.splitlines() if "trunk-bind-address:" in l
    )
    trunk_port = int(trunk_port_line.rsplit(":", 1)[1].strip())

    server_conf_path = tmp_path / "server.conf"
    client_conf_path = tmp_path / "client.conf"
    server_conf_path.write_text(server_conf)
    client_conf_path.write_text(client_conf)

    server_log = tmp_path / "snmpfwd-server.log"
    client_log = tmp_path / "snmpfwd-client.log"

    client_proc = spawn_supervised(
        name="snmpfwd-client",
        cmd=[
            _resolve_bin("snmpfwd-client"),
            f"--config-file={client_conf_path}",
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
                f"--config-file={server_conf_path}",
                f"--logging-method=file:{server_log}",
                "--log-level=debug",
            ],
            log_path=tmp_path / "snmpfwd-server.stdouterr.log",
            ready=lambda: log_contains(server_log, "client is now connected"),
            ready_timeout=15.0,
        )
        yield _Proxy(
            listen_address=listen_addr,
            listen_community=listen_community,
            server_log=server_log,
            client_log=client_log,
        )
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


# ---------------------------------------------------------------------------
# Tests


def test_v2c_in_v3_out_translation(
    tmp_path: Path, snmpd_v3: _SnmpdV3,
):
    """Manager speaks v2c to the proxy; the proxy speaks v3 USM authPriv
    to the backend. Proves snmpfwd-client can USM-encrypt an outbound
    request that arrived as v2c on the other side of the trunk."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"

    server_conf = render_server_conf(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        listen_community="public",
        trunk_port=trunk_port,
    )
    client_conf = render_client_v3_conf(
        snmp_engine_id=engine_id,
        backend_port=snmpd_v3.port,
        trunk_port=trunk_port,
        v3_user=snmpd_v3.user,
        v3_auth_key=snmpd_v3.auth,
        v3_priv_key=snmpd_v3.priv,
    )

    for proxy in _spawn_proxy_pair(tmp_path, server_conf, client_conf):
        vbs = snmp_get(
            target=f"127.0.0.1:{listen_port}",
            community="public",
            oids=[SYS_DESCR],
        )
        assert len(vbs) == 1, vbs
        assert vbs[0].type_name == "STRING"
        assert vbs[0].value.strip()


def test_v3_in_v2c_out_translation(
    tmp_path: Path, snmpd_backend,
):
    """Manager speaks v3 USM authPriv to the proxy; the proxy speaks
    v2c to a community-string backend. Proves snmpfwd-server can
    USM-decrypt an inbound request that the client then forwards as
    plain v2c."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"

    server_conf = render_server_v3_conf(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        trunk_port=trunk_port,
        v3_user=MANAGER_V3_USER,
        v3_auth_key=MANAGER_V3_AUTH,
        v3_priv_key=MANAGER_V3_PRIV,
    )
    client_conf = render_client_conf(
        snmp_engine_id=engine_id,
        backend_community=snmpd_backend.community,
        backend_port=snmpd_backend.port,
        trunk_port=trunk_port,
    )

    for proxy in _spawn_proxy_pair(tmp_path, server_conf, client_conf):
        result = subprocess.run(
            [
                "snmpget", "-v3", "-u", MANAGER_V3_USER,
                "-l", "authPriv",
                "-a", "SHA", "-A", MANAGER_V3_AUTH,
                "-x", "AES", "-X", MANAGER_V3_PRIV,
                "-t", "5", "-r", "0", "-On",
                f"127.0.0.1:{listen_port}",
                SYS_DESCR,
            ],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, (
            f"v3-in-v2c-out translation failed rc={result.returncode} "
            f"stderr={result.stderr!r}\n"
            f"--- server log ---\n"
            f"{proxy.server_log.read_text(errors='replace')[-2000:]}"
        )
        assert SYS_DESCR in result.stdout, result.stdout
        assert "STRING" in result.stdout.upper(), result.stdout
