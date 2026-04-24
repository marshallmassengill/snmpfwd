"""End-to-end SNMPv3 (USM, authPriv) coverage.

Every other integration test in this repo uses SNMPv2c on both sides of
the proxy. This file exercises the v3 path: manager speaks v3 to
snmpfwd-server, snmpfwd-server decrypts via USM, trunks the plaintext
PDU across, snmpfwd-client re-encrypts with a DIFFERENT v3 user / keys
and sends to a v3-configured snmpd backend. The distinct credentials
are the key point — a passing test proves the proxy is actually
decrypting and re-encrypting rather than passing wire bytes through.
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
    spawn_supervised,
    tcp_port_open,
)


def _resolve_snmpfwd_binary(name: str) -> str:
    """Match conftest.py's binary-resolution order so the test works
    both when the venv's bin is on $PATH and when pytest was invoked
    via the venv's absolute python path from a bare shell."""
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
    raise RuntimeError(
        f"could not locate {name!r} in $SNMPFWD_VENV/bin, "
        f"{Path(sys.executable).parent}, or $PATH"
    )
from .templates import (
    render_client_v3_conf,
    render_server_v3_conf,
    render_snmpd_v3_conf,
)


# ---------------------------------------------------------------------------
# USM credentials used by the test. Manager and backend deliberately
# differ so a passing query proves the proxy re-encrypts across the
# trunk rather than passing the wire bytes through unchanged.

MANAGER_USER = "mgr-user"
MANAGER_AUTH = "mgrauthpass-2026"
MANAGER_PRIV = "mgrprivpass-2026"

BACKEND_USER = "backend-user"
BACKEND_AUTH = "backauthpass-2026"
BACKEND_PRIV = "backprivpass-2026"


@dataclasses.dataclass
class SnmpdV3Backend:
    address: str
    port: int
    user: str
    auth_pass: str
    priv_pass: str


@pytest.fixture
def snmpd_v3_backend(tmp_path: Path) -> Iterator[SnmpdV3Backend]:
    """snmpd configured for SNMPv3 USM, SHA auth + AES priv, with
    read-only access for `BACKEND_USER` over authPriv."""
    snmpd = require_cli("snmpd")
    port = free_udp_port()
    conf_path = tmp_path / "snmpd.conf"
    conf_path.write_text(render_snmpd_v3_conf(
        v3_user=BACKEND_USER,
        sys_location="snmpv3-test-lab",
        sys_contact="v3test@localhost",
    ))
    log_path = tmp_path / "snmpd.log"
    cmd = [
        snmpd, "-f", "-Lo",
        "-C", "-c", str(conf_path),
        f"--createUser={BACKEND_USER} SHA {BACKEND_AUTH} AES {BACKEND_PRIV}",
        "--rwcommunity=",
        "--noPersistentSave=true",
        "--noPersistentLoad=true",
        f"udp:127.0.0.1:{port}",
    ]

    def ready() -> bool:
        return log_contains(log_path, "NET-SNMP version")

    proc = spawn_supervised(
        name="snmpd-v3", cmd=cmd, log_path=log_path,
        ready=ready, ready_timeout=10.0,
    )
    try:
        yield SnmpdV3Backend(
            address=f"127.0.0.1:{port}",
            port=port,
            user=BACKEND_USER,
            auth_pass=BACKEND_AUTH,
            priv_pass=BACKEND_PRIV,
        )
    finally:
        proc.terminate()


@dataclasses.dataclass
class SnmpfwdV3Proxy:
    backend: SnmpdV3Backend
    listen_address: str
    listen_port: int
    manager_user: str
    manager_auth: str
    manager_priv: str
    server_log: Path
    client_log: Path


@pytest.fixture
def snmpfwd_proxy_v3(
    tmp_path: Path, snmpd_v3_backend: SnmpdV3Backend,
) -> Iterator[SnmpfwdV3Proxy]:
    """snmpfwd-server listening with USM user `MANAGER_USER` (one set of
    keys), snmpfwd-client talking to the v3 snmpd with a DIFFERENT USM
    user `BACKEND_USER` / keys. The manager's side and the backend's
    side never share credentials — the trunk is where the PDU crosses
    in plaintext."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"

    server_conf = tmp_path / "server.conf"
    client_conf = tmp_path / "client.conf"
    server_conf.write_text(render_server_v3_conf(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        trunk_port=trunk_port,
        v3_user=MANAGER_USER,
        v3_auth_key=MANAGER_AUTH,
        v3_priv_key=MANAGER_PRIV,
    ))
    client_conf.write_text(render_client_v3_conf(
        snmp_engine_id=engine_id,
        backend_port=snmpd_v3_backend.port,
        trunk_port=trunk_port,
        v3_user=BACKEND_USER,
        v3_auth_key=BACKEND_AUTH,
        v3_priv_key=BACKEND_PRIV,
    ))

    try:
        server_bin = _resolve_snmpfwd_binary("snmpfwd-server")
        client_bin = _resolve_snmpfwd_binary("snmpfwd-client")
    except RuntimeError as exc:
        pytest.skip(str(exc))

    server_log = tmp_path / "snmpfwd-server.log"
    client_log = tmp_path / "snmpfwd-client.log"

    client_proc = spawn_supervised(
        name="snmpfwd-client",
        cmd=[
            client_bin,
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
                server_bin,
                f"--config-file={server_conf}",
                f"--logging-method=file:{server_log}",
                "--log-level=debug",
            ],
            log_path=tmp_path / "snmpfwd-server.stdouterr.log",
            ready=lambda: log_contains(server_log, "client is now connected"),
            ready_timeout=15.0,
        )
        yield SnmpfwdV3Proxy(
            backend=snmpd_v3_backend,
            listen_address=f"127.0.0.1:{listen_port}",
            listen_port=listen_port,
            manager_user=MANAGER_USER,
            manager_auth=MANAGER_AUTH,
            manager_priv=MANAGER_PRIV,
            server_log=server_log,
            client_log=client_log,
        )
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


# ---------------------------------------------------------------------------
# Helpers


def _snmpget_v3(
    target: str, user: str, auth: str, priv: str, oid: str,
    timeout_secs: float = 5.0,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "snmpget", "-v3", "-u", user,
            "-l", "authPriv",
            "-a", "SHA", "-A", auth,
            "-x", "AES", "-X", priv,
            "-t", str(int(timeout_secs)), "-r", "0",
            "-On",
            target, oid,
        ],
        capture_output=True, text=True, timeout=timeout_secs * 3,
    )


# ---------------------------------------------------------------------------
# Tests


def test_snmpv3_authpriv_end_to_end(snmpfwd_proxy_v3: SnmpfwdV3Proxy):
    """snmpget -v3 authPriv against the proxy must return the backend's
    sysDescr.0 STRING. Because the manager and the backend use distinct
    USM users/keys, success proves the server decrypted with the
    manager-facing credentials and the client re-encrypted with the
    backend-facing credentials across the trunk."""
    result = _snmpget_v3(
        target=snmpfwd_proxy_v3.listen_address,
        user=snmpfwd_proxy_v3.manager_user,
        auth=snmpfwd_proxy_v3.manager_auth,
        priv=snmpfwd_proxy_v3.manager_priv,
        oid="1.3.6.1.2.1.1.1.0",
    )
    assert result.returncode == 0, (
        f"snmpget -v3 failed: rc={result.returncode} stdout={result.stdout!r} "
        f"stderr={result.stderr!r}\n"
        f"--- server log ---\n"
        f"{snmpfwd_proxy_v3.server_log.read_text(errors='replace')[-2500:]}\n"
        f"--- client log ---\n"
        f"{snmpfwd_proxy_v3.client_log.read_text(errors='replace')[-2500:]}"
    )
    assert "1.3.6.1.2.1.1.1.0" in result.stdout, result.stdout
    assert "STRING" in result.stdout.upper(), result.stdout


def test_snmpv3_wrong_manager_auth_key_fails(
    snmpfwd_proxy_v3: SnmpfwdV3Proxy,
):
    """A manager with the correct user name but a *wrong* auth
    passphrase must not be able to get a response through. Confirms the
    server-side USM layer actually validates credentials rather than
    forwarding anything that parses as v3."""
    result = _snmpget_v3(
        target=snmpfwd_proxy_v3.listen_address,
        user=snmpfwd_proxy_v3.manager_user,
        auth="completely-wrong-auth-pass",
        priv=snmpfwd_proxy_v3.manager_priv,
        oid="1.3.6.1.2.1.1.1.0",
        timeout_secs=2.0,
    )
    # net-snmp returns non-zero on auth failure / timeout.
    assert result.returncode != 0, (
        f"expected failure with bad auth key but got rc=0, "
        f"stdout={result.stdout!r}"
    )


def test_snmpv3_unknown_manager_user_fails(
    snmpfwd_proxy_v3: SnmpfwdV3Proxy,
):
    """Unknown USM user → auth failure. Exercises the code path the
    server-side `securityAuditObserver` logs counters for."""
    result = _snmpget_v3(
        target=snmpfwd_proxy_v3.listen_address,
        user="never-heard-of-this-user",
        auth=snmpfwd_proxy_v3.manager_auth,
        priv=snmpfwd_proxy_v3.manager_priv,
        oid="1.3.6.1.2.1.1.1.0",
        timeout_secs=2.0,
    )
    assert result.returncode != 0, (
        f"expected failure with unknown user but got rc=0, "
        f"stdout={result.stdout!r}"
    )
