"""Daemon mode: `--daemonize` + `--pid-file`.

Exercises the double-fork path in snmpfwd/daemon.py that the rest of
the integration suite avoids (everything else runs snmpfwd in the
foreground so pytest can read its stdout/stderr directly). This test
spawns a real daemonized snmpfwd-server, asserts the parent exits 0
while a live grandchild writes the PID file, drives one SNMP query
through it, then SIGTERMs the daemon.
"""
from __future__ import annotations

import os
import random
import shutil
import signal
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
    snmp_get,
    spawn_supervised,
    tcp_port_open,
)
from .templates import render_client_conf, render_server_conf


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


def _pid_alive(pid: int) -> bool:
    """Returns True iff PID names a live process we can signal."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # process exists; we just can't signal it
    return True


def _wait_for(predicate, deadline_s: float) -> bool:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_server_daemonize_writes_pid_and_serves(tmp_path: Path, snmpd_backend):
    """Spawn snmpfwd-server with --daemonize --pid-file. The foreground
    process it forked from must exit rc=0 quickly, the PID file must
    contain a live PID different from the launcher's, the grandchild
    must keep running, and it must answer a forwarded SNMP GET.
    Cleanup: SIGTERM the daemon and wait for it to exit."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"
    pid_file = tmp_path / "snmpfwd-server.pid"

    # Client side can stay foreground — we only need the daemon for
    # the server to answer the snmpget.
    server_conf = tmp_path / "server.conf"
    client_conf = tmp_path / "client.conf"
    server_conf.write_text(render_server_conf(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        listen_community="public",
        trunk_port=trunk_port,
    ))
    client_conf.write_text(render_client_conf(
        snmp_engine_id=engine_id,
        backend_community=snmpd_backend.community,
        backend_port=snmpd_backend.port,
        trunk_port=trunk_port,
    ))

    client_proc = spawn_supervised(
        name="snmpfwd-client",
        cmd=[
            _resolve_bin("snmpfwd-client"),
            f"--config-file={client_conf}",
            f"--logging-method=file:{tmp_path / 'snmpfwd-client.log'}",
            "--log-level=debug",
        ],
        log_path=tmp_path / "snmpfwd-client.stdouterr.log",
        ready=lambda: tcp_port_open("127.0.0.1", trunk_port),
        ready_timeout=15.0,
    )
    daemon_pid = None
    server_log = tmp_path / "snmpfwd-server.log"
    try:
        # Fire the daemonized server. Because of the daemon's
        # double-fork, the process we spawn here is the GRANDPARENT
        # that exits 0 once the grandchild is detached. pytest must
        # see rc=0 from subprocess.run within a couple seconds.
        started = time.monotonic()
        result = subprocess.run(
            [
                _resolve_bin("snmpfwd-server"),
                f"--config-file={server_conf}",
                f"--logging-method=file:{server_log}",
                "--log-level=debug",
                "--daemonize",
                f"--pid-file={pid_file}",
            ],
            capture_output=True, text=True, timeout=10,
        )
        elapsed = time.monotonic() - started
        assert result.returncode == 0, (
            f"--daemonize launcher failed rc={result.returncode} "
            f"elapsed={elapsed:.2f}s stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )
        assert elapsed < 5.0, (
            f"--daemonize launcher hung for {elapsed:.2f}s — double-fork "
            f"should detach almost immediately"
        )

        # PID file should appear quickly.
        assert _wait_for(lambda: pid_file.is_file(), 3.0), (
            f"PID file {pid_file} never materialised"
        )
        daemon_pid = int(pid_file.read_text().strip())
        assert _pid_alive(daemon_pid), (
            f"PID {daemon_pid} from {pid_file} is not a live process"
        )
        assert daemon_pid != os.getpid(), (
            "daemonized PID equals pytest's — double-fork didn't detach"
        )

        # Wait for the daemon's trunk to connect.
        assert _wait_for(
            lambda: log_contains(server_log, "client is now connected"),
            deadline_s=15.0,
        ), f"daemon never connected the trunk\n{server_log.read_text()[-2000:]}"

        # Round-trip a GET through the daemonized forwarder.
        vbs = snmp_get(
            target=f"127.0.0.1:{listen_port}",
            community="public",
            oids=[SYS_DESCR],
        )
        assert len(vbs) == 1
        assert vbs[0].type_name == "STRING"
        assert vbs[0].value.strip()
    finally:
        client_proc.terminate()
        if daemon_pid and _pid_alive(daemon_pid):
            os.kill(daemon_pid, signal.SIGTERM)
            _wait_for(lambda: not _pid_alive(daemon_pid), 5.0)
            if _pid_alive(daemon_pid):
                os.kill(daemon_pid, signal.SIGKILL)
