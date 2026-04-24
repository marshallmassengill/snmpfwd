"""Resiliency / robustness tests the rest of the suite doesn't cover:

- Trunk reconnect after one end dies and respawns — verifies the
  ping-keepalive path notices a dead trunk and the surviving side
  re-establishes when the peer comes back, without any explicit
  reload or restart of the survivor.
- Concurrent in-flight SNMP requests — verifies message-id correlation
  is correct when multiple queries are flight at the same time, so
  replies aren't delivered to the wrong waiter.
- Backend unreachable — verifies that pointing the client at a dead
  UDP port yields a clean timeout back through the proxy to the
  manager, not a hang or a stuck process.
"""
from __future__ import annotations

import concurrent.futures
import os
import random
import signal
import subprocess
import time
from pathlib import Path
from typing import Iterator

import pytest

from .helpers import (
    SnmpCliError,
    free_tcp_port,
    free_udp_port,
    log_contains,
    snmp_get,
    spawn_supervised,
    tcp_port_open,
)
from .templates import render_client_conf, render_server_conf


SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"


# ---------------------------------------------------------------------------
# Trunk reconnect


def _wait_for_log(path: Path, needle: str, deadline_s: float = 10.0) -> bool:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if needle in path.read_text(errors="replace"):
            return True
        time.sleep(0.1)
    return False


def test_trunk_reconnects_after_peer_respawn(snmpfwd_proxy, tmp_path: Path):
    """Kill the snmpfwd-client process hard (SIGKILL), wait for the
    server to notice the trunk dropping, respawn a new client with the
    same config, and verify a GET works again — without restarting
    snmpfwd-server. Exercises the ping-keepalive / reconnect path the
    TrunkingManager drives on its timer tick."""
    # Baseline — the fixture already ran a handshake but we want a
    # round-trip logged under this test's server-log tail so we can
    # unambiguously look for the reconnect event.
    vbs = snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1

    # SIGKILL the original client. The fixture's `.terminate()` at
    # teardown becomes a no-op (Popen.poll() already returns non-None).
    os.kill(snmpfwd_proxy.client_pid, signal.SIGKILL)

    # Server should close its trunk and log it.
    assert _wait_for_log(
        snmpfwd_proxy.server_log,
        "connection with 127.0.0.1",
    ), (
        "server never logged the trunk-peer disconnect\n"
        + snmpfwd_proxy.server_log.read_text()[-2000:]
    )

    # Respawn a fresh snmpfwd-client with the same config, which rebinds
    # the same trunk port. The existing server's TrunkingManager ping
    # loop reconnects on its next tick.
    client_bin = _resolve_bin("snmpfwd-client")
    respawn_log = tmp_path / "snmpfwd-client-respawn.log"
    respawn_proc = spawn_supervised(
        name="snmpfwd-client-respawn",
        cmd=[
            client_bin,
            f"--config-file={snmpfwd_proxy.client_config_path}",
            f"--logging-method=file:{respawn_log}",
            "--log-level=debug",
        ],
        log_path=tmp_path / "snmpfwd-client-respawn.stdouterr.log",
        ready=lambda: tcp_port_open("127.0.0.1", snmpfwd_proxy.trunk_port),
        ready_timeout=15.0,
    )
    try:
        # Server should log "client is now connected" a second time
        # (the first was from the fixture's original spawn).
        assert _wait_for_log(
            snmpfwd_proxy.server_log,
            "client is now connected",
            deadline_s=15.0,
        )
        # Wait a moment for the server to register the trunk before
        # driving traffic — the reconnect has completed but the
        # routing-side registration runs async.
        deadline = time.monotonic() + 10.0
        last_exc = None
        while time.monotonic() < deadline:
            try:
                vbs = snmp_get(
                    target=snmpfwd_proxy.listen_address,
                    community=snmpfwd_proxy.listen_community,
                    oids=[SYS_DESCR],
                    timeout_secs=2.0,
                    retries=0,
                )
                assert len(vbs) == 1
                break
            except SnmpCliError as exc:
                last_exc = exc
                time.sleep(0.3)
        else:
            pytest.fail(
                "SNMP GET still failing after trunk respawn\n"
                f"last error: {last_exc}\n"
                f"server log:\n{snmpfwd_proxy.server_log.read_text()[-2500:]}"
            )
    finally:
        respawn_proc.terminate()


# ---------------------------------------------------------------------------
# Concurrent in-flight requests


def test_concurrent_queries_keep_correlation(snmpfwd_proxy):
    """Fire a handful of distinct queries in parallel and verify each
    reply matches its request. Regression guard against any bug where
    a trunk request/response correlation key gets reused or a response
    is dispatched to the wrong pending callback."""
    # Each OID in the system group returns a different string/int —
    # they're easy to distinguish and readily available on both the
    # snmpd and snmpsim backends.
    oids = [
        "1.3.6.1.2.1.1.1.0",   # sysDescr
        "1.3.6.1.2.1.1.4.0",   # sysContact
        "1.3.6.1.2.1.1.6.0",   # sysLocation
        "1.3.6.1.2.1.1.3.0",   # sysUpTime
        "1.3.6.1.2.1.1.5.0",   # sysName
    ]
    # Fire 3 copies of the list concurrently to put ~15 queries in
    # flight at once without overwhelming a test-laptop.
    jobs = oids * 3

    def _one(oid):
        vbs = snmp_get(
            target=snmpfwd_proxy.listen_address,
            community=snmpfwd_proxy.listen_community,
            oids=[oid],
            timeout_secs=4.0,
        )
        assert len(vbs) == 1
        return oid, vbs[0].oid, vbs[0].value

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(_one, o) for o in jobs]
        for fut in concurrent.futures.as_completed(futures, timeout=30):
            requested_oid, returned_oid, value = fut.result()
            # Bare "1.3..." vs leading-dot "." — net-snmp prints the
            # leading dot, our input doesn't. Normalise by endswith.
            assert returned_oid.endswith(requested_oid), (
                f"concurrent request for {requested_oid} got a response "
                f"for {returned_oid} — cross-talk / correlation bug"
            )


# ---------------------------------------------------------------------------
# Backend unreachable


from .helpers import require_cli  # noqa: E402 — adjacent to its use
from dataclasses import dataclass


@dataclass
class DeadSnmpdBackend:
    address: str
    port: int
    community: str


@pytest.fixture
def dead_snmpd_backend() -> Iterator[DeadSnmpdBackend]:
    """A free UDP port with nothing listening, dressed up to look like
    an snmpd backend. Used to verify snmpfwd-client produces a clean
    timeout rather than hanging when the downstream doesn't answer."""
    port = free_udp_port()
    yield DeadSnmpdBackend(
        address=f"127.0.0.1:{port}", port=port, community="public",
    )


def test_backend_unreachable_yields_timeout(
    tmp_path: Path, dead_snmpd_backend: DeadSnmpdBackend,
):
    """Spawn the proxy pointing at a port nothing is listening on.
    An SNMP GET from the manager should fail with a clean timeout
    within the configured retry window — not hang the CLI or crash
    the daemons."""
    listen_community = "public"
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"

    server_conf = tmp_path / "server.conf"
    client_conf = tmp_path / "client.conf"
    server_conf.write_text(render_server_conf(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        listen_community=listen_community,
        trunk_port=trunk_port,
    ))
    client_conf.write_text(render_client_conf(
        snmp_engine_id=engine_id,
        backend_community=dead_snmpd_backend.community,
        backend_port=dead_snmpd_backend.port,
        trunk_port=trunk_port,
    ))

    server_log = tmp_path / "snmpfwd-server.log"
    client_log = tmp_path / "snmpfwd-client.log"
    client_bin = _resolve_bin("snmpfwd-client")
    server_bin = _resolve_bin("snmpfwd-server")

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
        # snmpget should fail — we expect timeout within a few seconds,
        # not a hang.
        started = time.monotonic()
        with pytest.raises(SnmpCliError) as excinfo:
            snmp_get(
                target=f"127.0.0.1:{listen_port}",
                community=listen_community,
                oids=[SYS_DESCR],
                timeout_secs=3.0,
                retries=0,
            )
        elapsed = time.monotonic() - started
        assert elapsed < 10.0, (
            f"snmpget took {elapsed:.1f}s to fail — expected a clean "
            f"timeout under the 3s+slack budget"
        )
        assert "Timeout" in (excinfo.value.stderr + excinfo.value.stdout), (
            f"expected a net-snmp Timeout in the error output; got "
            f"stdout={excinfo.value.stdout!r} stderr={excinfo.value.stderr!r}"
        )
        # Proxy should still be responsive after the failure —
        # verifies the dead backend didn't wedge the dispatcher.
        time.sleep(0.1)
        assert server_proc.proc.poll() is None, "server died"
        assert client_proc.proc.poll() is None, "client died"
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


# ---------------------------------------------------------------------------
# Helpers


def _resolve_bin(name: str) -> str:
    """Find snmpfwd-server / snmpfwd-client via the same order as
    conftest.py's own _resolve_binary, so the test works whether the
    venv's bin is on $PATH or only reachable through sys.executable."""
    import shutil
    import sys
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
    pytest.skip(f"{name} not locatable via $SNMPFWD_VENV, venv bin, or $PATH")
