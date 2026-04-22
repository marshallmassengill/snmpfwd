"""
Integration-test fixtures: backend SNMP agents (snmpd, snmpsim) and snmpfwd
proxies (server + client connected via a trunk).

Each test gets its own tmp_path-scoped configs and ephemeral ports so tests
may run in parallel without collisions.
"""
from __future__ import annotations

import dataclasses
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterator, Optional

import pytest

from .helpers import (
    ManagedProcess,
    find_snmpsim_cmd,
    free_tcp_port,
    free_udp_port,
    log_contains,
    require_cli,
    spawn_supervised,
    tcp_port_open,
)
from .templates import (
    PluginSpec,
    render_client_conf,
    render_client_trap_conf,
    render_server_conf,
    render_server_trap_conf,
    render_snmpd_conf,
    render_snmptrapd_conf,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLED_PLUGINS_DIR = REPO_ROOT / "plugins"


# ---------------------------------------------------------------------------
# Backend: net-snmp snmpd


@dataclasses.dataclass
class SnmpBackend:
    name: str                # "snmpd" | "snmpsim"
    address: str             # "127.0.0.1:<port>"
    port: int
    community: str
    sys_descr: str           # substring guaranteed to appear in 1.3.6.1.2.1.1.1.0
    sys_location: str
    sys_contact: str


@pytest.fixture
def snmpd_backend(tmp_path: Path) -> Iterator[SnmpBackend]:
    """Spawn a net-snmp snmpd bound to an ephemeral port."""
    snmpd = require_cli("snmpd")
    port = free_udp_port()
    community = "public"
    sys_location = "integration-test-lab"
    sys_contact = "test@integration-lab"
    conf_path = tmp_path / "snmpd.conf"
    conf_path.write_text(render_snmpd_conf(
        community=community,
        sys_location=sys_location,
        sys_contact=sys_contact,
    ))
    log_path = tmp_path / "snmpd.log"
    cmd = [
        snmpd, "-f", "-Lo",
        "-C", "-c", str(conf_path),
        "--rwcommunity=",
        "--noPersistentSave=true",
        "--noPersistentLoad=true",
        f"udp:127.0.0.1:{port}",
    ]

    def ready() -> bool:
        # snmpd writes "NET-SNMP version" to stdout shortly after binding.
        # Probing the UDP port directly doesn't prove readiness, so use the
        # log marker.
        return log_contains(log_path, "NET-SNMP version")

    proc = spawn_supervised(name="snmpd", cmd=cmd, log_path=log_path, ready=ready,
                            ready_timeout=10.0)
    try:
        yield SnmpBackend(
            name="snmpd",
            address=f"127.0.0.1:{port}",
            port=port,
            community=community,
            # sysDescr from snmpd defaults to the running OS uname; we just
            # check non-empty — system-specific strings aren't portable.
            sys_descr="",
            sys_location=sys_location,
            sys_contact=sys_contact,
        )
    finally:
        proc.terminate()


# ---------------------------------------------------------------------------
# Backend: snmpsim (skipped when snmpsim-command-responder is not available)


@pytest.fixture
def snmpsim_backend(tmp_path: Path) -> Iterator[SnmpBackend]:
    cmd_path = find_snmpsim_cmd()
    if not cmd_path:
        pytest.skip("snmpsim-command-responder not available on PATH or via SNMPSIM_CMD")

    port = free_udp_port()
    community = "public"
    # Stage a writable data dir containing our checked-in public.snmprec.
    here = Path(__file__).parent
    src = here / "data" / "snmpsim" / "public.snmprec"
    data_dir = tmp_path / "snmpsim-data"
    data_dir.mkdir()
    shutil.copy(src, data_dir / "public.snmprec")

    log_path = tmp_path / "snmpsim.log"
    cache_dir = tmp_path / "snmpsim-cache"
    cache_dir.mkdir()
    cmd = [
        cmd_path,
        "--quiet",
        f"--data-dir={data_dir}",
        f"--cache-dir={cache_dir}",
        f"--agent-udpv4-endpoint=127.0.0.1:{port}",
        "--logging-method=stderr",
    ]

    def ready() -> bool:
        return log_contains(log_path, "Listening at UDP/IPv4 endpoint")

    proc = spawn_supervised(name="snmpsim", cmd=cmd, log_path=log_path, ready=ready,
                            ready_timeout=15.0)
    try:
        yield SnmpBackend(
            name="snmpsim",
            address=f"127.0.0.1:{port}",
            port=port,
            community=community,
            sys_descr="snmpsim-integration-agent",
            sys_location="integration-test-lab",
            sys_contact="test@integration-lab",
        )
    finally:
        proc.terminate()


# Parametrized over both backends, booting only the requested one (not the other
# — getfixturevalue is lazy, so we avoid paying to spawn an unused daemon).
@pytest.fixture(params=["snmpd", "snmpsim"])
def any_backend(request) -> SnmpBackend:
    if request.param == "snmpd":
        return request.getfixturevalue("snmpd_backend")
    if request.param == "snmpsim":
        return request.getfixturevalue("snmpsim_backend")
    raise ValueError(request.param)


# ---------------------------------------------------------------------------
# snmpfwd proxy: client + server wired via ephemeral trunk


@dataclasses.dataclass
class SnmpfwdProxy:
    backend: SnmpBackend
    listen_address: str                    # "127.0.0.1:<snmp_listen_port>"
    listen_port: int
    listen_community: str
    trunk_port: int
    server_log: Path
    client_log: Path
    # Exposed so reload-style tests can mutate the config file and
    # signal the daemons without re-implementing the whole fixture.
    server_config_path: Path = None
    client_config_path: Path = None
    server_pid: int = None
    client_pid: int = None


def _resolve_binary(name: str) -> str:
    """Locate an snmpfwd CLI binary.

    Order: explicit override via $SNMPFWD_VENV/bin/<name>, then the bin/
    directory sibling to the running Python (so the test runner's venv is
    picked up automatically), then $PATH.
    """
    override = os.environ.get("SNMPFWD_VENV")
    if override:
        candidate = Path(override) / "bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    venv_bin = Path(sys.executable).parent / name
    if venv_bin.is_file() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)

    path = shutil.which(name)
    if path:
        return path

    raise RuntimeError(
        f"could not locate {name!r} in $SNMPFWD_VENV/bin, "
        f"{Path(sys.executable).parent}, or $PATH"
    )


def _spawn_snmpfwd_proxy(
    *,
    tmp_path: Path,
    backend: SnmpBackend,
    server_plugin: Optional[PluginSpec] = None,
    client_plugin: Optional[PluginSpec] = None,
) -> Iterator[SnmpfwdProxy]:
    """Yield a running snmpfwd client+server pair wired to `backend`. Shared
    by the plain and plugin-enabled fixtures."""
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
        plugin=server_plugin,
    ))
    client_conf.write_text(render_client_conf(
        snmp_engine_id=engine_id,
        backend_community=backend.community,
        backend_port=backend.port,
        trunk_port=trunk_port,
        plugin=client_plugin,
    ))

    server_bin = _resolve_binary("snmpfwd-server")
    client_bin = _resolve_binary("snmpfwd-client")
    server_log = tmp_path / "snmpfwd-server.log"
    client_log = tmp_path / "snmpfwd-client.log"

    # Trunk-server side boots first so snmpfwd-server has somewhere to connect.
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
        yield SnmpfwdProxy(
            backend=backend,
            listen_address=f"127.0.0.1:{listen_port}",
            listen_port=listen_port,
            listen_community=listen_community,
            trunk_port=trunk_port,
            server_log=server_log,
            client_log=client_log,
            server_config_path=server_conf,
            client_config_path=client_conf,
            server_pid=server_proc.proc.pid,
            client_pid=client_proc.proc.pid,
        )
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


@pytest.fixture
def snmpfwd_proxy(tmp_path: Path, any_backend: SnmpBackend) -> Iterator[SnmpfwdProxy]:
    """Spawn snmpfwd-client + snmpfwd-server with no plugins configured."""
    yield from _spawn_snmpfwd_proxy(tmp_path=tmp_path, backend=any_backend)


@pytest.fixture
def snmpfwd_proxy_oidfilter(tmp_path: Path,
                            any_backend: SnmpBackend) -> Iterator[SnmpfwdProxy]:
    """Proxy with the bundled oidfilter plugin loaded on the SERVER side,
    configured to allow only sysDescr.0. Other GETs should be filtered."""
    # Allow only sysDescr.0 through. Format: "<skip_past> <begin> <end>".
    oidfilter_conf = tmp_path / "oidfilter.conf"
    oidfilter_conf.write_text(
        "# allow only sysDescr.0\n"
        "1.3.6.1.2.1.1.1 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.1.0\n"
    )
    spec = PluginSpec(
        plugin_id="oidfilter-sysdescr-only",
        plugin_module="oidfilter",
        plugin_options=f"config={oidfilter_conf} log-denials=true",
        modules_path=str(BUNDLED_PLUGINS_DIR),
    )
    yield from _spawn_snmpfwd_proxy(
        tmp_path=tmp_path, backend=any_backend, server_plugin=spec,
    )


# ---------------------------------------------------------------------------
# Trap forwarding: snmptrapd backend + trap-flavored proxy


@dataclasses.dataclass
class SnmptrapdBackend:
    address: str      # "127.0.0.1:<port>"
    port: int
    community: str
    log_path: Path


@pytest.fixture
def snmptrapd_backend(tmp_path: Path) -> Iterator[SnmptrapdBackend]:
    snmptrapd = require_cli("snmptrapd")
    port = free_udp_port()
    community = "public"
    conf_path = tmp_path / "snmptrapd.conf"
    conf_path.write_text(render_snmptrapd_conf(community=community))
    trap_log = tmp_path / "snmptrapd-traps.log"
    proc_log = tmp_path / "snmptrapd-stdouterr.log"
    cmd = [
        snmptrapd, "-f",
        "-Lf", str(trap_log),
        "-C", "-c", str(conf_path),
        f"udp:127.0.0.1:{port}",
    ]

    def ready() -> bool:
        # snmptrapd writes "NET-SNMP version" to its log file on startup.
        return log_contains(trap_log, "NET-SNMP version")

    proc = spawn_supervised(name="snmptrapd", cmd=cmd, log_path=proc_log,
                            ready=ready, ready_timeout=10.0)
    try:
        yield SnmptrapdBackend(
            address=f"127.0.0.1:{port}",
            port=port,
            community=community,
            log_path=trap_log,
        )
    finally:
        proc.terminate()


@dataclasses.dataclass
class SnmpfwdTrapProxy:
    backend: SnmptrapdBackend
    listen_address: str
    listen_port: int
    listen_community: str
    trunk_port: int
    server_log: Path
    client_log: Path


@pytest.fixture
def snmpfwd_trap_proxy(
    tmp_path: Path, snmptrapd_backend: SnmptrapdBackend
) -> Iterator[SnmpfwdTrapProxy]:
    """Trap-forwarding topology: snmpfwd-server receives TRAPv2 on an
    ephemeral UDP port, trunks to snmpfwd-client, which re-emits them to
    snmptrapd on another ephemeral port."""
    listen_community = "public"
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x80{random.randrange(0, 2**56):014x}"

    server_conf = tmp_path / "server-trap.conf"
    client_conf = tmp_path / "client-trap.conf"
    server_conf.write_text(render_server_trap_conf(
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

    server_bin = _resolve_binary("snmpfwd-server")
    client_bin = _resolve_binary("snmpfwd-client")
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
        yield SnmpfwdTrapProxy(
            backend=snmptrapd_backend,
            listen_address=f"127.0.0.1:{listen_port}",
            listen_port=listen_port,
            listen_community=listen_community,
            trunk_port=trunk_port,
            server_log=server_log,
            client_log=client_log,
        )
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


@pytest.fixture
def snmpfwd_proxy_rewrite(tmp_path: Path,
                          any_backend: SnmpBackend) -> Iterator[SnmpfwdProxy]:
    """Proxy with the bundled rewrite plugin loaded on the CLIENT side,
    configured to replace sysDescr.0 value with a fixed marker string."""
    rewrite_conf = tmp_path / "rewrite.conf"
    rewrite_conf.write_text(
        '# rewrite sysDescr.0 to a fixed marker\n'
        '"^1\\.3\\.6\\.1\\.2\\.1\\.1\\.1\\.0$" "(.*)" "PROXY-OVERRIDE" 0\n'
    )
    spec = PluginSpec(
        plugin_id="rewrite-sysdescr",
        plugin_module="rewrite",
        plugin_options=f"config={rewrite_conf}",
        modules_path=str(BUNDLED_PLUGINS_DIR),
    )
    yield from _spawn_snmpfwd_proxy(
        tmp_path=tmp_path, backend=any_backend, client_plugin=spec,
    )
