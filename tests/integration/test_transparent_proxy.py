"""
Transparent-proxy end-to-end test (server-side IP_TRANSPARENT + TPROXY).

Exercises the real feature that distinguishes `transport-options:
transparent-proxy` from plain `virtual-interface`: the server socket
is bound to a concrete address (127.0.0.1:<port>), but the Linux
kernel's iptables TPROXY target redirects packets destined for *other*
IPs to that socket, and `IP_TRANSPARENT` + `IP_PKTINFO` let the engine
read the original destination IP out of the packet's ancillary data.

A single host can't normally drive this end-to-end because
locally-originated packets skip the iptables mangle PREROUTING chain
where the TPROXY target lives. To work around that we put the SNMP
manager inside its own network namespace, connect it to the host via a
veth pair, and let the packets traverse the namespace boundary — at
which point they enter PREROUTING on the host side and get TPROXY'd
into snmpfwd-server.

Topology::

    [netns: snmpfwd-mgr]  <--veth-->  [host netns]
     192.0.2.2 (sfv-m)               192.0.2.1   (sfv-h)
        |                                |
        | snmpget -c public              | iptables mangle PREROUTING:
        |   192.0.2.100:161              |   -p udp --dport 161
        |                                |   -d 192.0.2.100 -j TPROXY
        v                                |   --tproxy-mark 0x1/0x1
                                         |   --on-port <snmpfwd-port>
                                         |
                                         | ip rule fwmark 0x1 lookup 100
                                         | ip route local default dev lo
                                         |                               table 100
                                         v
                                snmpfwd-server :: 127.0.0.1:<port>
                                  (transparent-proxy)
                                         |
                                         | (trunk)
                                         v
                                snmpfwd-client :: 127.0.0.1:<trunk>
                                         |
                                         v
                                snmpd :: 127.0.0.1:<backend_port>

Prerequisites to run:
  - root (needed for iptables, ip netns, ip rule/route, IP_TRANSPARENT).
  - iptables, ip (iproute2), snmpd, snmpget, snmpfwd-server,
    snmpfwd-client. The test skips cleanly if any are missing.
  - 192.0.2.0/24 not in use locally (it's TEST-NET-1, documentation-only).

How to run (from the repo root, with snmpfwd installed into a venv):

    sudo -E $(which pytest) -v tests/integration/test_transparent_proxy.py

`sudo -E` preserves $PATH so the snmpfwd-server / snmpfwd-client scripts
installed in your venv's `bin/` stay discoverable. If you pip-installed
system-wide, plain `sudo pytest ...` is fine.

The module-level `skipif`s make this test a no-op in normal CI
(non-root) runs; it only executes where it has the privileges it needs.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterator

import pytest

from .helpers import (
    ManagedProcess,
    free_tcp_port,
    free_udp_port,
    log_contains,
    spawn_supervised,
    tcp_port_open,
)
from .templates import (
    render_client_conf,
    render_server_tproxy_conf,
    render_snmpd_conf,
)


# ---------------------------------------------------------------------------
# Gating


pytestmark = [
    pytest.mark.skipif(
        os.geteuid() != 0,
        reason="transparent-proxy E2E needs root for iptables/ip/netns",
    ),
    pytest.mark.skipif(
        shutil.which("iptables") is None,
        reason="iptables binary not on PATH",
    ),
    pytest.mark.skipif(
        shutil.which("ip") is None,
        reason="iproute2 `ip` binary not on PATH",
    ),
    pytest.mark.skipif(
        shutil.which("snmpd") is None,
        reason="snmpd not on PATH",
    ),
    pytest.mark.skipif(
        shutil.which("snmpget") is None,
        reason="snmpget not on PATH",
    ),
]


# ---------------------------------------------------------------------------
# Fixed names for the test topology. Short enough to fit Linux's 15-char
# interface-name limit (IFNAMSIZ-1). The fixture runs a best-effort
# teardown of these names *before* setup so a previously-crashed run
# doesn't leave us wedged.

_NS = "snmpfwd-tp-mgr"
_VH = "sfv-h"
_VM = "sfv-m"
_HOST_IP = "192.0.2.1"
_MGR_IP = "192.0.2.2"
_VIRTUAL_IP = "192.0.2.100"
_FWMARK = "0x1"
_TABLE = "100"
_TPROXY_MASK = "0x1/0x1"


# ---------------------------------------------------------------------------
# Subprocess helpers


def _run(cmd, check=True, capture=True):
    return subprocess.run(
        cmd, check=check,
        capture_output=capture, text=True,
    )


def _run_quiet(cmd):
    """Run without raising. Used for teardown, where every remove is
    expected to fail harmlessly if the resource wasn't created."""
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


# ---------------------------------------------------------------------------
# Fixtures


def _teardown_stale_state(snmpfwd_port: int) -> None:
    """Best-effort cleanup of ANY state that a prior crashed run of this
    test may have left behind. Runs BEFORE setup so a partially-torn-down
    predecessor doesn't wedge us on 'RTNETLINK answers: File exists'.

    We don't know the previous snmpfwd_port, so this can't remove the
    previous iptables rule by exact-match. Instead it flushes the chain
    of any rule referencing _VIRTUAL_IP + TPROXY, since that's narrow
    enough not to touch unrelated mangle rules."""
    _run_quiet(["ip", "route", "flush", "table", _TABLE])
    _run_quiet(["ip", "rule", "del", "fwmark", _FWMARK, "lookup", _TABLE])
    # Drop any previous stale TPROXY rule for our virtual IP.
    result = _run_quiet(["iptables", "-t", "mangle", "-S", "PREROUTING"])
    for line in result.stdout.splitlines():
        if f"-d {_VIRTUAL_IP}" in line and "TPROXY" in line:
            # Turn "-A PREROUTING -d ..." into "-D PREROUTING -d ..."
            args = line.split()
            if args[0] == "-A":
                args[0] = "-D"
                _run_quiet(["iptables", "-t", "mangle"] + args)
    _run_quiet(["ip", "link", "del", _VH])
    _run_quiet(["ip", "netns", "del", _NS])


@pytest.fixture
def transparent_proxy_network():
    """Bring up the netns + veth + iptables + routing state required to
    TPROXY packets from the "manager" netns into the snmpfwd-server on
    the host. Yields a dict of parameters the test needs.

    The fixture records one undo command per successful setup step and
    runs them in reverse on exit, so a teardown is attempted even if
    the test raises mid-run."""
    snmpfwd_port = free_udp_port()

    _teardown_stale_state(snmpfwd_port)

    undo = []
    try:
        # Network namespace for the "external" manager.
        _run(["ip", "netns", "add", _NS])
        undo.append(["ip", "netns", "del", _NS])

        # veth pair — one end in host, the other in the netns.
        _run(["ip", "link", "add", _VH, "type", "veth", "peer", "name", _VM])
        undo.append(["ip", "link", "del", _VH])

        _run(["ip", "link", "set", _VM, "netns", _NS])

        # Bring up loopback + both veth ends.
        _run(["ip", "link", "set", _VH, "up"])
        _run(["ip", "netns", "exec", _NS, "ip", "link", "set", "lo", "up"])
        _run(["ip", "netns", "exec", _NS, "ip", "link", "set", _VM, "up"])

        # Addressing.
        _run(["ip", "addr", "add", f"{_HOST_IP}/24", "dev", _VH])
        _run(["ip", "netns", "exec", _NS,
              "ip", "addr", "add", f"{_MGR_IP}/24", "dev", _VM])
        _run(["ip", "netns", "exec", _NS,
              "ip", "route", "add", "default", "via", _HOST_IP])

        # TPROXY rule: packets from the manager netns destined to the
        # virtual IP on UDP/161 get marked and delivered to snmpfwd-server
        # on the host.
        tproxy_rule = [
            "-p", "udp", "--dport", "161",
            "-d", _VIRTUAL_IP,
            "-j", "TPROXY",
            "--tproxy-mark", _TPROXY_MASK,
            "--on-port", str(snmpfwd_port),
        ]
        _run(["iptables", "-t", "mangle", "-A", "PREROUTING"] + tproxy_rule)
        undo.append(["iptables", "-t", "mangle", "-D", "PREROUTING"] + tproxy_rule)

        # Policy-routing: any packet with the mark goes to a table whose
        # only route is "local default via lo", meaning the kernel
        # delivers it to a local socket regardless of the actual
        # destination IP. That's what lets an `IP_TRANSPARENT`-bound
        # socket on 127.0.0.1:<snmpfwd_port> receive the packet even
        # though it was destined for 192.0.2.100.
        _run(["ip", "rule", "add", "fwmark", _FWMARK, "lookup", _TABLE])
        undo.append(["ip", "rule", "del", "fwmark", _FWMARK, "lookup", _TABLE])
        _run(["ip", "route", "add", "local", "default", "dev", "lo",
              "table", _TABLE])
        undo.append(["ip", "route", "flush", "table", _TABLE])

        yield {
            "ns": _NS,
            "virtual_ip": _VIRTUAL_IP,
            "mgr_ip": _MGR_IP,
            "host_ip": _HOST_IP,
            "snmpfwd_port": snmpfwd_port,
        }
    finally:
        for cmd in reversed(undo):
            _run_quiet(cmd)


@pytest.fixture
def transparent_proxy_snmpd(tmp_path: Path) -> Iterator[dict]:
    """Spawn a backend snmpd bound to 127.0.0.1:<port> with a plain
    community. The client side of this test is a normal snmpfwd-client,
    so no source-IP restrictions — we're only testing the server-side
    transparent-proxy ingress path."""
    port = free_udp_port()
    conf_path = tmp_path / "snmpd.conf"
    conf_path.write_text(render_snmpd_conf(
        community="public",
        sys_location="tproxy-test-lab",
        sys_contact="tproxy-test@localhost",
    ))
    log_path = tmp_path / "snmpd.log"
    cmd = [
        shutil.which("snmpd"), "-f", "-Lo",
        "-C", "-c", str(conf_path),
        "--rwcommunity=",
        "--noPersistentSave=true",
        "--noPersistentLoad=true",
        f"udp:127.0.0.1:{port}",
    ]
    proc = spawn_supervised(
        name="snmpd", cmd=cmd, log_path=log_path,
        ready=lambda: log_contains(log_path, "NET-SNMP version"),
        ready_timeout=10.0,
    )
    try:
        yield {"port": port, "community": "public"}
    finally:
        proc.terminate()


@pytest.fixture
def transparent_proxy_stack(
    tmp_path: Path,
    transparent_proxy_network: dict,
    transparent_proxy_snmpd: dict,
) -> Iterator[dict]:
    """The full stack: network topology + backend snmpd + snmpfwd-client
    (normal) + snmpfwd-server (transparent-proxy)."""
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"
    snmpfwd_port = transparent_proxy_network["snmpfwd_port"]

    server_conf = tmp_path / "server.conf"
    client_conf = tmp_path / "client.conf"
    server_conf.write_text(render_server_tproxy_conf(
        snmp_listen_port=snmpfwd_port,
        snmp_engine_id=engine_id,
        listen_community="public",
        trunk_port=trunk_port,
    ))
    client_conf.write_text(render_client_conf(
        snmp_engine_id=engine_id,
        backend_community=transparent_proxy_snmpd["community"],
        backend_port=transparent_proxy_snmpd["port"],
        trunk_port=trunk_port,
    ))

    server_bin = shutil.which("snmpfwd-server")
    client_bin = shutil.which("snmpfwd-client")
    if server_bin is None or client_bin is None:
        pytest.skip("snmpfwd-server / snmpfwd-client not on PATH")

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
        yield {
            "ns": transparent_proxy_network["ns"],
            "virtual_ip": transparent_proxy_network["virtual_ip"],
            "server_log": server_log,
            "client_log": client_log,
        }
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


# ---------------------------------------------------------------------------
# Test


def test_transparent_proxy_forwards_query_from_virtual_ip(
    transparent_proxy_stack: dict,
):
    """snmpget from inside the manager netns to the virtual destination
    192.0.2.100:161 must be TPROXY-intercepted into snmpfwd-server,
    forwarded through the trunk to snmpfwd-client, and answered by the
    backend snmpd. The response must return to the manager — which
    implicitly verifies that the server socket's IP_TRANSPARENT set the
    outgoing source IP back to 192.0.2.100 (otherwise net-snmp's client
    rejects the response as from an unexpected peer)."""
    stack = transparent_proxy_stack
    result = subprocess.run(
        [
            "ip", "netns", "exec", stack["ns"],
            "snmpget", "-v2c", "-c", "public", "-On",
            "-t", "3", "-r", "0",
            f"{stack['virtual_ip']}:161",
            "1.3.6.1.2.1.1.1.0",
        ],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        pytest.fail(
            "snmpget failed:\n"
            f"  rc={result.returncode}\n"
            f"  stdout={result.stdout!r}\n"
            f"  stderr={result.stderr!r}\n"
            f"--- server log tail ---\n"
            f"{stack['server_log'].read_text(errors='replace')[-3000:]}"
        )

    # The reply line includes the OID we queried and a non-empty value.
    assert "1.3.6.1.2.1.1.1.0" in result.stdout, result.stdout
    assert "STRING" in result.stdout.upper() or "=" in result.stdout, result.stdout

    # Server log should show it observed the original destination as the
    # virtual IP, proving the IP_PKTINFO capture path ran.
    server_log = stack["server_log"].read_text(errors="replace")
    assert stack["virtual_ip"] in server_log, (
        f"server log did not record the virtual IP {stack['virtual_ip']!r} "
        f"from the inbound packet's PKTINFO; log tail:\n"
        f"{server_log[-2000:]}"
    )
