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
        |   198.51.100.100:161           |   -p udp --dport 161
        |                                |   -d 198.51.100.100 -j TPROXY
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

The virtual IP (198.51.100.100) deliberately lives in a DIFFERENT
subnet from the veth link (192.0.2.0/24). If both were in the same
subnet, the netns's connected route would claim the virtual IP as
on-link, ARP-resolve it, get no reply, and drop the packet before it
ever reaches the host.

Prerequisites to run:
  - root (needed for iptables, ip netns, ip rule/route, IP_TRANSPARENT).
  - iptables, ip (iproute2), snmpd, snmpget, snmpfwd-server,
    snmpfwd-client. The test skips cleanly if any are missing.
  - 192.0.2.0/24 and 198.51.100.0/24 not in use locally (TEST-NET-1
    and TEST-NET-2, documentation-reserved).

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
import sys
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
# 192.0.2.0/24 = TEST-NET-1 (RFC 5737), 198.51.100.0/24 = TEST-NET-2.
# Both are documentation-reserved so neither will collide with real
# routes on a dev host.
#
# _HOST_IP / _MGR_IP share TEST-NET-1 and are the point-to-point link
# between the host and the netns. _VIRTUAL_IP lives in TEST-NET-2 —
# importantly a DIFFERENT subnet from the link — so the netns sees it
# as off-link and routes it via the default gateway (the host). If
# _VIRTUAL_IP sat inside 192.0.2.0/24 the netns would treat it as
# link-local and ARP for the virtual IP itself, which nobody answers,
# so the packet never reaches the host's mangle PREROUTING.
_HOST_IP = "192.0.2.1"
_MGR_IP = "192.0.2.2"
_VIRTUAL_IP = "198.51.100.100"
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


def _sysctl_get(key: str) -> str:
    """Return the current value of a sysctl as a stripped string."""
    r = _run_quiet(["sysctl", "-n", key])
    return r.stdout.strip()


def _sysctl_set(key: str, value: str) -> None:
    _run(["sysctl", "-w", f"{key}={value}"])


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

    # Snapshot the sysctls we may need to flip, so we can restore them
    # on teardown even if setup fails partway.
    saved_sysctls = {
        key: _sysctl_get(key) for key in (
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
        )
    }

    undo = []
    # Always register sysctl restoration first so even a teardown_stale
    # that left state behind gets reverted on exit.
    for key, value in saved_sysctls.items():
        undo.append(["sysctl", "-w", f"{key}={value}"])

    try:
        # TPROXY wants packets delivered "locally" even when their
        # destination IP isn't on the host. That journey crosses the
        # routing decision the kernel normally gates on
        # net.ipv4.ip_forward; enable it for the duration of the test.
        # rp_filter=0 on the inbound side removes the reverse-path
        # filter check for the veth (belt-and-braces — our source IP
        # IS reachable via the same interface, but some kernels apply
        # the check before the TPROXY delivery).
        _sysctl_set("net.ipv4.ip_forward", "1")
        _sysctl_set("net.ipv4.conf.all.rp_filter", "0")
        # rp_filter on a new interface inherits from .default; setting it
        # to 0 here guarantees the veth created below starts with the
        # filter disabled. (The kernel takes max(conf.all, conf.<if>)
        # when deciding, so setting only `all` isn't enough if `default`
        # is 1 and the interface inherits that.)
        _sysctl_set("net.ipv4.conf.default.rp_filter", "0")
        # Network namespace for the "external" manager.
        _run(["ip", "netns", "add", _NS])
        undo.append(["ip", "netns", "del", _NS])

        # veth pair — one end in host, the other in the netns.
        _run(["ip", "link", "add", _VH, "type", "veth", "peer", "name", _VM])
        undo.append(["ip", "link", "del", _VH])
        # Belt-and-braces: force the veth interface itself to rp_filter=0
        # now that it exists, in case its inheritance already picked a 1.
        _run_quiet(["sysctl", "-w", f"net.ipv4.conf.{_VH}.rp_filter=0"])

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
        # virtual IP on UDP/161 (snmp commands) or UDP/162 (traps /
        # informs) get marked and delivered to snmpfwd-server on the
        # host. A single TPROXY --on-port is fine because snmpfwd binds
        # one socket that handles both command and notification PDUs at
        # runtime via pysnmp's dispatcher.
        tproxy_rule = [
            "-p", "udp", "-m", "multiport", "--dports", "161,162",
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


def _diagnostic_dump(stack: dict) -> str:
    """Capture kernel-side state the test depends on so a failure message
    carries enough info to triage without re-running (teardown runs
    immediately after, so this is our only window)."""
    def _grab(cmd):
        r = _run_quiet(cmd)
        return f"$ {' '.join(cmd)}\n{r.stdout}{r.stderr}".rstrip()

    ns = stack["ns"]
    parts = [
        # Host-side netfilter + routing state for the TPROXY path.
        _grab(["iptables", "-t", "mangle", "-L", "-v", "-n", "-x"]),
        _grab(["iptables", "-t", "raw", "-L", "-v", "-n", "-x"]),
        _grab(["iptables", "-t", "filter", "-L", "-v", "-n", "-x"]),
        _grab(["iptables", "-t", "nat", "-L", "-v", "-n", "-x"]),
        _grab(["nft", "list", "ruleset"]),   # nft may or may not be present
        _grab(["ip", "rule", "show"]),
        _grab(["ip", "route", "show", "table", str(_TABLE)]),
        _grab(["sysctl",
               "net.ipv4.ip_forward",
               "net.ipv4.conf.all.rp_filter",
               "net.ipv4.conf.default.rp_filter",
               f"net.ipv4.conf.{_VH}.rp_filter"]),
        _grab(["ip", "-d", "link", "show", "dev", _VH]),
        # Netns-side: interface up?, routing correct?, can it actually
        # reach the host? — if ping to the host gateway fails the TPROXY
        # rule will never see traffic regardless of iptables setup.
        _grab(["ip", "netns", "exec", ns, "ip", "-o", "link", "show"]),
        _grab(["ip", "netns", "exec", ns, "ip", "-o", "addr", "show"]),
        _grab(["ip", "netns", "exec", ns, "ip", "route", "show"]),
        _grab(["ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", _HOST_IP]),
        _grab(["ss", "-lun"]),
    ]
    return "\n\n".join(parts)


@pytest.mark.parametrize("op, extra_args", [
    pytest.param("snmpget",     ["1.3.6.1.2.1.1.1.0"],               id="get"),
    pytest.param("snmpgetnext", ["1.3.6.1.2.1.1.1"],                 id="getnext"),
    pytest.param("snmpbulkget", ["-Cn0", "-Cr3", "1.3.6.1.2.1.1"],   id="bulkget"),
    pytest.param("snmpwalk",    ["1.3.6.1.2.1.1"],                   id="walk"),
])
def test_transparent_proxy_forwards_command_from_virtual_ip(
    transparent_proxy_stack: dict, op: str, extra_args: list,
):
    """An SNMP command PDU (GET / GETNEXT / GETBULK / WALK) issued from
    inside the manager netns to the virtual destination 198.51.100.100:161
    must be TPROXY-intercepted into snmpfwd-server, forwarded through the
    trunk to snmpfwd-client, and answered by the backend snmpd. Reply
    returning to the manager proves the full round-trip is intact for
    the PDU type under test."""
    stack = transparent_proxy_stack
    if shutil.which(op) is None:
        pytest.skip(f"{op} not on PATH")
    result = subprocess.run(
        [
            "ip", "netns", "exec", stack["ns"],
            op, "-v2c", "-c", "public", "-On",
            "-t", "3", "-r", "0",
            f"{stack['virtual_ip']}:161",
            *extra_args,
        ],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        # If the user set SNMPFWD_TPROXY_TEST_KEEP=1, pause before
        # teardown so they can poke the live state (tcpdump on sfv-h,
        # manual snmpget from the netns, etc.) in another terminal.
        keep = os.environ.get("SNMPFWD_TPROXY_TEST_KEEP") == "1"
        if keep:
            banner = (
                f"\n*** SNMPFWD_TPROXY_TEST_KEEP=1: leaving netns {_NS!r}, "
                f"veth {_VH}/{_VM}, iptables rule and ip rules in place for "
                f"60s so you can inspect (e.g. "
                f"`sudo tcpdump -n -i {_VH} udp` + "
                f"`sudo ip netns exec {_NS} snmpget -v2c -c public "
                f"{_VIRTUAL_IP}:161 1.3.6.1.2.1.1.1.0`). ***\n"
            )
            # pytest captures stderr by default so `sys.stderr.write` is
            # invisible until the test completes — which is after the
            # sleep, defeating the purpose. Write directly to the
            # controlling tty so it's visible immediately.
            try:
                with open("/dev/tty", "w") as tty:
                    tty.write(banner)
                    tty.flush()
            except OSError:
                sys.stderr.write(banner)
                sys.stderr.flush()
            time.sleep(60)

        pytest.fail(
            "snmpget failed:\n"
            f"  rc={result.returncode}\n"
            f"  stdout={result.stdout!r}\n"
            f"  stderr={result.stderr!r}\n"
            f"--- kernel-side diagnostics ---\n"
            f"{_diagnostic_dump(stack)}\n"
            f"--- server log tail ---\n"
            f"{stack['server_log'].read_text(errors='replace')[-3000:]}"
        )

    # Every command type's reply set touches at least one OID under the
    # system group (1.3.6.1.2.1.1.*) — get/getnext/bulkget/walk all
    # land there because that's what we queried.
    assert ".1.3.6.1.2.1.1." in result.stdout, result.stdout
    assert "=" in result.stdout, result.stdout

    # Cross-check the forwarding path via the server log: it should
    # record a "received SNMP message, forwarded as trunk message"
    # line carrying the snmpget's source IP (the netns manager).
    server_log = stack["server_log"].read_text(errors="replace")
    assert "received SNMP message, forwarded as trunk message" in server_log, (
        f"server never logged an inbound forward; log tail:\n{server_log[-2000:]}"
    )
    assert _MGR_IP in server_log, (
        f"server log does not reference manager source IP {_MGR_IP!r}; "
        f"log tail:\n{server_log[-2000:]}"
    )
    # NOTE: ideally we'd also assert the original virtual-IP destination
    # in the log (proving IP_PKTINFO made it up to the engine), but
    # pysnmp 7's asyncio carrier calls into asyncio.DatagramProtocol's
    # high-level `datagram_received(data, addr)` — which drops the
    # ancillary data where PKTINFO lives. We set IP_PKTINFO on the
    # socket for forward-compat, but the original-destination IP isn't
    # surfaced to snmpfwd. Recovering it would require the asyncio
    # carrier to swap in a raw `sock.recvmsg()` loop. Until that lands
    # upstream (or we monkey-patch), the bind address logged under
    # transparent-proxy reflects the socket's wildcard bind (0.0.0.0)
    # rather than the per-packet original destination.


# ---------------------------------------------------------------------------
# Trap / INFORM forwarding under transparent-proxy


@pytest.fixture
def transparent_proxy_trap_stack(
    tmp_path: Path,
    transparent_proxy_network: dict,
    snmptrapd_backend,   # from tests/integration/conftest.py
) -> Iterator[dict]:
    """Same topology as `transparent_proxy_stack`, but with snmptrapd as
    the backend so we can exercise TRAPv2 / INFORM PDUs through the
    TPROXY chain. Uses the plain CLIENT_CONF — snmpfwd-client routes
    notifications through `notificationOriginator.send_pdu` and commands
    through `commandGenerator.send_pdu` at runtime based on the PDU's
    tagSet, so the same config handles both paths."""
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
        backend_community=snmptrapd_backend.community,
        backend_port=snmptrapd_backend.port,
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
            "snmptrapd_log": snmptrapd_backend.log_path,
        }
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


# A small, easy-to-spot trap OID so snmptrapd's log makes it obvious
# whether the trap reached the backend. 1.3.6.1.4.1.99999.1.2 is inside
# the documentation-style enterprise range snmpfwd already uses for its
# metrics MIB, so nothing real will collide.
_TEST_TRAP_OID = "1.3.6.1.4.1.99999.1.2.0.1"


@pytest.mark.parametrize("op", [
    pytest.param("snmptrap",   id="trapv2"),
    pytest.param("snmpinform", id="inform"),
])
def test_transparent_proxy_forwards_notification_from_virtual_ip(
    transparent_proxy_trap_stack: dict, op: str,
):
    """SNMPv2 TRAP and INFORM PDUs must traverse the same TPROXY chain
    and land in the backend snmptrapd's log."""
    stack = transparent_proxy_trap_stack
    if shutil.which(op) is None:
        pytest.skip(f"{op} not on PATH")

    # snmptrap / snmpinform args:
    #   <uptime> <trap-oid> [varbind ...]
    # We pass an empty uptime (net-snmp interprets "" as 0) and a
    # marker varbind net-snmp will dump verbatim into snmptrapd's log.
    marker_varbind = [
        "1.3.6.1.2.1.1.1.0", "s", f"tproxy-{op}-marker",
    ]
    result = subprocess.run(
        [
            "ip", "netns", "exec", stack["ns"],
            op, "-v2c", "-c", "public",
            "-t", "3", "-r", "0",
            f"{stack['virtual_ip']}:162",
            "",   # uptime
            _TEST_TRAP_OID,
            *marker_varbind,
        ],
        capture_output=True, text=True, timeout=15,
    )
    # snmptrap is fire-and-forget (rc 0, no stdout); snmpinform expects
    # an ack from the proxy (which snmpfwd's Phase-3B flow synthesizes
    # from the downstream ack) and returns non-zero on timeout.
    assert result.returncode == 0, (
        f"{op} failed rc={result.returncode} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}\n"
        f"--- server log ---\n"
        f"{stack['server_log'].read_text(errors='replace')[-2000:]}"
    )

    # Give snmptrapd a beat to flush the log file (it's line-buffered
    # but the kernel's socket buffer may delay by a hair).
    deadline = time.monotonic() + 3.0
    trap_log_text = ""
    while time.monotonic() < deadline:
        trap_log_text = stack["snmptrapd_log"].read_text(errors="replace")
        if _TEST_TRAP_OID in trap_log_text or "tproxy-" in trap_log_text:
            break
        time.sleep(0.1)

    assert "tproxy-" in trap_log_text or _TEST_TRAP_OID in trap_log_text, (
        f"snmptrapd never logged the {op!r} marker; log:\n"
        f"{trap_log_text[-2000:]}"
    )
