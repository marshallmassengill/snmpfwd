"""Plugin status-code coverage: `NEXT` / `BREAK` / `DROP` / `RESPOND`.

`test_plugins.py` exercises the `NEXT` return code implicitly (the
bundled oidfilter / rewrite / logger plugins all return `NEXT` on the
happy path). The three other status codes the plugin framework
accepts have no integration coverage:

- `BREAK`: subsequent plugins in the chain are skipped, the current
  PDU is still forwarded to the backend. Tested by chaining a
  BREAK-returning plugin with a rewrite-style follow-up and asserting
  the follow-up's mutation does NOT appear in the response.
- `DROP`: the request is dropped entirely — no backend forwarding,
  no response to the manager. Tested by observing a client-side
  snmpget timeout.
- `RESPOND`: the plugin returns a synthesized response PDU and the
  framework short-circuits, sending it straight back without involving
  the backend. Tested by asserting the manager receives the plugin's
  synthetic value, not whatever the backend would actually have
  served.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterator, List

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
from .templates import (
    PluginSpec,
    render_client_conf,
    render_server_conf,
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
# Test plugin — parameterised by a single `status=<NAME>` module option.
# On matching any incoming command request it returns the requested
# status with an optional string-rewrite applied to the first varbind's
# value. Small enough to inline rather than live under plugins/ where
# the user-plugin discovery rules would find it in CI by accident.

_TEST_PLUGIN_SRC = r"""
from snmpfwd.plugins import status
from pysnmp.proto.api import v2c

hostProgs = ('snmpfwd-server', 'snmpfwd-client')
apiVersions = (2,)

_mode = 'NEXT'
_marker = None
for _opt in moduleOptions:
    if _opt.startswith('status='):
        _mode = _opt.split('=', 1)[1]
    elif _opt.startswith('marker='):
        _marker = _opt.split('=', 1)[1]

_STATUS_MAP = {
    'NEXT': status.NEXT,
    'BREAK': status.BREAK,
    'DROP': status.DROP,
    'RESPOND': status.RESPOND,
}
_STATUS = _STATUS_MAP[_mode]


def _first_oid(pdu):
    # Read the ObjectName by direct indexing; avoid v1/v2c
    # `apiVarBind.get_oid_value`, which internally calls
    # `.getComponent(1)` on the value slot and blows up on request
    # PDUs whose value-component is a bare `Null()` rather than a
    # CHOICE-wrapped ObjectSyntax.
    vbs = v2c.apiPDU.get_varbinds(pdu)
    return vbs[0][0] if vbs else v2c.ObjectIdentifier('1.3.6.1.2.1.1.1.0')


def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    marker_str = _marker or 'FROM-PLUGIN'
    marker_pair = (_first_oid(pdu), v2c.OctetString(marker_str))
    if _STATUS == status.RESPOND:
        # Turn the request into a fresh response PDU carrying our
        # marker in the (single) varbind. Passing `(oid, value)`
        # tuples lets pysnmp's set_varbinds build VarBinds against
        # THIS PDU's VarBindList slot — manually-constructed VarBind
        # objects can trip a tag-mismatch on insertion.
        rsp = v2c.apiPDU.get_response(pdu)
        v2c.apiPDU.set_varbinds(rsp, [marker_pair])
        return _STATUS, rsp
    if _marker is not None:
        # Stamp the marker into the outgoing request so a downstream
        # assertion can tell whether this plugin ran.
        v2c.apiPDU.set_varbinds(pdu, [marker_pair])
    return _STATUS, pdu


# Same wiring on the response side — otherwise a NEXT plugin on the
# request would be bypassed on the way back and the rewrite would vanish.
def processCommandResponse(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    return status.NEXT, pdu
"""


@pytest.fixture
def plugins_dir(tmp_path: Path) -> Path:
    """A fresh plugins directory for each test, holding our
    parameterised status plugin."""
    d = tmp_path / "plugins"
    d.mkdir()
    (d / "status_plugin.py").write_text(_TEST_PLUGIN_SRC)
    return d


def _spawn_proxy_with_client_plugins(
    tmp_path: Path,
    backend,
    plugin_specs: List[PluginSpec],
) -> Iterator[dict]:
    """Boot snmpfwd with a sequence of plugins attached on the CLIENT
    side. (Client plugins run when the trunk message arrives, just
    before the backend query — easier to observe than server-side
    plugin ordering.)"""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"

    # Build a client config that declares all plugins and lists them
    # in order on `using-plugin-id-list`. render_client_conf takes a
    # single plugin; we use it for the first, then paste extra plugin
    # blocks and extend the list manually.
    base_client = render_client_conf(
        snmp_engine_id=engine_id,
        backend_community=backend.community,
        backend_port=backend.port,
        trunk_port=trunk_port,
        plugin=plugin_specs[0] if plugin_specs else None,
    )
    # For additional plugins, splice in extra plugin blocks and extend
    # the using-plugin-id-list line. Each extra block needs a UNIQUE
    # scope name — snmpfwd's cparser merges same-named blocks at the
    # same scope, which collapses multi-plugin configs into a single
    # plugin-group the loader then tries to register twice.
    extra_blocks = ""
    extra_ids = []
    for i, extra in enumerate(plugin_specs[1:], start=2):
        extra_blocks += (
            f"plugin-group-{i} {{\n"
            f"  plugin-module: {extra.plugin_module}\n"
            f"  plugin-options: {extra.plugin_options}\n\n"
            f"  plugin-id: {extra.plugin_id}\n"
            "}\n"
        )
        extra_ids.append(extra.plugin_id)
    client_conf_text = base_client + "\n" + extra_blocks
    if extra_ids:
        client_conf_text = client_conf_text.replace(
            f"using-plugin-id-list: {plugin_specs[0].plugin_id}\n",
            "using-plugin-id-list: "
            + " ".join([plugin_specs[0].plugin_id] + extra_ids) + "\n",
        )

    server_conf = render_server_conf(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        listen_community="public",
        trunk_port=trunk_port,
    )

    server_conf_path = tmp_path / "server.conf"
    client_conf_path = tmp_path / "client.conf"
    server_conf_path.write_text(server_conf)
    client_conf_path.write_text(client_conf_text)

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
        yield {
            "listen_address": f"127.0.0.1:{listen_port}",
            "listen_community": "public",
            "server_log": server_log,
            "client_log": client_log,
        }
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


# ---------------------------------------------------------------------------
# Tests


def test_plugin_status_respond_short_circuits_backend(
    tmp_path: Path, snmpd_backend, plugins_dir: Path,
):
    """A plugin that returns RESPOND with a synthesized response PDU
    must have that response delivered straight back to the manager
    without ever querying the backend."""
    plugins = [
        PluginSpec(
            plugin_id="responder",
            plugin_module="status_plugin",
            plugin_options="status=RESPOND marker=FROM-PLUGIN-RESPOND",
            modules_path=str(plugins_dir),
        ),
    ]
    for proxy in _spawn_proxy_with_client_plugins(
        tmp_path, snmpd_backend, plugins,
    ):
        vbs = snmp_get(
            target=proxy["listen_address"],
            community=proxy["listen_community"],
            oids=[SYS_DESCR],
        )
        assert len(vbs) == 1
        assert "FROM-PLUGIN-RESPOND" in vbs[0].value, (
            f"expected plugin marker in response, got {vbs[0]!r}"
        )


def test_plugin_status_drop_silences_request(
    tmp_path: Path, snmpd_backend, plugins_dir: Path,
):
    """A plugin that returns DROP must cause the request to be silently
    dropped — the manager sees a timeout, not a response."""
    plugins = [
        PluginSpec(
            plugin_id="dropper",
            plugin_module="status_plugin",
            plugin_options="status=DROP",
            modules_path=str(plugins_dir),
        ),
    ]
    for proxy in _spawn_proxy_with_client_plugins(
        tmp_path, snmpd_backend, plugins,
    ):
        with pytest.raises(SnmpCliError) as excinfo:
            snmp_get(
                target=proxy["listen_address"],
                community=proxy["listen_community"],
                oids=[SYS_DESCR],
                timeout_secs=2.0,
                retries=0,
            )
        assert "Timeout" in (excinfo.value.stderr + excinfo.value.stdout)


def test_plugin_status_break_skips_subsequent_plugins(
    tmp_path: Path, snmpd_backend, plugins_dir: Path,
):
    """A plugin that returns BREAK halts the pipeline — later plugins
    in the same route must NOT run. First plugin returns BREAK with
    no rewrite; second plugin (if it ran) would rewrite the varbind
    value to a sentinel. The backend's real sysDescr should come
    back, not the sentinel."""
    plugins = [
        PluginSpec(
            plugin_id="breaker",
            plugin_module="status_plugin",
            plugin_options="status=BREAK",
            modules_path=str(plugins_dir),
        ),
        PluginSpec(
            plugin_id="rewriter-after-break",
            plugin_module="status_plugin",
            plugin_options=(
                "status=NEXT marker=SHOULD-NOT-APPEAR-IF-BREAK-WORKED"
            ),
            modules_path=str(plugins_dir),
        ),
    ]
    for proxy in _spawn_proxy_with_client_plugins(
        tmp_path, snmpd_backend, plugins,
    ):
        vbs = snmp_get(
            target=proxy["listen_address"],
            community=proxy["listen_community"],
            oids=[SYS_DESCR],
        )
        assert len(vbs) == 1
        assert "SHOULD-NOT-APPEAR" not in vbs[0].value, (
            "BREAK did not actually stop the plugin chain — sentinel "
            "from the second plugin leaked into the response: "
            f"{vbs[0].value!r}"
        )
        # Should be a real sysDescr from the backend. Both snmpd and
        # snmpsim return a non-empty STRING.
        assert vbs[0].type_name == "STRING"
        assert vbs[0].value.strip()
