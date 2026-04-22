"""Plugin loader behavior — exercise the exec()-based module loading,
the hostProgs / apiVersions gating, and the process* dispatch path."""
from __future__ import annotations

from pathlib import Path

import pytest

from snmpfwd.plugins import status
from snmpfwd.plugins.manager import PluginManager
from snmpfwd.error import SnmpfwdError


def _write_plugin(tmp_path: Path, name: str, body: str) -> Path:
    plugins_dir = tmp_path / 'plugins'
    plugins_dir.mkdir(exist_ok=True)
    module = plugins_dir / f'{name}.py'
    module.write_text(body)
    return plugins_dir


def test_load_plugin_minimal(tmp_path):
    plugins_dir = _write_plugin(tmp_path, 'minimal', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.loadPlugin('p-id', 'minimal', [])
    assert mgr.hasPlugin('p-id')


def test_load_plugin_with_options(tmp_path):
    """moduleOptions gets injected into the module's exec globals, so the
    plugin body can read it at load time."""
    plugins_dir = _write_plugin(tmp_path, 'opts', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
captured_options = list(moduleOptions)
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.loadPlugin('p-id', 'opts', ['config=/etc/foo.conf', 'log-denials=true'])
    plugin = mgr._PluginManager__plugins['p-id']
    assert plugin['captured_options'] == ['config=/etc/foo.conf', 'log-denials=true']


def test_load_plugin_rejects_wrong_hostProgs(tmp_path, caplog):
    plugins_dir = _write_plugin(tmp_path, 'wrong_host', """
hostProgs = ('something-else',)
apiVersions = (2,)
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    # hostProgs mismatch logs an error and raises at end of the path search.
    with pytest.raises(SnmpfwdError):
        mgr.loadPlugin('p-id', 'wrong_host', [])


def test_load_plugin_rejects_incompatible_apiVersions(tmp_path):
    plugins_dir = _write_plugin(tmp_path, 'wrong_api', """
hostProgs = ('snmpfwd-server',)
apiVersions = (99,)
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    with pytest.raises(SnmpfwdError):
        mgr.loadPlugin('p-id', 'wrong_api', [])


def test_load_plugin_missing_module_raises(tmp_path):
    plugins_dir = tmp_path / 'plugins'
    plugins_dir.mkdir()
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    with pytest.raises(SnmpfwdError):
        mgr.loadPlugin('p-id', 'does_not_exist', [])


def test_process_command_request_without_override_returns_next(tmp_path):
    plugins_dir = _write_plugin(tmp_path, 'passthrough', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.loadPlugin('p-id', 'passthrough', [])
    pdu = object()
    st, out = mgr.processCommandRequest('p-id', None, pdu, {}, {})
    assert st == status.NEXT
    assert out is pdu


def test_process_command_request_with_override_invoked(tmp_path):
    plugins_dir = _write_plugin(tmp_path, 'customfilter', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)

def processCommandRequest(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
    reqCtx['visited'] = True
    return status.BREAK, pdu

# The plugin module gets its own globals, but `status` isn't injected —
# re-import it here so the module body can reference the enum.
from snmpfwd.plugins import status
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.loadPlugin('p-id', 'customfilter', [])
    ctx = {}
    st, out = mgr.processCommandRequest('p-id', None, 'PDU', {}, ctx)
    assert st == status.BREAK
    assert ctx == {'visited': True}


def test_unknown_plugin_id_is_logged_and_returns_next(tmp_path):
    plugins_dir = tmp_path / 'plugins'
    plugins_dir.mkdir()
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    # Never loaded the plugin id; manager should log the skip and return NEXT.
    st, out = mgr.processCommandRequest('ghost', None, 'PDU', {}, {})
    assert st == status.NEXT
    assert out == 'PDU'
