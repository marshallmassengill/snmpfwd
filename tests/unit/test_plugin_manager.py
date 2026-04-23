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


def test_reload_from_config_picks_up_new_plugin(tmp_path):
    plugins_dir = _write_plugin(tmp_path, 'p1', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
flavour = 'v1'
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.reload_from_config([('first', 'p1', [])])
    assert mgr.hasPlugin('first')
    assert mgr._PluginManager__plugins['first']['flavour'] == 'v1'

    # Bump the source file. Reload should pick the new value up.
    (plugins_dir / 'p1.py').write_text("""
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
flavour = 'v2'
""")
    mgr.reload_from_config([('first', 'p1', [])])
    assert mgr._PluginManager__plugins['first']['flavour'] == 'v2'


def test_reload_replaces_plugin_set_atomically(tmp_path):
    """Removing a plugin from the reload spec drops it from the
    registry; adding a new one lands it."""
    plugins_dir = _write_plugin(tmp_path, 'a', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
""")
    _write_plugin(tmp_path, 'b', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.reload_from_config([('x', 'a', []), ('y', 'b', [])])
    assert mgr.hasPlugin('x') and mgr.hasPlugin('y')

    mgr.reload_from_config([('y', 'b', []), ('z', 'a', [])])
    assert not mgr.hasPlugin('x')
    assert mgr.hasPlugin('y')
    assert mgr.hasPlugin('z')


def test_reload_failure_preserves_previous_plugin_set(tmp_path):
    """A broken reload spec must not leave the manager in a
    half-configured state."""
    plugins_dir = _write_plugin(tmp_path, 'good', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
marker = 'original'
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.loadPlugin('p-id', 'good', [])

    # Reload points at a non-existent module — everything should fail,
    # raise, and the original 'p-id' plugin should stay put with its
    # original marker value.
    with pytest.raises(SnmpfwdError):
        mgr.reload_from_config([('p-id', 'does-not-exist', [])])

    assert mgr.hasPlugin('p-id')
    assert mgr._PluginManager__plugins['p-id']['marker'] == 'original'


def test_reload_propagates_new_options(tmp_path):
    """The `moduleOptions` list the plugin sees at exec time reflects
    the values passed to reload_from_config, not the ones from an
    earlier loadPlugin."""
    plugins_dir = _write_plugin(tmp_path, 'opts_observer', """
hostProgs = ('snmpfwd-server',)
apiVersions = (2,)
observed_options = list(moduleOptions)
""")
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    mgr.loadPlugin('p', 'opts_observer', ['before=true'])
    assert mgr._PluginManager__plugins['p']['observed_options'] == ['before=true']
    mgr.reload_from_config([('p', 'opts_observer', ['after=true'])])
    assert mgr._PluginManager__plugins['p']['observed_options'] == ['after=true']


def test_unknown_plugin_id_is_logged_and_returns_next(tmp_path):
    plugins_dir = tmp_path / 'plugins'
    plugins_dir.mkdir()
    mgr = PluginManager([str(plugins_dir)], progId='snmpfwd-server', apiVer=2)
    # Never loaded the plugin id; manager should log the skip and return NEXT.
    st, out = mgr.processCommandRequest('ghost', None, 'PDU', {}, {})
    assert st == status.NEXT
    assert out == 'PDU'
