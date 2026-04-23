"""SIGHUP-triggered config reload. Verifies that rewriting the server's
config file and sending SIGHUP makes the running proxy adopt the new
routing without dropping or leaking in-flight state."""
from __future__ import annotations

import os
import signal
import time

import pytest

from .helpers import SnmpCliError, snmp_get


SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def _wait_for_log(path, needle: str, deadline_s: float = 5.0) -> bool:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace")
        if needle in text:
            return True
        time.sleep(0.1)
    return False


def test_sighup_reloads_server_routing(snmpfwd_proxy):
    """Rewrite the server config to use an impossible snmp-pdu-type-pattern
    and SIGHUP the server. Subsequent requests should be dropped (their
    content-id classifier now returns None, so no route matches)."""
    # Sanity check: a GET works with the initial config.
    vbs = snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1

    # Rewrite the server config so the content classifier refuses to
    # match any PDU type. Everything else stays the same.
    original = snmpfwd_proxy.server_config_path.read_text()
    modified = original.replace(
        'snmp-pdu-type-pattern: .*?',
        'snmp-pdu-type-pattern: NEVERMATCH',
    )
    assert modified != original, "the test config template is missing the expected pattern"
    snmpfwd_proxy.server_config_path.write_text(modified)

    # SIGHUP the running snmpfwd-server.
    os.kill(snmpfwd_proxy.server_pid, signal.SIGHUP)

    assert _wait_for_log(
        snmpfwd_proxy.server_log,
        'configuration plugins + routing reloaded',
    ), "server log never reported a successful reload\n--- log tail ---\n" + \
        snmpfwd_proxy.server_log.read_text()[-2000:]

    # After reload the classifier returns no route — GET times out.
    with pytest.raises(SnmpCliError) as excinfo:
        snmp_get(
            target=snmpfwd_proxy.listen_address,
            community=snmpfwd_proxy.listen_community,
            oids=[SYS_DESCR],
            timeout_secs=2.0,
            retries=0,
        )
    assert "Timeout" in excinfo.value.stdout + excinfo.value.stderr

    # Server log records the "no route configured" drop decision.
    log = snmpfwd_proxy.server_log.read_text(errors="replace")
    assert 'no route configured' in log


def test_sighup_invalid_config_keeps_old_routing(snmpfwd_proxy):
    """If the new config fails to parse/validate, the reload callback
    logs the error and the running proxy keeps serving with its
    previous routing."""
    # Sanity check.
    snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )

    # Rewrite the config with an invalid content-id regex so re-parse fails.
    snmpfwd_proxy.server_config_path.write_text('this is not valid snmpfwd config\n')
    os.kill(snmpfwd_proxy.server_pid, signal.SIGHUP)

    assert _wait_for_log(
        snmpfwd_proxy.server_log,
        'configuration reload failed',
    ), "server log never reported a reload failure"

    # Old routing still works — a GET still succeeds.
    vbs = snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1


def test_sighup_reloads_plugin_options(snmpfwd_proxy_logger_templated):
    """Flip the logger plugin's destination template in the server
    config, SIGHUP, drive a GET — the new file path (not the old one)
    should receive the log line."""
    proxy = snmpfwd_proxy_logger_templated

    # Baseline: one GET under the original template writes
    # 127.0.0.1.log into proxy.plugin_log_dir.
    snmp_get(
        target=proxy.listen_address,
        community=proxy.listen_community,
        oids=[SYS_DESCR],
    )
    original_file = proxy.plugin_log_dir / '127.0.0.1.log'
    assert original_file.exists(), (
        f'baseline log file missing before reload: '
        f'{sorted(proxy.plugin_log_dir.iterdir())}'
    )

    # Rewrite the server config: flip the plugin-options so the logger
    # plugin uses a differently-named config (swapped destination
    # template). Trick: easier than editing plugin-options is to edit
    # the logger.ini that plugin-options points at.
    logger_ini = proxy.server_config_path.parent / 'logger.ini'
    original_ini = logger_ini.read_text()
    modified_ini = original_ini.replace(
        '${snmp-peer-address}.log',
        'after-reload-${snmp-peer-address}.log',
    )
    assert modified_ini != original_ini, (
        'test config template no longer contains the pre-reload destination'
    )
    logger_ini.write_text(modified_ini)

    os.kill(proxy.server_pid, signal.SIGHUP)
    assert _wait_for_log(
        proxy.server_log,
        'configuration plugins + routing reloaded',
    ), 'server log never reported a successful plugin+routing reload\n' + \
        proxy.server_log.read_text()[-2000:]

    # Drive another GET; the plugin should now write under the NEW
    # destination pattern, leaving the old file untouched.
    snmp_get(
        target=proxy.listen_address,
        community=proxy.listen_community,
        oids=[SYS_DESCR],
    )
    post_reload_file = proxy.plugin_log_dir / 'after-reload-127.0.0.1.log'
    assert post_reload_file.exists(), (
        f'plugin did not pick up reloaded destination; '
        f'files: {sorted(proxy.plugin_log_dir.iterdir())}'
    )


def test_sighup_rejects_bad_plugin_options_and_keeps_old(
    snmpfwd_proxy_logger_templated,
):
    """If the new config's plugin block references a module that
    can't load (e.g. bad config filename), reload fails atomically —
    the previously-running plugin keeps handling traffic."""
    proxy = snmpfwd_proxy_logger_templated
    # Baseline forwarding works.
    snmp_get(
        target=proxy.listen_address,
        community=proxy.listen_community,
        oids=[SYS_DESCR],
    )

    # Rewrite the server config to point the logger plugin at a
    # non-existent ini file. Python logger plugin opens the config
    # eagerly at init, so re-exec will raise.
    new_conf = proxy.server_config_path.read_text().replace(
        'plugin-options: config=',
        'plugin-options: config=/tmp/does-not-exist-',
    )
    # Only change if the substitution actually applied.
    assert new_conf != proxy.server_config_path.read_text()
    proxy.server_config_path.write_text(new_conf)

    os.kill(proxy.server_pid, signal.SIGHUP)
    assert _wait_for_log(
        proxy.server_log,
        'plugin reload failed',
    ), 'server log never reported the plugin reload failure'

    # Forwarding still works under the pre-reload plugin state.
    vbs = snmp_get(
        target=proxy.listen_address,
        community=proxy.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1
