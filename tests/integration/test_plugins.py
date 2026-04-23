"""
Plugin scenarios: exercise the bundled plugins (oidfilter, rewrite) via the
proxy so that the plugin-loader path + `apiPDU.getVarBinds`/`setVarBinds`
call sites are under regression coverage before Phase 1 touches them.
"""
from __future__ import annotations

from .helpers import SnmpCliError, snmp_get

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"


def test_oidfilter_allows_permitted_oid(snmpfwd_proxy_oidfilter):
    """sysDescr.0 is in the allow list — request passes through the filter."""
    vbs = snmp_get(
        target=snmpfwd_proxy_oidfilter.listen_address,
        community=snmpfwd_proxy_oidfilter.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1
    assert vbs[0].type_name == "STRING"
    assert vbs[0].value.strip(), "sysDescr value was empty"


def test_oidfilter_blocks_other_oids(snmpfwd_proxy_oidfilter):
    """sysContact.0 is NOT in the allow list — oidfilter rewrites the request
    to an out-of-range OID, so the response carries endOfMibView / noSuch*."""
    vbs = snmp_get(
        target=snmpfwd_proxy_oidfilter.listen_address,
        community=snmpfwd_proxy_oidfilter.listen_community,
        oids=[SYS_CONTACT],
    )
    assert len(vbs) == 1
    # The filter nullifies out-of-range varbinds; the backend then returns one
    # of: noSuchInstance / noSuchObject / endOfMibView / empty value. Any of
    # those is an acceptable "blocked" signal — but a real STRING value would
    # indicate the filter failed.
    assert vbs[0].type_name.lower() not in ("string", "integer", "oid"), (
        f"expected filtered response, got live type/value: {vbs[0]}"
    )


def test_oidfilter_logs_denials_server_side(snmpfwd_proxy_oidfilter):
    """With `log-denials=true`, the oidfilter emits a deny line for blocked
    OIDs. Confirms the plugin's configured options actually reached it."""
    try:
        snmp_get(
            target=snmpfwd_proxy_oidfilter.listen_address,
            community=snmpfwd_proxy_oidfilter.listen_community,
            oids=[SYS_CONTACT],
        )
    except SnmpCliError:
        pass  # the filtered response might be a timeout or a non-zero CLI rc
    log = snmpfwd_proxy_oidfilter.server_log.read_text(errors="replace")
    # oidfilter logs "oidfilter: OID ... denied" when log-denials is on.
    assert "oidfilter" in log
    assert "denied" in log.lower() or "deny" in log.lower() or \
           "filtered" in log.lower(), (
        "expected oidfilter deny log line in server log; got:\n"
        + log[-2000:]
    )


def test_rewrite_overrides_response_value(snmpfwd_proxy_rewrite):
    """The rewrite plugin on the client side replaces sysDescr.0 value with
    a fixed marker before the proxy sends the response back."""
    vbs = snmp_get(
        target=snmpfwd_proxy_rewrite.listen_address,
        community=snmpfwd_proxy_rewrite.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1
    assert vbs[0].type_name == "STRING"
    assert "PROXY-OVERRIDE" in vbs[0].value, (
        f"rewrite did not apply; got value={vbs[0].value!r}"
    )


def test_logger_plugin_templated_destination_creates_per_peer_file(
    snmpfwd_proxy_logger_templated,
):
    """The logger plugin was given `destination = <dir>/${snmp-peer-address}.log`.
    A single GET from 127.0.0.1:<port> should produce exactly that file
    with the corresponding callflow log line inside."""
    snmp_get(
        target=snmpfwd_proxy_logger_templated.listen_address,
        community=snmpfwd_proxy_logger_templated.listen_community,
        oids=[SYS_DESCR],
    )
    files = sorted(snmpfwd_proxy_logger_templated.plugin_log_dir.iterdir())
    assert files, (
        'logger plugin produced no file under '
        f'{snmpfwd_proxy_logger_templated.plugin_log_dir}'
    )
    # trunkReq's ${snmp-peer-address} carries the host only — port is
    # exposed separately as ${snmp-peer-port}. Loopback is the fixed part
    # we can assert without coupling the test to the ephemeral port.
    names = [f.name for f in files]
    assert '127.0.0.1.log' in names, f'expected 127.0.0.1.log, got {names}'
    # The file contains a GetRequest line (log line template includes
    # ${snmp-pdu-type}).
    contents = ''.join(f.read_text() for f in files)
    assert 'GetRequest' in contents, contents


def test_rewrite_untouched_oid_passes_through(snmpfwd_proxy_rewrite):
    """sysLocation.0 is not matched by the rewrite rule — its value comes
    back unmodified from the backend."""
    vbs = snmp_get(
        target=snmpfwd_proxy_rewrite.listen_address,
        community=snmpfwd_proxy_rewrite.listen_community,
        oids=[SYS_LOCATION],
    )
    assert len(vbs) == 1
    assert "PROXY-OVERRIDE" not in vbs[0].value, (
        f"rewrite leaked beyond its OID pattern: {vbs[0]}"
    )
