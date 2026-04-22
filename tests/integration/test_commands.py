"""
Command-type coverage through the proxy: GETNEXT, GETBULK, WALK, and the
wrong-community drop path. Uses the same snmpfwd_proxy fixture as the smoke
test — these share topology and only differ in the client-side CLI issued.
"""
from __future__ import annotations

import pytest

from .helpers import SnmpCliError, snmp_bulkget, snmp_get, snmp_getnext, snmp_walk

SYSTEM_GROUP = "1.3.6.1.2.1.1"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def test_getnext_returns_sysdescr(snmpfwd_proxy):
    """GETNEXT on 1.3.6.1.2.1.1.1 (sysDescr prefix) resolves to sysDescr.0."""
    vb = snmp_getnext(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oid="1.3.6.1.2.1.1.1",
    )
    assert vb.oid.endswith("1.1.1.0"), f"unexpected OID: {vb.oid}"
    assert vb.type_name == "STRING"
    assert vb.value.strip()


def test_bulkget_returns_multiple_varbinds(snmpfwd_proxy):
    """GETBULK with max-repetitions=3 returns three consecutive varbinds."""
    vbs = snmp_bulkget(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oid=SYSTEM_GROUP,
        non_repeaters=0,
        max_repetitions=3,
    )
    assert len(vbs) == 3, f"expected 3 varbinds, got {len(vbs)}: {vbs}"
    # Distinct OIDs within the system group.
    oids = [vb.oid for vb in vbs]
    assert len(set(oids)) == 3, f"expected distinct OIDs: {oids}"
    for vb in vbs:
        assert vb.oid.startswith(".1.3.6.1.2.1.1."), f"outside system group: {vb.oid}"


def test_walk_returns_system_group(snmpfwd_proxy):
    """WALK of the system group returns at least sysDescr / sysObjectID /
    sysUpTime."""
    vbs = snmp_walk(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oid=SYSTEM_GROUP,
    )
    # net-snmp/snmpd return ~7+ entries; snmpsim data gives exactly 7.
    assert len(vbs) >= 5, f"walk returned too few entries: {vbs}"
    oids = {vb.oid for vb in vbs}
    assert ".1.3.6.1.2.1.1.1.0" in oids
    assert ".1.3.6.1.2.1.1.2.0" in oids
    assert ".1.3.6.1.2.1.1.3.0" in oids


def test_wrong_community_times_out(snmpfwd_proxy):
    """Requests with an unrecognized community are dropped by the server's
    classifier — the client sees a timeout, not a response."""
    with pytest.raises(SnmpCliError) as exc_info:
        snmp_get(
            target=snmpfwd_proxy.listen_address,
            community="wrong-community-string",
            oids=[SYS_DESCR],
            timeout_secs=1.0,
            retries=0,
        )
    assert "Timeout" in exc_info.value.stdout + exc_info.value.stderr
