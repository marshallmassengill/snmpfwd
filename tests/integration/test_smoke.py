"""
Smoke tests for the snmpfwd integration harness. Proves that a full
snmpget round-trip works through snmpfwd-server + trunk + snmpfwd-client +
backend agent, for each supported backend.

Richer scenario coverage lives in the sibling test modules added in Step 0.4.
"""
from __future__ import annotations

from .helpers import snmp_get

SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def test_get_sysdescr_roundtrip(snmpfwd_proxy):
    """snmpget of sysDescr.0 via the proxy returns a non-empty STRING."""
    vbs = snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1, f"expected one varbind, got {vbs}"
    vb = vbs[0]
    assert vb.oid.endswith("1.1.1.0"), f"unexpected OID: {vb.oid}"
    assert vb.type_name == "STRING", f"unexpected type: {vb.type_name}"
    assert vb.value.strip(), "sysDescr value was empty"

    # Backend-specific spot check so we're not just echoing constants.
    if snmpfwd_proxy.backend.name == "snmpsim":
        assert "snmpsim-integration-agent" in vb.value
