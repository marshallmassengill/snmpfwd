"""snmpfwd.metrics_mib — OID assignments and scalar registration.

These tests exercise the pure-Python pieces: the stable sub-OID table
that clients will hard-code in monitoring config, and the pysnmp-side
`register_metrics_mib` export. The actual end-to-end SNMP-GET path is
covered by the integration suite."""
from __future__ import annotations

import pytest

from pysnmp.entity import engine

from snmpfwd import metrics, metrics_mib


@pytest.fixture(autouse=True)
def _reset_metrics():
    metrics.reset()
    yield
    metrics.reset()


def test_oid_for_known_counter_returns_instance_oid():
    root = metrics_mib.METRICS_ROOT_OID
    assert metrics_mib.oid_for(metrics.SERVER_AUTH_FAILURES) == root + (1, 0)
    assert metrics_mib.oid_for(metrics.TRUNK_CONNECTIONS_UP) == root + (11, 0)


def test_oid_for_unknown_counter_raises():
    with pytest.raises(KeyError):
        metrics_mib.oid_for('nonesuch.counter')


def test_oid_table_enumerates_every_counter_uniquely():
    table = metrics_mib.oid_table()
    # No duplicate names, no duplicate OIDs.
    names = [name for name, _ in table]
    oids = [oid for _, oid in table]
    assert len(set(names)) == len(names), names
    assert len(set(oids)) == len(oids), oids


def test_register_exports_scalars_for_every_counter():
    eng = engine.SnmpEngine()
    metrics_mib.register_metrics_mib(eng)
    # The mibBuilder now holds our MIB module with the exported symbols.
    mb = eng.get_mib_builder()
    exported = mb.mibSymbols.get('SNMPFWD-METRICS-MIB', {})
    # Two exports per counter — a MibScalar definition plus its instance.
    assert len(exported) == 2 * len(metrics_mib.oid_table())


def test_scalar_instance_reads_live_counter_value():
    eng = engine.SnmpEngine()
    metrics_mib.register_metrics_mib(eng)
    metrics.increment(metrics.SERVER_REQUESTS_FORWARDED, n=7)

    # Locate the instance for server.requests_forwarded and call
    # getValue — the helper must read the current metrics value.
    mb = eng.get_mib_builder()
    wanted_oid = metrics_mib.oid_for(metrics.SERVER_REQUESTS_FORWARDED)
    symbols = mb.mibSymbols['SNMPFWD-METRICS-MIB']
    instance = None
    for obj in symbols.values():
        if tuple(obj.name) == wanted_oid:
            instance = obj
            break
    assert instance is not None, (
        f'no instance registered at OID {wanted_oid}; got {list(symbols)}'
    )
    value = instance.getValue(wanted_oid, ())
    assert int(value) == 7


def test_rebinding_metrics_root_oid_shifts_all_exports(monkeypatch):
    # Deployments with a real IANA PEN override the root before calling
    # register_metrics_mib. Prove we honour that.
    alt = (1, 3, 6, 1, 4, 1, 42424, 1, 2)
    monkeypatch.setattr(metrics_mib, 'METRICS_ROOT_OID', alt)
    assert metrics_mib.oid_for(metrics.SERVER_AUTH_FAILURES) == alt + (1, 0)
