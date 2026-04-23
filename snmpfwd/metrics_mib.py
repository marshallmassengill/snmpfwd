#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
"""Expose `snmpfwd.metrics` counters as a pysnmp MIB so the proxy's
own runtime observability is reachable over SNMP.

OID tree
--------

Every counter is registered as a Counter32 scalar under a private
enterprise subtree rooted at::

    METRICS_ROOT_OID = 1.3.6.1.4.1.55555.1.2

`55555` is a placeholder — it is not registered with IANA. If you
have a real IANA Private Enterprise Number, override
`METRICS_ROOT_OID` before calling `register_metrics_mib`:

    metrics_mib.METRICS_ROOT_OID = (1, 3, 6, 1, 4, 1, YOUR_PEN, 1, 2)
    metrics_mib.register_metrics_mib(snmpEngine)

Each counter occupies a stable sub-OID (`_COUNTER_ASSIGNMENTS` below).
Add new counters at the next unused sub-OID; never renumber an
existing one — the on-wire layout is a contract for clients that
hard-code OIDs in their monitoring config.
"""
from __future__ import annotations

from typing import Sequence, Tuple

from pysnmp.proto.api import v2c

from snmpfwd import metrics


METRICS_ROOT_OID: Tuple[int, ...] = (1, 3, 6, 1, 4, 1, 55555, 1, 2)


_COUNTER_ASSIGNMENTS: Sequence[Tuple[int, str]] = (
    (1, metrics.SERVER_AUTH_FAILURES),
    (2, metrics.SERVER_UNROUTABLE_REQUESTS),
    (3, metrics.SERVER_REQUESTS_FORWARDED),
    (4, metrics.SERVER_NOTIFICATIONS_FORWARDED),
    (5, metrics.SERVER_PLUGINS_DROPPED),
    (6, metrics.SERVER_PLUGINS_RESPONDED),
    (7, metrics.SERVER_INFORMS_ACKED),
    (8, metrics.SERVER_INFORMS_ACK_SKIPPED),
    (9, metrics.CLIENT_TRUNK_UNROUTABLE),
    (10, metrics.CLIENT_SNMP_ERRORS),
    (11, metrics.TRUNK_CONNECTIONS_UP),
    (12, metrics.TRUNK_CONNECTIONS_DOWN),
)


def oid_for(counter_name: str) -> Tuple[int, ...]:
    """Full scalar-instance OID (`.N.0`) for `counter_name`.

    Useful for tests and for building monitoring configuration. Raises
    KeyError if the counter is not in the on-wire assignment table."""
    for sub, name in _COUNTER_ASSIGNMENTS:
        if name == counter_name:
            return METRICS_ROOT_OID + (sub, 0)
    raise KeyError(counter_name)


def oid_table() -> Tuple[Tuple[str, Tuple[int, ...]], ...]:
    """Every (counter_name, scalar_instance_oid) pair in assignment order.
    Intended for documentation generation / debugging."""
    return tuple(
        (name, METRICS_ROOT_OID + (sub, 0)) for sub, name in _COUNTER_ASSIGNMENTS
    )


def register_metrics_mib(snmpEngine) -> None:
    """Install one Counter32 scalar per counter on `snmpEngine`'s
    mibBuilder. Every `getValue` call reads the live counter out of
    `snmpfwd.metrics` — no caching, so SNMP reads always reflect the
    current process-local count."""
    mb = snmpEngine.get_mib_builder()
    MibScalar, MibScalarInstance = mb.import_symbols(
        'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
    )

    class _LiveScalarInstance(MibScalarInstance):
        """Scalar instance whose syntax is filled lazily from the
        per-instance `_counter_name`."""
        _counter_name: str = ''

        def getValue(self, name, idx, **ctx):
            return self.getSyntax().clone(int(metrics.get(self._counter_name)))

    exports = []
    for sub, counter_name in _COUNTER_ASSIGNMENTS:
        scalar_oid = METRICS_ROOT_OID + (sub,)
        instance = _LiveScalarInstance(scalar_oid, (0,), v2c.Counter32(0))
        instance._counter_name = counter_name
        exports.append(MibScalar(scalar_oid, v2c.Counter32()))
        exports.append(instance)

    mb.export_symbols('SNMPFWD-METRICS-MIB', *exports)
