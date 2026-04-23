#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
"""Lightweight in-memory runtime counters for snmpfwd-server and
snmpfwd-client.

Counters record notable events (auth failures, unroutable requests,
dropped plugin traffic, trunk up/down, INFORM ack outcomes). The
registered-via-bootstrap timer dumps *deltas* to the log periodically
so operators can see whether the proxy is healthy without having to
diff full snapshots themselves.

The snmpfwd processes are single-threaded (asyncio event loop), so
increments do not need a lock — the GIL protects the Counter's
arithmetic and nothing preempts inside a timer callback.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict

from snmpfwd import log


# --- counter names (constants so typos become NameError, not silent
# counter namespace fragmentation) ---------------------------------------

# Server side
SERVER_AUTH_FAILURES = 'server.auth_failures'
SERVER_UNROUTABLE_REQUESTS = 'server.unroutable_requests'
SERVER_REQUESTS_FORWARDED = 'server.requests_forwarded'
SERVER_NOTIFICATIONS_FORWARDED = 'server.notifications_forwarded'
SERVER_PLUGINS_DROPPED = 'server.plugins_dropped'
SERVER_PLUGINS_RESPONDED = 'server.plugins_responded'
SERVER_INFORMS_ACKED = 'server.informs_acked'
SERVER_INFORMS_ACK_SKIPPED = 'server.informs_ack_skipped'

# Client side
CLIENT_TRUNK_UNROUTABLE = 'client.trunk_unroutable'
CLIENT_SNMP_ERRORS = 'client.snmp_errors'

# Trunking (shared between client and server)
TRUNK_CONNECTIONS_UP = 'trunk.connections_up'
TRUNK_CONNECTIONS_DOWN = 'trunk.connections_down'


# --- storage ------------------------------------------------------------

_counts: Counter = Counter()
_last_snapshot: Dict[str, int] = {}


def increment(name: str, n: int = 1) -> None:
    """Increment the counter `name` by `n`. No-op-safe (no registration
    required; new names appear on first increment)."""
    _counts[name] += n


def get(name: str) -> int:
    """Current value of counter `name`, 0 if never incremented."""
    return _counts.get(name, 0)


def snapshot() -> Dict[str, int]:
    """Immutable copy of every counter that has been touched."""
    return dict(_counts)


def reset() -> None:
    """Clear every counter and the delta tracking. Intended for tests;
    production code has no reason to call this."""
    _counts.clear()
    _last_snapshot.clear()


def log_deltas(_time_now=None) -> None:
    """Timer callback: log every counter whose value changed since the
    previous call. First call dumps all non-zero counters. Registered
    via `transportDispatcher.register_timer_callback(metrics.log_deltas,
    N)` from bootstrap."""
    global _last_snapshot
    changed = {
        name: value
        for name, value in _counts.items()
        if _last_snapshot.get(name, 0) != value
    }
    if changed:
        summary = ', '.join(
            '%s=%d' % (name, value) for name, value in sorted(changed.items())
        )
        log.info('runtime counters: %s' % summary)
    _last_snapshot = dict(_counts)
