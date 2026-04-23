"""Counter registry used for runtime health metrics."""
from __future__ import annotations

import logging

import pytest

from snmpfwd import metrics


@pytest.fixture(autouse=True)
def _reset_metrics():
    """Fresh counter state per test."""
    metrics.reset()
    yield
    metrics.reset()


def test_increment_and_get():
    metrics.increment('foo')
    metrics.increment('foo')
    metrics.increment('bar', 5)
    assert metrics.get('foo') == 2
    assert metrics.get('bar') == 5
    assert metrics.get('never-touched') == 0


def test_snapshot_returns_dict_copy():
    metrics.increment('a')
    snap = metrics.snapshot()
    assert snap == {'a': 1}
    # Mutating the snapshot must not corrupt the live counters.
    snap['a'] = 99
    assert metrics.get('a') == 1


def test_reset_clears_everything():
    metrics.increment('a', 10)
    metrics.reset()
    assert metrics.get('a') == 0
    assert metrics.snapshot() == {}


def test_log_deltas_emits_changed_counters_only(caplog):
    caplog.set_level(logging.INFO, logger='snmpfwd')
    metrics.increment('a')
    metrics.increment('b', 3)
    metrics.log_deltas()

    assert any('a=1' in r.message and 'b=3' in r.message
               for r in caplog.records), caplog.records

    caplog.clear()
    # Second call with no changes — nothing should be logged.
    metrics.log_deltas()
    assert not caplog.records

    caplog.clear()
    # Bump one counter — only that one appears.
    metrics.increment('a', 4)
    metrics.log_deltas()
    assert any('a=5' in r.message for r in caplog.records)
    # 'b' didn't change — should not appear in this dump.
    assert all('b=' not in r.message for r in caplog.records)


def test_log_deltas_includes_name_in_sorted_order(caplog):
    caplog.set_level(logging.INFO, logger='snmpfwd')
    metrics.increment('zebra')
    metrics.increment('alpha')
    metrics.log_deltas()

    line = next(r.message for r in caplog.records if 'runtime counters' in r.message)
    # Ensure alpha shows up before zebra in the dump.
    assert line.index('alpha=') < line.index('zebra=')


def test_known_constant_names_are_distinct():
    """Sanity: the module-level constants are unique. Guards against
    accidental copy-paste collisions as counters are added over time."""
    names = [
        getattr(metrics, n)
        for n in dir(metrics)
        if n.isupper() and isinstance(getattr(metrics, n), str)
    ]
    assert len(names) == len(set(names)), "duplicate counter name constants"
