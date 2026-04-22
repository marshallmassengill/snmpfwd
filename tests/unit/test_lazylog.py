"""LazyLogString — pretty-prints a context dict into a single log line,
applying ALIASES, GROUPINGS, and FORMATTERS. Used by the two scripts'
LogString subclasses; correctness here affects log output format."""
from __future__ import annotations

from snmpfwd.lazylog import LazyLogString


class _ToyLog(LazyLogString):
    ALIASES = {'alias-key': 'pretty-name'}
    GROUPINGS = [
        ['callflow-id'],
        ['alias-key', 'flag', 'count'],
    ]
    FORMATTERS = {
        'flag': lambda v: 'ON' if v else 'OFF',
    }


def test_renders_known_keys_in_grouping_order():
    s = str(_ToyLog({'callflow-id': 'abc', 'alias-key': 'val', 'flag': True, 'count': 3}))
    # GROUPINGS defines the order, not the dict iteration order.
    assert s.startswith('callflow-id=abc')
    assert 'pretty-name=val' in s     # ALIASES rewrite applied
    assert 'flag=ON' in s             # FORMATTER output
    assert 'count=3' in s


def test_keys_outside_groupings_are_omitted():
    s = str(_ToyLog({'callflow-id': 'x', 'unlisted-key': 'should-not-appear'}))
    assert 'callflow-id=x' in s
    assert 'unlisted-key' not in s
    assert 'should-not-appear' not in s


def test_nil_rendering_for_empty_values():
    s = str(_ToyLog({'callflow-id': '', 'flag': False}))
    # Empty string and False-y values render as "<nil>" / formatted form.
    assert 'callflow-id=<nil>' in s
    assert 'flag=OFF' in s


def test_update_invalidates_cache():
    obj = _ToyLog({'callflow-id': 'first'})
    out1 = str(obj)
    assert 'first' in out1
    obj.update({'callflow-id': 'second'})
    out2 = str(obj)
    assert 'second' in out2
    assert 'first' not in out2


def test_repeated_str_is_cached():
    """Second str() call must return the same string object (cached)."""
    obj = _ToyLog({'callflow-id': 'foo'})
    first = str(obj)
    second = str(obj)
    # Values equal, and implementation reuses _logMsg.
    assert first == second
