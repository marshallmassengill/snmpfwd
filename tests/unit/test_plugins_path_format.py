"""Macro expansion for log-file destination templates.

The bundled `logger` plugin consults snmpfwd.plugins.path_format.format_path
to resolve a destination like /var/log/snmpfwd/${snmp-peer-id}.log. These
tests pin down the sanitization rules and the missing-macro behaviour."""
from __future__ import annotations

import pytest

from snmpfwd.plugins.path_format import format_path


def test_substitutes_known_macro():
    resolved, missing = format_path(
        '/var/log/snmpfwd/${snmp-peer-id}.log',
        {'snmp-peer-id': 'manager-1'},
    )
    assert resolved == '/var/log/snmpfwd/manager-1.log'
    assert missing == []


def test_missing_macro_replaced_with_unknown():
    resolved, missing = format_path(
        '/var/log/snmpfwd/${snmp-peer-id}.log',
        {'snmp-context-id': 'any'},
    )
    assert resolved == '/var/log/snmpfwd/_unknown.log'
    assert missing == ['${snmp-peer-id}']


def test_multiple_missing_macros_reported_sorted_and_unique():
    resolved, missing = format_path(
        '${b}/${a}/${a}.log',
        {},
    )
    assert '_unknown' in resolved
    # Each distinct missing token is reported once, sorted.
    assert missing == ['${a}', '${b}']


def test_sanitizes_path_separators_in_macro_value():
    # snmp-peer-address can carry a "host:port" string — the ":" must not
    # slip through unescaped because that ambiguates the path on Windows.
    resolved, _ = format_path(
        '/var/log/snmpfwd/${snmp-peer-address}.log',
        {'snmp-peer-address': '127.0.0.1:1161'},
    )
    assert resolved == '/var/log/snmpfwd/127.0.0.1_1161.log'


def test_sanitizes_slashes_backslashes_nuls_and_spaces():
    resolved, _ = format_path(
        '${x}.log',
        {'x': 'a/b\\c d\x00e'},
    )
    assert resolved == 'a_b_c_d_e.log'


def test_template_without_macros_passes_through():
    resolved, missing = format_path('/var/log/snmpfwd.log', {})
    assert resolved == '/var/log/snmpfwd.log'
    assert missing == []


def test_value_stringified_non_str():
    # macros in the trunkReq context may carry pyasn1 OctetString or ints.
    # str() coercion is the caller contract.
    class _Stringy:
        def __str__(self):
            return 'rendered'
    resolved, _ = format_path('${k}.log', {'k': _Stringy()})
    assert resolved == 'rendered.log'
