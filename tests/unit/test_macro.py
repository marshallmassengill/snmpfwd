"""Macro expansion used by the config mini-language."""
from __future__ import annotations

from snmpfwd import macro


def test_expandMacro_substitutes_known_keys():
    assert macro.expandMacro('hello ${name}', {'name': 'world'}) == 'hello world'


def test_expandMacro_leaves_unknown_keys_alone():
    # Missing key → token stays in place (no KeyError).
    assert macro.expandMacro('${known} ${unknown}', {'known': 'Y'}) == 'Y ${unknown}'


def test_expandMacro_handles_repeated_occurrences():
    assert macro.expandMacro('${a}:${a}', {'a': 'x'}) == 'x:x'


def test_expandMacro_is_noop_without_dollar_brace():
    assert macro.expandMacro('plain text', {'a': 'x'}) == 'plain text'


def test_expandMacro_handles_none_and_empty():
    assert macro.expandMacro('', {'a': 'x'}) == ''
    assert macro.expandMacro(None, {'a': 'x'}) is None


def test_expandMacro_stringifies_non_string_values():
    assert macro.expandMacro('port=${p}', {'p': 161}) == 'port=161'


def test_expandMacros_processes_list():
    out = macro.expandMacros(['${k}', 'unchanged', '${k}-${k}'], {'k': 'v'})
    assert out == ['v', 'unchanged', 'v-v']


def test_expandMacros_returns_list_copy():
    src = ['${k}']
    out = macro.expandMacros(src, {'k': 'v'})
    assert out == ['v']
    assert src == ['${k}'], 'input should not be mutated'
