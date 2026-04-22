"""Config mini-language parser."""
from __future__ import annotations

from pathlib import Path

import pytest

from snmpfwd import cparser
from snmpfwd.error import SnmpfwdError


def _write(tmp_path: Path, text: str) -> str:
    path = tmp_path / 'test.conf'
    path.write_text(text)
    return str(path)


def test_parse_trivial(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, """
program-name: snmpfwd-server
config-version: 2
"""))
    assert cfg.getAttrValue('program-name', '') == 'snmpfwd-server'
    assert cfg.getAttrValue('config-version', '') == '2'


def test_parse_nested_scopes(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, """
group-a {
  attr-1: outer
  attr-2: also-outer

  subgroup-b {
    attr-1: inner
  }
}
"""))
    # Inner scope overrides outer for the same attribute. Paths always
    # include the empty root-scope name as the first element (matching
    # getPathsToAttr's convention).
    assert cfg.getAttrValue('attr-1', '', 'group-a', 'subgroup-b') == 'inner'
    # Outer attribute is inherited into inner scope when not overridden.
    assert cfg.getAttrValue('attr-2', '', 'group-a', 'subgroup-b') == 'also-outer'


def test_getAttrValue_default(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, 'k: v\n'))
    assert cfg.getAttrValue('missing', '', default='fallback') == 'fallback'


def test_getAttrValue_vector(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, 'list-attr: one two three\n'))
    assert cfg.getAttrValue('list-attr', '', vector=True) == ['one', 'two', 'three']


def test_getAttrValue_expect_int(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, 'num: 42\n'))
    assert cfg.getAttrValue('num', '', expect=int) == 42


def test_missing_attr_raises_without_default(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, 'k: v\n'))
    with pytest.raises(SnmpfwdError):
        cfg.getAttrValue('missing', '')


def test_comment_lines_are_skipped(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, """
# this is a comment
program-name: snmpfwd-server
# another comment
  # indented still counts
attr: v
"""))
    assert cfg.getAttrValue('program-name', '') == 'snmpfwd-server'
    assert cfg.getAttrValue('attr', '') == 'v'


def test_quoted_values_are_preserved(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, 'template: "hello world"\n'))
    assert cfg.getAttrValue('template', '') == 'hello world'


def test_hex_values_are_decoded(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, 'engine-id: 0x0102030405\n'))
    val = cfg.getAttrValue('engine-id', '')
    # cparser converts 0x-prefixed values to their OctetString byte form.
    assert val == '\x01\x02\x03\x04\x05'


def test_getPathsToAttr_enumerates_all_matches(tmp_path):
    cfg = cparser.Config().load(_write(tmp_path, """
peers {
  a {
    peer-id: first
  }
  b {
    peer-id: second
  }
}
"""))
    paths = cfg.getPathsToAttr('peer-id')
    ids = [cfg.getAttrValue('peer-id', *p) for p in paths]
    assert sorted(ids) == ['first', 'second']


def test_missing_file_raises(tmp_path):
    with pytest.raises(SnmpfwdError):
        cparser.Config().load(str(tmp_path / 'does-not-exist.conf'))
