"""
CLI smoke tests for the argparse migration. Confirms both entry points
still honor --help / --version (exit 0, useful output) and reject
unknown flags (non-zero exit).
"""
from __future__ import annotations

import shutil
import subprocess
import sys

import pytest

from .helpers import which_or_none


def _binary(name: str) -> str:
    # Prefer the venv's bin dir (same discovery order as snmpfwd_proxy
    # fixture): runs whatever pytest is running inside.
    from pathlib import Path
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.is_file():
        return str(venv_bin)
    path = which_or_none(name)
    if path:
        return path
    pytest.skip(f"{name} not on PATH")


@pytest.mark.parametrize("program", ["snmpfwd-server", "snmpfwd-client"])
def test_version_exits_zero(program):
    result = subprocess.run(
        [_binary(program), "--version"],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    # argparse writes --version to stdout.
    out = result.stdout + result.stderr
    assert "SNMP Proxy Forwarder version" in out
    assert "pysnmp" in out
    assert "pyasn1" in out


@pytest.mark.parametrize("program", ["snmpfwd-server", "snmpfwd-client"])
def test_help_exits_zero(program):
    result = subprocess.run(
        [_binary(program), "--help"],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout + result.stderr
    # A few flags we care about should be mentioned.
    for flag in ("--config-file", "--daemonize", "--log-level"):
        assert flag in out, f"{flag} missing from {program} --help"


@pytest.mark.parametrize("program", ["snmpfwd-server", "snmpfwd-client"])
def test_unknown_flag_exits_nonzero(program):
    result = subprocess.run(
        [_binary(program), "--no-such-flag"],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0
    assert "unrecognized" in result.stderr or "error" in result.stderr.lower()
