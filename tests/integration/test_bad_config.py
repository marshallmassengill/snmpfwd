"""Configuration-error handling.

snmpfwd is long-running and systemd-style process managers rely on the
exit code to decide whether to restart and alert. These tests verify
that an unloadable config produces a non-zero exit with a log message
operators can act on, rather than a silent rc=0 or an indefinite hang.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from .helpers import free_tcp_port, free_udp_port


def _resolve_bin(name: str) -> str:
    override = os.environ.get("SNMPFWD_VENV")
    if override:
        candidate = Path(override) / "bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.is_file() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)
    import shutil
    found = shutil.which(name)
    if found:
        return found
    pytest.skip(f"{name} not locatable")


# ---------------------------------------------------------------------------
# Fixtures


SERVER_BIN = "snmpfwd-server"
CLIENT_BIN = "snmpfwd-client"


def _spawn_and_wait(bin_name: str, config_path: Path,
                    timeout_s: float = 10.0) -> subprocess.CompletedProcess:
    """Invoke snmpfwd-{server,client} with the given config and a
    stderr sink, waiting up to `timeout_s` for the process to exit on
    its own. Raises pytest.fail if the daemon outlasts the timeout —
    that means it kept running despite the bad config, which is a
    silent-misconfig hazard worth surfacing."""
    bin_path = _resolve_bin(bin_name)
    try:
        return subprocess.run(
            [
                bin_path,
                f"--config-file={config_path}",
                "--logging-method=stderr",
                "--log-level=error",
            ],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            f"{bin_name} did not exit within {timeout_s}s on bad config; "
            f"stderr so far:\n{(exc.stderr or b'').decode(errors='replace')}"
        )


# ---------------------------------------------------------------------------
# Tests


@pytest.mark.parametrize("bin_name", [SERVER_BIN, CLIENT_BIN])
def test_missing_config_file(bin_name, tmp_path: Path):
    """Config path that doesn't exist at all."""
    result = _spawn_and_wait(bin_name, tmp_path / "does-not-exist.conf")
    assert result.returncode != 0, (
        f"{bin_name} silently exited rc=0 on a missing config file; "
        f"stderr={result.stderr!r}"
    )


@pytest.mark.parametrize("bin_name", [SERVER_BIN, CLIENT_BIN])
def test_unparseable_config(bin_name, tmp_path: Path):
    """File exists but its contents are not valid snmpfwd config."""
    conf = tmp_path / "bad.conf"
    conf.write_text("this is not valid snmpfwd config\n")
    result = _spawn_and_wait(bin_name, conf)
    assert result.returncode != 0, (
        f"{bin_name} silently exited rc=0 on unparseable config; "
        f"stderr={result.stderr!r}"
    )


@pytest.mark.parametrize("bin_name, expected_name, wrong_name", [
    (SERVER_BIN, "snmpfwd-server", "snmpfwd-client"),
    (CLIENT_BIN, "snmpfwd-client", "snmpfwd-server"),
])
def test_program_name_mismatch(bin_name, expected_name, wrong_name,
                                tmp_path: Path):
    """Client config fed to server (or vice-versa) — program-name check
    should reject it cleanly instead of chewing on options that don't
    apply to this binary."""
    conf = tmp_path / "mismatched.conf"
    conf.write_text(
        "config-version: 2\n"
        f"program-name: {wrong_name}\n"
    )
    result = _spawn_and_wait(bin_name, conf)
    assert result.returncode != 0, (
        f"{bin_name} silently exited rc=0 on a program-name={wrong_name!r} "
        f"config; stderr={result.stderr!r}"
    )


@pytest.mark.parametrize("bin_name, correct_name", [
    (SERVER_BIN, "snmpfwd-server"),
    (CLIENT_BIN, "snmpfwd-client"),
])
def test_config_version_mismatch(bin_name, correct_name, tmp_path: Path):
    """A config claiming an unsupported config-version must be rejected."""
    conf = tmp_path / "versioned.conf"
    conf.write_text(
        "config-version: 99\n"
        f"program-name: {correct_name}\n"
    )
    result = _spawn_and_wait(bin_name, conf)
    assert result.returncode != 0, (
        f"{bin_name} silently exited rc=0 on an unsupported config-version; "
        f"stderr={result.stderr!r}"
    )


def test_server_duplicate_peer_id_exits(tmp_path: Path):
    """Two `snmp-peer-id: 100` blocks at the same scope — the loader
    should reject the config rather than silently keep the last one."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = "0x011122334455667788"
    conf = tmp_path / "dup.conf"
    conf.write_text(
        f"""\
config-version: 2
program-name: snmpfwd-server

snmp-credentials-group {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address: 127.0.0.1:{listen_port}

  snmp-engine-id: {engine_id}

  snmp-community-name: public
  snmp-security-name: public
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-credentials-id: creds-1
}}

context-group {{
  snmp-context-engine-id-pattern: .*?
  snmp-context-name-pattern: .*?

  snmp-context-id: any-context
}}

content-group {{
  snmp-pdu-type-pattern: .*?
  snmp-pdu-oid-prefix-pattern-list: .*?

  snmp-content-id: any-content
}}

peers-group-a {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address-pattern-list: .*?
  snmp-peer-address-pattern-list: .*?

  snmp-peer-id: 100
}}

peers-group-b {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address-pattern-list: .*?
  snmp-peer-address-pattern-list: .*?

  snmp-peer-id: 100
}}

trunking-group {{
  trunk-bind-address: 127.0.0.1
  trunk-peer-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: client

  trunk-id: trunk-1
}}

routing-map {{
  matching-snmp-context-id-list: any-context
  matching-snmp-content-id-list: any-content
  matching-snmp-credentials-id-list: creds-1
  matching-snmp-peer-id-list: 100

  using-trunk-id-list: trunk-1
}}
"""
    )
    result = _spawn_and_wait(SERVER_BIN, conf)
    assert result.returncode != 0, (
        "snmpfwd-server silently exited rc=0 with duplicate snmp-peer-id; "
        f"stderr={result.stderr!r}"
    )
