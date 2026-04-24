"""Trunk encryption end-to-end.

snmpfwd's trunk protocol can be AES-encrypted via `trunk-crypto-key`.
The crypto module itself is unit-tested for round-trips, but no
integration test actually fires a real encrypted trunk between two
running snmpfwd processes. This test wires up snmpfwd-server ↔
snmpfwd-client with matching crypto keys, drives one GET through, and
asserts the round-trip works. Also checks that a mismatched key is
rejected (the surviving side must NOT silently succeed)."""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator

import pytest

from .helpers import (
    SnmpCliError,
    free_tcp_port,
    free_udp_port,
    log_contains,
    snmp_get,
    spawn_supervised,
    tcp_port_open,
)


SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def _resolve_bin(name: str) -> str:
    override = os.environ.get("SNMPFWD_VENV")
    if override:
        candidate = Path(override) / "bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.is_file() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)
    found = shutil.which(name)
    if found:
        return found
    pytest.skip(f"{name} not locatable")


# Minimal inline configs — the only meaningful difference from the
# stock SERVER_CONF / CLIENT_CONF templates is the trunk-crypto-key
# line, and writing the whole thing out keeps the crypto-ness obvious.

_SERVER_CONF = """\
config-version: 2
program-name: snmpfwd-server

snmp-credentials-group {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address: 127.0.0.1:{snmp_listen_port}

  snmp-engine-id: {snmp_engine_id}

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

peers-group {{
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
  trunk-crypto-key: {trunk_crypto_key}
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


_CLIENT_CONF = """\
config-version: 2
program-name: snmpfwd-client

peers-group {{
  snmp-engine-id: {snmp_engine_id}

  snmp-transport-domain: 1.3.6.1.6.1.1.1
  snmp-bind-address: 0.0.0.0:0

  snmp-peer-timeout: 500
  snmp-peer-retries: 0

  snmp-community-name: {backend_community}
  snmp-security-name: backend
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-peer-address: 127.0.0.1:{backend_port}
  snmp-peer-id: backend-1
}}

trunking-group {{
  trunk-bind-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: server
  trunk-crypto-key: {trunk_crypto_key}
  trunk-id: <discover>
}}

server-snmp-entity-info-group {{
  server-snmp-bind-address-pattern: .*?
  server-snmp-context-name-pattern: .*?
  server-snmp-pdu-type-pattern: .*?
  server-snmp-oid-prefix-pattern: .*?
  server-snmp-engine-id-pattern: .*?
  server-snmp-context-engine-id-pattern: .*?
  server-snmp-transport-domain-pattern: .*?
  server-snmp-peer-address-pattern: .*?
  server-snmp-security-level-pattern: .*?
  server-snmp-security-name-pattern: .*?
  server-snmp-security-model-pattern: .*?

  server-snmp-entity-id: any-manager
}}

server-classification-group {{
  server-snmp-context-id-pattern: .*?
  server-snmp-content-id-pattern: .*?
  server-snmp-peer-id-pattern: .*?
  server-snmp-credentials-id-pattern: .*?
  server-classification-id: pass-through
}}

routing-map {{
  matching-trunk-id-list: trunk-1
  matching-server-snmp-entity-id-list: any-manager
  matching-server-classification-id-list: pass-through
  using-snmp-peer-id-list: backend-1
}}
"""


def _spawn_encrypted_proxy(
    tmp_path: Path, backend, server_key: str, client_key: str,
) -> Iterator[dict]:
    """Start snmpfwd-server + snmpfwd-client with the supplied
    trunk_crypto_key values. Keys that differ produce a trunk that
    never successfully exchanges messages."""
    listen_port = free_udp_port()
    trunk_port = free_tcp_port()
    engine_id = f"0x01{random.randrange(0, 2**56):014x}"

    server_conf = tmp_path / "server.conf"
    client_conf = tmp_path / "client.conf"
    server_conf.write_text(_SERVER_CONF.format(
        snmp_listen_port=listen_port,
        snmp_engine_id=engine_id,
        trunk_port=trunk_port,
        trunk_crypto_key=server_key,
    ))
    client_conf.write_text(_CLIENT_CONF.format(
        snmp_engine_id=engine_id,
        backend_community=backend.community,
        backend_port=backend.port,
        trunk_port=trunk_port,
        trunk_crypto_key=client_key,
    ))

    server_log = tmp_path / "snmpfwd-server.log"
    client_log = tmp_path / "snmpfwd-client.log"
    client_proc = spawn_supervised(
        name="snmpfwd-client",
        cmd=[
            _resolve_bin("snmpfwd-client"),
            f"--config-file={client_conf}",
            f"--logging-method=file:{client_log}",
            "--log-level=debug",
        ],
        log_path=tmp_path / "snmpfwd-client.stdouterr.log",
        ready=lambda: tcp_port_open("127.0.0.1", trunk_port),
        ready_timeout=15.0,
    )
    server_proc = None
    try:
        # When keys match the server logs "client is now connected"
        # as part of the standard trunk handshake. When they don't
        # match the crypto layer throws a protocol error inside
        # `prepareDataElements` and the trunk loops reconnecting —
        # neither side ever reaches the "connected" state. So the
        # readiness check has to cope with both outcomes.
        server_proc = spawn_supervised(
            name="snmpfwd-server",
            cmd=[
                _resolve_bin("snmpfwd-server"),
                f"--config-file={server_conf}",
                f"--logging-method=file:{server_log}",
                "--log-level=debug",
            ],
            log_path=tmp_path / "snmpfwd-server.stdouterr.log",
            ready=lambda: (
                log_contains(server_log, "client is now connected")
                or log_contains(server_log, "protocol error")
            ),
            ready_timeout=15.0,
        )
        yield {
            "listen_address": f"127.0.0.1:{listen_port}",
            "listen_community": "public",
            "server_log": server_log,
            "client_log": client_log,
        }
    finally:
        if server_proc is not None:
            server_proc.terminate()
        client_proc.terminate()


@pytest.fixture
def snmpfwd_proxy_encrypted_trunk(
    tmp_path: Path, any_backend,
) -> Iterator[dict]:
    """Matching crypto keys on both sides — the encrypted trunk must
    work end-to-end."""
    key = "shared-trunk-secret-0123456789abcdef"
    yield from _spawn_encrypted_proxy(
        tmp_path=tmp_path, backend=any_backend,
        server_key=key, client_key=key,
    )


@pytest.fixture
def snmpfwd_proxy_mismatched_trunk_keys(
    tmp_path: Path, any_backend,
) -> Iterator[dict]:
    """Deliberately-mismatched crypto keys. Trunk should never carry
    a successful message and an SNMP GET through the proxy must time
    out rather than silently succeed."""
    yield from _spawn_encrypted_proxy(
        tmp_path=tmp_path, backend=any_backend,
        server_key="key-alpha-this-side-only",
        client_key="key-beta-other-side-entirely",
    )


# ---------------------------------------------------------------------------
# Tests


def test_encrypted_trunk_matching_keys_forwards_get(
    snmpfwd_proxy_encrypted_trunk,
):
    """Shared key on both sides: snmpget must round-trip through the
    encrypted trunk."""
    proxy = snmpfwd_proxy_encrypted_trunk
    vbs = snmp_get(
        target=proxy["listen_address"],
        community=proxy["listen_community"],
        oids=[SYS_DESCR],
    )
    assert len(vbs) == 1
    assert vbs[0].type_name == "STRING"
    assert vbs[0].value.strip()


def test_encrypted_trunk_mismatched_keys_blocks_traffic(
    snmpfwd_proxy_mismatched_trunk_keys,
):
    """Different key on each side: the trunk's AES-CBC encode/decode
    cycle yields garbage that can't parse as a trunk protocol message,
    so no SNMP query can cross. The manager's snmpget times out."""
    proxy = snmpfwd_proxy_mismatched_trunk_keys
    with pytest.raises(SnmpCliError) as excinfo:
        snmp_get(
            target=proxy["listen_address"],
            community=proxy["listen_community"],
            oids=[SYS_DESCR],
            timeout_secs=2.0,
            retries=0,
        )
    assert "Timeout" in (excinfo.value.stderr + excinfo.value.stdout)
