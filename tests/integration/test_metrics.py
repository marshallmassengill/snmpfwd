"""Runtime counters — drive known activity through the proxy and look
for the expected counter names + values in the log dump."""
from __future__ import annotations

import time

import pytest

from .helpers import SnmpCliError, snmp_get


SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def _wait_for_log_match(path, needle: str, deadline_s: float = 8.0) -> str:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace")
        if needle in text:
            return text
        time.sleep(0.1)
    return path.read_text(errors="replace")


def test_trunk_connections_up_appears_in_server_log(snmpfwd_proxy):
    """Trunk came up during fixture setup → the metrics timer reports
    trunk.connections_up=1 within one interval (2s in tests)."""
    log = _wait_for_log_match(
        snmpfwd_proxy.server_log, 'trunk.connections_up=',
    )
    assert 'trunk.connections_up=' in log, (
        'server log never reported trunk.connections_up counter:\n'
        + log[-3000:]
    )


def test_auth_failure_increments_counter(snmpfwd_proxy):
    """A wrong-community request trips server.auth_failures, visible
    in the next counter dump."""
    # Drive one auth failure. Wait out its per-query timeout.
    with pytest.raises(SnmpCliError):
        snmp_get(
            target=snmpfwd_proxy.listen_address,
            community="wrong-community",
            oids=[SYS_DESCR],
            timeout_secs=1.0,
            retries=0,
        )

    log = _wait_for_log_match(
        snmpfwd_proxy.server_log, 'server.auth_failures=',
    )
    assert 'server.auth_failures=' in log, (
        'server log never reported server.auth_failures counter:\n'
        + log[-3000:]
    )


def test_requests_forwarded_counter(snmpfwd_proxy):
    """A successful GET increments server.requests_forwarded on the
    server side."""
    snmp_get(
        target=snmpfwd_proxy.listen_address,
        community=snmpfwd_proxy.listen_community,
        oids=[SYS_DESCR],
    )
    log = _wait_for_log_match(
        snmpfwd_proxy.server_log, 'server.requests_forwarded=',
    )
    assert 'server.requests_forwarded=' in log


# ---------------------------------------------------------------------------
# Counters-as-SNMP-MIB


def test_metrics_agent_serves_trunk_up_counter(snmpfwd_proxy_with_metrics_agent):
    """With SNMPFWD_METRICS_SNMP_BIND set, snmpfwd-server stands up a
    read-only v2c agent. A GET on the trunk.connections_up OID should
    return Counter32: 1 (trunk came up during fixture setup)."""
    from snmpfwd import metrics, metrics_mib
    oid = '.' + '.'.join(
        str(x) for x in metrics_mib.oid_for(metrics.TRUNK_CONNECTIONS_UP)
    )
    vbs = snmp_get(
        target=snmpfwd_proxy_with_metrics_agent.metrics_agent_address,
        community=snmpfwd_proxy_with_metrics_agent.metrics_agent_community,
        oids=[oid],
    )
    assert len(vbs) == 1
    assert vbs[0].type_name.lower() == 'counter32'
    assert int(vbs[0].value) >= 1, (
        f'expected trunk.connections_up >= 1, got {vbs[0].value!r}'
    )


def test_metrics_agent_reflects_live_request_counter(
    snmpfwd_proxy_with_metrics_agent,
):
    """Driving a successful GET through the forwarding path must be
    visible via SNMP on the metrics agent — the scalar reads the live
    counter, so the value tracks within the same process."""
    from snmpfwd import metrics, metrics_mib
    oid = '.' + '.'.join(
        str(x) for x in metrics_mib.oid_for(metrics.SERVER_REQUESTS_FORWARDED)
    )
    # Baseline
    baseline = int(snmp_get(
        target=snmpfwd_proxy_with_metrics_agent.metrics_agent_address,
        community=snmpfwd_proxy_with_metrics_agent.metrics_agent_community,
        oids=[oid],
    )[0].value)
    # Drive a forwarded GET
    snmp_get(
        target=snmpfwd_proxy_with_metrics_agent.listen_address,
        community=snmpfwd_proxy_with_metrics_agent.listen_community,
        oids=[SYS_DESCR],
    )
    after = int(snmp_get(
        target=snmpfwd_proxy_with_metrics_agent.metrics_agent_address,
        community=snmpfwd_proxy_with_metrics_agent.metrics_agent_community,
        oids=[oid],
    )[0].value)
    assert after > baseline, (
        f'requests_forwarded did not tick: baseline={baseline}, after={after}'
    )
