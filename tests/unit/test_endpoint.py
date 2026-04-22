"""Transport-address parsing for SNMP endpoints and trunk endpoints."""
from __future__ import annotations

import socket

import pytest

from snmpfwd import endpoint
from snmpfwd.error import SnmpfwdError
from snmpfwd.trunking.endpoint import parseTrunkEndpoint


# ---------------------------------------------------------------------------
# snmpfwd.endpoint.parseTransportAddress — user-facing SNMP bind address


UDP4 = (1, 3, 6, 1, 6, 1, 1, 1)
UDP6 = (1, 3, 6, 1, 2, 1, 100, 1, 2)


def test_ipv4_host_and_port():
    (host, port), macro = endpoint.parseTransportAddress(
        UDP4, '127.0.0.1:1161', transportOptions=[])
    assert host == '127.0.0.1'
    assert port == 1161
    assert macro is None


def test_ipv4_host_default_port():
    (host, port), macro = endpoint.parseTransportAddress(
        UDP4, '127.0.0.1', transportOptions=[], defaultPort=161)
    assert host == '127.0.0.1'
    assert port == 161
    assert macro is None


def test_ipv4_bad_port_raises():
    with pytest.raises(SnmpfwdError):
        endpoint.parseTransportAddress(
            UDP4, '127.0.0.1:notanumber', transportOptions=[])


def test_ipv6_bracketed_host_and_port():
    (host, port), macro = endpoint.parseTransportAddress(
        UDP6, '[::1]:1161', transportOptions=[])
    assert host == '::1'
    assert port == 1161


def test_transparent_proxy_macro_pass_through():
    (host, port), macro = endpoint.parseTransportAddress(
        UDP4, '${dest}', transportOptions=['transparent-proxy'])
    assert macro == '${dest}'
    # Host/port default to 0.0.0.0:0 for the bind until macro is resolved.
    assert host == '0.0.0.0'
    assert port == 0


def test_virtual_interface_macro_pass_through_ipv6():
    (host, port), macro = endpoint.parseTransportAddress(
        UDP6, '${bind}', transportOptions=['virtual-interface'])
    assert macro == '${bind}'
    assert host == '::0'


# ---------------------------------------------------------------------------
# trunking.endpoint.parseTrunkEndpoint — TCP trunk address


def test_trunk_ipv4_host_and_port():
    af, host, port = parseTrunkEndpoint('127.0.0.1:30301')
    assert af == socket.AF_INET
    assert host == '127.0.0.1'
    assert port == 30301


def test_trunk_ipv4_default_port():
    af, host, port = parseTrunkEndpoint('127.0.0.1', defaultPort=30201)
    assert af == socket.AF_INET
    assert host == '127.0.0.1'
    assert port == 30201


@pytest.mark.skipif(not socket.has_ipv6, reason='no IPv6 support on this host')
def test_trunk_ipv6_bracketed():
    af, host, port = parseTrunkEndpoint('[::1]:30301')
    assert af == socket.AF_INET6
    assert host == '::1'
    assert port == 30301


def test_trunk_bad_address_raises():
    with pytest.raises(SnmpfwdError):
        parseTrunkEndpoint('not a valid address')


def test_trunk_bad_port_raises():
    with pytest.raises(SnmpfwdError):
        parseTrunkEndpoint('127.0.0.1:abc')
