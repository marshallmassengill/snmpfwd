#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
import re

from snmpfwd.error import SnmpfwdError

from pysnmp.carrier.asyncio.dgram import udp
try:
    from pysnmp.carrier.asyncio.dgram import udp6
except ImportError:
    udp6 = None


# Bracketed IPv6 address with an optional :port suffix.
# Hex letters and dots are in the host character class so IPv4-mapped
# forms like [::ffff:1.2.3.4] and normal link-local addresses like
# [fe80::1] parse correctly.
_IPV6_HOST_PORT_RE = re.compile(r'^\[([0-9A-Fa-f:.]+)\](?::([0-9]+))?$')


def parse_optional_port(port_str, defaultPort=0, *, context=''):
    """Coerce a possibly-absent port string into an int.

    `port_str=None` or `''` → `defaultPort`. Otherwise `int(port_str)`.
    Non-integer port raises `SnmpfwdError`, with `context` appended to
    the message so the user sees the full bad address.

    Shared by `parseTransportAddress` (SNMP bind/peer addresses) and
    `snmpfwd.trunking.endpoint.parseTrunkEndpoint` (trunk addresses)
    so the two keep identical default-port and error semantics.
    """
    if port_str is None or port_str == '':
        return defaultPort
    try:
        return int(port_str)
    except (ValueError, TypeError):
        raise SnmpfwdError(
            'bad port specification%s' % ((': ' + context) if context else '')
        )


def parseTransportAddress(transportDomain, transportAddress, transportOptions, defaultPort=0):
    if (('transparent-proxy' in transportOptions or
         'virtual-interface' in transportOptions) and '$' in transportAddress):
        addrMacro = transportAddress

        if transportDomain[:len(udp.domainName)] == udp.domainName:
            h, p = '0.0.0.0', defaultPort
        else:
            h, p = '::0', defaultPort

        return (h, p), addrMacro

    addrMacro = None

    if transportDomain[:len(udp.domainName)] == udp.domainName:
        if ':' in transportAddress:
            h, port_str = transportAddress.split(':', 1)
        else:
            h, port_str = transportAddress, None
        p = parse_optional_port(port_str, defaultPort, context=transportAddress)
    else:
        m = _IPV6_HOST_PORT_RE.match(transportAddress)
        if not m:
            raise SnmpfwdError('bad address specification: %s' % transportAddress)
        h = m.group(1)
        p = parse_optional_port(m.group(2), defaultPort, context=transportAddress)

    return (h, p), addrMacro
