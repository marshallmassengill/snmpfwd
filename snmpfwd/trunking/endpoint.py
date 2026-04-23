#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
import re
import socket

from snmpfwd.endpoint import parse_optional_port
from snmpfwd.error import SnmpfwdError


_IPV4_RE = re.compile(r'^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?::([0-9]+))?$')

# Bracketed IPv6 host with an optional :port suffix. Matches
# snmpfwd.endpoint._IPV6_HOST_PORT_RE so both parsers accept the same
# spelling of an IPv6 endpoint.
_IPV6_RE = (
    re.compile(r'^\[([0-9A-Fa-f:.]+)\](?::([0-9]+))?$')
    if socket.has_ipv6 else None
)


def parseTrunkEndpoint(address, defaultPort=0):
    m = _IPV4_RE.match(address)
    if m:
        return (
            socket.AF_INET,
            m.group(1),
            parse_optional_port(m.group(2), defaultPort, context=address),
        )
    if _IPV6_RE is not None:
        m = _IPV6_RE.match(address)
        if m:
            return (
                socket.AF_INET6,
                m.group(1),
                parse_optional_port(m.group(2), defaultPort, context=address),
            )
    raise SnmpfwdError('bad address specification: %s' % (address,))
