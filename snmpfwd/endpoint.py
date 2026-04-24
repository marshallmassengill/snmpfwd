#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
import re
import socket

from snmpfwd.error import SnmpfwdError

from pysnmp.carrier.asyncio.dgram import udp
try:
    from pysnmp.carrier.asyncio.dgram import udp6
except ImportError:
    udp6 = None


# Linux socket-option numbers Python's stdlib `socket` module doesn't
# expose on every build: IP_PKTINFO and IPV6_TRANSPARENT. `IP_TRANSPARENT`
# and `IPV6_RECVPKTINFO` are already in `socket.*`.
_IP_PKTINFO = 8
_IPV6_TRANSPARENT = 75


def make_transport_socket(af, bindAddr, transportOptions):
    """Create and bind a datagram socket with the kernel options required
    by `snmp-transport-options = transparent-proxy | virtual-interface`.

    pysnmp 4's asyncore carrier used to expose `enablePktInfo()` /
    `enableTransparent()` helpers on the transport object. pysnmp 7's
    asyncio carrier dropped those — but its `open_server_mode` does
    accept a pre-built `sock=`, so we can set the options ourselves
    before handing the socket to pysnmp.

    IP_TRANSPARENT lets the socket receive packets destined for non-local
    IPs (needed for `transparent-proxy` ingress with iptables TPROXY
    and for spoofed-source outbound sends).  IP_PKTINFO / IPV6_RECVPKTINFO
    get the original destination IP delivered to `recvmsg` as ancillary
    data (needed by both `transparent-proxy` and `virtual-interface` so
    snmpfwd can tell which bound IP a request landed on).
    """
    sock = socket.socket(af, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    transparent = 'transparent-proxy' in transportOptions
    pktinfo = transparent or 'virtual-interface' in transportOptions

    if af == socket.AF_INET:
        if transparent:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TRANSPARENT, 1)
        if pktinfo:
            sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
    elif af == socket.AF_INET6:
        if transparent:
            sock.setsockopt(socket.IPPROTO_IPV6, _IPV6_TRANSPARENT, 1)
        if pktinfo:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
    else:
        sock.close()
        raise SnmpfwdError('unsupported address family %r' % (af,))

    try:
        sock.bind(bindAddr)
    except OSError:
        sock.close()
        raise

    return sock


def transport_af_for_domain(transportDomain):
    """Map a pysnmp transport-domain OID to a `socket.AF_*` constant."""
    if transportDomain[:len(udp.domainName)] == udp.domainName:
        return socket.AF_INET
    if udp6 is not None and transportDomain[:len(udp6.domainName)] == udp6.domainName:
        return socket.AF_INET6
    raise SnmpfwdError('unknown transport domain %r' % (transportDomain,))


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
