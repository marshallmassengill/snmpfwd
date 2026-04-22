#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
"""Per-request target-address override helper used by snmpfwd-client.

The SNMP manager side of snmpfwd needs to send outbound queries from a
bind-address and to a peer-address that are selected per-request based
on trunk-message content (transparent-proxy / virtual-interface modes),
rather than the static configuration that pysnmp normally resolves from
the target-address table.

pysnmp doesn't expose a first-class hook for that, so we wrap its
`pysnmp.entity.rfc3413.config.get_target_address` function: queue up
(bind, peer) overrides via `updateEndpoints(...)` immediately before
issuing a send_pdu, and the wrapped getter pops the queue and rewrites
the returned address info before pysnmp reads it.

The wrap works in pysnmp 7 because callers inside rfc3413/config.py and
rfc3413/ntforg.py reference get_target_address either as a bare name
(same-module binding, looked up at call time) or as `config.get_target_address`
(module-attribute, looked up at call time). Rebinding the module
attribute catches both.

Separated out of snmpfwdclient.main() so it can be unit-tested — the
inner closure made that impossible before.
"""
from __future__ import annotations

import sys
from typing import Callable, Tuple

from pysnmp.error import PySnmpError


def make_target_addr_override(
    target_addr: Callable,
) -> "Tuple[Callable, Callable]":
    """Return `(wrapped_get_target_address, update_endpoints)`.

    `wrapped_get_target_address(snmpEngine, snmpTargetAddrName)` has the
    same signature and contract as the original `target_addr`. If an
    endpoint override was queued via `update_endpoints(bindAddr, peerAddr)`
    since the last call, it pops and applies the override to the
    address info tuple before returning.

    Intended usage: `lcd.get_target_address, updateEndpoints =
    make_target_addr_override(lcd.get_target_address)`. Callers then
    invoke `updateEndpoints(bind, peer)` just before
    `commandGenerator.send_pdu(...)` or `notificationOriginator.send_pdu(...)`
    so the override fires on the very next pysnmp internal address
    resolution."""

    endpoints: list = []

    def wrapped_get_target_address(snmpEngine, snmpTargetAddrName):
        addrInfo = list(target_addr(snmpEngine, snmpTargetAddrName))

        if endpoints:
            peerAddr, bindAddr = endpoints.pop(), endpoints.pop()

            try:
                addrInfo[1] = addrInfo[1].__class__(peerAddr).set_local_address(bindAddr)
            except Exception:
                raise PySnmpError(
                    'failure replacing bind address %s -> %s for transport '
                    'domain %s' % (addrInfo[1], bindAddr, addrInfo[0])
                )

        return addrInfo

    def update_endpoints(bindAddr, peerAddr) -> None:
        endpoints.extend((bindAddr, peerAddr))

    return wrapped_get_target_address, update_endpoints
