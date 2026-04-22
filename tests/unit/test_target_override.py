"""Per-request target-address override used by snmpfwd-client."""
from __future__ import annotations

import pytest

from snmpfwd.target_override import make_target_addr_override


class _FakeAddress:
    """Stand-in for pysnmp's UdpTransportAddress. Records set_local_address
    so the test can verify the override reached pysnmp's address class."""

    def __init__(self, addr):
        self.addr = addr
        self.local = None

    def set_local_address(self, bind):
        self.local = bind
        return self

    def __repr__(self):
        return '<FakeAddr addr=%r local=%r>' % (self.addr, self.local)


def _make_backend(peer_addr=('10.0.0.1', 161)):
    """Produce a get_target_address stub that returns a tuple starting
    with (transport-domain, FakeAddress, ...)."""
    return lambda engine, name: (
        ('udp', 'domain'), _FakeAddress(peer_addr), 500, 0,
    )


def test_pass_through_without_override():
    """Without updateEndpoints, the wrapped getter returns the backend's
    address unmodified."""
    wrapped, _ = make_target_addr_override(_make_backend())
    info = wrapped(snmpEngine=None, snmpTargetAddrName='foo')
    assert info[1].addr == ('10.0.0.1', 161)
    assert info[1].local is None


def test_single_override_applied_once():
    """After updateEndpoints, the next wrapped call rewrites the peer
    address and records the requested bind address."""
    wrapped, update = make_target_addr_override(_make_backend())
    update(bindAddr=('127.0.0.1', 0), peerAddr=('192.168.1.1', 1161))

    info = wrapped(snmpEngine=None, snmpTargetAddrName='foo')
    assert info[1].addr == ('192.168.1.1', 1161)
    assert info[1].local == ('127.0.0.1', 0)

    # A subsequent call with no new override re-fetches from the backend
    # unmodified — the queue is empty.
    info2 = wrapped(snmpEngine=None, snmpTargetAddrName='foo')
    assert info2[1].addr == ('10.0.0.1', 161)
    assert info2[1].local is None


def test_failure_in_address_construction_raises_PySnmpError():
    """If the address class rejects the override bytes, the wrapper
    surfaces a PySnmpError with the relevant context."""
    from pysnmp.error import PySnmpError

    class _Picky(_FakeAddress):
        """Valid for the default backend address, raises on the override."""
        def __init__(self, addr):
            if isinstance(addr, tuple) and addr == ('rejected', 0):
                raise ValueError('bad address')
            super().__init__(addr)

    def backend(engine, name):
        return (('udp', 'domain'), _Picky(('ok', 161)), 500, 0)

    wrapped, update = make_target_addr_override(backend)
    update(bindAddr=('127.0.0.1', 0), peerAddr=('rejected', 0))
    with pytest.raises(PySnmpError):
        wrapped(None, 'foo')
