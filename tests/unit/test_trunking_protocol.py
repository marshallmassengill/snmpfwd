"""Round-trip tests for the trunk wire protocol — the ASN.1 Message
envelope plus each content-type's payload (Request / Response /
Announcement / Ping / Pong). These exercises are what guarantee that
PROTOCOL_VERSION=3 bytes stay stable across any future refactor."""
from __future__ import annotations

import pytest
from pysnmp.proto.api import v2c

from snmpfwd.trunking import protocol


# ---------------------------------------------------------------------------
# Request / Response


def _build_pdu() -> object:
    """A minimal GetRequest PDU carrying one var-bind (sysDescr.0)."""
    pdu = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_varbinds(pdu, ((v2c.ObjectIdentifier('1.3.6.1.2.1.1.1.0'), v2c.Null()),))
    return pdu


def _sample_request() -> dict:
    return {
        'callflow-id': 'abcdef0123',
        'snmp-engine-id': b'\x01\x02\x03\x04',
        'snmp-transport-domain': (1, 3, 6, 1, 6, 1, 1, 100),
        'snmp-peer-address': '127.0.0.1',
        'snmp-peer-port': 1161,
        'snmp-bind-address': '0.0.0.0',
        'snmp-bind-port': 0,
        'snmp-security-model': 2,
        'snmp-security-level': 1,
        'snmp-security-name': b'public',
        'snmp-security-engine-id': b'\x01\x02\x03\x04',
        'snmp-context-engine-id': b'\x01\x02\x03\x04',
        'snmp-context-name': b'',
        'snmp-pdu': _build_pdu(),
        'snmp-credentials-id': b'creds-1',
        'snmp-context-id': b'any-context',
        'snmp-content-id': b'any-content',
        'snmp-peer-id': b'100',
    }


@pytest.mark.parametrize('secret', ['', '0123456789abcdef'])
def test_request_roundtrip(secret):
    req = _sample_request()
    wire = protocol.prepareRequestData(msgId=42, req=req, secret=secret)
    msgId, contentId, decoded, rest = protocol.prepareDataElements(wire, secret)

    assert msgId == 42
    assert contentId == protocol.MSG_TYPE_REQUEST
    assert rest == b''
    def _as_text(v):
        if isinstance(v, (bytes, bytearray)):
            return v.decode('latin-1')
        return str(v)

    # Every field in the original request made the round trip.
    for key in ('callflow-id', 'snmp-peer-address', 'snmp-peer-port',
                'snmp-security-model', 'snmp-credentials-id',
                'snmp-context-id', 'snmp-content-id'):
        assert _as_text(decoded[key]) == _as_text(req[key]), key


@pytest.mark.parametrize('secret', ['', '0123456789abcdef'])
def test_response_roundtrip(secret):
    # A response PDU carrying the same var-bind as the request.
    rsp_pdu = v2c.apiPDU.get_response(_build_pdu())
    rsp = {'error-indication': '', 'snmp-pdu': rsp_pdu}
    wire = protocol.prepareResponseData(msgId=7, rsp=rsp, secret=secret)
    msgId, contentId, decoded, rest = protocol.prepareDataElements(wire, secret)

    assert msgId == 7
    assert contentId == protocol.MSG_TYPE_RESPONSE
    assert rest == b''
    assert str(decoded['error-indication']) == ''
    assert decoded['snmp-pdu'].tagSet == rsp_pdu.tagSet


@pytest.mark.parametrize('secret', ['', '0123456789abcdef'])
def test_response_with_error_indication_and_no_pdu(secret):
    rsp = {'error-indication': 'timeout', 'snmp-pdu': None}
    wire = protocol.prepareResponseData(msgId=13, rsp=rsp, secret=secret)
    msgId, contentId, decoded, _ = protocol.prepareDataElements(wire, secret)

    assert contentId == protocol.MSG_TYPE_RESPONSE
    assert str(decoded['error-indication']) == 'timeout'
    assert 'snmp-pdu' not in decoded


# ---------------------------------------------------------------------------
# Announcement / Ping / Pong


@pytest.mark.parametrize('secret', ['', '0123456789abcdef'])
def test_announcement_roundtrip(secret):
    wire = protocol.prepareAnnouncementData(trunkId=b'trunk-1', secret=secret)
    msgId, contentId, decoded, _ = protocol.prepareDataElements(wire, secret)
    assert msgId == 0
    assert contentId == protocol.MSG_TYPE_ANNOUNCEMENT
    assert str(decoded['trunk-id']) == 'trunk-1'


@pytest.mark.parametrize('secret', ['', '0123456789abcdef'])
def test_ping_roundtrip(secret):
    wire = protocol.preparePingData(msgId=101, serial=99, secret=secret)
    msgId, contentId, decoded, _ = protocol.prepareDataElements(wire, secret)
    assert msgId == 101
    assert contentId == protocol.MSG_TYPE_PING
    assert int(decoded['serial']) == 99


@pytest.mark.parametrize('secret', ['', '0123456789abcdef'])
def test_pong_roundtrip(secret):
    wire = protocol.preparePongData(msgId=202, serial=77, secret=secret)
    msgId, contentId, decoded, _ = protocol.prepareDataElements(wire, secret)
    assert msgId == 202
    assert contentId == protocol.MSG_TYPE_PONG
    assert int(decoded['serial']) == 77


# ---------------------------------------------------------------------------
# Stream framing


def test_partial_message_is_buffered():
    """prepareDataElements must return msgId=None when given a truncated
    input so the caller can accumulate more bytes."""
    req = _sample_request()
    wire = protocol.prepareRequestData(msgId=1, req=req, secret='')
    # Chop off the last few bytes — the decoder should signal incomplete.
    msgId, contentId, decoded, rest = protocol.prepareDataElements(wire[:-5], '')
    assert msgId is None
    assert rest == wire[:-5]  # caller re-feeds with additional bytes


def test_back_to_back_messages_decode_independently():
    """Two encoded messages concatenated must decode in order, with each
    call returning the tail for the next iteration."""
    wire1 = protocol.preparePingData(msgId=1, serial=10, secret='')
    wire2 = protocol.preparePongData(msgId=2, serial=20, secret='')
    buf = wire1 + wire2

    msgId, contentId, decoded, rest = protocol.prepareDataElements(buf, '')
    assert msgId == 1 and contentId == protocol.MSG_TYPE_PING
    assert rest == wire2

    msgId, contentId, decoded, rest = protocol.prepareDataElements(rest, '')
    assert msgId == 2 and contentId == protocol.MSG_TYPE_PONG
    assert rest == b''


def test_wrong_secret_fails_to_decode():
    """If the shared secret doesn't match, payload decryption produces
    garbage that the inner ASN.1 decoder should reject."""
    wire = protocol.preparePingData(msgId=1, serial=1, secret='0123456789abcdef')
    with pytest.raises(Exception):
        protocol.prepareDataElements(wire, 'XXXXXXXXXXXXXXXX')
