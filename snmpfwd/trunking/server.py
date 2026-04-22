#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
import asyncio
import socket
import sys
import traceback
from snmpfwd import log, msgid, error
from snmpfwd.trunking import protocol


class TrunkingSuperServer(object):
    """Listener on the trunk-server side. Schedules `asyncio.Server` creation
    on the running event loop; each accepted connection becomes a fresh
    `TrunkingServer` protocol instance."""

    def __init__(self, localEndpoint, secret, dataCbFun, ctlCbFun, ctlCbCtx, loop):
        self.__localAf, self.__localHost, self.__localPort = localEndpoint
        self.__secret = secret
        self.__dataCbFun = dataCbFun
        self.__ctlCbFun = ctlCbFun
        self.__ctlCbCtx = ctlCbCtx
        self.__loop = loop
        self.__server = None

        self.__start_task = self.__loop.create_task(self._start())

    async def _start(self):
        try:
            self.__server = await self.__loop.create_server(
                lambda: TrunkingServer(
                    (self.__localAf, self.__localHost, self.__localPort),
                    self.__secret,
                    self.__dataCbFun,
                    self.__ctlCbFun,
                    self.__ctlCbCtx,
                ),
                host=self.__localHost,
                port=self.__localPort,
                family=self.__localAf,
                reuse_address=True,
            )
            log.info('%s: listening...' % self)
        except (OSError, socket.error):
            log.error('%s socket error: %s' % (self, sys.exc_info()[1]))

    def __str__(self):
        return '%s at %s:%s' % (
            self.__class__.__name__, self.__localHost, self.__localPort)

    def __repr__(self):
        return '%s(%r)' % (
            self.__class__.__name__,
            (self.__localAf, self.__localHost, self.__localPort),
        )


class TrunkingServer(asyncio.Protocol):
    """Passive side of a trunk connection, created per inbound TCP accept.
    Handles the full request/response/announcement/ping wire protocol; public
    sendReq/sendRsp/sendPing API matches the asyncore version."""

    def __init__(self, localEndpoint, secret, dataCbFun, ctlCbFun, ctlCbCtx):
        self.__localAf, self.__localHost, self.__localPort = localEndpoint
        self.__secret = secret
        self.__dataCbFun = dataCbFun
        self.__ctlCbFun = ctlCbFun
        self.__ctlCbCtx = ctlCbCtx
        self.__pendingReqs = {}
        self.__pendingCounter = 0
        self.__input = b''
        self.__transport = None
        self.__remoteHost = None
        self.__remotePort = None

    # asyncio.Protocol

    def connection_made(self, transport):
        self.__transport = transport
        peer = transport.get_extra_info('peername')
        if peer is not None and len(peer) >= 2:
            self.__remoteHost, self.__remotePort = peer[0], peer[1]
        sock = transport.get_extra_info('socket')
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65535)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65535)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except socket.error:
                pass
        log.info('TrunkingSuperServer at %s:%s new connection from %s:%s' % (
            self.__localHost, self.__localPort,
            self.__remoteHost, self.__remotePort))
        log.info('%s: serving new connection...' % self)

    def data_received(self, chunk):
        self.__input += chunk
        while self.__input:
            try:
                msgId, contentId, msg, self.__input = protocol.prepareDataElements(
                    self.__input, self.__secret
                )
            except error.SnmpfwdError:
                log.error('%s: protocol error: %s' % (self, sys.exc_info()[1]))
                self.close()
                return

            if msgId is None:
                if self.__pendingCounter > 5:
                    log.error('%s: incomplete message pending for too long, closing connection' % self)
                    self.close()
                    return
                self.__pendingCounter += 1
                return

            self.__pendingCounter = 0

            if contentId == protocol.MSG_TYPE_REQUEST:
                self.__dataCbFun(self, msgId, msg)
            elif contentId == protocol.MSG_TYPE_RESPONSE:
                if msgId in self.__pendingReqs:
                    cbFun, cbCtx = self.__pendingReqs.pop(msgId)
                    cbFun(msgId, msg, cbCtx)
            elif contentId == protocol.MSG_TYPE_PING:
                self.__ackPingCbFun(msgId, msg)
            elif contentId == protocol.MSG_TYPE_PONG:
                if msgId in self.__pendingReqs:
                    cbFun, cbCtx = self.__pendingReqs.pop(msgId)
                    cbFun(msg, cbCtx)
            elif contentId == protocol.MSG_TYPE_ANNOUNCEMENT:
                self.__ctlCbFun(self, msg, self.__ctlCbCtx)
            else:
                log.error('%s: unknown trunk message content-id %s ignored' % (self, contentId))

    def connection_lost(self, exc):
        if exc is not None and not isinstance(exc, (socket.error, ConnectionError)):
            log.error('%s: connection with %s:%s broken: %s' % (
                self, self.__remoteHost, self.__remotePort, exc))
            for line in traceback.format_exception(type(exc), exc, exc.__traceback__):
                log.error(line.replace('\n', ';'))
        log.info('%s: connection closed' % self)
        # Notify TrunkingManager so it can unregister.
        try:
            self.__ctlCbFun(self, {}, self.__ctlCbCtx)
        except Exception:
            log.error('%s: ctlCbFun on close raised: %s' % (self, sys.exc_info()[1]))
        self.__transport = None

    # Public API — called from TrunkingManager

    def sendReq(self, req, cbFun, cbCtx):
        msgId = msgid.getId()
        if self.__transport is None:
            return msgId
        self.__transport.write(protocol.prepareRequestData(msgId, req, self.__secret))
        self.__pendingReqs[msgId] = cbFun, cbCtx
        return msgId

    def sendRsp(self, msgId, rsp):
        if self.__transport is None:
            return
        self.__transport.write(protocol.prepareResponseData(msgId, rsp, self.__secret))

    def sendPing(self, serial, cbFun, cbCtx):
        msgId = msgid.getId()
        if self.__transport is None:
            return
        self.__transport.write(protocol.preparePingData(msgId, serial, self.__secret))
        self.__pendingReqs[msgId] = cbFun, cbCtx

    def __ackPingCbFun(self, msgId, req):
        if self.__transport is None:
            return
        self.__transport.write(protocol.preparePongData(msgId, req['serial'], self.__secret))

    def close(self):
        if self.__transport is not None:
            try:
                self.__transport.close()
            except Exception:
                pass

    def __str__(self):
        return '%s at %s:%s, peer %s:%s' % (
            self.__class__.__name__,
            self.__localHost, self.__localPort,
            self.__remoteHost, self.__remotePort,
        )

    def __repr__(self):
        return '%s(%s, %s)' % (
            self.__class__.__name__,
            (self.__localAf, self.__localHost, self.__localPort),
            (self.__remoteHost, self.__remotePort),
        )
