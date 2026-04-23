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
from snmpfwd import log, msgid, error, metrics
from snmpfwd.trunking import protocol


class TrunkingClient(asyncio.Protocol):
    """Active side of a trunk connection. `TrunkingManager` constructs one
    per configured client trunk and schedules the TCP connect as a task on
    the running asyncio loop; public sendReq/sendRsp/sendPing/sendAnnouncement
    API behaves the same as the asyncore version (fire-and-forget writes to
    the transport once it is established; buffers the announcement until
    connection_made)."""

    isUp = False

    def __init__(self, localEndpoint, remoteEndpoint, secret, dataCbFun, loop):
        self.__localAf, self.__localHost, self.__localPort = localEndpoint
        self.__remoteAf, self.__remoteHost, self.__remotePort = remoteEndpoint
        self.__secret = secret
        self.__dataCbFun = dataCbFun
        self.__loop = loop
        self.__pendingReqs = {}
        self.__pendingCounter = 0
        self.__input = b''
        self.__announcementData = b''
        self.__transport = None

        if self.__localAf != self.__remoteAf:
            raise error.SnmpfwdError('%s: mismatching address family' % self)

        self.__connect_task = self.__loop.create_task(self._connect())

        log.info('%s: initiated trunk client connection from %s to %s...' % (
            self,
            (self.__localAf, self.__localHost, self.__localPort),
            (self.__remoteAf, self.__remoteHost, self.__remotePort),
        ))

    async def _connect(self):
        local_addr = (self.__localHost, self.__localPort)
        try:
            await self.__loop.create_connection(
                lambda: self,
                host=self.__remoteHost,
                port=self.__remotePort,
                local_addr=local_addr,
                family=self.__remoteAf,
            )
        except (OSError, socket.error):
            log.error('%s socket error: %s' % (self, sys.exc_info()[1]))

    # asyncio.Protocol

    def connection_made(self, transport):
        self.__transport = transport
        sock = transport.get_extra_info('socket')
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65535)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65535)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except socket.error:
                pass  # best-effort — remote may already have dropped
        self.isUp = True
        if self.__announcementData:
            transport.write(self.__announcementData)
            self.__announcementData = b''
            log.debug('%s: trunk announcement sent' % self)
        metrics.increment(metrics.TRUNK_CONNECTIONS_UP)
        log.info('%s: client is now connected' % self)

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
                    log.error('%s: incomplete trunk message pending for too long, closing connection' % self)
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
            else:
                log.error('%s: unknown trunk message content-id %s ignored' % (self, contentId))

    def connection_lost(self, exc):
        if exc is not None and not isinstance(exc, (socket.error, ConnectionError)):
            log.error('%s: connection with %s:%s broken: %s' % (
                self, self.__remoteHost, self.__remotePort, exc))
            for line in traceback.format_exception(type(exc), exc, exc.__traceback__):
                log.error(line.replace('\n', ';'))
        else:
            log.info('%s: connection with %s:%s closed' % (
                self, self.__remoteHost, self.__remotePort))
        if self.isUp:
            metrics.increment(metrics.TRUNK_CONNECTIONS_DOWN)
        self.isUp = False
        self.__transport = None

    # Public API — called from TrunkingManager

    def sendReq(self, req, cbFun, cbCtx):
        msgId = msgid.getId()
        if self.__transport is None:
            # Trunk is not connected yet; TrunkingManager will detect this
            # on its next setupTrunks tick and rebuild.
            return msgId
        self.__transport.write(protocol.prepareRequestData(msgId, req, self.__secret))
        self.__pendingReqs[msgId] = cbFun, cbCtx
        return msgId

    def sendRsp(self, msgId, rsp):
        if self.__transport is None:
            return
        self.__transport.write(protocol.prepareResponseData(msgId, rsp, self.__secret))

    def sendAnnouncement(self, trunkId):
        self.__announcementData = protocol.prepareAnnouncementData(
            trunkId, self.__secret
        )
        if self.isUp and self.__transport is not None:
            self.__transport.write(self.__announcementData)
            self.__announcementData = b''
            log.debug('%s: trunk announcement sent' % self)

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
        self.isUp = False

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
            (self.__remoteAf, self.__remoteHost, self.__remotePort),
        )
