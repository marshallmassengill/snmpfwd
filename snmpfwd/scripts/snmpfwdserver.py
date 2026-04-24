#!/usr/bin/env python
#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
import sys
import traceback
import random
import re
from pysnmp.error import PySnmpError
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, ntfrcv, context
from pysnmp.proto.proxy import rfc2576
from pysnmp.carrier.asyncio.dgram import udp
try:
    from pysnmp.carrier.asyncio.dgram import udp6
except ImportError:
    udp6 = None
# UNIX domain SNMP transport has no asyncio carrier equivalent.
unix = None
from pysnmp.proto import rfc1157, rfc1902, rfc1905, rfc3411
from pysnmp.proto.api import v1, v2c
from snmpfwd.error import SnmpfwdError
from snmpfwd import log, macro, endpoint, bootstrap, metrics
from snmpfwd.plugins import status
from snmpfwd.trunking.manager import TrunkingManager
from snmpfwd.lazylog import LazyLogString

# Settings
PROGRAM_NAME = 'snmpfwd-server'
CONFIG_VERSION = '2'
PLUGIN_API_VERSION = 2
CONFIG_FILE = '/usr/local/etc/snmpfwd/server.cfg'

authProtocols = {
  'MD5': config.usmHMACMD5AuthProtocol,
  'SHA': config.usmHMACSHAAuthProtocol,
  'SHA224': config.usmHMAC128SHA224AuthProtocol,
  'SHA256': config.usmHMAC192SHA256AuthProtocol,
  'SHA384': config.usmHMAC256SHA384AuthProtocol,
  'SHA512': config.usmHMAC384SHA512AuthProtocol,
  'NONE': config.usmNoAuthProtocol
}

privProtocols = {
  'DES': config.usmDESPrivProtocol,
  '3DES': config.usm3DESEDEPrivProtocol,
  'AES': config.usmAesCfb128Protocol,
  'AES128': config.usmAesCfb128Protocol,
  'AES192': config.usmAesCfb192Protocol,
  'AES192BLMT': config.usmAesBlumenthalCfb192Protocol,
  'AES256': config.usmAesCfb256Protocol,
  'AES256BLMT': config.usmAesBlumenthalCfb256Protocol,
  'NONE': config.usmNoPrivProtocol
}

snmpPduTypesMap = {
    rfc1905.GetRequestPDU.tagSet: 'GET',
    rfc1905.SetRequestPDU.tagSet: 'SET',
    rfc1905.GetNextRequestPDU.tagSet: 'GETNEXT',
    rfc1905.GetBulkRequestPDU.tagSet: 'GETBULK',
    rfc1905.ResponsePDU.tagSet: 'RESPONSE',
    rfc1157.TrapPDU.tagSet: 'TRAPv1',
    rfc1905.SNMPv2TrapPDU.tagSet: 'TRAPv2',
    rfc1905.InformRequestPDU.tagSet: 'INFORM',
}


def _inform_ack_cb(*args, **kwargs):
    """No-op callback passed to pysnmp's NotificationReceiver base. pysnmp
    invokes it after dispatching the INFORM ack Response; snmpfwd does
    its own trunk-forwarding inside the subclass's process_pdu, so this
    hook doesn't need to do anything."""
    pass


def _run():

    class CommandResponder(cmdrsp.CommandResponderBase):
        SUPPORTED_PDU_TYPES = (rfc1905.SetRequestPDU.tagSet,
                               rfc1905.GetRequestPDU.tagSet,
                               rfc1905.GetNextRequestPDU.tagSet,
                               rfc1905.GetBulkRequestPDU.tagSet)

        # pysnmp 7 unconditionally calls release_state_information at the
        # end of process_pdu, but snmpfwd forwards PDUs asynchronously over
        # a trunk and needs the pysnmp per-request state to survive until
        # trunkCbFun receives the reply. We stash a copy of the state on
        # the way in and re-insert it into pysnmp's pending-request dict
        # just before calling send_pdu from trunkCbFun.
        _stashedState = {}

        def _peek_pending_state(self, stateReference):
            return self._CommandResponderBase__pendingReqs.get(stateReference)

        def _restore_pending_state(self, stateReference):
            state = self._stashedState.pop(stateReference, None)
            if state is not None:
                self._CommandResponderBase__pendingReqs[stateReference] = state

        def handle_management_operation(self, snmpEngine, stateReference,
                                        contextName, pdu):
            # Stash pysnmp's state before pysnmp 7's process_pdu auto-releases it.
            state = self._peek_pending_state(stateReference)
            if state is not None:
                self._stashedState[stateReference] = state

            trunkReq = gCurrentRequestContext.copy()

            trunkReq['snmp-pdu'] = pdu

            pluginIdList = trunkReq['plugins-list']

            logCtx = LogString(trunkReq)

            reqCtx = {}

            for pluginNum, pluginId in enumerate(pluginIdList):

                st, pdu = pluginManager.processCommandRequest(
                    pluginId, snmpEngine, pdu, trunkReq, reqCtx
                )

                if st == status.BREAK:
                    log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                    pluginIdList = pluginIdList[:pluginNum]
                    break

                elif st == status.DROP:
                    log.debug('received SNMP message, plugin %s muted request' % pluginId, ctx=logCtx)
                    metrics.increment(metrics.SERVER_PLUGINS_DROPPED)
                    self.release_state_information(stateReference)
                    return

                elif st == status.RESPOND:
                    log.debug('received SNMP message, plugin %s forced immediate response' % pluginId, ctx=logCtx)
                    metrics.increment(metrics.SERVER_PLUGINS_RESPONDED)

                    try:
                        self.send_pdu(snmpEngine, stateReference, pdu)

                    except PySnmpError:
                        log.error('failure sending SNMP response: %s' % sys.exc_info()[1], ctx=logCtx)

                    else:
                        self.release_state_information(stateReference)

                    return

            # pass query to trunk

            trunkIdList = trunkReq['trunk-id-list']
            if trunkIdList is None:
                log.error('no route configured', ctx=logCtx)
                metrics.increment(metrics.SERVER_UNROUTABLE_REQUESTS)
                self.release_state_information(stateReference)
                return

            for trunkId in trunkIdList:

                cbCtx = pluginIdList, trunkId, trunkReq, snmpEngine, stateReference, reqCtx

                try:
                    msgId = trunkingManager.sendReq(trunkId, trunkReq, self.trunkCbFun, cbCtx)

                except SnmpfwdError:
                    log.error('received SNMP message, message not sent to trunk "%s"' % sys.exc_info()[1], ctx=logCtx)
                    return

                metrics.increment(metrics.SERVER_REQUESTS_FORWARDED)
                log.debug('received SNMP message, forwarded as trunk message #%s' % msgId, ctx=logCtx)

        def trunkCbFun(self, msgId, trunkRsp, cbCtx):
            pluginIdList, trunkId, trunkReq, snmpEngine, stateReference, reqCtx = cbCtx

            for key in tuple(trunkRsp):
                if key != 'callflow-id':
                    trunkRsp['client-' + key] = trunkRsp[key]
                    del trunkRsp[key]

            trunkRsp['callflow-id'] = trunkReq['callflow-id']

            logCtx = LogString(trunkRsp)

            if trunkRsp['client-error-indication']:
                log.info('received trunk message #%s, remote end reported error-indication "%s", NOT responding' % (msgId, trunkRsp['client-error-indication']), ctx=logCtx)

            elif 'client-snmp-pdu' not in trunkRsp:
                log.info('received trunk message #%s, remote end does not send SNMP PDU, NOT responding' % msgId, ctx=logCtx)

            else:
                pdu = trunkRsp['client-snmp-pdu']

                for pluginId in pluginIdList:
                    st, pdu = pluginManager.processCommandResponse(
                        pluginId, snmpEngine, pdu, trunkReq, reqCtx
                    )

                    if st == status.BREAK:
                        log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                        break
                    elif st == status.DROP:
                        log.debug('plugin %s muted response' % pluginId, ctx=logCtx)
                        self.release_state_information(stateReference)
                        return

                # Re-insert the state we stashed in handle_management_operation
                # so pysnmp's send_pdu can find it.
                self._restore_pending_state(stateReference)

                try:
                    self.send_pdu(snmpEngine, stateReference, pdu)

                except PySnmpError:
                    log.error('trunk message #%s, SNMP response error: %s' % (msgId, sys.exc_info()[1]),
                              ctx=logCtx)

                else:
                    log.debug('received trunk message #%s, forwarded as SNMP message' % msgId, ctx=logCtx)

            self.release_state_information(stateReference)

    #
    # SNMPv3 NotificationReceiver implementation
    #

    class NotificationReceiver(ntfrcv.NotificationReceiver):
        # Include InformRequestPDU so pysnmp dispatches INFORMs to our
        # process_pdu (the base class's SUPPORTED_PDU_TYPES includes it
        # but our override narrowed it to TRAPs only).
        SUPPORTED_PDU_TYPES = (rfc1157.TrapPDU.tagSet,
                               rfc1905.SNMPv2TrapPDU.tagSet,
                               rfc1905.InformRequestPDU.tagSet)

        def process_pdu(self, snmpEngine, messageProcessingModel,
                        securityModel, securityName, securityLevel,
                        contextEngineId, contextName, pduVersion, pdu,
                        maxSizeResponseScopedPDU, stateReference):

            # Phase 3B: end-to-end confirmed INFORM. For confirmed-class
            # PDUs we DO NOT send an ack here — instead we stash pysnmp's
            # message-dispatcher state (stateReference + security/MP
            # context + the original request-id via the PDU itself) and
            # defer the ack until trunkCbFun receives the downstream
            # response. On downstream failure the ack is skipped and the
            # original sender retransmits; that's RFC-strict INFORM
            # semantics for a proxy.
            is_confirmed = pdu.tagSet in rfc3411.CONFIRMED_CLASS_PDUS
            ack_ctx = None
            if is_confirmed:
                ack_ctx = {
                    'messageProcessingModel': messageProcessingModel,
                    'securityModel': securityModel,
                    'securityName': securityName,
                    'securityLevel': securityLevel,
                    'contextEngineId': contextEngineId,
                    'contextName': contextName,
                    'pduVersion': pduVersion,
                    'maxSizeResponseScopedPDU': maxSizeResponseScopedPDU,
                    'stateReference': stateReference,
                    'requestPdu': pdu,
                }

            trunkReq = gCurrentRequestContext.copy()

            if messageProcessingModel == 0:
                pdu = rfc2576.v1_to_v2(pdu)

            trunkReq['snmp-pdu'] = pdu

            pluginIdList = trunkReq['plugins-list']

            logCtx = LogString(trunkReq)

            reqCtx = {}

            for pluginNum, pluginId in enumerate(pluginIdList):

                st, pdu = pluginManager.processNotificationRequest(
                    pluginId, snmpEngine, pdu, trunkReq, reqCtx
                )

                if st == status.BREAK:
                    log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                    pluginIdList = pluginIdList[:pluginNum]
                    break

                elif st == status.DROP:
                    log.debug('plugin %s muted request' % pluginId, ctx=logCtx)
                    return

                elif st == status.RESPOND:
                    log.debug('plugin %s NOT forced immediate response' % pluginId, ctx=logCtx)
                    # TODO: implement immediate response for confirmed-class PDU
                    return

            # pass query to trunk

            trunkIdList = trunkReq['trunk-id-list']
            if trunkIdList is None:
                log.error('no route configured', ctx=logCtx)
                return

            for trunkId in trunkIdList:

                cbCtx = (pluginIdList, trunkId, trunkReq, snmpEngine,
                         stateReference, reqCtx, ack_ctx)

                try:
                    msgId = trunkingManager.sendReq(trunkId, trunkReq, self.trunkCbFun, cbCtx)

                except SnmpfwdError:
                    log.error('received SNMP message, message not sent to trunk "%s" %s' % (trunkId, sys.exc_info()[1]), ctx=logCtx)
                    return

                metrics.increment(metrics.SERVER_NOTIFICATIONS_FORWARDED)
                log.debug('received SNMP message, forwarded as trunk message #%s' % msgId, ctx=logCtx)

        def trunkCbFun(self, msgId, trunkRsp, cbCtx):
            pluginIdList, trunkId, trunkReq, snmpEngine, stateReference, reqCtx, ack_ctx = cbCtx

            for key in tuple(trunkRsp):
                if key != 'callflow-id':
                    trunkRsp['client-' + key] = trunkRsp[key]
                    del trunkRsp[key]

            trunkRsp['callflow-id'] = trunkReq['callflow-id']

            logCtx = LazyLogString(trunkReq, trunkRsp)

            downstream_err = trunkRsp['client-error-indication']
            if downstream_err:
                log.info('received trunk message #%s, remote end reported error-indication "%s", NOT responding' % (msgId, downstream_err), ctx=logCtx)
            else:
                if 'client-snmp-pdu' not in trunkRsp:
                    log.debug('received trunk message #%s -- unconfirmed SNMP message' % msgId, ctx=logCtx)
                    return

                pdu = trunkRsp['client-snmp-pdu']

                for pluginId in pluginIdList:
                    st, pdu = pluginManager.processNotificationResponse(
                        pluginId, snmpEngine, pdu, trunkReq, reqCtx
                    )

                    if st == status.BREAK:
                        log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                        break
                    elif st == status.DROP:
                        log.debug('received trunk message #%s, plugin %s muted response' % (msgId, pluginId), ctx=logCtx)
                        return

                log.debug('received trunk message #%s, forwarded as SNMP message' % msgId, ctx=logCtx)

            # Phase 3B: if this was an INFORM, ack the original sender now
            # that we've heard from the downstream. On downstream error
            # indication (timeout / unreachable / auth-fail), we skip the
            # ack deliberately so the sender can retry — RFC-strict
            # semantic for a proxy.
            if ack_ctx is not None and not downstream_err:
                self._ack_inform(snmpEngine, ack_ctx)
                metrics.increment(metrics.SERVER_INFORMS_ACKED)
            elif ack_ctx is not None:
                metrics.increment(metrics.SERVER_INFORMS_ACK_SKIPPED)
                log.debug(
                    'INFORM downstream failed (%s); skipping ack to the '
                    'original sender' % downstream_err, ctx=logCtx,
                )

        @staticmethod
        def _ack_inform(snmpEngine, ack_ctx):
            """Build an ack ResponsePDU for an INFORM using the pysnmp
            message-dispatcher state we stashed at process_pdu time, and
            dispatch it back to the original sender. Mirrors the
            confirmed-class branch of pysnmp's NotificationReceiver
            base."""
            reqPdu = ack_ctx['requestPdu']
            # v2 path only — INFORM doesn't exist in SNMPv1.
            rspPDU = v2c.apiPDU.get_response(reqPdu)
            v2c.apiPDU.set_error_status(rspPDU, 'noError')
            v2c.apiPDU.set_error_index(rspPDU, 0)
            v2c.apiPDU.set_varbinds(rspPDU, v2c.apiPDU.get_varbinds(reqPdu))

            try:
                snmpEngine.message_dispatcher.return_response_pdu(
                    snmpEngine,
                    ack_ctx['messageProcessingModel'],
                    ack_ctx['securityModel'],
                    ack_ctx['securityName'],
                    ack_ctx['securityLevel'],
                    ack_ctx['contextEngineId'],
                    ack_ctx['contextName'],
                    ack_ctx['pduVersion'],
                    rspPDU,
                    ack_ctx['maxSizeResponseScopedPDU'],
                    ack_ctx['stateReference'],
                    {},
                )
            except Exception:
                log.error('INFORM ack dispatch failed: %s' % sys.exc_info()[1])

    class LogString(LazyLogString):

        GROUPINGS = [
            ['callflow-id'],
            ['snmp-engine-id',
             'snmp-transport-domain',
             'snmp-bind-address',
             'snmp-bind-port',
             'snmp-security-model',
             'snmp-security-level',
             'snmp-security-name',
             'snmp-credentials-id'],
            ['snmp-context-engine-id',
             'snmp-context-name',
             'snmp-context-id'],
            ['snmp-pdu',
             'snmp-content-id'],
            ['snmp-peer-address',
             'snmp-peer-port',
             'snmp-peer-id'],
            ['trunk-id'],
            ['client-snmp-pdu'],
        ]

        FORMATTERS = {
            'client-snmp-pdu': LazyLogString.prettyVarBinds,
            'snmp-pdu': LazyLogString.prettyVarBinds,
        }

    def securityAuditObserver(snmpEngine, execpoint, variables, cbCtx):
        securityModel = variables.get('securityModel', 0)

        # pysnmp 7's asyncio carrier delivers transportAddress as a plain
        # (host, port) tuple without the old `.getLocalAddress()` helper,
        # so we read the bind host/port from transportDomainBindAddr
        # (populated at config load) the same way requestObserver does.
        bindHost, bindPort = transportDomainBindAddr.get(
            str(variables.get('transportDomain')), ('', 0)
        )
        peerHost, peerPort = variables['transportAddress'][0], variables['transportAddress'][1]

        logMsg = 'SNMPv%s auth failure' % securityModel
        logMsg += ' at %s:%s' % (bindHost, bindPort)
        logMsg += ' from %s:%s' % (peerHost, peerPort)

        statusInformation = variables.get('statusInformation', {})

        if securityModel in (1, 2):
            logMsg += ' using snmp-community-name "%s"' % statusInformation.get('communityName', '?')
        elif securityModel == 3:
            logMsg += ' using snmp-usm-user "%s"' % statusInformation.get('msgUserName', '?')

        try:
            logMsg += ': %s' % statusInformation['errorIndication']

        except KeyError:
            pass

        metrics.increment(metrics.SERVER_AUTH_FAILURES)
        log.error(logMsg)

    def usmRequestObserver(snmpEngine, execpoint, variables, cbCtx):

        trunkReq = {
            'snmp-security-engine-id': variables['securityEngineId']
        }

        cbCtx.clear()
        cbCtx.update(trunkReq)

    def requestObserver(snmpEngine, execpoint, variables, cbCtx):

        bindHost, bindPort = transportDomainBindAddr.get(
            str(variables['transportDomain']), ('', 0)
        )
        trunkReq = {
            'callflow-id': '%10.10x' % random.randint(0, 0xffffffffff),
            'snmp-engine-id': snmpEngine.snmpEngineID,
            'snmp-transport-domain': variables['transportDomain'],
            'snmp-peer-address': variables['transportAddress'][0],
            'snmp-peer-port': variables['transportAddress'][1],
            'snmp-bind-address': bindHost,
            'snmp-bind-port': bindPort,
            'snmp-security-model': variables['securityModel'],
            'snmp-security-level': variables['securityLevel'],
            'snmp-security-name': variables['securityName'],
            'snmp-context-engine-id': variables['contextEngineId'],
            'snmp-context-name': variables['contextName'],
        }

        try:
            trunkReq['snmp-security-engine-id'] = cbCtx.pop('snmp-security-engine-id')

        except KeyError:
            # SNMPv1/v2c
            trunkReq['snmp-security-engine-id'] = trunkReq['snmp-engine-id']

        trunkReq['snmp-credentials-id'] = macro.expandMacro(
            credIdMap.get(
                (str(snmpEngine.snmpEngineID),
                 variables['transportDomain'],
                 variables['securityModel'],
                 variables['securityLevel'],
                 str(variables['securityName']))
            ),
            trunkReq
        )

        # Use prettyPrint() rather than str() so binary-valued OctetStrings
        # (most notably the engine-id) render as stable printable text like
        # "0x01d68ba0..." — str() on a pyasn1 OctetString returns the raw
        # bytes, which can include characters such as 0x0a that prevent
        # `.` from matching in the configured regex.
        def _text(x):
            return x.prettyPrint() if hasattr(x, 'prettyPrint') else str(x)
        k = '#'.join([_text(x) for x in (variables['contextEngineId'], variables['contextName'])])
        for x, y in contextIdList:
            if y.match(k):
                trunkReq['snmp-context-id'] = macro.expandMacro(x, trunkReq)
                break
            else:
                trunkReq['snmp-context-id'] = None

        addr = '%s:%s#%s:%s' % (variables['transportAddress'][0], variables['transportAddress'][1], bindHost, bindPort)

        for pat, peerId in peerIdMap.get(str(variables['transportDomain']), ()):
            if pat.match(addr):
                trunkReq['snmp-peer-id'] = macro.expandMacro(peerId, trunkReq)
                break
        else:
            trunkReq['snmp-peer-id'] = None

        pdu = variables['pdu']
        if pdu.tagSet == v1.TrapPDU.tagSet:
            pdu = rfc2576.v1_to_v2(pdu)
            v2c.apiTrapPDU.set_defaults(pdu)

        k = '#'.join(
            [snmpPduTypesMap.get(variables['pdu'].tagSet, '?'),
             '|'.join([str(x[0]) for x in v2c.apiTrapPDU.get_varbinds(pdu)])]
        )

        for x, y in contentIdList:
            if y.match(k):
                trunkReq['snmp-content-id'] = macro.expandMacro(x, trunkReq)
                break
            else:
                trunkReq['snmp-content-id'] = None

        trunkReq['plugins-list'] = pluginIdMap.get(
            (trunkReq['snmp-credentials-id'],
             trunkReq['snmp-context-id'],
             trunkReq['snmp-peer-id'],
             trunkReq['snmp-content-id']), []
        )
        trunkReq['trunk-id-list'] = trunkIdMap.get(
            (trunkReq['snmp-credentials-id'],
             trunkReq['snmp-context-id'],
             trunkReq['snmp-peer-id'],
             trunkReq['snmp-content-id'])
        )

        cbCtx.clear()
        cbCtx.update(trunkReq)

    #
    # main script starts here
    #

    try:
        args = bootstrap.bootstrap_cli_and_logging(
            program_name=PROGRAM_NAME,
            default_config_file=CONFIG_FILE,
            synopsis=(
                'SNMP Proxy Forwarder: server part. Receives SNMP requests at '
                'one or many built-in SNMP Agents and routes them to encrypted '
                "trunks established with Forwarder's Manager part(s) running "
                'elsewhere. Can implement complex routing logic through '
                'analyzing parts of SNMP messages and matching them against '
                'proxy rules.'
            ),
        )
    except SnmpfwdError:
        return

    cfgFile = args.config_file
    procUser = args.process_user
    procGroup = args.process_group

    try:
        cfgTree = bootstrap.load_config(args, PROGRAM_NAME, CONFIG_VERSION)
    except SnmpfwdError:
        return

    random.seed()

    gCurrentRequestContext = {}

    credIdMap = {}
    peerIdMap = {}
    contextIdList = []
    contentIdList = []
    pluginIdMap = {}
    trunkIdMap = {}
    engineIdMap = {}

    # Map transport-domain OID (as string) -> (bindHost, bindPort). Populated
    # during config load because pysnmp 7's asyncio carrier delivers
    # transportAddress as a plain (host, port) tuple without the old
    # getLocalAddress() helper, so we need to recover the local bind info
    # ourselves inside the observer.
    transportDomainBindAddr = {}

    transportDispatcher = bootstrap.build_transport_dispatcher()

    try:
        pluginManager = bootstrap.build_plugin_manager(
            cfgTree, args, PROGRAM_NAME, PLUGIN_API_VERSION,
        )
    except SnmpfwdError:
        return

    for configEntryPath in cfgTree.getPathsToAttr('snmp-credentials-id'):
        credId = cfgTree.getAttrValue('snmp-credentials-id', *configEntryPath)
        configKey = []
        log.info('configuring snmp-credentials %s (at %s)...' % (credId, '.'.join(configEntryPath)))

        engineId = cfgTree.getAttrValue('snmp-engine-id', *configEntryPath)

        if engineId in engineIdMap:
            snmpEngine, snmpContext, snmpEngineMap = engineIdMap[engineId]
            log.info('using engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())
        else:
            snmpEngine = engine.SnmpEngine(snmpEngineID=engineId)
            snmpContext = context.SnmpContext(snmpEngine)
            snmpEngineMap = {
                'transportDomain': {},
                'securityName': {}
            }

            snmpEngine.observer.register_observer(
                securityAuditObserver,
                'rfc2576.prepareDataElements:sm-failure',
                'rfc3412.prepareDataElements:sm-failure',
                cbCtx=gCurrentRequestContext
            )

            snmpEngine.observer.register_observer(
                requestObserver,
                'rfc3412.receiveMessage:request',
                cbCtx=gCurrentRequestContext
            )

            snmpEngine.observer.register_observer(
                usmRequestObserver,
                'rfc3414.processIncomingMsg',
                cbCtx=gCurrentRequestContext
            )

            CommandResponder(snmpEngine, snmpContext)

            NotificationReceiver(snmpEngine, _inform_ack_cb)

            engineIdMap[engineId] = snmpEngine, snmpContext, snmpEngineMap

            log.info('new engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())

        configKey.append(str(snmpEngine.snmpEngineID))

        transportDomain = cfgTree.getAttrValue('snmp-transport-domain', *configEntryPath)
        transportDomain = rfc1902.ObjectName(transportDomain)

        if (transportDomain[:len(udp.domainName)] != udp.domainName and
                udp6 and transportDomain[:len(udp6.domainName)] != udp6.domainName):
            log.error('unknown transport domain %s' % (transportDomain,))
            return

        if transportDomain in snmpEngineMap['transportDomain']:
            bindAddr, transportDomain = snmpEngineMap['transportDomain'][transportDomain]
            log.info('using transport endpoint [%s]:%s, transport ID %s' % (bindAddr[0], bindAddr[1], transportDomain))

        else:
            bindAddr = cfgTree.getAttrValue('snmp-bind-address', *configEntryPath)

            transportOptions = cfgTree.getAttrValue('snmp-transport-options', *configEntryPath, **dict(default=[], vector=True))

            try:
                bindAddr, bindAddrMacro = endpoint.parseTransportAddress(transportDomain, bindAddr,
                                                                         transportOptions)

            except SnmpfwdError:
                log.error('bad snmp-bind-address specification %s at %s' % (bindAddr, '.'.join(configEntryPath)))
                return

            if transportDomain[:len(udp.domainName)] == udp.domainName:
                transport = udp.UdpTransport(loop=transportDispatcher.loop)
            else:
                transport = udp6.Udp6Transport(loop=transportDispatcher.loop)

            # pysnmp 7's asyncio carrier dropped enablePktInfo /
            # enableTransparent. When either transport-option is
            # requested we pre-create the socket with the kernel flags
            # set and hand it to open_server_mode(sock=...), which is
            # the replacement path pysnmp still supports.
            if ('transparent-proxy' in transportOptions
                    or 'virtual-interface' in transportOptions):
                af = endpoint.transport_af_for_domain(transportDomain)
                sock = endpoint.make_transport_socket(af, bindAddr, transportOptions)
                t = transport.open_server_mode(sock=sock)
            else:
                t = transport.openServerMode(bindAddr)

            snmpEngine.register_transport_dispatcher(
                transportDispatcher, transportDomain
            )

            config.addSocketTransport(snmpEngine, transportDomain, t)

            snmpEngineMap['transportDomain'][transportDomain] = bindAddr, transportDomain
            transportDomainBindAddr[str(transportDomain)] = bindAddr

            log.info('new transport endpoint [%s]:%s, options %s, transport ID %s' % (bindAddr[0], bindAddr[1], transportOptions and '/'.join(transportOptions) or '<none>', transportDomain))

        configKey.append(transportDomain)

        securityModel = cfgTree.getAttrValue('snmp-security-model', *configEntryPath)
        securityModel = rfc1902.Integer(securityModel)
        securityLevel = cfgTree.getAttrValue('snmp-security-level', *configEntryPath)
        securityLevel = rfc1902.Integer(securityLevel)
        securityName = cfgTree.getAttrValue('snmp-security-name', *configEntryPath)

        if securityModel in (1, 2):
            if securityName in snmpEngineMap['securityName']:
                if snmpEngineMap['securityName'][securityModel] == securityModel:
                    log.info('using security-name %s' % securityName)
                else:
                    raise SnmpfwdError('snmp-security-name %s already in use at snmp-security-model %s' % (securityName, securityModel))
            else:
                communityName = cfgTree.getAttrValue('snmp-community-name', *configEntryPath)
                config.addV1System(snmpEngine, securityName, communityName,
                                   securityName=securityName)
                log.info('new community-name %s, security-model %s, security-name %s, security-level %s' % (communityName, securityModel, securityName, securityLevel))
                snmpEngineMap['securityName'][securityName] = securityModel

            configKey.append(securityModel)
            configKey.append(securityLevel)
            configKey.append(securityName)

        elif securityModel == 3:
            if securityName in snmpEngineMap['securityName']:
                log.info('using USM security-name: %s' % securityName)
            else:
                usmUser = cfgTree.getAttrValue('snmp-usm-user', *configEntryPath)
                securityEngineId = cfgTree.getAttrValue('snmp-security-engine-id', *configEntryPath,
                                                        **dict(default=None))
                if securityEngineId:
                    securityEngineId = rfc1902.OctetString(securityEngineId)

                log.info('new USM user %s, security-model %s, security-level %s, '
                         'security-name %s, security-engine-id %s' % (usmUser, securityModel, securityLevel,
                                                                      securityName, securityEngineId and securityEngineId.prettyPrint() or '<none>'))

                if securityLevel in (2, 3):
                    usmAuthProto = cfgTree.getAttrValue('snmp-usm-auth-protocol', *configEntryPath, **dict(default=config.usmHMACMD5AuthProtocol))
                    try:
                        usmAuthProto = authProtocols[usmAuthProto.upper()]
                    except KeyError:
                        pass
                    usmAuthProto = rfc1902.ObjectName(usmAuthProto)
                    usmAuthKey = cfgTree.getAttrValue('snmp-usm-auth-key', *configEntryPath)
                    log.info('new USM authentication key: %s, authentication protocol: %s' % (usmAuthKey, usmAuthProto))

                    if securityLevel == 3:
                        usmPrivProto = cfgTree.getAttrValue('snmp-usm-priv-protocol', *configEntryPath, **dict(default=config.usmDESPrivProtocol))
                        try:
                            usmPrivProto = privProtocols[usmPrivProto.upper()]
                        except KeyError:
                            pass
                        usmPrivProto = rfc1902.ObjectName(usmPrivProto)
                        usmPrivKey = cfgTree.getAttrValue('snmp-usm-priv-key', *configEntryPath, **dict(default=None))
                        log.info('new USM encryption key: %s, encryption protocol: %s' % (usmPrivKey, usmPrivProto))

                        config.addV3User(
                            snmpEngine, usmUser,
                            usmAuthProto, usmAuthKey,
                            usmPrivProto, usmPrivKey,
                            securityEngineId=securityEngineId
                        )

                    else:
                        config.addV3User(snmpEngine, usmUser,
                                         usmAuthProto, usmAuthKey,
                                         securityEngineId=securityEngineId)

                else:
                    config.addV3User(snmpEngine, usmUser,
                                     securityEngineId=securityEngineId)

                snmpEngineMap['securityName'][securityName] = securityModel

            configKey.append(securityModel)
            configKey.append(securityLevel)
            configKey.append(securityName)

        else:
            raise SnmpfwdError('unknown snmp-security-model: %s' % securityModel)

        configKey = tuple(configKey)
        if configKey in credIdMap:
            log.error('ambiguous configuration for key snmp-credentials-id=%s at %s' % (credId, '.'.join(configEntryPath)))
            return

        credIdMap[configKey] = credId

    duplicates = {}

    for peerCfgPath in cfgTree.getPathsToAttr('snmp-peer-id'):
        peerId = cfgTree.getAttrValue('snmp-peer-id', *peerCfgPath)
        if peerId in duplicates:
            log.error('duplicate snmp-peer-id=%s at %s and %s' % (peerId, '.'.join(peerCfgPath), '.'.join(duplicates[peerId])))
            return

        duplicates[peerId] = peerCfgPath

        log.info('configuring peer ID %s (at %s)...' % (peerId, '.'.join(peerCfgPath)))
        transportDomain = cfgTree.getAttrValue('snmp-transport-domain', *peerCfgPath)
        if transportDomain not in peerIdMap:
            peerIdMap[transportDomain] = []
        for peerAddress in cfgTree.getAttrValue('snmp-peer-address-pattern-list', *peerCfgPath, **dict(vector=True)):
            for bindAddress in cfgTree.getAttrValue('snmp-bind-address-pattern-list', *peerCfgPath, **dict(vector=True)):
                peerIdMap[transportDomain].append(
                    (re.compile(peerAddress+'#'+bindAddress), peerId)
                )

    def populate_routing(cfgTree):
        """Build fresh routing tables from `cfgTree` and atomically swap
        them into the live dicts/lists. Called once at startup and
        again on SIGHUP reload. Raises SnmpfwdError on any config error
        so the running proxy keeps its old routing on failure."""
        new_context = []
        new_content = []
        new_plugin = {}
        new_trunk = {}

        seen = {}
        for contextCfgPath in cfgTree.getPathsToAttr('snmp-context-id'):
            contextId = cfgTree.getAttrValue('snmp-context-id', *contextCfgPath)
            if contextId in seen:
                raise SnmpfwdError(
                    'duplicate snmp-context-id=%s at %s and %s'
                    % (contextId, '.'.join(contextCfgPath), '.'.join(seen[contextId]))
                )
            seen[contextId] = contextCfgPath

            k = '#'.join((
                cfgTree.getAttrValue('snmp-context-engine-id-pattern', *contextCfgPath),
                cfgTree.getAttrValue('snmp-context-name-pattern', *contextCfgPath),
            ))
            log.info('configuring context ID %s (at %s), composite key: %s'
                     % (contextId, '.'.join(contextCfgPath), k))
            new_context.append((contextId, re.compile(k)))

        seen = {}
        for contentCfgPath in cfgTree.getPathsToAttr('snmp-content-id'):
            contentId = cfgTree.getAttrValue('snmp-content-id', *contentCfgPath)
            if contentId in seen:
                raise SnmpfwdError(
                    'duplicate snmp-content-id=%s at %s and %s'
                    % (contentId, '.'.join(contentCfgPath), '.'.join(seen[contentId]))
                )
            seen[contentId] = contentCfgPath

            for x in cfgTree.getAttrValue('snmp-pdu-oid-prefix-pattern-list',
                                          *contentCfgPath, vector=True):
                k = '#'.join([
                    cfgTree.getAttrValue('snmp-pdu-type-pattern', *contentCfgPath), x,
                ])
                log.info('configuring content ID %s (at %s), composite key: %s'
                         % (contentId, '.'.join(contentCfgPath), k))
                new_content.append((contentId, re.compile(k)))

        for pluginCfgPath in cfgTree.getPathsToAttr('using-plugin-id-list'):
            pluginIdList = cfgTree.getAttrValue('using-plugin-id-list', *pluginCfgPath, vector=True)
            log.info('configuring plugin ID(s) %s (at %s)...' % (','.join(pluginIdList), '.'.join(pluginCfgPath)))
            for credId in cfgTree.getAttrValue('matching-snmp-credentials-id-list', *pluginCfgPath, vector=True):
                for peerId in cfgTree.getAttrValue('matching-snmp-peer-id-list', *pluginCfgPath, vector=True):
                    for contextId in cfgTree.getAttrValue('matching-snmp-context-id-list', *pluginCfgPath, vector=True):
                        for contentId in cfgTree.getAttrValue('matching-snmp-content-id-list', *pluginCfgPath, vector=True):
                            k = credId, contextId, peerId, contentId
                            if k in new_plugin:
                                raise SnmpfwdError(
                                    'duplicate snmp-credentials-id %s, snmp-context-id %s, '
                                    'snmp-peer-id %s, snmp-content-id %s at plugin-id(s) %s'
                                    % (credId, contextId, peerId, contentId, ','.join(pluginIdList))
                                )
                            log.info('configuring plugin(s) %s (at %s), composite key: %s'
                                     % (','.join(pluginIdList), '.'.join(pluginCfgPath), '/'.join(k)))
                            for pluginId in pluginIdList:
                                if not pluginManager.hasPlugin(pluginId):
                                    raise SnmpfwdError(
                                        'undefined plugin ID %s referenced at %s'
                                        % (pluginId, '.'.join(pluginCfgPath))
                                    )
                            new_plugin[k] = pluginIdList

        for routeCfgPath in cfgTree.getPathsToAttr('using-trunk-id-list'):
            trunkIdList = cfgTree.getAttrValue('using-trunk-id-list', *routeCfgPath, vector=True)
            log.info('configuring destination trunk ID(s) %s (at %s)...' % (','.join(trunkIdList), '.'.join(routeCfgPath)))
            for credId in cfgTree.getAttrValue('matching-snmp-credentials-id-list', *routeCfgPath, vector=True):
                for peerId in cfgTree.getAttrValue('matching-snmp-peer-id-list', *routeCfgPath, vector=True):
                    for contextId in cfgTree.getAttrValue('matching-snmp-context-id-list', *routeCfgPath, vector=True):
                        for contentId in cfgTree.getAttrValue('matching-snmp-content-id-list', *routeCfgPath, vector=True):
                            k = credId, contextId, peerId, contentId
                            if k in new_trunk:
                                raise SnmpfwdError(
                                    'duplicate snmp-credentials-id %s, snmp-context-id %s, '
                                    'snmp-peer-id %s, snmp-content-id %s at trunk-id(s) %s'
                                    % (credId, contextId, peerId, contentId, ','.join(trunkIdList))
                                )
                            new_trunk[k] = trunkIdList
                            log.info('configuring trunk routing to %s (at %s), composite key: %s'
                                     % (','.join(trunkIdList), '.'.join(routeCfgPath), '/'.join(k)))

        # Everything parsed cleanly — atomically swap into the live dicts
        # that observer closures hold references to.
        contextIdList.clear()
        contextIdList.extend(new_context)
        contentIdList.clear()
        contentIdList.extend(new_content)
        pluginIdMap.clear()
        pluginIdMap.update(new_plugin)
        trunkIdMap.clear()
        trunkIdMap.update(new_trunk)

    try:
        populate_routing(cfgTree)
    except SnmpfwdError:
        log.error(str(sys.exc_info()[1]))
        return

    def reload_callback():
        log.info('SIGHUP received; re-parsing %s' % args.config_file)
        new_cfg = bootstrap.load_config(args, PROGRAM_NAME, CONFIG_VERSION)
        # Plugins first: populate_routing validates routing against the
        # plugin set, so ordering lets a newly-added plugin be
        # referenced by new routing in the same reload.
        bootstrap.reload_plugin_manager(new_cfg, args, pluginManager)
        populate_routing(new_cfg)
        log.info('configuration plugins + routing reloaded from %s' % args.config_file)

    def dataCbFun(trunkId, msgId, msg):
        log.debug('message ID %s received from trunk %s' % (msgId, trunkId))

    trunkingManager = TrunkingManager(dataCbFun, transportDispatcher.loop)

    bootstrap.configure_trunks(cfgTree, trunkingManager)
    bootstrap.register_trunk_timers(transportDispatcher, trunkingManager)
    bootstrap.register_metrics_timer(transportDispatcher)
    bootstrap.start_metrics_agent(transportDispatcher)
    bootstrap.install_reload_handler(transportDispatcher, reload_callback)
    bootstrap.run_dispatcher_loop(args, transportDispatcher)


def main():
    """Entry point for both the console-script (`snmpfwd-server`) and
    direct `python -m` invocation. Wraps `_run()` so that:

    - graceful shutdown (run_dispatcher_loop raising KeyboardInterrupt)
      surfaces as rc=0;
    - any normal return from `_run()` means an error path was taken
      (the dispatcher loop never returns normally — it only raises)
      and becomes rc=1, not the rc=0 that `sys.exit(main())` would
      otherwise yield when main() returns None. Systemd-style process
      managers rely on the non-zero to decide whether to alert
      / restart, and snmpfwd used to exit 0 on every config error.
    """
    rc = 1
    try:
        _run()
    except KeyboardInterrupt:
        log.info('shutting down process...')
        rc = 0
    except Exception:
        for line in traceback.format_exception(*sys.exc_info()):
            log.error(line.replace('\n', ';'))
    log.info('process terminated')
    return rc


if __name__ == '__main__':
    sys.exit(main())
