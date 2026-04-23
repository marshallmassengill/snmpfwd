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
from pysnmp.entity.rfc3413 import config as lcd
from pysnmp.entity.rfc3413 import cmdgen, ntforg, context
from pysnmp.carrier.asyncio.dgram import udp
try:
    from pysnmp.carrier.asyncio.dgram import udp6
except ImportError:
    udp6 = None
# UNIX domain SNMP transport has no asyncio carrier equivalent.
unix = None
from pysnmp.proto import rfc1157, rfc1902, rfc1905, rfc3411
from pysnmp.proto.api import v2c
from snmpfwd import macro
from snmpfwd.error import SnmpfwdError
from snmpfwd import log, endpoint, bootstrap, target_override, metrics
from snmpfwd.plugins import status
from snmpfwd.trunking.manager import TrunkingManager
from snmpfwd.lazylog import LazyLogString

# Settings
PROGRAM_NAME = 'snmpfwd-client'
CONFIG_FILE = '/usr/local/etc/snmpfwd/client.cfg'
CONFIG_VERSION = '2'
PLUGIN_API_VERSION = 2

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


def main():

    class LogString(LazyLogString):

        GROUPINGS = [
            ['callflow-id'],
            ['trunk-id'],
            ['server-snmp-engine-id',
             'server-snmp-transport-domain',
             'server-snmp-peer-address',
             'server-snmp-peer-port',
             'server-snmp-bind-address',
             'server-snmp-bind-port',
             'server-snmp-security-model',
             'server-snmp-security-level',
             'server-snmp-security-name',
             'server-snmp-context-engine-id',
             'server-snmp-context-name',
             'server-snmp-pdu',
             'server-snmp-entity-id'],
            ['server-snmp-credentials-id',
             'server-snmp-context-id',
             'server-snmp-content-id',
             'server-snmp-peer-id',
             'server-classification-id'],
            ['snmp-peer-id',
             'snmp-bind-address',
             'snmp-bind-port',
             'snmp-peer-address',
             'snmp-peer-port',
             'snmp-context-engine-id',
             'snmp-context-name',
             'snmp-pdu'],
        ]

        FORMATTERS = {
            'server-snmp-pdu': LazyLogString.prettyVarBinds,
            'snmp-pdu': LazyLogString.prettyVarBinds,
        }

    def snmpCbFun(snmpEngine, sendRequestHandle, errorIndication, rspPDU, cbCtx):

        trunkId, msgId, trunkReq, pluginIdList, reqCtx = cbCtx

        trunkRsp = {
            'callflow-id': trunkReq['callflow-id'],
            'snmp-pdu': rspPDU,
        }

        logCtx = LogString(trunkRsp)

        if errorIndication:
            log.info('received SNMP error-indication "%s"' % errorIndication, ctx=logCtx)
            trunkRsp['error-indication'] = errorIndication
            metrics.increment(metrics.CLIENT_SNMP_ERRORS)

        if rspPDU:
            reqPdu = trunkReq['server-snmp-pdu']

            for pluginId in pluginIdList:
                if reqPdu.tagSet in rfc3411.NOTIFICATION_CLASS_PDUS:
                    st, rspPDU = pluginManager.processNotificationResponse(
                        pluginId, snmpEngine, rspPDU, trunkReq, reqCtx
                    )

                elif reqPdu.tagSet not in rfc3411.UNCONFIRMED_CLASS_PDUS:
                    st, rspPDU = pluginManager.processCommandResponse(
                        pluginId, snmpEngine, rspPDU, trunkReq, reqCtx
                    )
                else:
                    log.error('ignoring unsupported PDU', ctx=logCtx)
                    break

                if st == status.BREAK:
                    log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                    break

                elif st == status.DROP:
                    log.debug('received SNMP %s, plugin %s muted response' % (errorIndication and 'error' or 'response', pluginId), ctx=logCtx)
                    trunkRsp['snmp-pdu'] = None
                    break

        try:
            trunkingManager.sendRsp(trunkId, msgId, trunkRsp)

        except SnmpfwdError:
            log.error('received SNMP %s message, trunk message not sent "%s"' % (msgId, sys.exc_info()[1]), ctx=logCtx)
            return

        log.debug('received SNMP %s message, forwarded as trunk message #%s' % (errorIndication and 'error' or 'response', msgId), ctx=logCtx)

    # Patch pysnmp so we can rewrite the target bind/peer address per
    # outbound request (transparent-proxy / virtual-interface modes).
    # See snmpfwd.target_override for the mechanism.
    lcd.get_target_address, updateEndpoints = target_override.make_target_addr_override(
        lcd.get_target_address
    )

    def trunkCbFun(trunkId, msgId, trunkReq):

        for key in tuple(trunkReq):
            if key != 'callflow-id':
                trunkReq['server-' + key] = trunkReq[key]
                del trunkReq[key]

        trunkReq['trunk-id'] = trunkId

        # Use prettyPrint() for binary OctetStrings (engine ids, security
        # names, etc.) so regex matching is not foiled by raw bytes that
        # contain characters like 0x0a. See the matching comment in
        # snmpfwdserver.py's requestObserver.
        def _text(x):
            return x.prettyPrint() if hasattr(x, 'prettyPrint') else str(x)
        k = [_text(x) for x in (trunkReq['server-snmp-engine-id'],
                                trunkReq['server-snmp-transport-domain'],
                                trunkReq['server-snmp-peer-address'] + ':' + str(trunkReq['server-snmp-peer-port']),
                                trunkReq['server-snmp-bind-address'] + ':' + str(trunkReq['server-snmp-bind-port']),
                                trunkReq['server-snmp-security-model'],
                                trunkReq['server-snmp-security-level'],
                                trunkReq['server-snmp-security-name'],
                                trunkReq['server-snmp-context-engine-id'],
                                trunkReq['server-snmp-context-name'])]

        k.append(snmpPduTypesMap.get(trunkReq['server-snmp-pdu'].tagSet, '?'))
        k.append('|'.join([str(x[0]) for x in v2c.apiPDU.get_varbinds(trunkReq['server-snmp-pdu'])]))
        k = '#'.join(k)

        for x, y in origCredIdList:
            if y.match(k):
                origPeerId = trunkReq['server-snmp-entity-id'] = macro.expandMacro(x, trunkReq)
                break
        else:
            origPeerId = None

        k = [str(x) for x in (trunkReq['server-snmp-credentials-id'],
                              trunkReq['server-snmp-context-id'],
                              trunkReq['server-snmp-content-id'],
                              trunkReq['server-snmp-peer-id'])]
        k = '#'.join(k)

        for x, y in srvClassIdList:
            if y.match(k):
                srvClassId = trunkReq['server-classification-id'] = macro.expandMacro(x, trunkReq)
                break
        else:
            srvClassId = None


        logCtx = LogString(trunkReq)

        errorIndication = None

        peerIdList = routingMap.get((origPeerId, srvClassId, macro.expandMacro(trunkId, trunkReq)))
        if not peerIdList:
            log.error('unroutable trunk message #%s' % msgId, ctx=logCtx)
            metrics.increment(metrics.CLIENT_TRUNK_UNROUTABLE)
            errorIndication = 'no route to SNMP peer configured'

        cbCtx = trunkId, msgId, trunkReq, (), {}

        if errorIndication:
            snmpCbFun(None, None, errorIndication, None, cbCtx)
            return

        pluginIdList = pluginIdMap.get((origPeerId, srvClassId, macro.expandMacro(trunkId, trunkReq)))
        for peerId in peerIdList:
            peerId = macro.expandMacro(peerId, trunkReq)

            trunkReqCopy = trunkReq.copy()

            (snmpEngine,
             contextEngineId,
             contextName,
             bindAddr,
             bindAddrMacro,
             peerAddr,
             peerAddrMacro) = peerIdMap[peerId]

            if bindAddrMacro:
                bindAddr = macro.expandMacro(bindAddrMacro, trunkReqCopy), 0

            if peerAddrMacro:
                peerAddr = macro.expandMacro(peerAddrMacro, trunkReqCopy), 161

            if bindAddr and peerAddr:
                updateEndpoints(bindAddr, peerAddr)

            trunkReqCopy['snmp-peer-id'] = peerId

            trunkReqCopy['snmp-context-engine-id'] = contextEngineId
            trunkReqCopy['snmp-context-name'] = contextName

            trunkReqCopy['snmp-bind-address'], trunkReqCopy['snmp-bind-port'] = bindAddr
            trunkReqCopy['snmp-peer-address'], trunkReqCopy['snmp-peer-port'] = peerAddr

            logCtx.update(trunkReqCopy)

            pdu = trunkReqCopy['server-snmp-pdu']

            if pluginIdList:
                reqCtx = {}

                cbCtx = trunkId, msgId, trunkReqCopy, pluginIdList, reqCtx

                for pluginNum, pluginId in enumerate(pluginIdList):

                    if pdu.tagSet in rfc3411.NOTIFICATION_CLASS_PDUS:
                        st, pdu = pluginManager.processNotificationRequest(
                            pluginId, snmpEngine, pdu, trunkReqCopy, reqCtx
                        )

                    elif pdu.tagSet not in rfc3411.UNCONFIRMED_CLASS_PDUS:
                        st, pdu = pluginManager.processCommandRequest(
                            pluginId, snmpEngine, pdu, trunkReqCopy, reqCtx
                        )

                    else:
                        log.error('ignoring unsupported PDU', ctx=logCtx)
                        break

                    if st == status.BREAK:
                        log.debug('plugin %s inhibits other plugins' % pluginId, ctx=logCtx)
                        cbCtx = trunkId, msgId, trunkReqCopy, pluginIdList[:pluginNum], reqCtx
                        break

                    elif st == status.DROP:
                        log.debug('received trunk message #%s, plugin %s muted request' % (msgId, pluginId), ctx=logCtx)
                        snmpCbFun(snmpEngine, None, None, None, cbCtx)
                        return

                    elif st == status.RESPOND:
                        log.debug('received trunk message #%s, plugin %s forced immediate response' % (msgId, pluginId), ctx=logCtx)
                        snmpCbFun(snmpEngine, None, None, pdu, cbCtx)
                        return

            snmpMessageSent = False

            if pdu.tagSet in rfc3411.NOTIFICATION_CLASS_PDUS:
                if pdu.tagSet in rfc3411.UNCONFIRMED_CLASS_PDUS:
                    try:
                        notificationOriginator.send_pdu(
                            snmpEngine,
                            peerId,
                            macro.expandMacro(contextEngineId, trunkReq),
                            macro.expandMacro(contextName, trunkReq),
                            pdu
                        )

                        snmpMessageSent = True

                    except PySnmpError:
                        errorIndication = 'failure sending SNMP notification'
                        log.error('trunk message #%s, SNMP error: %s' % (msgId, sys.exc_info()[1]), ctx=logCtx)

                    else:
                        errorIndication = None

                    # respond to trunk right away
                    snmpCbFun(snmpEngine, None, errorIndication, None, cbCtx)

                else:
                    try:
                        notificationOriginator.send_pdu(
                            snmpEngine,
                            peerId,
                            macro.expandMacro(contextEngineId, trunkReq),
                            macro.expandMacro(contextName, trunkReq),
                            pdu,
                            snmpCbFun,
                            cbCtx
                        )

                        snmpMessageSent = True

                    except PySnmpError:
                        log.error('trunk message #%s, SNMP error: %s' % (msgId, sys.exc_info()[1]), ctx=logCtx)

            elif pdu.tagSet not in rfc3411.UNCONFIRMED_CLASS_PDUS:
                try:
                    commandGenerator.send_pdu(
                        snmpEngine,
                        peerId,
                        macro.expandMacro(contextEngineId, trunkReq),
                        macro.expandMacro(contextName, trunkReq),
                        pdu,
                        snmpCbFun,
                        cbCtx
                    )

                    snmpMessageSent = True

                except PySnmpError:
                    errorIndication = 'failure sending SNMP command'
                    log.error('trunk message #%s, SNMP error: %s' % (msgId, sys.exc_info()[1]), ctx=logCtx)

                    # respond to trunk right away
                    snmpCbFun(snmpEngine, None, errorIndication, None, cbCtx)

            else:
                log.error('ignoring unsupported PDU', ctx=logCtx)

            if snmpMessageSent:
                log.debug('received trunk message #%s, forwarded as SNMP message' % msgId, ctx=logCtx)

    #
    # Main script body starts here
    #

    try:
        args = bootstrap.bootstrap_cli_and_logging(
            program_name=PROGRAM_NAME,
            default_config_file=CONFIG_FILE,
            synopsis=(
                'SNMP Proxy Forwarder: client part. Receives SNMP PDUs via one '
                "or many encrypted trunks established with the Forwarder's "
                'Agent part(s) running elsewhere and routes PDUs to built-in '
                'SNMP Managers for further transmission towards SNMP Agents. '
                'Can implement complex routing and protocol conversion logic '
                'through analyzing parts of SNMP messages and matching them '
                'against proxying rules.'
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

    #
    # SNMPv3 CommandGenerator & NotificationOriginator implementation
    #

    origCredIdList = []
    srvClassIdList = []
    peerIdMap = {}
    pluginIdMap = {}
    routingMap = {}
    engineIdMap = {}

    commandGenerator = cmdgen.CommandGenerator()

    notificationOriginator = ntforg.NotificationOriginator()

    transportDispatcher = bootstrap.build_transport_dispatcher()

    try:
        pluginManager = bootstrap.build_plugin_manager(
            cfgTree, args, PROGRAM_NAME, PLUGIN_API_VERSION,
        )
    except SnmpfwdError:
        return

    for peerEntryPath in cfgTree.getPathsToAttr('snmp-peer-id'):
        peerId = cfgTree.getAttrValue('snmp-peer-id', *peerEntryPath)
        if peerId in peerIdMap:
            log.error('duplicate snmp-peer-id=%s at %s' % (peerId, '.'.join(peerEntryPath)))
            return

        log.info('configuring SNMP peer %s (at %s)...' % (peerId, '.'.join(peerEntryPath)))

        engineId = cfgTree.getAttrValue('snmp-engine-id', *peerEntryPath)
        if engineId in engineIdMap:
            snmpEngine, snmpContext, snmpEngineMap = engineIdMap[engineId]
            log.info('using engine-id: %s' % snmpEngine.snmpEngineID.prettyPrint())
        else:
            snmpEngine = engine.SnmpEngine(snmpEngineID=engineId)
            snmpContext = context.SnmpContext(snmpEngine)
            snmpEngineMap = {
                'transportDomain': {},
                'securityName': {},
                'credIds': set()
            }

            engineIdMap[engineId] = snmpEngine, snmpContext, snmpEngineMap

            log.info('new engine-id %s' % snmpEngine.snmpEngineID.prettyPrint())

        transportDomain = cfgTree.getAttrValue('snmp-transport-domain', *peerEntryPath)
        transportDomain = rfc1902.ObjectName(str(transportDomain))

        if (transportDomain[:len(udp.domainName)] != udp.domainName and
                udp6 and transportDomain[:len(udp6.domainName)] != udp6.domainName):
            log.error('unknown transport domain %s' % (transportDomain,))
            return

        transportOptions = cfgTree.getAttrValue('snmp-transport-options', *peerEntryPath,
                                                **dict(default=[], vector=True))

        bindAddr = cfgTree.getAttrValue('snmp-bind-address', *peerEntryPath)

        try:
            bindAddr, bindAddrMacro = endpoint.parseTransportAddress(transportDomain, bindAddr,
                                                                     transportOptions)

        except SnmpfwdError:
            log.error('bad snmp-bind-address specification %s at %s' % (bindAddr, '.'.join(peerEntryPath)))
            return

        if transportDomain in snmpEngineMap['transportDomain']:
            log.info('using transport endpoint with transport ID %s' % (transportDomain,))

        else:
            if transportDomain[:len(udp.domainName)] == udp.domainName:
                transport = udp.UdpTransport(loop=transportDispatcher.loop)
            else:
                transport = udp6.Udp6Transport(loop=transportDispatcher.loop)

            snmpEngine.register_transport_dispatcher(
                transportDispatcher, transportDomain
            )

            t = transport.openClientMode(bindAddr)

            if 'transparent-proxy' in transportOptions:
                t.enablePktInfo()
                t.enableTransparent()
            elif 'virtual-interface' in transportOptions:
                t.enablePktInfo()

            config.addSocketTransport(snmpEngine, transportDomain, t)

            snmpEngineMap['transportDomain'][transportDomain] = bindAddr[0], bindAddr[1], transportDomain
            log.info('new transport endpoint at bind address [%s]:%s, options %s, transport ID %s' % (bindAddr[0], bindAddr[1], transportOptions and '/'.join(transportOptions) or '<none>', transportDomain))

        securityModel = cfgTree.getAttrValue('snmp-security-model', *peerEntryPath)
        securityModel = rfc1902.Integer(securityModel)
        securityLevel = cfgTree.getAttrValue('snmp-security-level', *peerEntryPath)
        securityLevel = rfc1902.Integer(securityLevel)
        securityName = cfgTree.getAttrValue('snmp-security-name', *peerEntryPath)

        contextEngineId = cfgTree.getAttrValue('snmp-context-engine-id', *peerEntryPath, **dict(default=None))
        contextName = cfgTree.getAttrValue('snmp-context-name', *peerEntryPath, **dict(default=''))

        if securityModel in (1, 2):
            if securityName in snmpEngineMap['securityName']:
                if snmpEngineMap['securityName'][securityName] == securityModel:
                    log.info('using security-name %s' % securityName)
                else:
                    log.error('security-name %s already in use at security-model %s' % (securityName, securityModel))
                    return
            else:
                communityName = cfgTree.getAttrValue('snmp-community-name', *peerEntryPath)
                config.addV1System(snmpEngine, securityName, communityName,
                                   securityName=securityName)

                log.info('new community-name %s, security-model %s, security-name %s, security-level %s' % (communityName, securityModel, securityName, securityLevel))
                snmpEngineMap['securityName'][securityName] = securityModel

        elif securityModel == 3:
            if securityName in snmpEngineMap['securityName']:
                if snmpEngineMap['securityName'][securityName] == securityModel:
                    log.info('using USM security-name: %s' % securityName)
                else:
                    raise SnmpfwdError('security-name %s already in use at security-model %s' % (securityName, securityModel))
            else:
                usmUser = cfgTree.getAttrValue('snmp-usm-user', *peerEntryPath)
                securityEngineId = cfgTree.getAttrValue('snmp-security-engine-id', *peerEntryPath,
                                                        **dict(default=None))
                if securityEngineId:
                    securityEngineId = rfc1902.OctetString(securityEngineId)

                log.info('new USM user %s, security-model %s, security-level %s, '
                         'security-name %s, security-engine-id %s' % (usmUser, securityModel, securityLevel,
                                                                      securityName, securityEngineId and securityEngineId.prettyPrint() or '<none>'))

                if securityLevel in (2, 3):
                    usmAuthProto = cfgTree.getAttrValue('snmp-usm-auth-protocol', *peerEntryPath, **dict(default=config.usmHMACMD5AuthProtocol))
                    try:
                        usmAuthProto = authProtocols[usmAuthProto.upper()]
                    except KeyError:
                        pass
                    usmAuthProto = rfc1902.ObjectName(usmAuthProto)
                    usmAuthKey = cfgTree.getAttrValue('snmp-usm-auth-key', *peerEntryPath)
                    log.info('new USM authentication key: %s, authentication protocol: %s' % (usmAuthKey, usmAuthProto))

                    if securityLevel == 3:
                        usmPrivProto = cfgTree.getAttrValue('snmp-usm-priv-protocol', *peerEntryPath, **dict(default=config.usmDESPrivProtocol))
                        try:
                            usmPrivProto = privProtocols[usmPrivProto.upper()]
                        except KeyError:
                            pass
                        usmPrivProto = rfc1902.ObjectName(usmPrivProto)
                        usmPrivKey = cfgTree.getAttrValue('snmp-usm-priv-key', *peerEntryPath, **dict(default=None))
                        log.info('new USM encryption key: %s, encryption protocol: %s' % (usmPrivKey, usmPrivProto))

                        config.addV3User(
                            snmpEngine, usmUser,
                            usmAuthProto, usmAuthKey,
                            usmPrivProto, usmPrivKey,
                        )

                    else:
                        config.addV3User(snmpEngine, usmUser,
                                         usmAuthProto, usmAuthKey,
                                         securityEngineId=securityEngineId)

                else:
                    config.addV3User(snmpEngine, usmUser, securityEngineId=securityEngineId)

                snmpEngineMap['securityName'][securityName] = securityModel

        else:
            log.error('unknown security-model: %s' % securityModel)
            sys.exit(1)

        credId = '/'.join([str(x) for x in (securityName, securityLevel, securityModel)])
        if credId in snmpEngineMap['credIds']:
            log.info('using credentials ID %s...' % credId)
        else:
            config.addTargetParams(
                snmpEngine, credId, securityName, securityLevel,
                securityModel == 3 and 3 or securityModel-1
            )
            log.info('new credentials %s, security-name %s, security-level %s, security-model %s' % (credId, securityName, securityLevel, securityModel))
            snmpEngineMap['credIds'].add(credId)

        peerAddr = cfgTree.getAttrValue('snmp-peer-address', *peerEntryPath)

        try:
            peerAddr, peerAddrMacro = endpoint.parseTransportAddress(transportDomain, peerAddr,
                                                                     transportOptions, defaultPort=161)

        except SnmpfwdError:
            log.error('bad snmp-peer-address specification %s at %s' % (peerAddr, '.'.join(peerEntryPath)))
            return

        timeout = cfgTree.getAttrValue('snmp-peer-timeout', *peerEntryPath)
        retries = cfgTree.getAttrValue('snmp-peer-retries', *peerEntryPath)

        config.addTargetAddr(
            snmpEngine, peerId, transportDomain, peerAddr, credId, timeout, retries
        )

        peerIdMap[peerId] = snmpEngine, contextEngineId, contextName, bindAddr, bindAddrMacro, peerAddr, peerAddrMacro

        log.info('new peer ID %s, bind address %s, peer address %s, timeout %s*0.01 secs, retries %s, credentials ID %s' % (peerId, bindAddrMacro or '<default>', peerAddrMacro or '%s:%s' % peerAddr, timeout, retries, credId))

    duplicates = {}

    for origCredCfgPath in cfgTree.getPathsToAttr('server-snmp-entity-id'):
        origCredId = cfgTree.getAttrValue('server-snmp-entity-id', *origCredCfgPath)
        if origCredId in duplicates:
            log.error('duplicate server-snmp-entity-id=%s at %s and %s' % (origCredId, '.'.join(origCredCfgPath), '.'.join(duplicates[origCredId])))
            return

        duplicates[origCredId] = origCredCfgPath

        k = '#'.join(
            (cfgTree.getAttrValue('server-snmp-engine-id-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-transport-domain-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-peer-address-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-bind-address-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-security-model-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-security-level-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-security-name-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-context-engine-id-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-context-name-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-pdu-type-pattern', *origCredCfgPath),
             cfgTree.getAttrValue('server-snmp-oid-prefix-pattern', *origCredCfgPath))
        )

        log.info('configuring server SNMP entity ID %s (at %s), composite key: %s' % (origCredId, '.'.join(origCredCfgPath), k))

        origCredIdList.append((origCredId, re.compile(k)))

    duplicates = {}

    for srvClassCfgPath in cfgTree.getPathsToAttr('server-classification-id'):
        srvClassId = cfgTree.getAttrValue('server-classification-id', *srvClassCfgPath)
        if srvClassId in duplicates:
            log.error('duplicate server-classification-id=%s at %s and %s' % (srvClassId, '.'.join(srvClassCfgPath), '.'.join(duplicates[srvClassId])))
            return

        duplicates[srvClassId] = srvClassCfgPath

        k = '#'.join(
            (cfgTree.getAttrValue('server-snmp-credentials-id-pattern', *srvClassCfgPath),
             cfgTree.getAttrValue('server-snmp-context-id-pattern', *srvClassCfgPath),
             cfgTree.getAttrValue('server-snmp-content-id-pattern', *srvClassCfgPath),
             cfgTree.getAttrValue('server-snmp-peer-id-pattern', *srvClassCfgPath))
        )

        log.info('configuring server classification ID %s (at %s), composite key: %s' % (srvClassId, '.'.join(srvClassCfgPath), k))

        srvClassIdList.append((srvClassId, re.compile(k)))

    del duplicates

    def populate_routing(cfgTree):
        """Build fresh plugin-routing and peer-routing tables from cfgTree
        and atomically swap them into the live dicts. Called once at
        startup and again on SIGHUP reload. Raises SnmpfwdError on any
        config error so the running proxy keeps its old routing on
        failure."""
        new_plugin = {}
        new_routing = {}

        for pluginCfgPath in cfgTree.getPathsToAttr('using-plugin-id-list'):
            pluginIdList = cfgTree.getAttrValue('using-plugin-id-list', *pluginCfgPath, vector=True)
            log.info('configuring plugin ID(s) %s (at %s)...' % (','.join(pluginIdList), '.'.join(pluginCfgPath)))
            for credId in cfgTree.getAttrValue('matching-server-snmp-entity-id-list', *pluginCfgPath, vector=True):
                for srvClassId in cfgTree.getAttrValue('matching-server-classification-id-list', *pluginCfgPath, vector=True):
                    for trunkId in cfgTree.getAttrValue('matching-trunk-id-list', *pluginCfgPath, vector=True):
                        k = credId, srvClassId, trunkId
                        if k in new_plugin:
                            raise SnmpfwdError(
                                'duplicate snmp-credentials-id=%s and '
                                'server-classification-id=%s and trunk-id=%s at plugin-id %s'
                                % (credId, srvClassId, trunkId, ','.join(pluginIdList))
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

        for routeCfgPath in cfgTree.getPathsToAttr('using-snmp-peer-id-list'):
            peerIdList = cfgTree.getAttrValue('using-snmp-peer-id-list', *routeCfgPath, vector=True)
            log.info('configuring routing entry with peer IDs %s (at %s)...' % (','.join(peerIdList), '.'.join(routeCfgPath)))
            for credId in cfgTree.getAttrValue('matching-server-snmp-entity-id-list', *routeCfgPath, vector=True):
                for srvClassId in cfgTree.getAttrValue('matching-server-classification-id-list', *routeCfgPath, vector=True):
                    for trunkId in cfgTree.getAttrValue('matching-trunk-id-list', *routeCfgPath, vector=True):
                        k = credId, srvClassId, trunkId
                        if k in new_routing:
                            raise SnmpfwdError(
                                'duplicate snmp-credentials-id=%s and '
                                'server-classification-id=%s and trunk-id=%s at snmp-peer-id %s'
                                % (credId, srvClassId, trunkId, ','.join(peerIdList))
                            )
                        for peerId in peerIdList:
                            if peerId not in peerIdMap:
                                raise SnmpfwdError(
                                    'missing peer-id %s at %s'
                                    % (peerId, '.'.join(routeCfgPath))
                                )
                        new_routing[k] = peerIdList

        # Atomically swap into the live dicts captured by trunkCbFun / snmpCbFun.
        pluginIdMap.clear()
        pluginIdMap.update(new_plugin)
        routingMap.clear()
        routingMap.update(new_routing)

    try:
        populate_routing(cfgTree)
    except SnmpfwdError:
        log.error(str(sys.exc_info()[1]))
        return

    def reload_callback():
        log.info('SIGHUP received; re-parsing %s' % args.config_file)
        new_cfg = bootstrap.load_config(args, PROGRAM_NAME, CONFIG_VERSION)
        bootstrap.reload_plugin_manager(new_cfg, args, pluginManager)
        populate_routing(new_cfg)
        log.info('configuration plugins + routing reloaded from %s' % args.config_file)

    trunkingManager = TrunkingManager(trunkCbFun, transportDispatcher.loop)

    bootstrap.configure_trunks(cfgTree, trunkingManager)
    bootstrap.register_trunk_timers(transportDispatcher, trunkingManager)
    bootstrap.register_metrics_timer(transportDispatcher)
    bootstrap.start_metrics_agent(transportDispatcher)
    bootstrap.install_reload_handler(transportDispatcher, reload_callback)
    bootstrap.run_dispatcher_loop(args, transportDispatcher)


if __name__ == '__main__':
    rc = 1

    try:
        main()

    except KeyboardInterrupt:
        log.info('shutting down process...')
        rc = 0

    except Exception:
        for line in traceback.format_exception(*sys.exc_info()):
            log.error(line.replace('\n', ';'))

    log.info('process terminated')

    sys.exit(rc)
