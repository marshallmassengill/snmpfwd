#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
import os
import sys
from snmpfwd.plugins.status import *
from snmpfwd import log, error


class PluginManager(object):
    def __init__(self, path, progId, apiVer):
        self.__path = path
        self.__progId = progId
        self.__apiVer = apiVer
        self.__plugins = {}

    def hasPlugin(self, pluginId):
        return pluginId in self.__plugins

    def _exec_plugin(self, pluginModuleName, pluginOptions):
        """Locate `pluginModuleName` on the search path, exec it, and
        return the resulting module-globals dict. Raises
        SnmpfwdError if the module can't be found, fails to exec, or
        doesn't advertise a compatible hostProgs/apiVersions pair.

        Shared by loadPlugin (initial boot) and reload_from_config
        (SIGHUP reload) so both paths run through the same validation."""
        for pluginModulesDir in self.__path:
            log.info('scanning "%s" directory for plugin modules...' % pluginModulesDir)
            if not os.path.exists(pluginModulesDir):
                log.error('directory "%s" does not exist' % pluginModulesDir)
                continue

            modPath = os.path.join(pluginModulesDir, pluginModuleName + '.py')
            if not os.path.exists(modPath):
                log.error('Variation module "%s" not found' % modPath)
                continue

            ctx = {'modulePath': modPath,
                   'moduleContext': {},
                   'moduleOptions': pluginOptions}

            with open(modPath) as f:
                modData = f.read()

            try:
                exec(compile(modData, modPath, 'exec'), ctx)
            except Exception:
                raise error.SnmpfwdError(
                    'plugin module "%s" execution failure: %s'
                    % (modPath, sys.exc_info()[1])
                )

            try:
                if self.__progId not in ctx['hostProgs']:
                    log.error('ignoring plugin module "%s" (unmatched program ID)' % modPath)
                    continue
                if self.__apiVer not in ctx['apiVersions']:
                    log.error('ignoring plugin module "%s" (incompatible API version)' % modPath)
                    continue
            except KeyError:
                log.error('ignoring plugin module "%s" (missing versioning info)' % modPath)
                continue

            log.info('plugin module "%s" loaded' % modPath)
            return ctx

        raise error.SnmpfwdError(
            'plugin module "%s" not found in search path(s): %s'
            % (pluginModuleName, ', '.join(self.__path))
        )

    def loadPlugin(self, pluginId, pluginModuleName, pluginOptions):
        if pluginId in self.__plugins:
            raise error.SnmpfwdError('duplicate plugin ID %s' % pluginId)
        self.__plugins[pluginId] = self._exec_plugin(pluginModuleName, pluginOptions)

    def reload_from_config(self, plugin_specs):
        """Re-exec every plugin in `plugin_specs` (iterable of
        (pluginId, pluginModuleName, pluginOptions) triples) and
        atomically replace the registered plugin set.

        All-or-nothing: if ANY plugin fails to exec or validate, the
        existing plugin set is preserved and SnmpfwdError is raised
        with every failure rolled up into one message. Callers
        (typically the SIGHUP handler) can log and keep serving.

        The plugin search path is NOT re-read here — a changed
        `plugin-modules-path-list` requires a full restart.

        Plugin state carried in module globals (for example the
        logger plugin's per-path file-handler cache) is reset by the
        re-exec; old file handles are closed by GC once no in-flight
        request still references them."""
        new_plugins = {}
        errors = []
        for pluginId, pluginModuleName, pluginOptions in plugin_specs:
            if pluginId in new_plugins:
                errors.append('duplicate plugin ID %s' % pluginId)
                continue
            try:
                new_plugins[pluginId] = self._exec_plugin(
                    pluginModuleName, pluginOptions,
                )
            except error.SnmpfwdError as exc:
                errors.append('%s: %s' % (pluginId, exc))

        if errors:
            raise error.SnmpfwdError(
                'plugin reload failed, keeping previous plugin set (%s)'
                % '; '.join(errors)
            )

        self.__plugins = new_plugins

    def processCommandRequest(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processCommandRequest' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processCommandRequest']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)

    def processCommandResponse(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processCommandResponse' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processCommandResponse']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)

    def processNotificationRequest(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processNotificationRequest' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processNotificationRequest']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)

    def processNotificationResponse(self, pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx):
        if pluginId not in self.__plugins:
            log.error('skipping non-existing plugin %s' % pluginId)
            return NEXT, pdu

        if 'processNotificationResponse' not in self.__plugins[pluginId]:
            return NEXT, pdu

        plugin = self.__plugins[pluginId]['processNotificationResponse']

        return plugin(pluginId, snmpEngine, pdu, snmpReqInfo, reqCtx)
