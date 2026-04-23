#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
"""Shared startup scaffolding used by snmpfwd-server and snmpfwd-client.

The two entry points historically had ~900-line main() functions with
80%+ overlapping setup logic. This module factors out the program-neutral
pieces — CLI + logging, config load, plugin manager init, transport
dispatcher construction, trunk configuration, daemonize + main loop —
so each script's main() focuses on the SNMP-engine / routing logic that
actually differs between the two.

The general flow a script follows is:

    def main():
        args = bootstrap.bootstrap_cli_and_logging(program_name=..., ...)
        cfgTree = bootstrap.load_config(args, program_name, config_version)
        random.seed()
        pluginManager = bootstrap.build_plugin_manager(cfgTree, args, ...)
        transportDispatcher = bootstrap.build_transport_dispatcher()

        # ... program-specific: SNMP engines, credentials, routing ...

        trunkingManager = TrunkingManager(dataCbFun, transportDispatcher.loop)
        bootstrap.configure_trunks(cfgTree, trunkingManager)
        bootstrap.register_trunk_timers(transportDispatcher, trunkingManager)
        bootstrap.run_dispatcher_loop(args, transportDispatcher)
"""
from __future__ import annotations

import os
import random
import signal
import socket
import sys
from typing import TYPE_CHECKING, Optional

from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.error import PySnmpError

from snmpfwd import cli, cparser, daemon, log, macro
from snmpfwd.error import SnmpfwdError
from snmpfwd.plugins.manager import PluginManager
from snmpfwd.trunking.endpoint import parseTrunkEndpoint

if TYPE_CHECKING:
    import argparse
    from snmpfwd.trunking.manager import TrunkingManager


def bootstrap_cli_and_logging(
    *,
    program_name: str,
    default_config_file: str,
    synopsis: str,
) -> "argparse.Namespace":
    """Parse CLI args, apply --debug-* flags, configure the logger, and
    apply --log-level. Logger setup runs under dropped process
    privileges — matches the behaviour of the pre-refactor script."""
    parser = cli.build_parser(
        prog_name=program_name,
        default_config_file=default_config_file,
        synopsis=synopsis,
    )
    args = parser.parse_args()
    cli.apply_debug_flags(args, program_name)

    logging_methods = args.logging_method or ['stderr']
    with daemon.PrivilegesOf(args.process_user, args.process_group):
        try:
            for i, spec in enumerate(logging_methods):
                # force=True on the first spec clears the default NullHandler
                # (and any stale handlers from a previous setLogger call);
                # subsequent specs append their sink alongside.
                log.setLogger(program_name, *spec.split(':'), force=(i == 0))
            if args.log_level:
                log.setLevel(args.log_level)
        except SnmpfwdError:
            sys.stderr.write('%s\r\n' % sys.exc_info()[1])
            raise

    return args


def load_config(
    args: "argparse.Namespace",
    program_name: str,
    config_version: str,
) -> cparser.Config:
    """Load the config file, verify program-name / config-version match,
    and return the parsed tree. Raises SnmpfwdError on any mismatch."""
    try:
        cfgTree = cparser.Config().load(args.config_file)
    except SnmpfwdError:
        log.error('configuration parsing error: %s' % sys.exc_info()[1])
        raise

    if cfgTree.getAttrValue('program-name', '', default=None) != program_name:
        msg = ('config file %s does not match program name %s'
               % (args.config_file, program_name))
        log.error(msg)
        raise SnmpfwdError(msg)

    if cfgTree.getAttrValue('config-version', '', default=None) != config_version:
        msg = ('config file %s version is not compatible with program version %s'
               % (args.config_file, config_version))
        log.error(msg)
        raise SnmpfwdError(msg)

    return cfgTree


def build_plugin_manager(
    cfgTree: cparser.Config,
    args: "argparse.Namespace",
    program_name: str,
    plugin_api_version: int,
) -> PluginManager:
    """Build a PluginManager from the plugin-modules-path-list in the
    config and populate it by executing each plugin-id block under
    dropped privileges."""
    pluginManager = PluginManager(
        macro.expandMacros(
            cfgTree.getAttrValue('plugin-modules-path-list', '',
                                 default=[], vector=True),
            {'config-dir': os.path.dirname(args.config_file)},
        ),
        progId=program_name,
        apiVer=plugin_api_version,
    )

    for pluginCfgPath in cfgTree.getPathsToAttr('plugin-id'):
        pluginId = cfgTree.getAttrValue('plugin-id', *pluginCfgPath)
        pluginMod = cfgTree.getAttrValue('plugin-module', *pluginCfgPath)
        pluginOptions = macro.expandMacros(
            cfgTree.getAttrValue('plugin-options', *pluginCfgPath,
                                 default=[], vector=True),
            {'config-dir': os.path.dirname(args.config_file)},
        )

        log.info(
            'configuring plugin ID %s (at %s) from module %s with options %s...' %
            (pluginId, '.'.join(pluginCfgPath), pluginMod,
             ', '.join(pluginOptions) or '<none>')
        )

        with daemon.PrivilegesOf(args.process_user, args.process_group):
            try:
                pluginManager.loadPlugin(pluginId, pluginMod, pluginOptions)
            except SnmpfwdError:
                log.error('plugin %s not loaded: %s'
                          % (pluginId, sys.exc_info()[1]))
                raise

    return pluginManager


def build_transport_dispatcher() -> AsyncioDispatcher:
    """Construct an AsyncioDispatcher and wire its routing callback. The
    routing callback returns the transport-domain as the recv-callable
    key — preserves the pysnmp-4 convention that snmpfwd has always
    used."""
    transportDispatcher = AsyncioDispatcher()
    transportDispatcher.register_routing_callback(lambda td, t, d: td)
    return transportDispatcher


def configure_trunks(
    cfgTree: cparser.Config,
    trunkingManager: "TrunkingManager",
) -> None:
    """Walk each `trunk-id` config block and register it with the
    trunking manager as either a client or a server side."""
    for trunkCfgPath in cfgTree.getPathsToAttr('trunk-id'):
        trunkId = cfgTree.getAttrValue('trunk-id', *trunkCfgPath)
        secret = cfgTree.getAttrValue('trunk-crypto-key', *trunkCfgPath,
                                      default='')
        # Repeat the key up to (and truncate at) 16 bytes — matches the
        # AES-128 block size used in snmpfwd.trunking.crypto.
        secret = secret and (secret * ((16 // len(secret)) + 1))[:16]
        log.info('configuring trunk ID %s (at %s)...'
                 % (trunkId, '.'.join(trunkCfgPath)))
        connectionMode = cfgTree.getAttrValue('trunk-connection-mode',
                                              *trunkCfgPath)
        ping_period = cfgTree.getAttrValue('trunk-ping-period', *trunkCfgPath,
                                           default=0, expect=int)

        if connectionMode == 'client':
            trunkingManager.addClient(
                trunkId,
                parseTrunkEndpoint(cfgTree.getAttrValue('trunk-bind-address',
                                                       *trunkCfgPath)),
                parseTrunkEndpoint(cfgTree.getAttrValue('trunk-peer-address',
                                                       *trunkCfgPath), 30201),
                ping_period,
                secret,
            )
            log.info('new trunking client from %s to %s' % (
                cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath),
                cfgTree.getAttrValue('trunk-peer-address', *trunkCfgPath),
            ))
        elif connectionMode == 'server':
            trunkingManager.addServer(
                parseTrunkEndpoint(cfgTree.getAttrValue('trunk-bind-address',
                                                       *trunkCfgPath), 30201),
                ping_period,
                secret,
            )
            log.info('new trunking server at %s'
                     % cfgTree.getAttrValue('trunk-bind-address', *trunkCfgPath))


def register_trunk_timers(
    transportDispatcher: AsyncioDispatcher,
    trunkingManager: "TrunkingManager",
) -> None:
    """Wire TrunkingManager's periodic setup/monitor callbacks into the
    dispatcher's timer. Random intervals avoid all timers firing on the
    same tick."""
    transportDispatcher.register_timer_callback(
        trunkingManager.setupTrunks, random.randrange(1, 5)
    )
    transportDispatcher.register_timer_callback(
        trunkingManager.monitorTrunks, random.randrange(1, 5)
    )


def register_metrics_timer(
    transportDispatcher: AsyncioDispatcher,
    interval_secs: Optional[int] = None,
) -> None:
    """Log deltas from `snmpfwd.metrics` every `interval_secs`. Cheap —
    at worst one INFO line per interval containing the subset of
    counters that changed since the previous tick. Nothing is emitted
    when the proxy is idle.

    Interval defaults to 60 seconds, overridable via the
    `SNMPFWD_METRICS_INTERVAL` env variable (integer seconds). The env
    var is how the integration tests ask for a short interval without
    needing an extra CLI flag."""
    from snmpfwd import metrics
    if interval_secs is None:
        try:
            interval_secs = int(os.environ.get('SNMPFWD_METRICS_INTERVAL', '60'))
        except ValueError:
            interval_secs = 60
    transportDispatcher.register_timer_callback(
        metrics.log_deltas, interval_secs
    )


def start_metrics_agent(transport_dispatcher: AsyncioDispatcher) -> None:
    """Optionally stand up a dedicated SNMP v2c agent that serves the
    counters registered in `snmpfwd.metrics` under the
    `snmpfwd.metrics_mib` OID subtree.

    Configuration (environment variables, opt-in):

    - `SNMPFWD_METRICS_SNMP_BIND=<host>:<port>` — address the metrics
      agent listens on. If unset, this function is a no-op. The host
      must be IPv4; IPv6 is not yet wired up.
    - `SNMPFWD_METRICS_SNMP_COMMUNITY=<name>` — read-only community
      string. Defaults to `public`.

    The agent runs inside the existing event loop by reusing the
    `transport_dispatcher` the rest of snmpfwd already shares. It binds
    its OWN `SnmpEngine` and transport-domain OID so it doesn't
    interfere with any forwarding engines configured by the calling
    program."""
    bind = os.environ.get('SNMPFWD_METRICS_SNMP_BIND', '').strip()
    if not bind:
        return

    try:
        host, port_str = bind.rsplit(':', 1)
        host = host.strip('[]')
        port = int(port_str)
    except (ValueError, TypeError):
        log.error('SNMPFWD_METRICS_SNMP_BIND=%r is not <host>:<port>; '
                  'metrics SNMP agent not started' % bind)
        return

    community = os.environ.get('SNMPFWD_METRICS_SNMP_COMMUNITY', 'public')

    # Local imports — these aren't needed when the feature is off, and
    # importing at module scope pulls in the pysnmp MIB builder during
    # every bootstrap run.
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import engine, config as pysnmp_config
    from pysnmp.entity.rfc3413 import cmdrsp, context

    from snmpfwd import metrics_mib

    # A private transport-domain OID so this agent's transport doesn't
    # collide with forwarding transports on the same dispatcher.
    metrics_transport_domain = udp.domainName + (999,)

    metrics_engine = engine.SnmpEngine()
    metrics_engine.register_transport_dispatcher(
        transport_dispatcher, metrics_transport_domain,
    )

    try:
        transport = udp.UdpTransport(
            loop=transport_dispatcher.loop
        ).openServerMode((host, port))
    except Exception:
        log.error('metrics SNMP agent cannot bind %s:%d: %s'
                  % (host, port, sys.exc_info()[1]))
        return

    pysnmp_config.addSocketTransport(
        metrics_engine, metrics_transport_domain, transport,
    )
    pysnmp_config.addV1System(metrics_engine, community, community)
    pysnmp_config.addVacmUser(
        metrics_engine, 2, community, 'noAuthNoPriv',
        metrics_mib.METRICS_ROOT_OID, metrics_mib.METRICS_ROOT_OID,
    )

    snmp_context = context.SnmpContext(metrics_engine)
    metrics_mib.register_metrics_mib(metrics_engine)

    # Serve GET / GETNEXT / GETBULK; no SET support (no config below).
    cmdrsp.GetCommandResponder(metrics_engine, snmp_context)
    cmdrsp.NextCommandResponder(metrics_engine, snmp_context)
    cmdrsp.BulkCommandResponder(metrics_engine, snmp_context)

    log.info(
        'metrics SNMP agent listening at %s:%d (community=%s), MIB root %s'
        % (host, port, community,
           '.'.join(str(x) for x in metrics_mib.METRICS_ROOT_OID))
    )


def _install_signal_handlers(loop) -> None:
    """Wire SIGTERM/SIGINT/SIGQUIT to stop the event loop. SIGHUP is
    deliberately excluded — `install_reload_handler` claims it for
    config reloading, the convention used by most Unix daemons.

    Uses loop.add_signal_handler rather than signal.signal so the loop
    wakes up cleanly — signal.signal delivers to an arbitrary thread
    during an arbitrary syscall, which races with asyncio's internals.
    On Windows, where add_signal_handler is NotImplementedError, fall
    back to signal.signal with a threadsafe loop.stop dispatch."""
    handled = (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT)
    for sig in handled:
        try:
            loop.add_signal_handler(sig, loop.stop)
        except (NotImplementedError, RuntimeError):
            try:
                signal.signal(sig, lambda *_: loop.call_soon_threadsafe(loop.stop))
            except (ValueError, OSError):
                # Not all signals are available on every platform (e.g.,
                # SIGQUIT on Windows). Skip silently.
                pass


def install_reload_handler(
    transportDispatcher: AsyncioDispatcher,
    reload_callback,
) -> None:
    """Register a SIGHUP handler that invokes `reload_callback()`.

    The callback is expected to re-parse the config and apply any
    safely-applicable changes (routing maps, classifier lists, etc.).
    Exceptions raised by the callback are caught and logged — the
    running process keeps whatever configuration it already had."""
    loop = transportDispatcher.loop

    def _on_sighup():
        try:
            reload_callback()
        except Exception:
            log.error(
                'configuration reload failed, keeping previous config: %s'
                % sys.exc_info()[1]
            )

    try:
        loop.add_signal_handler(signal.SIGHUP, _on_sighup)
    except (AttributeError, NotImplementedError, RuntimeError):
        # Windows has no SIGHUP; fall back silently.
        pass


def run_dispatcher_loop(
    args: "argparse.Namespace",
    transportDispatcher: AsyncioDispatcher,
) -> None:
    """Daemonize (if requested), install signal handlers, drop privileges
    finally, run the asyncio event loop. Soft-fails on (PySnmpError,
    SnmpfwdError, socket.error) with a retry; a clean return from
    runDispatcher() (i.e. loop.stop() fired) is treated as a graceful
    shutdown and surfaced as KeyboardInterrupt so the outer __main__
    wrapper logs "shutting down process..." and exits zero."""
    if args.daemonize:
        try:
            daemon.daemonize(args.pid_file)
        except Exception:
            log.error('can not daemonize process: %s' % sys.exc_info()[1])
            raise

    # Must happen after any daemonize() fork so the handlers attach to
    # the loop in the final child process.
    _install_signal_handlers(transportDispatcher.loop)

    log.info('starting I/O engine...')
    transportDispatcher.jobStarted(1)  # prevent the loop from auto-exiting

    with daemon.PrivilegesOf(args.process_user, args.process_group, final=True):
        while True:
            try:
                transportDispatcher.runDispatcher()
            except (PySnmpError, SnmpfwdError, socket.error):
                log.error(str(sys.exc_info()[1]))
                continue
            except Exception:
                transportDispatcher.closeDispatcher()
                raise
            else:
                # runDispatcher() returned on its own — the loop was
                # stopped, presumably by a signal handler. Close cleanly.
                transportDispatcher.closeDispatcher()
                raise KeyboardInterrupt
