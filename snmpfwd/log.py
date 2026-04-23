#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
"""Logging front-end used across snmpfwd.

Dispatches through a standard `logging.Logger`; the custom `AbstractLogger`
class tree and the module-level `msg`/`logLevel` sentinels that older
versions shipped have been replaced with stock `logging` handlers driven
via factory functions. The public API (`setLogger`, `setLevel`,
`error`/`info`/`debug`, `methodsMap`, `levelsMap`, and
`FileLogger.TimedRotatingFileHandler`) is preserved — snmpfwd's own
code and third-party plugins (via `log.FileLogger.TimedRotatingFileHandler`)
rely on those names.
"""
from __future__ import annotations

import logging
import os
import socket
import stat
import sys
import time
from logging import handlers

from snmpfwd.error import SnmpfwdError


# ---------------------------------------------------------------------------
# Module-level logger.
#
# Starts out as the "snmpfwd" logger with a NullHandler so log() calls made
# before setLogger() runs don't emit "No handlers could be found" warnings
# on stderr. setLogger() then rebinds this to a program-specific logger
# ("snmpfwd-server" / "snmpfwd-client") and attaches the user-selected
# handler to it.

_logger: logging.Logger = logging.getLogger('snmpfwd')
_logger.addHandler(logging.NullHandler())
_logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Formatters
#
# The file sink keeps the historical centisecond timestamp (e.g.
# "2026-04-22T08:47:29.23"); stream and syslog sinks use the stock
# logging.Formatter asctime ("2026-04-22 08:47:29,230"). That split is
# preserved verbatim from the pre-refactor behavior so log-parsing scripts
# outside this repo don't need to change.


class _CentiSecondFormatter(logging.Formatter):
    default_time_format = '%Y-%m-%dT%H:%M:%S'

    def formatTime(self, record, datefmt=None):
        base = time.strftime(
            datefmt or self.default_time_format, time.localtime(record.created)
        )
        return '%s.%02d' % (base, int((record.created % 1) * 100))


_FILE_FORMATTER = _CentiSecondFormatter('%(asctime)s %(name)s: %(message)s')
_STREAM_FORMATTER = logging.Formatter('%(asctime)s %(message)s')
_SYSLOG_FORMATTER = logging.Formatter('%(asctime)s %(name)s: %(message)s')


# ---------------------------------------------------------------------------
# Handler factories


def _make_stderr_handler(_priv):
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(_STREAM_FORMATTER)
    return h


def _make_stdout_handler(_priv):
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(_STREAM_FORMATTER)
    return h


def _make_null_handler(_priv):
    return logging.NullHandler()


_SYSLOG_SOCKET_PATHS = ('/dev/log', '/var/run/syslog')


def _make_syslog_handler(priv):
    priv = list(priv)
    if len(priv) < 1:
        raise SnmpfwdError(
            'Bad syslog params, need at least facility, also accept '
            'host, port, socktype (tcp|udp)'
        )
    if len(priv) < 2:
        priv = [priv[0], 'debug']
    if len(priv) < 3:
        for dev in _SYSLOG_SOCKET_PATHS:
            if os.path.exists(dev):
                priv = [priv[0], priv[1], dev]
                break
        else:
            priv = [priv[0], priv[1], 'localhost', 514, 'udp']

    if not priv[2].startswith('/'):
        if len(priv) < 4:
            priv = [priv[0], priv[1], priv[2], 514, 'udp']
        if len(priv) < 5:
            priv = [priv[0], priv[1], priv[2], 514, 'udp']
        priv = [priv[0], priv[1], priv[2], int(priv[3]), priv[4]]

    try:
        handler = handlers.SysLogHandler(
            address=(priv[2] if priv[2].startswith('/')
                     else (priv[2], int(priv[3]))),
            facility=priv[0].lower(),
            socktype=(socket.SOCK_STREAM
                      if len(priv) > 4 and priv[4] == 'tcp'
                      else socket.SOCK_DGRAM),
        )
    except Exception:
        raise SnmpfwdError('Bad syslog option(s): %s' % sys.exc_info()[1])

    handler.setFormatter(_SYSLOG_FORMATTER)
    return handler


class FileLogger:
    """Namespace wrapper kept for backward compatibility — external plugins
    reach in via `snmpfwd.log.FileLogger.TimedRotatingFileHandler`."""

    class TimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
        """Record the last rotation time in a stand-aside dotfile so restarts
        don't reset the rollover schedule."""

        def __init__(self, *args, **kwargs):
            handlers.TimedRotatingFileHandler.__init__(self, *args, **kwargs)

            self.__failure = False

            try:
                timestamp = os.stat(self.__filename)[stat.ST_MTIME]
            except IOError:
                return

            self.rolloverAt = self.computeRollover(timestamp)

        @property
        def __filename(self):
            return os.path.join(
                os.path.dirname(self.baseFilename),
                '.' + os.path.basename(self.baseFilename) + '-timestamp',
            )

        def doRollover(self):
            try:
                handlers.TimedRotatingFileHandler.doRollover(self)

                if os.path.exists(self.__filename):
                    os.unlink(self.__filename)

                with open(self.__filename, 'w'):
                    pass

                self.__failure = False

            except IOError:
                timestamp = time.time()
                self.rolloverAt = self.computeRollover(timestamp)

                if not self.__failure:
                    self.__failure = True
                    error(
                        'Failed to rotate log/timestamp file %s: %s'
                        % (self.__filename, sys.exc_info()[1])
                    )


def _make_file_handler(priv):
    priv = list(priv)
    if not priv:
        raise SnmpfwdError('Bad log file params, need filename')
    if sys.platform[:3] == 'win':
        # Rebuild an absolute Windows path like "C:/path" that got split
        # on the colon used as the method/args separator.
        if len(priv[0]) == 1 and priv[0].isalpha() and len(priv) > 1:
            priv = [priv[0] + ':' + priv[1]] + list(priv[2:])

    maxsize = 0
    maxage = None
    if len(priv) > 1 and priv[1]:
        try:
            if priv[1][-1] == 'k':
                maxsize = int(priv[1][:-1]) * 1024
            elif priv[1][-1] == 'm':
                maxsize = int(priv[1][:-1]) * 1024 * 1024
            elif priv[1][-1] == 'g':
                maxsize = int(priv[1][:-1]) * 1024 * 1024 * 1024
            elif priv[1][-1] == 'S':
                maxage = ('S', int(priv[1][:-1]))
            elif priv[1][-1] == 'M':
                maxage = ('M', int(priv[1][:-1]))
            elif priv[1][-1] == 'H':
                maxage = ('H', int(priv[1][:-1]))
            elif priv[1][-1] == 'D':
                maxage = ('D', int(priv[1][:-1]))
            else:
                raise ValueError('Unknown log rotation criterion: %s' % priv[1][-1])
        except ValueError:
            raise SnmpfwdError(
                'Error in timed log rotation specification. Use <NNN>k,m,g '
                'for size or <NNN>S,M,H,D for time limits'
            )

    try:
        if maxsize:
            handler = handlers.RotatingFileHandler(
                priv[0], backupCount=30, maxBytes=maxsize
            )
        elif maxage:
            handler = FileLogger.TimedRotatingFileHandler(
                priv[0], backupCount=30, when=maxage[0], interval=maxage[1]
            )
        else:
            handler = handlers.WatchedFileHandler(priv[0])
    except Exception:
        raise SnmpfwdError(
            'Failure configuring logging: %s' % sys.exc_info()[1]
        )

    handler.setFormatter(_FILE_FORMATTER)
    # Announce the file + rotation policy on the newly-configured handler so
    # users can tell what they got.
    _log_rotation_banner = (
        ('> %sKB' % (maxsize / 1024)) if maxsize
        else ('%s%s' % (maxage[1], maxage[0])) if maxage
        else '<none>'
    )
    # Defer the "Log file configured" info() until setLogger() has actually
    # installed `handler` on the active logger — doing it here, before the
    # handler is attached, would be silently dropped.
    _pending_info_lines.append(
        'Log file %s, rotation rules: %s' % (priv[0], _log_rotation_banner)
    )
    return handler


# Buffer for info() lines that factories want to emit once the logger is
# actually wired up (populated by _make_file_handler).
_pending_info_lines: list[str] = []


# ---------------------------------------------------------------------------
# Public API


methodsMap = {
    'syslog': _make_syslog_handler,
    'file': _make_file_handler,
    'stdout': _make_stdout_handler,
    'stderr': _make_stderr_handler,
    'null': _make_null_handler,
}


levelsMap = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'error': logging.ERROR,
}


def setLogger(progId, *priv, **options):
    """Install a handler on the snmpfwd logger based on --logging-method args.

    `priv[0]` is the method name (entry in methodsMap); the remaining priv
    elements are method-specific arguments. `force=True` clears any
    existing handlers on the target logger before attaching; `force=False`
    (the default) appends, so the caller can wire up multiple sinks by
    invoking this function once per sink."""
    global _logger

    if not priv:
        raise SnmpfwdError('setLogger: missing logging method')

    try:
        factory = methodsMap[priv[0]]
    except KeyError:
        raise SnmpfwdError(
            'Unknown logging method "%s", known methods are: %s'
            % (priv[0], ', '.join(methodsMap))
        )

    new_logger = logging.getLogger(progId)
    if new_logger.level == logging.NOTSET:
        new_logger.setLevel(logging.INFO)

    if options.get('force'):
        for existing in list(new_logger.handlers):
            new_logger.removeHandler(existing)

    new_logger.addHandler(factory(list(priv[1:])))
    _logger = new_logger

    # Flush any messages factories queued (e.g. the file rotation banner)
    # now that the handler is active.
    while _pending_info_lines:
        info(_pending_info_lines.pop(0))


def setLevel(level):
    try:
        _logger.setLevel(levelsMap[level])
    except KeyError:
        raise SnmpfwdError(
            'Unknown log level "%s", known levels are: %s'
            % (level, ', '.join(levelsMap))
        )


def error(message, ctx=''):
    _logger.error('ERROR %s %s' % (message, ctx))


def info(message, ctx=''):
    _logger.info('INFO %s %s' % (message, ctx))


def debug(message, ctx=''):
    _logger.debug('DEBUG %s %s' % (message, ctx))
