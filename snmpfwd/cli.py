#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
"""Shared argparse setup for snmpfwd-server and snmpfwd-client.

The two CLI entry points expose the exact same flag set, so we build
their parsers from a single helper here. Preserves every long-form flag
name and short form (-h, -v) that the legacy getopt-based code accepted.
"""
from __future__ import annotations

import argparse
import sys

from pyasn1 import debug as pyasn1_debug
from pysnmp import debug as pysnmp_debug

from snmpfwd import log


def _pysnmp_debug_flags() -> list[str]:
    flag_map = getattr(pysnmp_debug, 'FLAG_MAP',
                       getattr(pysnmp_debug, 'flagMap', ()))
    return [flag for flag in flag_map if flag != 'mibview']


def _pyasn1_debug_flags() -> list[str]:
    flag_map = getattr(pyasn1_debug, 'FLAG_MAP',
                       getattr(pyasn1_debug, 'flagMap', ()))
    return list(flag_map)


def _version_text() -> str:
    # Imported lazily: avoids a hard dependency on these during module
    # import (helpful for unit tests that don't need pysnmp loaded).
    import snmpfwd
    import pysnmp
    import pyasn1
    return (
        'SNMP Proxy Forwarder version %s, written by Ilya Etingof '
        '<etingof@gmail.com>\n'
        'Using foundation libraries: pysnmp %s, pyasn1 %s.\n'
        'Python interpreter: %s\n'
        'Software documentation and support at https://www.pysnmp.com/snmpfwd/'
        % (
            snmpfwd.__version__,
            getattr(pysnmp, '__version__', 'unknown'),
            getattr(pyasn1, '__version__', 'unknown'),
            sys.version,
        )
    )


def build_parser(*, prog_name: str, synopsis: str,
                 default_config_file: str) -> argparse.ArgumentParser:
    """Construct the argparse parser shared by both entry points.

    `synopsis` is a paragraph describing the program's role; it becomes
    the parser description shown at the top of --help.
    `default_config_file` is the value used when --config-file is omitted.
    """
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description=synopsis,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Documentation: https://www.pysnmp.com/snmpfwd/',
    )
    parser.add_argument(
        '-v', '--version', action='version', version=_version_text(),
    )
    parser.add_argument(
        '--debug-snmp', metavar='FLAGS',
        help=('Comma-separated pysnmp debug flags: '
              + '|'.join(_pysnmp_debug_flags())),
    )
    parser.add_argument(
        '--debug-asn1', metavar='FLAGS',
        help=('Comma-separated pyasn1 debug flags: '
              + '|'.join(_pyasn1_debug_flags())),
    )
    parser.add_argument(
        '--daemonize', action='store_true',
        help='Fork and detach from the controlling terminal after startup.',
    )
    parser.add_argument(
        '--process-user', metavar='UNAME',
        help='Drop root privileges to this user after binding sockets.',
    )
    parser.add_argument(
        '--process-group', metavar='GNAME',
        help='Drop root privileges to this group after binding sockets.',
    )
    parser.add_argument(
        '--pid-file', metavar='FILE', default='',
        help='Write the PID to FILE after daemonization.',
    )
    parser.add_argument(
        '--logging-method', metavar='METHOD[:args]',
        action='append', default=None,
        help=('Logging sink. One of: ' + '|'.join(log.methodsMap)
              + '. Method-specific arguments follow the colon. May be '
              'given more than once to attach multiple sinks (e.g. '
              '--logging-method=stderr --logging-method=file:/var/log/snmpfwd.log); '
              'defaults to a single `stderr` sink if omitted.'),
    )
    parser.add_argument(
        '--log-level', choices=list(log.levelsMap), default=None,
    )
    parser.add_argument(
        '--config-file', metavar='FILE', default=default_config_file,
    )
    return parser


def apply_debug_flags(args: argparse.Namespace, program_name: str) -> None:
    """Mirror the --debug-snmp / --debug-asn1 options onto the backing
    loggers. Called immediately after parse_args."""
    if args.debug_snmp:
        pysnmp_debug.set_logger(
            pysnmp_debug.Debug(
                *args.debug_snmp.split(','),
                loggerName=program_name + '.pysnmp',
            )
        )
    if args.debug_asn1:
        # pyasn1 still exposes setLogger (the snake_case variant doesn't
        # exist as a compat alias on pyasn1 7 / 0.6); keep camelCase.
        pyasn1_debug.setLogger(
            pyasn1_debug.Debug(
                *args.debug_asn1.split(','),
                loggerName=program_name + '.pyasn1',
            )
        )
