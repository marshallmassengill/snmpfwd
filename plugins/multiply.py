#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
# SNMP Proxy Forwarder plugin module
#
# This plugin multiplies numeric SNMP response values by a configurable factor
#
import re
import sys
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import debug, info, error
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'

apiVersions = 0, 2

PLUGIN_NAME = 'multiply'

# Default multiplier
multiplier = 10

# List of (OID pattern, multiplier) tuples
multiplyRules = []

# Parse module options
for moduleOption in moduleOptions:
    optionName, optionValue = moduleOption.split('=', 1)

    if optionName == 'factor':
        try:
            multiplier = float(optionValue)
            info('%s: using global multiplier factor: %s' % (PLUGIN_NAME, multiplier))
        except ValueError:
            raise SnmpfwdError('%s: invalid multiplier factor: %s' % (PLUGIN_NAME, optionValue))

    elif optionName == 'config':
        try:
            configFile = optionValue

            for lineNo, line in enumerate(open(configFile).readlines()):
                line = line.strip()

                if not line or line.startswith('#'):
                    continue

                try:
                    # Format: "OID-pattern" multiplier
                    parts = line.split()
                    if len(parts) == 2:
                        oidPattern = parts[0].strip('"')
                        ruleFactor = float(parts[1])
                        multiplyRules.append((re.compile(oidPattern), ruleFactor))
                        debug('%s: OID pattern "%s" will be multiplied by %s' % (PLUGIN_NAME, oidPattern, ruleFactor))
                    else:
                        raise ValueError("Expected format: \"OID-pattern\" multiplier")

                except ValueError as e:
                    raise SnmpfwdError('%s: syntax error at %s:%d: %s' % (PLUGIN_NAME, configFile, lineNo + 1, e))

        except IOError as e:
            raise SnmpfwdError('%s: config file load failure: %s' % (PLUGIN_NAME, e))

# If no config file, apply global multiplier to all numeric OIDs
if not multiplyRules:
    info('%s: using global multiplier %s for all numeric values' % (PLUGIN_NAME, multiplier))

info('%s: plugin initialization complete' % PLUGIN_NAME)


def multiplyValue(val, factor):
    """Multiply a value by the given factor, preserving SNMP type."""

    # Identify numeric SNMP types
    numericTypes = (
        v2c.Integer,
        v2c.Integer32,
        v2c.Counter32,
        v2c.Gauge32,
        v2c.Unsigned32,
        v2c.TimeTicks,
        v2c.Counter64
    )

    # Check if this is a numeric type
    for numType in numericTypes:
        if val.tagSet == numType.tagSet:
            try:
                originalValue = int(val)
                newValue = int(originalValue * factor)
                debug('%s: multiplying %s by %s = %s' % (PLUGIN_NAME, originalValue, factor, newValue))
                return val.clone(newValue)
            except (ValueError, OverflowError) as e:
                error('%s: failed to multiply value: %s' % (PLUGIN_NAME, e))
                return val

    # Non-numeric type, return unchanged
    return val


def processCommandResponse(pluginId, snmpEngine, pdu, trunkMsg, reqCtx):
    """Process SNMP command response and multiply numeric values."""

    varBinds = []

    for oid, val in v2c.apiPDU.getVarBinds(pdu):
        oidStr = str(oid)

        # Check if there's a specific rule for this OID
        ruleMatched = False
        for oidPattern, ruleFactor in multiplyRules:
            if oidPattern.match(oidStr):
                val = multiplyValue(val, ruleFactor)
                ruleMatched = True
                break

        # If no specific rule, use global multiplier
        if not ruleMatched and not multiplyRules:
            val = multiplyValue(val, multiplier)

        varBinds.append((oid, val))

    v2c.apiPDU.setVarBinds(pdu, varBinds)

    return status.NEXT, pdu


# Also process notifications (traps)
processNotificationRequest = processCommandResponse
