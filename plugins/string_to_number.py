#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2019, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/snmpfwd/license.html
#
# SNMP Proxy Forwarder plugin module
#
# This plugin converts string (OctetString) SNMP response values to numeric types
#
import re
import sys
from snmpfwd.plugins import status
from snmpfwd.error import SnmpfwdError
from snmpfwd.log import debug, info, error
from pysnmp.proto.api import v2c

hostProgs = 'snmpfwd-server', 'snmpfwd-client'

apiVersions = 0, 2

PLUGIN_NAME = 'string_to_number'

# Map of string type names to pysnmp classes
TYPE_MAP = {
    'Integer': v2c.Integer,
    'Integer32': v2c.Integer32,
    'Counter32': v2c.Counter32,
    'Counter64': v2c.Counter64,
    'Gauge32': v2c.Gauge32,
    'Unsigned32': v2c.Unsigned32,
    'TimeTicks': v2c.TimeTicks,
}

# Default type for conversion
defaultType = 'Integer32'

# List of (OID pattern, target type) tuples
conversionRules = []

# Parse module options
for moduleOption in moduleOptions:
    optionName, optionValue = moduleOption.split('=', 1)

    if optionName == 'default-type':
        if optionValue in TYPE_MAP:
            defaultType = optionValue
            info('%s: using default type: %s' % (PLUGIN_NAME, defaultType))
        else:
            raise SnmpfwdError('%s: unknown type: %s (valid: %s)' % (
                PLUGIN_NAME, optionValue, ', '.join(TYPE_MAP.keys())))

    elif optionName == 'config':
        try:
            configFile = optionValue

            for lineNo, line in enumerate(open(configFile).readlines()):
                line = line.strip()

                if not line or line.startswith('#'):
                    continue

                try:
                    # Format: "OID-pattern" target-type
                    parts = line.split()
                    if len(parts) == 2:
                        oidPattern = parts[0].strip('"')
                        targetType = parts[1]

                        if targetType not in TYPE_MAP:
                            raise ValueError("Unknown type: %s (valid: %s)" % (
                                targetType, ', '.join(TYPE_MAP.keys())))

                        conversionRules.append((re.compile(oidPattern), targetType))
                        debug('%s: OID pattern "%s" will convert strings to %s' % (
                            PLUGIN_NAME, oidPattern, targetType))
                    else:
                        raise ValueError('Expected format: "OID-pattern" target-type')

                except ValueError as e:
                    raise SnmpfwdError('%s: syntax error at %s:%d: %s' % (
                        PLUGIN_NAME, configFile, lineNo + 1, e))

        except IOError as e:
            raise SnmpfwdError('%s: config file load failure: %s' % (PLUGIN_NAME, e))

# If no config file, use default type for all strings
if not conversionRules:
    info('%s: will convert all string values to %s' % (PLUGIN_NAME, defaultType))

info('%s: plugin initialization complete' % PLUGIN_NAME)


def parseNumber(stringValue):
    """
    Parse a string value into a number.

    Returns (value, is_float) tuple.
    Raises ValueError if not a valid number.
    """
    stringValue = stringValue.strip()

    # Try parsing as integer first
    try:
        return int(stringValue), False
    except ValueError:
        pass

    # Try parsing as float
    try:
        value = float(stringValue)
        # Check if it's actually an integer disguised as float
        if value.is_integer():
            return int(value), False
        return value, True
    except ValueError:
        raise ValueError('Not a valid number: "%s"' % stringValue)


def stringToNumber(val, targetType):
    """Convert an OctetString value to a numeric SNMP type."""

    # Only convert OctetString values
    if val.tagSet != v2c.OctetString.tagSet:
        debug('%s: value is not OctetString, skipping' % PLUGIN_NAME)
        return val

    try:
        # Get the string value
        stringValue = str(val)

        # Parse the number
        numericValue, isFloat = parseNumber(stringValue)

        # Get target SNMP type class
        targetClass = TYPE_MAP[targetType]

        # Counter64 can handle large integers
        if targetType == 'Counter64':
            maxValue = 2**64 - 1
        # Most 32-bit types
        elif targetType in ('Counter32', 'Gauge32', 'Unsigned32', 'TimeTicks'):
            maxValue = 2**32 - 1
            numericValue = abs(int(numericValue))  # Ensure unsigned
        # Integer types (signed)
        else:
            maxValue = 2**31 - 1
            minValue = -(2**31)
            if numericValue < minValue or numericValue > maxValue:
                error('%s: value %s out of range for %s' % (
                    PLUGIN_NAME, numericValue, targetType))
                return val

        # Check range for unsigned types
        if targetType in ('Counter32', 'Counter64', 'Gauge32', 'Unsigned32', 'TimeTicks'):
            if numericValue < 0 or numericValue > maxValue:
                error('%s: value %s out of range for %s' % (
                    PLUGIN_NAME, numericValue, targetType))
                return val

        # Warn if float is being converted to integer type
        if isFloat and targetType != 'Float':
            info('%s: converting float %s to integer %s for type %s' % (
                PLUGIN_NAME, stringValue, int(numericValue), targetType))
            numericValue = int(numericValue)

        # Create the new value
        newValue = targetClass(numericValue)

        debug('%s: converted string "%s" to %s(%s)' % (
            PLUGIN_NAME, stringValue, targetType, numericValue))

        return newValue

    except ValueError as e:
        # Not a valid number, keep original
        debug('%s: cannot convert "%s" to number: %s' % (PLUGIN_NAME, stringValue, e))
        return val
    except Exception as e:
        error('%s: conversion error: %s' % (PLUGIN_NAME, e))
        return val


def processCommandResponse(pluginId, snmpEngine, pdu, trunkMsg, reqCtx):
    """Process SNMP command response and convert strings to numbers."""

    varBinds = []

    for oid, val in v2c.apiPDU.getVarBinds(pdu):
        oidStr = str(oid)

        # Check if there's a specific rule for this OID
        ruleMatched = False
        for oidPattern, targetType in conversionRules:
            if oidPattern.match(oidStr):
                val = stringToNumber(val, targetType)
                ruleMatched = True
                break

        # If no specific rule, use default type
        if not ruleMatched and not conversionRules:
            val = stringToNumber(val, defaultType)

        varBinds.append((oid, val))

    v2c.apiPDU.setVarBinds(pdu, varBinds)

    return status.NEXT, pdu


# Also process notifications (traps)
processNotificationRequest = processCommandResponse
