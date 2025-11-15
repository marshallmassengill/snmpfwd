# SNMP String-to-Number Plugin Example

This example demonstrates the **string_to_number plugin** which converts string (OctetString) SNMP response values into proper numeric SNMP types.

## Problem Statement

Some SNMP devices return numeric data as strings (OctetString), which causes issues for:
- **Monitoring systems** that expect proper numeric types for graphing
- **Alerting tools** that can't do numeric comparisons on strings
- **Data aggregation** that needs to perform calculations

**Example of the problem:**
```
Backend returns: sysUpTime.0 = STRING: "12345"
Expected:        sysUpTime.0 = Timeticks: (12345) 0:02:03.45
```

## Solution

This plugin intercepts SNMP responses and converts string values to the appropriate numeric SNMP types.

## Architecture

```
┌─────────────┐     ┌──────────────────────┐     ┌────────────┐     ┌─────────┐
│ SNMP Client │────►│ snmpfwd-server       │────►│ snmpfwd-   │────►│ Backend │
│             │     │ (port 1161)          │     │ client     │     │ Agent   │
│             │     │ + string_to_number   │     │            │     │ :10161  │
│   Expects   │     │   plugin             │     │            │     │ Returns │
│   numeric   │◄────│                      │◄────│            │◄────│ strings │
│   types     │     └──────────────────────┘     └────────────┘     └─────────┘
│             │              │
│ Gets proper │              ▼
│ TimeTicks!  │     Convert "12345" string
└─────────────┘     to TimeTicks(12345)
```

## How It Works

**Backend Returns:**
```
OID: 1.3.6.1.2.1.1.3.0 (sysUpTime.0)
Type: OctetString
Value: "12345"
```

**Plugin Processing:**
1. Matches OID against pattern: `^1\.3\.6\.1\.2\.1\.1\.3\.0$`
2. Found rule: Convert to `TimeTicks`
3. Checks type: OctetString ✓
4. Parses string: "12345" → integer 12345
5. Creates: TimeTicks(12345)
6. Returns modified PDU

**Client Receives:**
```
OID: 1.3.6.1.2.1.1.3.0 (sysUpTime.0)
Type: TimeTicks
Value: 12345
Display: Timeticks: (12345) 0:02:03.45
```

## Supported Conversions

The plugin can convert strings to these SNMP numeric types:

| Type | Description | Range | Use Case |
|------|-------------|-------|----------|
| **Integer** | Signed 32-bit | -2^31 to 2^31-1 | General integers |
| **Integer32** | Signed 32-bit | -2^31 to 2^31-1 | General integers |
| **Counter32** | Unsigned 32-bit counter | 0 to 2^32-1 | Packet counts |
| **Counter64** | Unsigned 64-bit counter | 0 to 2^64-1 | Byte counts |
| **Gauge32** | Unsigned 32-bit gauge | 0 to 2^32-1 | Current values |
| **Unsigned32** | Unsigned 32-bit | 0 to 2^32-1 | Unsigned integers |
| **TimeTicks** | Unsigned 32-bit | 0 to 2^32-1 | Time intervals |

## Configuration

### Server Config (`server.conf`)

```
plugin-group {
  plugin-module: string_to_number
  plugin-options: config=${config-dir}/plugins/string_to_number.conf

  plugin-id: convert-strings-to-numbers
}

routing-map {
  using-plugin-id-list: convert-strings-to-numbers
  using-trunk-id-list: trunk-1
}
```

### Plugin Config (`plugins/string_to_number.conf`)

```
# Format: "OID-pattern" target-type

# Convert system uptime string to TimeTicks
"^1\.3\.6\.1\.2\.1\.1\.3\.0$" TimeTicks

# Convert interface counters to Counter32
"^1\.3\.6\.1\.2\.1\.2\.2\.1\.10\..*$" Counter32
"^1\.3\.6\.1\.2\.1\.2\.2\.1\.16\..*$" Counter32

# Convert interface speeds to Gauge32
"^1\.3\.6\.1\.2\.1\.2\.2\.1\.5\..*$" Gauge32

# Convert general system values to Integer32
"^1\.3\.6\.1\.2\.1\.1\..*$" Integer32
```

## Plugin Options

### Option 1: Config File (Recommended)

```
plugin-options: config=/path/to/string_to_number.conf
```

Different OID patterns can be converted to different types.

### Option 2: Default Type

```
plugin-options: default-type=Integer32
```

All string values are converted to the specified type.

### Option 3: Combined

```
plugin-options: config=/path/to/config.conf,default-type=Gauge32
```

Use config rules for specific OIDs, default type for others.

## Example Scenarios

### Scenario 1: Uptime as String

**Problem:** Device returns uptime as string
```bash
$ snmpget -v2c -c public 127.0.0.1:10161 sysUpTime.0
SNMPv2-MIB::sysUpTime.0 = STRING: "12345"
```

**Solution:** Through proxy with conversion
```bash
$ snmpget -v2c -c public 127.0.0.1:1161 sysUpTime.0
SNMPv2-MIB::sysUpTime.0 = Timeticks: (12345) 0:02:03.45
```

### Scenario 2: Counter as String

**Problem:** Interface counter is a string
```bash
$ snmpget -v2c -c public 127.0.0.1:10161 ifInOctets.1
IF-MIB::ifInOctets.1 = STRING: "98765432"
```

**Solution:** Converted to Counter32
```bash
$ snmpget -v2c -c public 127.0.0.1:1161 ifInOctets.1
IF-MIB::ifInOctets.1 = Counter32: 98765432
```

### Scenario 3: Float to Integer

**Problem:** Device returns "123.456" as string
```
Input:  OctetString("123.456")
Config: Convert to Integer32
Output: Integer32(123)
```

The plugin automatically truncates floats to integers when needed.

## Number Parsing

The plugin intelligently parses string values:

### Integer Strings
```
"12345"     → 12345
"-123"      → -123 (for signed types)
"  456  "   → 456 (whitespace trimmed)
```

### Float Strings
```
"123.0"     → 123 (recognized as integer)
"456.789"   → 456 (truncated to integer)
"-78.9"     → -78 (truncated, for signed types)
```

### Invalid Strings
```
"abc"       → Not converted (kept as string)
"12x34"     → Not converted (invalid number)
""          → Not converted (empty string)
```

## Type Safety

The plugin enforces proper range checks:

**Counter32 Example:**
- Range: 0 to 4,294,967,295
- String "-100" → Rejected (negative)
- String "5000000000" → Rejected (too large)

**Integer32 Example:**
- Range: -2,147,483,648 to 2,147,483,647
- String "-100" → Accepted
- String "3000000000" → Rejected (out of range)

## Use Cases

### 1. Legacy Device Integration
Device returns all values as strings, but modern monitoring needs typed values.

### 2. Custom SNMP Extensions
In-house SNMP extensions that return numeric data as strings for simplicity.

### 3. Protocol Translation
Converting from text-based protocols to proper SNMP types.

### 4. Data Normalization
Standardizing heterogeneous data sources to use correct SNMP types.

### 5. Monitoring System Compatibility
Some monitoring systems (Nagios, Zabbix, etc.) require specific SNMP types for:
- Graphing (needs Counter/Gauge)
- Alerting (numeric comparisons)
- Rate calculations (requires Counter types)

## Implementation Highlights

### Number Parsing
```python
def parseNumber(stringValue):
    """Parse a string value into a number."""
    stringValue = stringValue.strip()

    # Try integer first
    try:
        return int(stringValue), False
    except ValueError:
        pass

    # Try float
    try:
        value = float(stringValue)
        if value.is_integer():
            return int(value), False
        return value, True
    except ValueError:
        raise ValueError('Not a valid number')
```

### Type Conversion
```python
def stringToNumber(val, targetType):
    """Convert OctetString to numeric type."""

    if val.tagSet != v2c.OctetString.tagSet:
        return val  # Not a string, skip

    stringValue = str(val)
    numericValue, isFloat = parseNumber(stringValue)

    # Get target class and create value
    targetClass = TYPE_MAP[targetType]
    newValue = targetClass(numericValue)

    return newValue
```

## Error Handling

The plugin gracefully handles errors:

| Error | Behavior |
|-------|----------|
| Not a number | Keeps original OctetString value |
| Out of range | Keeps original value, logs error |
| Wrong type | Keeps original value (only converts OctetString) |
| Parse error | Keeps original value, logs warning |

## Logging

The plugin provides detailed logging:

```
DEBUG: OID pattern "^1\.3\.6\.1\.2\.1\.1\.3\.0$" will convert strings to TimeTicks
DEBUG: converted string "12345" to TimeTicks(12345)
INFO:  converting float 123.456 to integer 123 for type Integer32
ERROR: value 5000000000 out of range for Counter32
```

## Testing

### Create a Mock Backend

For testing, you can use `snmpset` to create string OIDs:

```bash
# Set a string value (if writable)
snmpset -v2c -c private 127.0.0.1:10161 \
  .1.3.6.1.4.1.12345.1.0 s "12345"

# Query through proxy (should be converted)
snmpget -v2c -c public 127.0.0.1:1161 \
  .1.3.6.1.4.1.12345.1.0
```

### Verification

1. **Query backend directly** - should return OctetString
2. **Query through proxy** - should return numeric type
3. **Check type with `-Of` flag** for full OID display
4. **Verify value** is numerically correct

## Files

```
conf/command-forwarding-string-to-number/
├── server.conf                     Server with plugin
├── client.conf                     Client configuration
├── plugins/
│   └── string_to_number.conf      Conversion rules
└── README.md                       This file

plugins/
└── string_to_number.py            Plugin implementation (180 lines)
```

## Benefits

✅ **Fixes type mismatches** - Proper SNMP types for monitoring
✅ **Enables graphing** - Counters/Gauges can be graphed
✅ **Allows calculations** - Numeric operations work correctly
✅ **Improves compatibility** - Works with type-strict systems
✅ **Validates data** - Range checking ensures valid values
✅ **Transparent** - No backend changes needed

## Limitations

- Only converts OctetString values (not other types)
- Float values are truncated when converting to integer types
- Very large numbers may exceed type limits
- Non-numeric strings pass through unchanged
