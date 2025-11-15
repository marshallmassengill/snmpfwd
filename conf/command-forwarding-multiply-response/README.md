# SNMP Multiply Plugin Example

This example demonstrates the **multiply plugin** which multiplies numeric SNMP response values by a configurable factor.

## Use Case

This plugin is useful for:
- **Testing**: Simulate higher traffic/counter values without actual traffic
- **Scaling**: Scale up/down reported values for visualization
- **Demonstration**: Show SNMP proxy modification capabilities

## How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌────────────┐     ┌─────────┐
│ SNMP Client │────►│ snmpfwd-server   │────►│ snmpfwd-   │────►│ Backend │
│             │     │ (port 1161)      │     │ client     │     │ Agent   │
│             │     │ + multiply plugin│     │            │     │ :10161  │
│             │◄────│                  │◄────│            │◄────│         │
└─────────────┘     └──────────────────┘     └────────────┘     └─────────┘
                             │
                             ▼
                    Multiply numeric
                    values by 10
```

## Plugin Features

1. **Selective Multiplication**: Use regex patterns to target specific OIDs
2. **Type-Safe**: Only multiplies numeric SNMP types (Integer, Counter, Gauge, TimeTicks, etc.)
3. **Configurable Factors**: Different OID patterns can have different multipliers
4. **Global or Specific**: Apply a global multiplier or OID-specific rules

## Configuration

### Server Config (`server.conf`)

```
plugin-group {
  plugin-module: multiply
  plugin-options: config=${config-dir}/plugins/multiply.conf

  plugin-id: multiply-numeric-values
}

routing-map {
  using-plugin-id-list: multiply-numeric-values
  using-trunk-id-list: trunk-1
}
```

### Plugin Config (`plugins/multiply.conf`)

```
# Format: "OID-pattern" multiplier

# Multiply sysUpTime by 10
"^1\.3\.6\.1\.2\.1\.1\.3\.0$" 10

# Multiply interface counters by 100
"^1\.3\.6\.1\.2\.1\.2\.2\.1\.10\..*$" 100

# Multiply all system branch values by 10
"^1\.3\.6\.1\.2\.1\.1\..*$" 10
```

## Example Output

### Direct Query (Backend Agent)

```bash
$ snmpget -v2c -c public 127.0.0.1:10161 sysUpTime.0
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (5295) 0:00:52.95
```

**Value: 5295 (52.95 seconds)**

### Through Proxy (with multiply plugin)

```bash
$ snmpget -v2c -c public 127.0.0.1:1161 sysUpTime.0
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (52950) 0:08:49.50
```

**Value: 52950 (8 minutes 49.5 seconds) = 5295 × 10**

## Plugin Options

### Option 1: Global Multiplier (no config file)

```
plugin-options: factor=10
```

Multiplies ALL numeric values by 10.

### Option 2: OID-Specific Rules (with config file)

```
plugin-options: config=/path/to/multiply.conf
```

Apply different multipliers to different OID patterns.

## Supported SNMP Types

The plugin multiplies these numeric types:
- **Integer** / **Integer32**
- **Counter32** / **Counter64**
- **Gauge32**
- **Unsigned32**
- **TimeTicks**

Non-numeric types (OctetString, IpAddress, etc.) pass through unchanged.

## Running This Example

1. **Start the backend SNMP agent** (already running on port 10161)

2. **Start the server** with multiply plugin:
   ```bash
   poetry run snmpfwd-server --config-file=server.conf \
     --process-user=nobody --process-group=nogroup
   ```

3. **Start the client**:
   ```bash
   poetry run snmpfwd-client --config-file=client.conf \
     --process-user=nobody --process-group=nogroup
   ```

4. **Test direct query**:
   ```bash
   snmpget -v2c -c public 127.0.0.1:10161 sysUpTime.0
   ```

5. **Test through proxy** (value should be 10x larger):
   ```bash
   snmpget -v2c -c public 127.0.0.1:1161 sysUpTime.0
   ```

## Plugin Implementation Highlights

```python
def multiplyValue(val, factor):
    """Multiply a value by the given factor, preserving SNMP type."""

    numericTypes = (
        v2c.Integer, v2c.Integer32, v2c.Counter32,
        v2c.Gauge32, v2c.Unsigned32, v2c.TimeTicks,
        v2c.Counter64
    )

    for numType in numericTypes:
        if val.tagSet == numType.tagSet:
            originalValue = int(val)
            newValue = int(originalValue * factor)
            return val.clone(newValue)

    return val  # Non-numeric, unchanged
```

## Architecture Notes

- **Plugin runs on server side** (where responses are received from client)
- **Processes after backend response** but before sending to SNMP client
- **Preserves SNMP data types** (Counter stays Counter, Gauge stays Gauge)
- **OID patterns use regex** for flexible matching
- **Can be combined** with other plugins (rewrite, filtering, etc.)
