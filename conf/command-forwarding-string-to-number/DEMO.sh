#!/bin/bash
#
# Demonstration of the string_to_number plugin
#

set -e

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║       SNMP STRING-TO-NUMBER PLUGIN DEMONSTRATION                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

echo "This demo shows how the plugin converts string values to numeric types."
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "THE PROBLEM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Some SNMP devices return numeric data as strings (OctetString)."
echo "This causes problems for:"
echo "  • Monitoring systems that need to graph values"
echo "  • Alerting tools that compare numbers"
echo "  • Data aggregation that performs calculations"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "EXAMPLE USE CASE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat << 'EOF'
Backend device returns:
  sysUpTime.0 = STRING: "12345"

Problem: Monitoring system can't graph a STRING value!

Solution: Plugin converts it to:
  sysUpTime.0 = Timeticks: (12345) 0:02:03.45

Now monitoring can graph, alert, and calculate with proper types!
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SUPPORTED TYPE CONVERSIONS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat << 'EOF'
String Input  →  Numeric SNMP Type

"12345"       →  Integer32(12345)
"98765"       →  Counter32(98765)
"1234567890"  →  Counter64(1234567890)
"100"         →  Gauge32(100)
"12345"       →  TimeTicks(12345)
"123.456"     →  Integer32(123)      [float truncated]
"-100"        →  Integer(-100)       [signed types only]

Invalid:
"abc"         →  OctetString("abc")  [kept as-is]
""            →  OctetString("")     [kept as-is]
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Plugin config file (plugins/string_to_number.conf):"
echo ""
cat plugins/string_to_number.conf
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ARCHITECTURE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat << 'EOF'
┌─────────────┐  ┌──────────────────┐  ┌────────────┐  ┌─────────┐
│SNMP Client  │  │snmpfwd-server    │  │snmpfwd-    │  │Backend  │
│             │  │(port 1161)       │  │client      │  │Agent    │
│  Expects    │  │+ string_to_number│  │            │  │:10161   │
│  TimeTicks  │  │  plugin          │  │            │  │Returns  │
│             │  │                  │  │            │  │STRING   │
│   REQUEST   │  │                  │  │            │  │         │
├─────────────┤  ├──────────────────┤  ├────────────┤  ├─────────┤
│GET uptime   ├─►│ Forward via      ├─►│ Send GET   ├─►│         │
│             │  │ encrypted trunk  │  │            │  │         │
│             │  │                  │  │            │  │Response:│
│             │  │ Receive response │◄─┤ Receive    │◄─┤"12345"  │
│             │  │ STRING: "12345"  │  │ from agent │  │         │
│             │  │                  │  │            │  │         │
│             │  │ ▼ PLUGIN ▼       │  │            │  │         │
│             │  │ Convert to       │  │            │  │         │
│             │  │ TimeTicks(12345) │  │            │  │         │
│             │  │                  │  │            │  │         │
│RECEIVE      │  │                  │  │            │  │         │
│TimeTicks    │◄─┤ Send response    │  │            │  │         │
│(12345)      │  │                  │  │            │  │         │
└─────────────┘  └──────────────────┘  └────────────┘  └─────────┘
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "REAL-WORLD USE CASES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat << 'EOF'
1. Legacy Device Integration
   ─────────────────────────
   Old devices return all metrics as strings. Modern monitoring
   (Grafana, Prometheus exporters) needs typed values for graphing.

2. Custom SNMP Extensions
   ──────────────────────
   In-house device extensions return strings for simplicity.
   Plugin converts them to proper types for standard tools.

3. Protocol Translation
   ────────────────────
   Converting from text-based protocols (CSV, JSON) to SNMP.
   Plugin ensures proper SNMP types.

4. Monitoring System Compatibility
   ───────────────────────────────
   Systems like Nagios/Zabbix require:
   • Counter types for rate calculations
   • Gauge types for current value graphing
   • TimeTicks for uptime tracking

5. Data Aggregation
   ────────────────
   Combining data from multiple sources requires consistent types
   for mathematical operations.
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "To test this configuration, you would:"
echo "  1. Configure backend to return numeric values as strings"
echo "  2. Start snmpfwd-server and snmpfwd-client with this config"
echo "  3. Query through proxy - values converted to proper types!"
echo ""
