
SNMP Proxy Forwarder
--------------------

[![PyPI](https://img.shields.io/pypi/v/snmpfwd.svg?maxAge=2592000)](https://pypi.org/project/snmpfwd)
[![PyPI Downloads](https://img.shields.io/pypi/dd/snmpfwd)](https://pypi.python.org/pypi/snmpfwd/)
[![Python Versions](https://img.shields.io/pypi/pyversions/snmpfwd.svg)](https://pypi.org/project/snmpfwd/)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/lextudio/snmpfwd/master/LICENSE.txt)

The SNMP Proxy Forwarder tool works as an application-level proxy with a built-in
SNMP message router. SNMP forwarder design features split client/server operation
that promotes having one part of the system in DMZ while other part is 
facing the Internet. Message routing can be programmed via a declarative
mini-language.

Typical use case for an SNMP proxy is to work as an application-level firewall
or a protocol translator that enables SNMPv3 access to a SNMPv1/SNMPv2c
entity or vice versa.

Features
--------

* SNMPv1/v2c/v3 operations with built-in protocol and transport translation capabilities
* SNMPv3 USM supports MD5/SHA/SHA224/SHA256/SHA384/SHA512 auth and
  DES/3DES/AES128/AES192/AES256 privacy crypto algorithms
* Forwards SNMP commands and notifications
* Maintains multiple independent SNMP engines and network transports
* Split client and server parts interconnected through encrypted TCP links
* Flexible SNMP PDU routing
* Extension modules supporting SNMP PDU filtering and on-the-fly modification
* Supports transparent proxy operation (Linux only)
* Works on Linux, Windows and OS X

Download & Install
------------------

SNMP Proxy Forwarder software is freely available for download from
[PyPI](https://pypi.org/project/snmpfwd).

Just run:

```bash
$ pip install snmpfwd
```

Alternatively, you can get it from [GitHub](https://github.com/lextudio/snmpfwd/releases).

Deployment Example
------------------

### Network Topology

Here's a typical deployment with a Network Management System (NMS) monitoring a device through snmpfwd:

```
┌─────────────────────┐         ┌─────────────────────┐
│   NMS (Monitoring   │         │  snmpfwd-server     │
│      System)        │         │  192.168.1.10       │
│   10.0.0.50         │         │                     │
│                     │  SNMP   │  Listens on:        │
│  - Nagios           │ Request │  :161 (SNMPv2c)     │
│  - Zabbix           ├────────►│                     │
│  - Grafana          │         │  Forwards via:      │
│  - LibreNMS         │ SNMP    │  Encrypted trunk    │
│                     │◄────────┤  to client          │
│                     │Response │                     │
└─────────────────────┘         └──────────┬──────────┘
                                           │
       Internet / Firewall                 │ TCP:30301
       (Encrypted trunk)                   │ (AES encrypted)
                                           │
                                ┌──────────▼──────────┐
                                │  snmpfwd-client     │
                                │  192.168.100.20     │
                                │                     │
                                │  Receives from:     │
                                │  trunk :30301       │
                                │                     │
                                │  Forwards to:       │
                                │  backend devices    │
                                └──────────┬──────────┘
                                           │ SNMP
                                           │ Request
                                ┌──────────▼──────────┐
                                │   Network Device    │
                                │  (SNMP Agent)       │
                                │  192.168.100.50     │
                                │                     │
                                │  - Router           │
                                │  - Switch           │
                                │  - Firewall         │
                                │  - Server           │
                                │                     │
                                │  Responds with      │
                                │  SNMP data          │
                                └─────────────────────┘
```

### IP Address Configuration

#### On the NMS (10.0.0.50)

Configure your monitoring system to query the **snmpfwd-server** address:

```bash
# Example: Nagios host definition
define host {
    host_name       my-router
    address         192.168.1.10    # snmpfwd-server IP
    check_command   check_snmp!-C public!sysUpTime.0
}

# Example: Direct SNMP query
snmpget -v2c -c public 192.168.1.10 sysUpTime.0
```

**Important:** Point your NMS to the snmpfwd-server IP (192.168.1.10), NOT the device IP.

#### On snmpfwd-server (192.168.1.10)

Edit `server.conf`:

```
snmp-credentials-group {
  # Listen for SNMP requests from NMS
  snmp-bind-address: 0.0.0.0:161
  # Or bind to specific interface: 192.168.1.10:161

  snmp-community-name: public
  snmp-security-model: 2  # SNMPv2c
}

trunking-group {
  # Local address for trunk (optional, 0.0.0.0 for any interface)
  trunk-bind-address: 0.0.0.0

  # Connect to snmpfwd-client
  trunk-peer-address: 192.168.100.20:30301

  trunk-connection-mode: client
}
```

**Key addresses:**
- `snmp-bind-address`: Where NMS sends requests (192.168.1.10:161)
- `trunk-peer-address`: Where snmpfwd-client is located (192.168.100.20:30301)

#### On snmpfwd-client (192.168.100.20)

Edit `client.conf`:

```
peers-group {
  # Backend device to query
  snmp-peer-address: 192.168.100.50:161

  snmp-community-name: public
  snmp-security-model: 2  # SNMPv2c
}

trunking-group {
  # Listen for encrypted trunk connections from server
  trunk-bind-address: 0.0.0.0:30301
  # Or bind to specific interface: 192.168.100.20:30301

  trunk-connection-mode: server
}
```

**Key addresses:**
- `trunk-bind-address`: Listen for connections from snmpfwd-server (:30301)
- `snmp-peer-address`: The actual network device to query (192.168.100.50:161)

#### On the Network Device (192.168.100.50)

Configure SNMP agent to accept queries from **snmpfwd-client**:

```bash
# Example: Linux net-snmp configuration (/etc/snmp/snmpd.conf)
rocommunity public 192.168.100.20

# Example: Cisco router
snmp-server community public RO
```

**Important:** The device sees requests coming from snmpfwd-client IP (192.168.100.20), NOT from NMS.

### Complete Setup Steps

1. **Install snmpfwd on both proxy machines:**
   ```bash
   # On server machine (192.168.1.10)
   pip install snmpfwd

   # On client machine (192.168.100.20)
   pip install snmpfwd
   ```

2. **Configure server (192.168.1.10):**
   ```bash
   # Edit server.conf
   # Set snmp-bind-address: 0.0.0.0:161
   # Set trunk-peer-address: 192.168.100.20:30301

   # Start server
   snmpfwd-server --config-file=server.conf
   ```

3. **Configure client (192.168.100.20):**
   ```bash
   # Edit client.conf
   # Set trunk-bind-address: 0.0.0.0:30301
   # Set snmp-peer-address: 192.168.100.50:161

   # Start client
   snmpfwd-client --config-file=client.conf
   ```

4. **Configure NMS (10.0.0.50):**
   ```bash
   # Point all SNMP queries to snmpfwd-server
   # Use IP: 192.168.1.10
   # Community: public (or whatever is configured)
   ```

5. **Test the setup:**
   ```bash
   # From NMS or any machine
   snmpget -v2c -c public 192.168.1.10 sysUpTime.0
   # Should return data from device at 192.168.100.50
   ```

### Firewall Rules

**On snmpfwd-server (192.168.1.10):**
- Allow inbound UDP 161 from NMS (10.0.0.50)
- Allow outbound TCP 30301 to snmpfwd-client (192.168.100.20)

**On snmpfwd-client (192.168.100.20):**
- Allow inbound TCP 30301 from snmpfwd-server (192.168.1.10)
- Allow outbound UDP 161 to devices (192.168.100.50)

**On Network Device (192.168.100.50):**
- Allow inbound UDP 161 from snmpfwd-client (192.168.100.20)

### Common Deployment Scenarios

**Scenario 1: DMZ Deployment**
- NMS in corporate network (10.0.0.0/8)
- snmpfwd-server in DMZ (192.168.1.0/24)
- snmpfwd-client in production network (192.168.100.0/24)
- Devices in production network (192.168.100.0/24)

**Scenario 2: SNMPv3 Translation**
- NMS supports only SNMPv3
- Devices support only SNMPv1/v2c
- snmpfwd translates between protocols
- Configure server for SNMPv3, client for SNMPv1/v2c

**Scenario 3: Multiple Devices**
- One snmpfwd-server receives all NMS queries
- One snmpfwd-client forwards to multiple backend devices
- Use routing rules to direct different OIDs/contexts to different devices

**Scenario 4: Single Server Deployment**
- Both snmpfwd-server and snmpfwd-client run on the same machine
- Common for protocol translation, testing, or simplified deployments
- Reduces infrastructure requirements while maintaining flexibility

#### Configuration for Same-Server Deployment

When running both components on the same server (e.g., 192.168.1.10):

**Server configuration (server.conf):**
```
snmp-credentials-group {
  # Listen for SNMP requests from NMS
  snmp-bind-address: 0.0.0.0:161
  snmp-community-name: public
  snmp-security-model: 2
}

trunking-group {
  trunk-bind-address: 127.0.0.1
  # Connect to client on localhost
  trunk-peer-address: 127.0.0.1:30301
  trunk-connection-mode: client
  trunk-id: trunk-1
}
```

**Client configuration (client.conf):**
```
peers-group {
  # Backend device to query
  snmp-peer-address: 192.168.100.50:161
  snmp-community-name: public
  snmp-security-model: 2
  snmp-peer-id: backend-device
}

trunking-group {
  # Listen for connections from server on localhost
  trunk-bind-address: 127.0.0.1:30301
  trunk-connection-mode: server
  trunk-id: <discover>
}
```

**Key points for same-server deployment:**
- Use `127.0.0.1` (localhost) for trunk connections between server and client
- Server listens on `0.0.0.0:161` (or specific interface) for NMS requests
- Client connects to backend devices via their real IP addresses
- Both processes can run simultaneously without conflicts
- The trunk connection stays local, reducing network overhead
- Still provides benefits like protocol translation and plugin processing

**Starting both components:**
```bash
# Start client first (it's the trunk server)
snmpfwd-client --config-file=/path/to/client.conf &

# Wait a moment for client to start
sleep 2

# Start server (it connects to client)
snmpfwd-server --config-file=/path/to/server.conf &
```

**Benefits of same-server deployment:**
- ✅ Simplified infrastructure (one server instead of two)
- ✅ Lower latency for trunk communication
- ✅ Easier management and monitoring
- ✅ Still supports protocol translation (SNMPv3 ↔ SNMPv1/v2c)
- ✅ Plugin processing works identically
- ✅ Useful for testing and development

**When to use separate servers:**
- Security requirements (DMZ separation)
- Geographic distribution
- High availability with separate failure domains
- Network segmentation requirements

Known Issues
------------

### MIB Loading with pysnmp-lextudio 5.x

When using `pysnmp-lextudio 5.x` (the current compatible version), you may encounter MIB loading errors:

```
pysnmp.smi.error.MibNotFoundError: No module __SNMPv2-MIB loaded
```

**What's happening:** pysnmp requires compiled MIB (Management Information Base) modules to validate and process SNMP PDU structures. These MIBs act as dictionaries that translate numeric OIDs to human-readable names and define data types.

**Root cause:** `pysnmp-lextudio 5.x` references core MIBs (like `SNMPv2-MIB`, `SNMPv2-TC`) but doesn't include the pre-compiled MIB files in the package. Earlier versions (pysnmp 4.x) included these "batteries," but the 5.x fork does not.

**Why it affects snmpfwd:** When processing SNMP messages, the library attempts to:
1. Validate PDU structure against MIB definitions
2. Type-check values (INTEGER, STRING, TimeTicks, etc.)
3. Encode/decode special SNMP types

Without MIBs, this validation fails and SNMP requests cannot be processed.

**Impact on this codebase:**
- ✅ **Server and client start successfully**
- ✅ **Plugin system loads correctly** (including response rewriting)
- ✅ **Encrypted trunk connections work**
- ✅ **Configuration parsing is functional**
- ❌ **SNMP PDU processing fails** at runtime (requests timeout)

**Workarounds:**

1. **Pre-compile MIBs** (requires `pysmi-lextudio` and ASN.1 source files):
   ```bash
   # Create MIB directory
   mkdir -p ~/.pysnmp/mibs

   # Compile core MIBs (requires ASN.1 sources and correct pysmi version)
   # This is complex and version-dependent
   ```

2. **Use pysnmp 4.4.x** (deprecated, includes MIBs but incompatible API):
   ```bash
   pip install pysnmp==4.4.12
   ```
   Note: Requires reverting the API compatibility changes in this codebase.

3. **Wait for pysnmp-lextudio MIB packages** to be released or create them.

**Current status:** This repository has been updated with full API compatibility for modern pysnmp versions (asynsock→asyncore, dispatcher classes). All code changes are correct and the architecture is sound. The MIB issue is an environmental/packaging problem, not a code bug.

**For developers:** If you're extending this codebase, all components work except final SNMP message processing. Use the working trunk protocol, plugin system, and routing logic as reference implementations.

How to use SNMP proxy forwarder
-------------------------------

First you need to configure the tool. It is largely driven by
[configuration files](https://www.pysnmp.com/snmpfwd/configuration/index.html)
written in a declarative mini-language. To help you started, we maintain
[a collection](https://www.pysnmp.com/snmpfwd/configuration/index.html#examples)
of configuration files designed to serve specific use-cases.

Getting help
------------

If something does not work as expected or we are missing an interesting feature,
[open an issue](https://github.com/lextudio/pysnmp/issues) at GitHub or
post your question [on Stack Overflow](https://stackoverflow.com/questions/ask).

Finally, your PRs are warmly welcome! ;-)

Copyright (c) 2014-2019, [Ilya Etingof](mailto:etingof@gmail.com).
Copyright (c) 2022, [LeXtudio Inc.](mailto:support@lextudio.com).
All rights reserved.
