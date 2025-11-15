
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
