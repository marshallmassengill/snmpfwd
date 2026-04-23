
SNMP Proxy Forwarder
--------------------

[![Python Versions](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](./LICENSE.txt)

The SNMP Proxy Forwarder tool works as an application-level proxy with a built-in
SNMP message router. SNMP forwarder design features split client/server operation
that promotes having one part of the system in DMZ while other part is
facing the Internet. Message routing can be programmed via a declarative
mini-language.

Typical use case for an SNMP proxy is to work as an application-level firewall
or a protocol translator that enables SNMPv3 access to a SNMPv1/SNMPv2c
entity or vice versa.

> This is a personal fork of [lextudio/snmpfwd](https://github.com/lextudio/snmpfwd)
> modernized against pysnmp-lextudio 7.x and asyncio. It is not published to PyPI
> — install it directly from this repository (see below).

Features
--------

* SNMPv1/v2c/v3 operations with built-in protocol and transport translation capabilities
* SNMPv3 USM supports MD5/SHA/SHA224/SHA256/SHA384/SHA512 auth and
  DES/3DES/AES128/AES192/AES256 privacy crypto algorithms
* Forwards SNMP commands and notifications, with end-to-end INFORM
  confirmation between the original sender and the downstream agent
* Maintains multiple independent SNMP engines and network transports
* Split client and server parts interconnected through encrypted TCP links
* Flexible SNMP PDU routing
* Extension modules supporting SNMP PDU filtering and on-the-fly modification
* Supports transparent proxy operation (Linux only)
* SIGHUP-triggered reload of routing maps and classifier lists (trunks,
  credentials, and plugins still require a restart)
* Runtime counters with periodic log dump (auth failures, routing misses,
  forwarded request/notification counts, INFORM ack outcomes, trunk up/down);
  interval configurable via `SNMPFWD_METRICS_INTERVAL`
* Works on Linux, Windows and macOS

Requirements
------------

* Python 3.11, 3.12 or 3.13
* pysnmp-lextudio 7.x, pyasn1 0.6.x, pycryptodomex 3.20+

Installation
------------

Install straight from the repository with `pip`:

```bash
$ pip install git+https://github.com/marshallmassengill/snmpfwd.git@rebuild
```

To pin a released version:

```bash
$ pip install git+https://github.com/marshallmassengill/snmpfwd.git@v0.5.0
```

Or clone the repository and install a local editable checkout (useful for
development):

```bash
$ git clone https://github.com/marshallmassengill/snmpfwd.git
$ cd snmpfwd
$ pip install -e .
```

The project uses [Poetry](https://python-poetry.org/) for dependency
management. If you have Poetry installed, `poetry install` inside the
clone will set up a virtualenv with the dev dependencies (pytest, Sphinx)
pulled in as well.

Both entry points (`snmpfwd-server` and `snmpfwd-client`) are exposed as
console scripts after install.

How to use SNMP proxy forwarder
-------------------------------

First you need to configure the tool. It is largely driven by
[configuration files](https://docs.lextudio.com/snmpfwd/configuration/index.html)
written in a declarative mini-language. To help you get started, a
[collection of example configs](./conf/) is included in this repository.

Run the two halves of the proxy:

```bash
$ snmpfwd-server --config-file=/path/to/server.conf --log-level=info
$ snmpfwd-client --config-file=/path/to/client.conf --log-level=info
```

Pass `--help` to either entry point for the full CLI reference.

Testing
-------

The repository ships a pytest suite covering unit tests and end-to-end
integration scenarios driven through the net-snmp CLI (`snmpget`,
`snmpwalk`, `snmpinform`, ...):

```bash
$ pip install -e .[dev]
$ pytest tests/
```

Integration tests require net-snmp and snmpsim-lextudio to be available on
`PATH`; unit tests run standalone.

Getting help
------------

This is a personal fork — issues and PRs are welcome on this repository,
but this code is not planned on being contributed directly back to
lextudio/snmpfwd upstream.

For questions about the upstream project, see
[lextudio/snmpfwd](https://github.com/lextudio/snmpfwd).

Copyright (c) 2014-2019, [Ilya Etingof](mailto:etingof@gmail.com).
Copyright (c) 2022, [LeXtudio Inc.](mailto:support@lextudio.com).
Copyright (c) 2026, [Marshall Massengill](mailto:marshallmassengill@gmail.com).
All rights reserved.
