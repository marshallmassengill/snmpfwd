"""
Config templates for the integration test harness.

Kept as Python string constants rather than separate .conf.tmpl files so
tests can tweak per-scenario values without extra I/O. snmpfwd's own config
language uses ${...} macros which do not collide with Python str.format's {}.
"""
from __future__ import annotations

import dataclasses
from typing import Optional


@dataclasses.dataclass
class PluginSpec:
    """Plugin registration for either snmpfwd-server or snmpfwd-client."""
    plugin_id: str
    plugin_module: str
    plugin_options: str   # single line, e.g. "config=/path/to/oidfilter.conf"
    modules_path: str     # absolute path to the directory containing the .py


def _plugin_block(spec: Optional[PluginSpec]) -> str:
    if spec is None:
        return ""
    return (
        f"\nplugin-modules-path-list: {spec.modules_path}\n\n"
        "plugin-group {\n"
        f"  plugin-module: {spec.plugin_module}\n"
        f"  plugin-options: {spec.plugin_options}\n\n"
        f"  plugin-id: {spec.plugin_id}\n"
        "}\n"
    )


def _plugin_route_line(spec: Optional[PluginSpec]) -> str:
    if spec is None:
        return ""
    return f"\n  using-plugin-id-list: {spec.plugin_id}\n"


SERVER_CONF = """\
#
# snmpfwd-server config (integration test, generated)
#

config-version: 2
program-name: snmpfwd-server

snmp-credentials-group {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address: 127.0.0.1:{snmp_listen_port}

  snmp-engine-id: {snmp_engine_id}

  snmp-community-name: {listen_community}
  snmp-security-name: {listen_community}
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-credentials-id: creds-1
}}

context-group {{
  snmp-context-engine-id-pattern: .*?
  snmp-context-name-pattern: .*?

  snmp-context-id: any-context
}}

content-group {{
  snmp-pdu-type-pattern: .*?
  snmp-pdu-oid-prefix-pattern-list: .*?

  snmp-content-id: any-content
}}

peers-group {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address-pattern-list: .*?
  snmp-peer-address-pattern-list: .*?

  snmp-peer-id: 100
}}
{plugin_block}
trunking-group {{
  trunk-bind-address: 127.0.0.1
  trunk-peer-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: client

  trunk-id: trunk-1
}}

routing-map {{
  matching-snmp-context-id-list: any-context
  matching-snmp-content-id-list: any-content

  matching-snmp-credentials-id-list: creds-1
  matching-snmp-peer-id-list: 100
{plugin_route_line}
  using-trunk-id-list: trunk-1
}}
"""


CLIENT_CONF = """\
#
# snmpfwd-client config (integration test, generated)
#

config-version: 2
program-name: snmpfwd-client

peers-group {{
  snmp-engine-id: {snmp_engine_id}

  snmp-transport-domain: 1.3.6.1.6.1.1.1
  snmp-bind-address: 0.0.0.0:0

  snmp-peer-timeout: 500
  snmp-peer-retries: 0

  snmp-community-name: {backend_community}
  snmp-security-name: backend
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-peer-address: 127.0.0.1:{backend_port}
  snmp-peer-id: backend-1
}}
{plugin_block}
trunking-group {{
  trunk-bind-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: server

  trunk-id: <discover>
}}

server-snmp-entity-info-group {{
  server-snmp-bind-address-pattern: .*?
  server-snmp-context-name-pattern: .*?

  server-snmp-pdu-type-pattern: .*?
  server-snmp-oid-prefix-pattern: .*?

  server-snmp-engine-id-pattern: .*?
  server-snmp-context-engine-id-pattern: .*?

  server-snmp-transport-domain-pattern: .*?
  server-snmp-peer-address-pattern: .*?

  server-snmp-security-level-pattern: .*?
  server-snmp-security-name-pattern: .*?
  server-snmp-security-model-pattern: .*?

  server-snmp-entity-id: any-manager
}}

server-classification-group {{
  server-snmp-context-id-pattern: .*?
  server-snmp-content-id-pattern: .*?
  server-snmp-peer-id-pattern: .*?
  server-snmp-credentials-id-pattern: .*?

  server-classification-id: pass-through
}}

routing-map {{
  matching-trunk-id-list: trunk-1
  matching-server-snmp-entity-id-list: any-manager
  matching-server-classification-id-list: pass-through
{plugin_route_line}
  using-snmp-peer-id-list: backend-1
}}
"""


SNMPD_CONF = """\
# net-snmp snmpd config (integration test, generated)
rocommunity {community} 127.0.0.1
syslocation "{sys_location}"
syscontact "{sys_contact}"
sysServices 72
"""


SNMPTRAPD_CONF = """\
# net-snmp snmptrapd config (integration test, generated)
authCommunity log,execute,net {community}
disableAuthorization yes
"""


# Trap-forwarding variant of the server config: listens for incoming SNMP
# notifications (TRAPv1 / TRAPv2c) and forwards them over the trunk. Differs
# from SERVER_CONF in content-group's snmp-pdu-type-pattern + snmp-content-id.
SERVER_TRAP_CONF = """\
#
# snmpfwd-server config (integration test, trap forwarding)
#

config-version: 2
program-name: snmpfwd-server

snmp-credentials-group {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address: 127.0.0.1:{snmp_listen_port}

  snmp-engine-id: {snmp_engine_id}

  snmp-community-name: {listen_community}
  snmp-security-name: {listen_community}
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-credentials-id: creds-1
}}

context-group {{
  snmp-context-engine-id-pattern: .*?
  snmp-context-name-pattern: .*?

  snmp-context-id: any-context
}}

content-group {{
  snmp-pdu-type-pattern: (TRAPv1|TRAPv2|INFORM)
  snmp-pdu-oid-prefix-pattern-list: .*?

  snmp-content-id: trap-content
}}

peers-group {{
  snmp-transport-domain: 1.3.6.1.6.1.1.100
  snmp-bind-address-pattern-list: .*?
  snmp-peer-address-pattern-list: .*?

  snmp-peer-id: 100
}}

trunking-group {{
  trunk-bind-address: 127.0.0.1
  trunk-peer-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: client

  trunk-id: trunk-1
}}

routing-map {{
  matching-snmp-credentials-id-list: creds-1
  matching-snmp-context-id-list: any-context
  matching-snmp-content-id-list: trap-content
  matching-snmp-peer-id-list: 100

  using-trunk-id-list: trunk-1
}}
"""


# Trap-forwarding variant of the client config: receives trunk messages and
# forwards them as SNMP notifications to a downstream trap receiver.
CLIENT_TRAP_CONF = """\
#
# snmpfwd-client config (integration test, trap forwarding)
#

config-version: 2
program-name: snmpfwd-client

peers-group {{
  snmp-engine-id: {snmp_engine_id}

  snmp-transport-domain: 1.3.6.1.6.1.1.1
  snmp-bind-address: 0.0.0.0:0

  snmp-peer-timeout: 500
  snmp-peer-retries: 0

  snmp-community-name: {backend_community}
  snmp-security-name: backend
  snmp-security-model: 2
  snmp-security-level: 1

  snmp-peer-address: 127.0.0.1:{backend_port}
  snmp-peer-id: backend-1
}}

trunking-group {{
  trunk-bind-address: 127.0.0.1:{trunk_port}
  trunk-ping-period: 60
  trunk-connection-mode: server

  trunk-id: <discover>
}}

server-snmp-entity-info-group {{
  server-snmp-bind-address-pattern: .*?
  server-snmp-context-name-pattern: .*?

  server-snmp-pdu-type-pattern: (TRAPv1|TRAPv2|INFORM)
  server-snmp-oid-prefix-pattern: .*?

  server-snmp-engine-id-pattern: .*?
  server-snmp-context-engine-id-pattern: .*?

  server-snmp-transport-domain-pattern: .*?
  server-snmp-peer-address-pattern: .*?

  server-snmp-security-level-pattern: .*?
  server-snmp-security-name-pattern: .*?
  server-snmp-security-model-pattern: .*?

  server-snmp-entity-id: any-agent
}}

server-classification-group {{
  server-snmp-credentials-id-pattern: .*?
  server-snmp-context-id-pattern: .*?
  server-snmp-content-id-pattern: .*?
  server-snmp-peer-id-pattern: .*?

  server-classification-id: pass-through
}}

routing-map {{
  matching-trunk-id-list: trunk-1
  matching-server-snmp-entity-id-list: any-agent
  matching-server-classification-id-list: pass-through

  using-snmp-peer-id-list: backend-1
}}
"""


def render_server_conf(*, snmp_listen_port: int, snmp_engine_id: str,
                       listen_community: str, trunk_port: int,
                       plugin: Optional[PluginSpec] = None) -> str:
    return SERVER_CONF.format(
        snmp_listen_port=snmp_listen_port,
        snmp_engine_id=snmp_engine_id,
        listen_community=listen_community,
        trunk_port=trunk_port,
        plugin_block=_plugin_block(plugin),
        plugin_route_line=_plugin_route_line(plugin),
    )


def render_client_conf(*, snmp_engine_id: str, backend_community: str,
                       backend_port: int, trunk_port: int,
                       plugin: Optional[PluginSpec] = None) -> str:
    return CLIENT_CONF.format(
        snmp_engine_id=snmp_engine_id,
        backend_community=backend_community,
        backend_port=backend_port,
        trunk_port=trunk_port,
        plugin_block=_plugin_block(plugin),
        plugin_route_line=_plugin_route_line(plugin),
    )


def render_snmpd_conf(*, community: str, sys_location: str, sys_contact: str) -> str:
    return SNMPD_CONF.format(
        community=community,
        sys_location=sys_location,
        sys_contact=sys_contact,
    )


def render_snmptrapd_conf(*, community: str) -> str:
    return SNMPTRAPD_CONF.format(community=community)


def render_server_trap_conf(*, snmp_listen_port: int, snmp_engine_id: str,
                            listen_community: str, trunk_port: int) -> str:
    return SERVER_TRAP_CONF.format(
        snmp_listen_port=snmp_listen_port,
        snmp_engine_id=snmp_engine_id,
        listen_community=listen_community,
        trunk_port=trunk_port,
    )


def render_client_trap_conf(*, snmp_engine_id: str, backend_community: str,
                            backend_port: int, trunk_port: int) -> str:
    return CLIENT_TRAP_CONF.format(
        snmp_engine_id=snmp_engine_id,
        backend_community=backend_community,
        backend_port=backend_port,
        trunk_port=trunk_port,
    )
