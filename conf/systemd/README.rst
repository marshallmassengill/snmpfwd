systemd unit files
==================

Drop-in unit files for running the two halves of snmpfwd under systemd.

Files
-----

* ``snmpfwd-server.service`` — runs the server (SNMP listener + trunk client)
* ``snmpfwd-client.service`` — runs the client (trunk server + SNMP manager)

Install
-------

1. Install snmpfwd so that ``snmpfwd-server`` and ``snmpfwd-client`` are
   on the system PATH. The unit files assume the default pip install
   location of ``/usr/local/bin/``. If you installed into a virtualenv
   or a different prefix, edit the ``ExecStart`` lines accordingly.

2. Create the config directory and drop your own configs there::

       sudo install -d -m 0755 /etc/snmpfwd
       sudo install -m 0644 server.conf /etc/snmpfwd/server.conf
       sudo install -m 0644 client.conf /etc/snmpfwd/client.conf

3. Copy the unit files into place and reload systemd::

       sudo install -m 0644 snmpfwd-server.service /etc/systemd/system/
       sudo install -m 0644 snmpfwd-client.service /etc/systemd/system/
       sudo systemctl daemon-reload

4. Enable and start::

       sudo systemctl enable --now snmpfwd-server.service
       sudo systemctl enable --now snmpfwd-client.service

5. Tail the journal to watch startup and request flow::

       sudo journalctl -u snmpfwd-server -f

Reloading
---------

Both units support ``systemctl reload`` which sends ``SIGHUP``. That
triggers an on-the-fly reload of the routing maps, classifier lists,
and plugin modules without dropping in-flight traffic. Changes to
trunks or credentials still require a full restart
(``systemctl restart``).

Running as a dedicated user
---------------------------

The units use ``DynamicUser=yes`` by default, which lets systemd
allocate a transient service user. If you prefer a fixed account (for
ownership on mounted paths, audit trails, etc.), replace::

    DynamicUser=yes

with::

    User=snmpfwd
    Group=snmpfwd

and create the account::

    sudo useradd --system --no-create-home --shell /usr/sbin/nologin snmpfwd

Privileged ports
----------------

The server unit ships ``CAP_NET_BIND_SERVICE`` so the listener can bind
to 161/udp without running as root. Comment those lines out if your
configuration only uses ports ≥ 1024.

Transparent proxy deployment
----------------------------

The stock units do NOT enable ``transparent-proxy`` mode. Transparent
proxy requires extra kernel capabilities and out-of-band routing
setup; turning it on requires changes beyond the stock service files.
``virtual-interface`` mode has the same capability requirements.

**1. Capabilities.** Both sides need ``CAP_NET_ADMIN`` to set
``IP_TRANSPARENT`` on their sockets. Client-side transparent-proxy /
virtual-interface also wants ``CAP_NET_RAW`` for spoofed-source
sends. Both unit files ship with a commented-out alternative
``CapabilityBoundingSet`` / ``AmbientCapabilities`` pair — uncomment
the alternative and comment out the default, e.g. on the server::

    # CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    # AmbientCapabilities=CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
    AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

and on the client::

    CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
    AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

``NoNewPrivileges=yes`` is fine — ambient capabilities survive it as
long as both ``BoundingSet`` and ``AmbientCapabilities`` include the
needed caps.

**2. iptables + routing.** The kernel-side TPROXY plumbing lives
outside snmpfwd. A typical host-level setup that the snmpfwd-server
socket relies on (for an SNMP-listener port of 1161, say)::

    # Mark packets destined for the virtual subnet on UDP/161 and
    # hand them to the snmpfwd-server socket.
    iptables -t mangle -A PREROUTING -p udp --dport 161 \
        -d <virtual-subnet>/<prefix> \
        -j TPROXY --tproxy-mark 0x1/0x1 --on-port 1161

    # Deliver fwmark-matched packets to local sockets regardless of
    # the original destination IP.
    ip rule add fwmark 0x1 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100

    # net.ipv4.ip_forward=1 is required for TPROXY on most kernels.
    sysctl -w net.ipv4.ip_forward=1

Ship that as a ``oneshot`` systemd unit (e.g.
``snmpfwd-tproxy-setup.service``) and declare a dependency on it from
the snmpfwd units so the ordering is correct::

    [Unit]
    ...
    After=network-online.target snmpfwd-tproxy-setup.service
    Wants=network-online.target snmpfwd-tproxy-setup.service

Without this, snmpfwd-server starts with an IP_TRANSPARENT socket
that the kernel never routes traffic to, and every query times out.

See ``docs/source/configuration/examples/command-forwarding-transparent-proxy.rst``
for the accompanying snmpfwd config.

.. note::

   Under pysnmp 7's asyncio carrier the ``IP_PKTINFO`` ancillary data
   that would normally expose the per-packet original destination IP
   to snmpfwd isn't surfaced. Transparent-proxy INGRESS works (packets
   reach the listener, get forwarded, and the response goes back with
   the intercepted source address), but if your routing / log macros
   need the per-virtual-IP original destination, fall back to
   ``virtual-interface`` mode with explicit per-IP binds instead.
