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
triggers an on-the-fly reload of the routing maps and classifier lists
without dropping in-flight traffic. Changes to trunks, credentials, or
plugin modules still require a full restart (``systemctl restart``).

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

Privileged ports and transparent proxy
--------------------------------------

The server unit ships ``CAP_NET_BIND_SERVICE`` so the listener can bind
to 161/udp without running as root. Comment those lines out if your
configuration only uses ports ≥ 1024.

For transparent-proxy or virtual-interface deployments on Linux the
client needs ``CAP_NET_ADMIN`` and ``CAP_NET_RAW`` — the relevant
directives are present in the client unit file, commented out.
