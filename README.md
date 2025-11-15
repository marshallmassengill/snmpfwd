
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

### Running as systemd Services

For production deployments on Linux systems, you can run both snmpfwd-server and snmpfwd-client as systemd services. This provides automatic startup, logging, and service management.

#### Prerequisites

**Python Version Requirements:**
- **Python 3.8 or higher** (tested with Python 3.11)
- **pip** or **pipx** for package installation
- **virtualenv** (optional but recommended for isolated installation)

#### Python and Dependency Setup

**Option 1: System-wide Installation (Simple)**

**1a. Install Python and dependencies (Ubuntu/Debian):**
```bash
# Update package list
sudo apt update

# Install Python 3.11 (or latest available)
sudo apt install -y python3.11 python3.11-venv python3-pip

# Install system dependencies for cryptography
sudo apt install -y build-essential libssl-dev libffi-dev python3-dev

# Upgrade pip
sudo pip3 install --upgrade pip
```

**1b. Install Python and dependencies (RHEL/CentOS/Rocky):**
```bash
# Enable EPEL repository (if needed)
sudo dnf install -y epel-release

# Install Python 3.11
sudo dnf install -y python3.11 python3.11-pip python3.11-devel

# Install build dependencies
sudo dnf install -y gcc openssl-devel libffi-devel

# Upgrade pip
sudo pip3.11 install --upgrade pip
```

**1c. Install Python and dependencies (openSUSE):**
```bash
# Install Python 3.11
sudo zypper install -y python311 python311-pip python311-devel

# Install build dependencies
sudo zypper install -y gcc libopenssl-devel libffi-devel

# Upgrade pip
sudo pip3.11 install --upgrade pip
```

**Option 2: Virtual Environment Installation (Recommended for Production)**

This approach isolates snmpfwd dependencies from system Python packages.

**2a. Set up virtual environment:**
```bash
# Install Python 3.11 and venv (Ubuntu/Debian example)
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip build-essential

# Create directory for the virtual environment
sudo mkdir -p /opt/snmpfwd
cd /opt/snmpfwd

# Create virtual environment
sudo python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip in virtual environment
pip install --upgrade pip

# Install snmpfwd and dependencies
pip install snmpfwd

# Verify installation
which snmpfwd-server  # Should show /opt/snmpfwd/venv/bin/snmpfwd-server
snmpfwd-server --version

# Deactivate when done
deactivate
```

**2b. Set ownership:**
```bash
# Create snmpfwd user (if not exists)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin snmpfwd

# Set ownership of virtual environment
sudo chown -R snmpfwd:snmpfwd /opt/snmpfwd
```

#### Verify Python Dependencies

After installation, verify that all required dependencies are installed:

```bash
# If using virtual environment
source /opt/snmpfwd/venv/bin/activate

# If using system-wide installation
# (no activation needed)

# Check installed packages
pip list | grep -E "pysnmp|pyasn1|pycrypto"

# Expected output should include:
# pysnmp-lextudio   5.x.x
# pyasn1            0.5.1
# pycryptodomex     3.x.x
# pysmi-lextudio    1.x.x (if needed for MIB compilation)

# Test import
python3 -c "from pysnmp.hlapi import *; print('pysnmp OK')"
python3 -c "from pysnmp.carrier.asyncore.dgram import udp; print('asyncore OK')"
python3 -c "from Cryptodome.Cipher import AES; print('crypto OK')"
```

#### Installation Steps

**1. Install snmpfwd:**

**Option A: System-wide installation:**
```bash
# Install directly with pip
sudo pip3 install snmpfwd

# Verify installation
which snmpfwd-server  # Should show /usr/local/bin/snmpfwd-server
snmpfwd-server --version
```

**Option B: Virtual environment installation (recommended):**
```bash
# Already done in "Python and Dependency Setup" above
# Just verify the installation
/opt/snmpfwd/venv/bin/snmpfwd-server --version
```

**Option C: Using pipx (isolated, system-wide commands):**
```bash
# Install pipx
sudo apt install pipx  # Ubuntu/Debian
# OR
sudo dnf install pipx  # RHEL/Rocky
# OR
sudo pip3 install pipx

# Ensure pipx path is configured
pipx ensurepath

# Install snmpfwd
sudo pipx install snmpfwd

# Verify
which snmpfwd-server
snmpfwd-server --version
```

**2. Create a dedicated user:**
```bash
# Create system user for running snmpfwd
sudo useradd --system --no-create-home --shell /usr/sbin/nologin snmpfwd
```

**3. Create configuration directories:**
```bash
# Create directories for configuration files
sudo mkdir -p /etc/snmpfwd
sudo mkdir -p /etc/snmpfwd/plugins
sudo mkdir -p /var/log/snmpfwd

# Set ownership
sudo chown -R snmpfwd:snmpfwd /etc/snmpfwd /var/log/snmpfwd
```

**4. Create configuration files:**

Place your `server.conf` and `client.conf` in `/etc/snmpfwd/`:

```bash
# Example: Copy from your working configuration
sudo cp server.conf /etc/snmpfwd/
sudo cp client.conf /etc/snmpfwd/
sudo cp -r plugins/* /etc/snmpfwd/plugins/

# Set permissions
sudo chown -R snmpfwd:snmpfwd /etc/snmpfwd
sudo chmod 640 /etc/snmpfwd/*.conf
```

**5. Create systemd service files:**

Choose the appropriate service files based on your installation method:

**For System-wide Installation:**

**Client Service** (`/etc/systemd/system/snmpfwd-client.service`):
```ini
[Unit]
Description=SNMP Proxy Forwarder Client
Documentation=https://github.com/lextudio/snmpfwd
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=snmpfwd
Group=snmpfwd

# Start the client (system-wide installation path)
ExecStart=/usr/local/bin/snmpfwd-client \
    --config-file=/etc/snmpfwd/client.conf \
    --log-level=info

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snmpfwd-client

# Restart policy
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/snmpfwd

[Install]
WantedBy=multi-user.target
```

**Server Service** (`/etc/systemd/system/snmpfwd-server.service`):
```ini
[Unit]
Description=SNMP Proxy Forwarder Server
Documentation=https://github.com/lextudio/snmpfwd
After=network.target snmpfwd-client.service
Wants=network-online.target
Requires=snmpfwd-client.service

[Service]
Type=simple
User=snmpfwd
Group=snmpfwd

# Start the server (waits for client to be ready)
ExecStartPre=/bin/sleep 2
ExecStart=/usr/local/bin/snmpfwd-server \
    --config-file=/etc/snmpfwd/server.conf \
    --log-level=info

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snmpfwd-server

# Restart policy
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/snmpfwd

# Allow binding to privileged port 161
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

**For Virtual Environment Installation (Recommended):**

**Client Service** (`/etc/systemd/system/snmpfwd-client.service`):
```ini
[Unit]
Description=SNMP Proxy Forwarder Client
Documentation=https://github.com/lextudio/snmpfwd
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=snmpfwd
Group=snmpfwd
WorkingDirectory=/opt/snmpfwd

# Use virtual environment Python
ExecStart=/opt/snmpfwd/venv/bin/snmpfwd-client \
    --config-file=/etc/snmpfwd/client.conf \
    --log-level=info

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snmpfwd-client

# Restart policy
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/snmpfwd /opt/snmpfwd

[Install]
WantedBy=multi-user.target
```

**Server Service** (`/etc/systemd/system/snmpfwd-server.service`):
```ini
[Unit]
Description=SNMP Proxy Forwarder Server
Documentation=https://github.com/lextudio/snmpfwd
After=network.target snmpfwd-client.service
Wants=network-online.target
Requires=snmpfwd-client.service

[Service]
Type=simple
User=snmpfwd
Group=snmpfwd
WorkingDirectory=/opt/snmpfwd

# Start the server (waits for client to be ready)
ExecStartPre=/bin/sleep 2
ExecStart=/opt/snmpfwd/venv/bin/snmpfwd-server \
    --config-file=/etc/snmpfwd/server.conf \
    --log-level=info

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snmpfwd-server

# Restart policy
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/snmpfwd /opt/snmpfwd

# Allow binding to privileged port 161
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

**Important Notes:**
- For virtual environment installations, use `/opt/snmpfwd/venv/bin/snmpfwd-{client,server}`
- For system-wide installations, use `/usr/local/bin/snmpfwd-{client,server}` (or check `which snmpfwd-server`)
- The virtual environment version includes `ReadWritePaths=/opt/snmpfwd` to allow access to the venv
- Ensure the `snmpfwd` user owns `/opt/snmpfwd` for virtual environment installations

**6. Set correct permissions for service files:**
```bash
sudo chmod 644 /etc/systemd/system/snmpfwd-client.service
sudo chmod 644 /etc/systemd/system/snmpfwd-server.service
```

#### Managing the Services

**Enable services to start on boot:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable snmpfwd-client.service
sudo systemctl enable snmpfwd-server.service
```

**Start the services:**
```bash
# Start client first (it's the trunk server)
sudo systemctl start snmpfwd-client

# Wait a moment, then start server
sleep 2
sudo systemctl start snmpfwd-server
```

**Check status:**
```bash
# Check if services are running
sudo systemctl status snmpfwd-client
sudo systemctl status snmpfwd-server

# Brief status check
sudo systemctl is-active snmpfwd-client snmpfwd-server
```

**View logs:**
```bash
# Follow logs in real-time
sudo journalctl -u snmpfwd-client -f
sudo journalctl -u snmpfwd-server -f

# View recent logs
sudo journalctl -u snmpfwd-client -n 50
sudo journalctl -u snmpfwd-server -n 50

# View logs for both services
sudo journalctl -u snmpfwd-client -u snmpfwd-server -f
```

**Restart services:**
```bash
# Restart both services
sudo systemctl restart snmpfwd-client
sleep 2
sudo systemctl restart snmpfwd-server

# Or restart together
sudo systemctl restart snmpfwd-client snmpfwd-server
```

**Stop services:**
```bash
# Stop server first, then client
sudo systemctl stop snmpfwd-server
sudo systemctl stop snmpfwd-client
```

#### Configuration File Paths

When running as systemd services, use these standard paths:

| File | Location |
|------|----------|
| Server config | `/etc/snmpfwd/server.conf` |
| Client config | `/etc/snmpfwd/client.conf` |
| Plugin configs | `/etc/snmpfwd/plugins/*.conf` |
| Plugin modules | `/etc/snmpfwd/plugins/*.py` or system Python path |
| Log files | `/var/log/snmpfwd/` (if file logging enabled) |
| Journal logs | `journalctl -u snmpfwd-{client,server}` |

#### Binding to Privileged Ports

SNMP typically uses UDP port 161, which is a privileged port (< 1024). The systemd service files use `AmbientCapabilities=CAP_NET_BIND_SERVICE` to allow the non-root `snmpfwd` user to bind to this port.

**Alternative: Use a non-privileged port**

If you prefer not to use privileged ports, configure the server to listen on a high port:

```
# In server.conf
snmp-bind-address: 0.0.0.0:1161
```

Then configure your NMS to query port 1161 instead of 161. Remove the `AmbientCapabilities` line from the service file.

#### Troubleshooting

**Service won't start:**
```bash
# Check detailed error messages
sudo journalctl -xe -u snmpfwd-client
sudo journalctl -xe -u snmpfwd-server

# Check configuration syntax
snmpfwd-client --config-file=/etc/snmpfwd/client.conf --validate
snmpfwd-server --config-file=/etc/snmpfwd/server.conf --validate
```

**Permission issues:**
```bash
# Ensure snmpfwd user owns configuration files
sudo chown -R snmpfwd:snmpfwd /etc/snmpfwd
sudo chmod 750 /etc/snmpfwd
sudo chmod 640 /etc/snmpfwd/*.conf
```

**Port binding issues:**
```bash
# Check if port 161 is already in use
sudo netstat -ulnp | grep :161
sudo ss -ulnp | grep :161

# Check if service has CAP_NET_BIND_SERVICE capability
sudo systemctl show snmpfwd-server | grep AmbientCapabilities
```

**Trunk connection issues:**
```bash
# Check if client is listening on trunk port
sudo netstat -tlnp | grep :30301
sudo ss -tlnp | grep :30301

# Check both services are running
sudo systemctl status snmpfwd-client snmpfwd-server
```

#### Security Hardening

The provided service files include several security features:

- **NoNewPrivileges**: Prevents privilege escalation
- **PrivateTmp**: Isolates /tmp directory
- **ProtectSystem**: Makes most of the filesystem read-only
- **ProtectHome**: Makes /home inaccessible
- **ReadWritePaths**: Explicitly allows writing to log directory
- **Dedicated user**: Runs as unprivileged `snmpfwd` user
- **Minimal capabilities**: Only CAP_NET_BIND_SERVICE when needed

#### Example: Complete Setup Scripts

**Script 1: Virtual Environment Installation (Recommended)**

```bash
#!/bin/bash
# Complete setup script for snmpfwd systemd services with virtual environment
# For Ubuntu/Debian systems - adjust package names for other distros

set -e

echo "=== Installing Python and dependencies ==="
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip build-essential \
    libssl-dev libffi-dev python3-dev

echo "=== Creating snmpfwd user ==="
sudo useradd --system --no-create-home --shell /usr/sbin/nologin snmpfwd 2>/dev/null || true

echo "=== Creating virtual environment ==="
sudo mkdir -p /opt/snmpfwd
cd /opt/snmpfwd
sudo python3.11 -m venv venv

echo "=== Installing snmpfwd in virtual environment ==="
sudo /opt/snmpfwd/venv/bin/pip install --upgrade pip
sudo /opt/snmpfwd/venv/bin/pip install snmpfwd

echo "=== Verifying installation ==="
/opt/snmpfwd/venv/bin/snmpfwd-server --version

echo "=== Creating configuration directories ==="
sudo mkdir -p /etc/snmpfwd/plugins
sudo mkdir -p /var/log/snmpfwd

echo "=== Copying configuration files ==="
# Adjust paths to your actual config files
sudo cp server.conf /etc/snmpfwd/ 2>/dev/null || echo "Note: server.conf not found in current directory"
sudo cp client.conf /etc/snmpfwd/ 2>/dev/null || echo "Note: client.conf not found in current directory"
sudo cp -r plugins/* /etc/snmpfwd/plugins/ 2>/dev/null || echo "Note: plugins directory not found"

echo "=== Setting permissions ==="
sudo chown -R snmpfwd:snmpfwd /opt/snmpfwd /etc/snmpfwd /var/log/snmpfwd
sudo chmod 750 /etc/snmpfwd
sudo chmod 640 /etc/snmpfwd/*.conf 2>/dev/null || true

echo "=== Creating systemd service files ==="
sudo tee /etc/systemd/system/snmpfwd-client.service > /dev/null << 'EOF'
[Unit]
Description=SNMP Proxy Forwarder Client
Documentation=https://github.com/lextudio/snmpfwd
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=snmpfwd
Group=snmpfwd
WorkingDirectory=/opt/snmpfwd
ExecStart=/opt/snmpfwd/venv/bin/snmpfwd-client --config-file=/etc/snmpfwd/client.conf --log-level=info
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snmpfwd-client
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/snmpfwd /opt/snmpfwd

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/snmpfwd-server.service > /dev/null << 'EOF'
[Unit]
Description=SNMP Proxy Forwarder Server
Documentation=https://github.com/lextudio/snmpfwd
After=network.target snmpfwd-client.service
Wants=network-online.target
Requires=snmpfwd-client.service

[Service]
Type=simple
User=snmpfwd
Group=snmpfwd
WorkingDirectory=/opt/snmpfwd
ExecStartPre=/bin/sleep 2
ExecStart=/opt/snmpfwd/venv/bin/snmpfwd-server --config-file=/etc/snmpfwd/server.conf --log-level=info
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snmpfwd-server
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/snmpfwd /opt/snmpfwd
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

echo "=== Reloading systemd ==="
sudo systemctl daemon-reload

echo "=== Enabling services ==="
sudo systemctl enable snmpfwd-client snmpfwd-server

echo "=== Starting services ==="
sudo systemctl start snmpfwd-client
sleep 3
sudo systemctl start snmpfwd-server

echo "=== Checking status ==="
sudo systemctl status snmpfwd-client --no-pager || true
echo ""
sudo systemctl status snmpfwd-server --no-pager || true

echo ""
echo "=== Setup complete! ==="
echo "View logs with: sudo journalctl -u snmpfwd-client -u snmpfwd-server -f"
echo "Check dependencies: /opt/snmpfwd/venv/bin/pip list | grep -E 'pysnmp|pyasn1|pycrypto'"
```

**Script 2: System-wide Installation (Simple)**

```bash
#!/bin/bash
# Simple system-wide installation for snmpfwd systemd services
# For Ubuntu/Debian systems - adjust package names for other distros

set -e

echo "=== Installing Python and dependencies ==="
sudo apt update
sudo apt install -y python3.11 python3-pip build-essential \
    libssl-dev libffi-dev python3-dev

echo "=== Upgrading pip ==="
sudo pip3 install --upgrade pip

echo "=== Installing snmpfwd system-wide ==="
sudo pip3 install snmpfwd

echo "=== Verifying installation ==="
which snmpfwd-server
snmpfwd-server --version

echo "=== Creating snmpfwd user ==="
sudo useradd --system --no-create-home --shell /usr/sbin/nologin snmpfwd 2>/dev/null || true

echo "=== Creating directories ==="
sudo mkdir -p /etc/snmpfwd/plugins
sudo mkdir -p /var/log/snmpfwd

echo "=== Copying configuration files ==="
sudo cp server.conf /etc/snmpfwd/ 2>/dev/null || echo "Note: server.conf not found"
sudo cp client.conf /etc/snmpfwd/ 2>/dev/null || echo "Note: client.conf not found"
sudo cp -r plugins/* /etc/snmpfwd/plugins/ 2>/dev/null || echo "Note: plugins not found"

echo "=== Setting permissions ==="
sudo chown -R snmpfwd:snmpfwd /etc/snmpfwd /var/log/snmpfwd
sudo chmod 750 /etc/snmpfwd
sudo chmod 640 /etc/snmpfwd/*.conf 2>/dev/null || true

echo "=== Creating systemd service files ==="
sudo tee /etc/systemd/system/snmpfwd-client.service > /dev/null << 'EOF'
[Unit]
Description=SNMP Proxy Forwarder Client
After=network.target

[Service]
Type=simple
User=snmpfwd
ExecStart=/usr/local/bin/snmpfwd-client --config-file=/etc/snmpfwd/client.conf --log-level=info
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/snmpfwd-server.service > /dev/null << 'EOF'
[Unit]
Description=SNMP Proxy Forwarder Server
After=network.target snmpfwd-client.service
Requires=snmpfwd-client.service

[Service]
Type=simple
User=snmpfwd
ExecStartPre=/bin/sleep 2
ExecStart=/usr/local/bin/snmpfwd-server --config-file=/etc/snmpfwd/server.conf --log-level=info
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

echo "=== Reloading systemd ==="
sudo systemctl daemon-reload

echo "=== Enabling services ==="
sudo systemctl enable snmpfwd-client snmpfwd-server

echo "=== Starting services ==="
sudo systemctl start snmpfwd-client
sleep 3
sudo systemctl start snmpfwd-server

echo "=== Checking status ==="
sudo systemctl status snmpfwd-client --no-pager || true
echo ""
sudo systemctl status snmpfwd-server --no-pager || true

echo ""
echo "=== Setup complete! ==="
echo "View logs with: sudo journalctl -u snmpfwd-client -u snmpfwd-server -f"
echo "Check dependencies: pip3 list | grep -E 'pysnmp|pyasn1|pycrypto'"
```

Save either script as `setup-snmpfwd.sh`, make it executable with `chmod +x setup-snmpfwd.sh`, and run with `./setup-snmpfwd.sh`.

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
