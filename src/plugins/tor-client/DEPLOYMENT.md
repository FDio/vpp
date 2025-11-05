# Tor Client Plugin - Production Deployment Guide

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Security Hardening](#security-hardening)
6. [Monitoring](#monitoring)
7. [Backup and Recovery](#backup-and-recovery)
8. [Performance Tuning](#performance-tuning)
9. [Troubleshooting](#troubleshooting)
10. [Maintenance](#maintenance)

---

## Pre-Deployment Checklist

- [ ] System meets minimum requirements (4GB RAM, 10GB disk)
- [ ] Rust 1.86+ installed
- [ ] VPP dependencies installed
- [ ] Firewall rules reviewed and configured
- [ ] Backup system in place
- [ ] Monitoring solution configured
- [ ] Security policies reviewed
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] Team trained on operations

---

## System Requirements

### Minimum Requirements

- **OS**: Linux 4.4+, Ubuntu 20.04 LTS or later recommended
- **CPU**: 2 cores (4+ recommended for production)
- **RAM**: 4GB minimum, 8GB+ recommended
- **Disk**: 20GB minimum, SSD recommended
- **Network**: 1Gbps+ for high-throughput scenarios

### Recommended Production Setup

- **CPU**: 8+ cores
- **RAM**: 16GB+
- **Disk**: 100GB+ SSD with RAID
- **Network**: 10Gbps+ with redundancy

### Software Dependencies

```bash
# Ubuntu/Debian
apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    pkg-config \
    python3-pip \
    curl \
    git

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup update

# Verify versions
rustc --version  # Should be 1.86+
cargo --version
```

---

## Installation

### 1. Build from Source

```bash
# Clone VPP repository (or use your fork)
git clone https://github.com/FDio/vpp.git
cd vpp

# Checkout appropriate version/branch
git checkout <your-branch-with-tor-plugin>

# Install VPP dependencies
make install-dep

# Configure with tor-client plugin
./configure --enable-plugin tor_client

# Build
make build-release

# Run tests
make test

# Install
sudo make install
```

### 2. System User Setup

```bash
# Create dedicated user for VPP
sudo useradd -r -s /sbin/nologin -d /var/lib/vpp vpp

# Set up directories
sudo mkdir -p /var/lib/vpp/tor
sudo mkdir -p /var/cache/vpp/tor
sudo mkdir -p /var/log/vpp
sudo mkdir -p /etc/vpp

# Set permissions
sudo chown -R vpp:vpp /var/lib/vpp
sudo chown -R vpp:vpp /var/cache/vpp
sudo chown -R vpp:vpp /var/log/vpp
sudo chmod 750 /var/lib/vpp/tor
sudo chmod 750 /var/cache/vpp/tor
```

### 3. Systemd Service

Create `/etc/systemd/system/vpp-tor.service`:

```ini
[Unit]
Description=VPP with Tor Client Plugin
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=vpp
Group=vpp
ExecStart=/usr/bin/vpp -c /etc/vpp/startup.conf
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=8192
LimitMEMLOCK=infinity
LimitCORE=infinity

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vpp /var/cache/vpp /var/log/vpp /run/vpp

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vpp-tor
sudo systemctl start vpp-tor
sudo systemctl status vpp-tor
```

---

## Configuration

### 1. VPP Startup Configuration

Edit `/etc/vpp/startup.conf`:

```
unix {
  nodaemon
  log /var/log/vpp/vpp.log
  full-coredump
  cli-listen /run/vpp/cli.sock
  gid vpp
}

api-trace {
  on
}

api-segment {
  gid vpp
}

cpu {
  main-core 0
  corelist-workers 1-3
}

buffers {
  buffers-per-numa 128000
  default data-size 2048
}

plugins {
  plugin default { disable }
  plugin dpdk_plugin.so { enable }
  plugin tor_client_plugin.so { enable }
}

tor {
  enabled
  socks-port 9050
  config-dir /var/lib/vpp/tor
  cache-dir /var/cache/vpp/tor
  max-connections 10000
}
```

### 2. Network Configuration

```
# Interface configuration
dpdk {
  dev 0000:00:08.0
}

# Create host interface for SOCKS5
create host-interface name vpp-tor
set interface ip address host-vpp-tor 127.0.0.1/8
set interface state host-vpp-tor up
```

### 3. Firewall Rules

```bash
#!/bin/bash
# firewall-rules.sh

# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SOCKS5 from trusted sources only
iptables -A INPUT -p tcp --dport 9050 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 9050 -s 10.0.0.0/8 -j ACCEPT  # Internal network

# Allow SSH (adjust as needed)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow Tor network traffic (outbound)
iptables -A OUTPUT -p tcp --dport 9001 -j ACCEPT  # Tor OR port
iptables -A OUTPUT -p tcp --dport 9030 -j ACCEPT  # Tor Dir port

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: "
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

---

## Security Hardening

### 1. SELinux/AppArmor

#### AppArmor Profile (`/etc/apparmor.d/usr.bin.vpp`)

```
#include <tunables/global>

/usr/bin/vpp {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability net_admin,
  capability net_raw,
  capability sys_admin,
  capability ipc_lock,

  /etc/vpp/** r,
  /var/lib/vpp/** rw,
  /var/cache/vpp/** rw,
  /var/log/vpp/** rw,
  /run/vpp/** rw,

  /usr/lib/x86_64-linux-gnu/vpp_plugins/** rm,
  /proc/sys/net/** r,
  /sys/devices/** r,

  deny /home/** rw,
  deny /root/** rw,
}
```

Load profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.vpp
```

### 2. Resource Limits

Edit `/etc/security/limits.conf`:

```
vpp soft nofile 1048576
vpp hard nofile 1048576
vpp soft nproc 8192
vpp hard nproc 8192
vpp soft memlock unlimited
vpp hard memlock unlimited
```

### 3. Sysctl Tuning

Create `/etc/sysctl.d/99-vpp-tor.conf`:

```
# Network tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0

# Connection tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# File descriptors
fs.file-max = 2097152
```

Apply:

```bash
sudo sysctl -p /etc/sysctl.d/99-vpp-tor.conf
```

### 4. Log Rotation

Create `/etc/logrotate.d/vpp-tor`:

```
/var/log/vpp/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 vpp vpp
    sharedscripts
    postrotate
        systemctl reload vpp-tor > /dev/null 2>&1 || true
    endscript
}
```

---

## Monitoring

### 1. Prometheus Exporter (Future Enhancement)

While not yet implemented, here's the recommended monitoring approach:

```bash
# Monitor VPP stats
vppctl show runtime
vppctl show tor status
vppctl show errors
```

### 2. Monitoring Script

Create `/usr/local/bin/monitor-vpp-tor.sh`:

```bash
#!/bin/bash

while true; do
    echo "=== $(date) ==="

    # Check if VPP is running
    if ! pgrep -x vpp > /dev/null; then
        echo "ALERT: VPP is not running!"
        systemctl restart vpp-tor
    fi

    # Check Tor status
    vppctl show tor status | grep -q "Enabled"
    if [ $? -ne 0 ]; then
        echo "ALERT: Tor client is not enabled!"
    fi

    # Check active streams
    STREAMS=$(vppctl show tor status | grep "Active Streams" | awk '{print $3}')
    echo "Active streams: $STREAMS"

    # Check memory usage
    MEM=$(ps aux | grep '[v]pp' | awk '{sum+=$6} END {print sum/1024}')
    echo "VPP memory usage: ${MEM}MB"

    sleep 60
done
```

### 3. Health Check Endpoint

```bash
#!/bin/bash
# /usr/local/bin/vpp-tor-health.sh

vppctl show tor status | grep -q "Status: Enabled"
if [ $? -eq 0 ]; then
    echo "OK"
    exit 0
else
    echo "FAILED"
    exit 1
fi
```

---

## Backup and Recovery

### 1. Backup Script

```bash
#!/bin/bash
# /usr/local/bin/backup-vpp-tor.sh

BACKUP_DIR="/backup/vpp-tor"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration
tar czf $BACKUP_DIR/config-$DATE.tar.gz /etc/vpp/

# Backup Tor state (optional, can be large)
tar czf $BACKUP_DIR/tor-state-$DATE.tar.gz /var/lib/vpp/tor/

# Keep only last 7 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
```

### 2. Disaster Recovery

```bash
# Stop VPP
sudo systemctl stop vpp-tor

# Restore configuration
cd /
sudo tar xzf /backup/vpp-tor/config-YYYYMMDD-HHMMSS.tar.gz

# Restore Tor state (optional)
sudo tar xzf /backup/vpp-tor/tor-state-YYYYMMDD-HHMMSS.tar.gz

# Fix permissions
sudo chown -R vpp:vpp /var/lib/vpp
sudo chown -R vpp:vpp /etc/vpp

# Start VPP
sudo systemctl start vpp-tor
```

---

## Performance Tuning

### 1. High-Throughput Configuration

```
cpu {
  main-core 0
  corelist-workers 1-15  # More workers
  skip-cores 8           # NUMA optimization
}

buffers {
  buffers-per-numa 256000  # More buffers
  default data-size 2048
}

tor {
  max-connections 50000    # Higher limit
}

session {
  evt_qs_memfd_seg
  event-queue-length 65536
  preallocated-sessions 50000
}
```

### 2. NUMA Optimization

```bash
# Check NUMA topology
numactl --hardware

# Pin VPP to specific NUMA node
numactl --cpunodebind=0 --membind=0 /usr/bin/vpp -c /etc/vpp/startup.conf
```

---

## Troubleshooting

See README.md for detailed troubleshooting guide.

---

## Maintenance

### Regular Tasks

**Daily**:
- Check logs for errors
- Monitor resource usage
- Verify Tor connectivity

**Weekly**:
- Review security logs
- Check for updates
- Run backups

**Monthly**:
- Update dependencies
- Review performance metrics
- Test disaster recovery

### Update Procedure

```bash
# 1. Backup current installation
/usr/local/bin/backup-vpp-tor.sh

# 2. Download new version
git pull origin main

# 3. Build
make rebuild

# 4. Test in staging
make test

# 5. Stop production
sudo systemctl stop vpp-tor

# 6. Install
sudo make install

# 7. Start production
sudo systemctl start vpp-tor

# 8. Verify
vppctl show tor status
```

---

## Support and Escalation

### Log Collection

```bash
#!/bin/bash
# collect-logs.sh

DEST="/tmp/vpp-tor-logs-$(date +%Y%m%d-%H%M%S)"
mkdir -p $DEST

# System info
uname -a > $DEST/system-info.txt
free -h >> $DEST/system-info.txt
df -h >> $DEST/system-info.txt

# VPP logs
cp /var/log/vpp/*.log $DEST/
vppctl show version > $DEST/vpp-version.txt
vppctl show tor status > $DEST/tor-status.txt
vppctl show errors > $DEST/vpp-errors.txt
vppctl show runtime > $DEST/vpp-runtime.txt

# System logs
journalctl -u vpp-tor > $DEST/systemd.log

# Configuration
cp -r /etc/vpp $DEST/

# Create archive
tar czf vpp-tor-logs.tar.gz -C /tmp $(basename $DEST)
echo "Logs collected: vpp-tor-logs.tar.gz"
```

---

## License

Copyright (c) 2025 Internet Mastering & Company, Inc.
Licensed under the Apache License, Version 2.0.
