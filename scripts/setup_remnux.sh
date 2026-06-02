#!/usr/bin/env bash
# ============================================================
#  REMnux Gateway Setup — Network Simulation Configuration
#  Run on a fresh REMnux 20.04 instance in the analysis subnet
# ============================================================
# This script configures REMnux as the network gateway for FlareVM,
# enabling INetSim to intercept and simulate all internet services
# that malware attempts to contact during analysis.
#
# Network role:
#   eth0 (10.10.0.x) — management (orchestrator comms, SSM, S3)
#   eth1 (10.10.1.10) — analysis (default gateway for FlareVM)
# ============================================================

set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

ANALYSIS_IP="10.10.1.10"
ANALYSIS_IFACE="eth1"    # Interface facing FlareVM
MGMT_IFACE="eth0"        # Interface facing management subnet

log "Configuring REMnux as malware analysis network gateway …"

# ── Update and install tools ───────────────────────────────────────────────
log "Installing/updating analysis tools …"
apt-get update -qq
apt-get install -y --no-install-recommends \
  inetsim \
  suricata \
  tcpdump \
  tshark \
  ngrep \
  dnsmasq \
  iptables-persistent \
  python3-pip \
  jq \
  awscli \
  curl \
  net-tools

# ── IP forwarding ──────────────────────────────────────────────────────────
log "Enabling IP forwarding …"
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# ── INetSim configuration ──────────────────────────────────────────────────
log "Configuring INetSim …"
cat > /etc/inetsim/inetsim.conf << INETSIM_EOF
# INetSim Configuration — RAIccoon Malware Sandbox
# Intercepts all malware C2 traffic and returns fake responses

start_service dns
start_service http
start_service https
start_service smtp
start_service smtps
start_service pop3
start_service pop3s
start_service ftp
start_service ftps
start_service irc
start_service tftp
start_service finger
start_service ident
start_service syslog

service_bind_address ${ANALYSIS_IP}
dns_bind_port        53
http_bind_port       80
https_bind_port      443
smtp_bind_port       25
pop3_bind_port       110

# All DNS queries respond with our IP (redirect all C2 to INetSim)
dns_default_ip       ${ANALYSIS_IP}
dns_default_ttl      3600

# HTTP responses
http_fakemode        yes
https_fakemode       yes

# Logging
report_dir           /var/log/inetsim/report
report_format        txt
log_dir              /var/log/inetsim
INETSIM_EOF

mkdir -p /var/log/inetsim/report
chown -R inetsim:inetsim /var/log/inetsim 2>/dev/null || true

# ── Suricata configuration ─────────────────────────────────────────────────
log "Configuring Suricata IDS on analysis interface …"
cat > /etc/suricata/suricata-sandbox.yaml << SURICATA_EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.10.1.0/24]"
    EXTERNAL_NET: "any"

af-packet:
  - interface: ${ANALYSIS_IFACE}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - flow
        - netflow

default-log-dir: /var/log/suricata/

# Rule sets
rule-files:
  - suricata.rules
  - /etc/suricata/rules/emerging-malware.rules
  - /etc/suricata/rules/emerging-trojan.rules
  - /etc/suricata/rules/emerging-exploit.rules
SURICATA_EOF

# Download Emerging Threats rules
log "Downloading Emerging Threats Open rules …"
mkdir -p /etc/suricata/rules
curl -sL "https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz" \
  | tar xz -C /etc/suricata/rules/ --strip-components=1 2>/dev/null || \
  warn "ET rules download failed — using default rules only"

# ── PCAP directory ─────────────────────────────────────────────────────────
log "Setting up PCAP capture directory …"
mkdir -p /pcaps
chmod 777 /pcaps

# ── iptables rules ─────────────────────────────────────────────────────────
log "Configuring iptables …"

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow FlareVM (10.10.1.x) traffic to reach INetSim on REMnux
iptables -A INPUT -i "$ANALYSIS_IFACE" -j ACCEPT
iptables -A OUTPUT -o "$ANALYSIS_IFACE" -j ACCEPT

# NAT: redirect all FlareVM outbound traffic to INetSim (captures C2)
iptables -t nat -A PREROUTING -i "$ANALYSIS_IFACE" -p tcp --dport 80  -j REDIRECT --to-ports 80
iptables -t nat -A PREROUTING -i "$ANALYSIS_IFACE" -p tcp --dport 443 -j REDIRECT --to-ports 443
iptables -t nat -A PREROUTING -i "$ANALYSIS_IFACE" -p udp --dport 53  -j REDIRECT --to-ports 53

# Block all FlareVM outbound to real internet (safety net)
iptables -A FORWARD -i "$ANALYSIS_IFACE" -o "$MGMT_IFACE" -j DROP
iptables -A FORWARD -i "$ANALYSIS_IFACE" -o eth0 -j DROP

# Allow management interface to reach S3 (via VPC endpoint) and SSM
iptables -A OUTPUT -o "$MGMT_IFACE" -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -o "$MGMT_IFACE" -p tcp --dport 80  -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4

log "iptables rules saved — FlareVM internet traffic redirected to INetSim"

# ── Systemd services ───────────────────────────────────────────────────────
log "Creating systemd service units …"

# INetSim service
cat > /etc/systemd/system/inetsim-sandbox.service << SERVICE_EOF
[Unit]
Description=INetSim — Internet Simulator for Malware Sandbox
After=network.target

[Service]
Type=forking
User=inetsim
ExecStart=/usr/bin/inetsim --config /etc/inetsim/inetsim.conf
ExecStop=/usr/bin/pkill -f inetsim
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# PCAP rotation service
cat > /etc/systemd/system/sandbox-pcap.service << SERVICE_EOF
[Unit]
Description=Sandbox PCAP Capture on ${ANALYSIS_IFACE}
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/tcpdump -i ${ANALYSIS_IFACE} -w /pcaps/%\$(date +%%s).pcap -G 300 -Z root
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable inetsim-sandbox
systemctl enable suricata
systemctl enable sandbox-pcap

log "Starting services …"
systemctl start inetsim-sandbox || warn "INetSim may need manual start"
systemctl start suricata || warn "Suricata may need manual start"
systemctl start sandbox-pcap || warn "PCAP capture may need manual start"

# ── Verify services ────────────────────────────────────────────────────────
sleep 3
systemctl is-active inetsim-sandbox && log "INetSim: RUNNING" || warn "INetSim: NOT RUNNING"
systemctl is-active suricata        && log "Suricata: RUNNING" || warn "Suricata: NOT RUNNING"

# ── Signal ready state to SSM Parameter Store ─────────────────────────────
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "eu-west-2")
aws ssm put-parameter \
  --name "/sandbox/remnux/ready" \
  --value "true" \
  --type String \
  --overwrite \
  --region "$REGION" 2>/dev/null || warn "Could not update SSM parameter (check IAM role)"

echo ""
log "REMnux gateway configuration complete."
log "Analysis interface: ${ANALYSIS_IFACE} (${ANALYSIS_IP})"
log "  - INetSim: simulating HTTP/HTTPS/DNS/SMTP/FTP/IRC"
log "  - Suricata: monitoring traffic on ${ANALYSIS_IFACE}"
log "  - tcpdump: capturing all traffic to /pcaps/"
log "  - iptables: FlareVM internet traffic redirected to INetSim"
warn "Build this as an AMI snapshot before deploying FlareVM"
