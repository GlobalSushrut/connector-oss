#!/usr/bin/env bash
# Connector OS — Fresh server bootstrap (Ubuntu 24.04, Hetzner CX22+)
#
# Run as root on a brand-new VPS:
#   curl -fsSL https://raw.githubusercontent.com/.../setup-server.sh | bash
#
# What it does:
#   1. System hardening (unattended-upgrades, UFW firewall)
#   2. Install Docker + Compose
#   3. Mount Hetzner data volume at /mnt/connector-data
#   4. Install sqlite3, awscli (for backups)
#   5. Clone repo, configure .env, deploy

set -euo pipefail

DEPLOY_DIR="/opt/connector"
DATA_MOUNT="/mnt/connector-data"
CONNECTOR_USER="connector"

# ── 1. System hardening ──────────────────────────────────────────────────────
echo "[setup] Updating system..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y --no-install-recommends \
    ufw fail2ban unattended-upgrades \
    curl wget sqlite3 jq \
    ca-certificates gnupg lsb-release

# Automatic security updates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ── 2. Firewall ──────────────────────────────────────────────────────────────
echo "[setup] Configuring UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment "SSH"
ufw allow 80/tcp   comment "HTTP (Caddy ACME)"
ufw allow 443/tcp  comment "HTTPS"
ufw --force enable
echo "[setup] UFW status:"
ufw status verbose

# ── 3. Fail2ban ──────────────────────────────────────────────────────────────
cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 3600
EOF
systemctl enable --now fail2ban

# ── 4. Docker ────────────────────────────────────────────────────────────────
echo "[setup] Installing Docker..."
if ! command -v docker &>/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
systemctl enable --now docker

# ── 5. AWS CLI (for R2 backups) ──────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
    echo "[setup] Installing AWS CLI..."
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install
    rm -rf /tmp/awscliv2.zip /tmp/aws
fi

# ── 6. Data volume ───────────────────────────────────────────────────────────
echo "[setup] Preparing data mount at $DATA_MOUNT..."
mkdir -p "$DATA_MOUNT"

# Detect Hetzner volume (first non-root disk that's not sda)
VOL_DEV=$(lsblk -dpno NAME,TYPE | awk '$2=="disk" && $1!="/dev/sda" {print $1; exit}' || true)
if [[ -n "$VOL_DEV" ]]; then
    if ! blkid "$VOL_DEV" &>/dev/null; then
        echo "[setup] Formatting $VOL_DEV as ext4..."
        mkfs.ext4 -F "$VOL_DEV"
    fi
    FSTAB_LINE="$VOL_DEV $DATA_MOUNT ext4 discard,nofail,defaults 0 2"
    if ! grep -qF "$VOL_DEV" /etc/fstab; then
        echo "$FSTAB_LINE" >> /etc/fstab
    fi
    mount -a
    echo "[setup] Volume mounted at $DATA_MOUNT"
else
    echo "[setup] No additional volume found — using $DATA_MOUNT on root disk"
fi

chmod 755 "$DATA_MOUNT"

# ── 7. Create connector user ─────────────────────────────────────────────────
if ! id "$CONNECTOR_USER" &>/dev/null; then
    useradd -r -m -s /usr/sbin/nologin "$CONNECTOR_USER"
fi
chown -R "${CONNECTOR_USER}:${CONNECTOR_USER}" "$DATA_MOUNT"
usermod -aG docker "$CONNECTOR_USER"

# ── 8. Deploy directory ──────────────────────────────────────────────────────
echo "[setup] Setting up deploy directory at $DEPLOY_DIR..."
mkdir -p "$DEPLOY_DIR"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Server setup complete."
echo "  Next steps:"
echo ""
echo "  1. Copy your deploy files to $DEPLOY_DIR:"
echo "     scp platform/deploy/.env.example root@YOUR_IP:$DEPLOY_DIR/.env"
echo "     scp platform/deploy/docker-compose.control-plane.yml root@YOUR_IP:$DEPLOY_DIR/"
echo "     scp platform/deploy/Caddyfile root@YOUR_IP:$DEPLOY_DIR/"
echo ""
echo "  2. Edit .env on the server:"
echo "     nano $DEPLOY_DIR/.env"
echo ""
echo "  3. Deploy:"
echo "     cd $DEPLOY_DIR && docker compose -f docker-compose.control-plane.yml up -d --build"
echo ""
echo "  4. Set up backup cron:"
echo "     crontab -e"
echo "     0 2 * * * /opt/connector/scripts/backup-db.sh >> /var/log/connector-backup.log 2>&1"
echo "═══════════════════════════════════════════════════════"
