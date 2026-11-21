#!/usr/bin/env bash
set -euo pipefail

# Helper installer for Ubuntu/Debian servers running Apache (e.g. previous WordPress servers)
# Usage: sudo bash deploy/apache/setup-apache-ubuntu.sh panel.example.com

DOMAIN="${1:-}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: sudo bash $0 <panel-domain-or-subdomain>"
  echo "Example: sudo bash $0 panel.example.com"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)."
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js not found. Installing Node.js 22 LTS..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

NODE_MAJOR="$(node -p "process.versions.node.split('.')[0]")"
if [[ "$NODE_MAJOR" -lt 22 ]]; then
  echo "Error: Node.js 22+ is required for node:sqlite (found $(node -v))."
  exit 1
fi

cd "$APP_DIR"
npm install
npm run build

if [[ ! -f "$APP_DIR/.env" ]]; then
  SESSION_SECRET="$(openssl rand -hex 32)"
  ENC_KEY="$(openssl rand -hex 32)"
  cat > "$APP_DIR/.env" <<EOF
NODE_ENV=production
HOST=127.0.0.1
PORT=3000
BASE_PATH=
TRUST_PROXY=1
DATABASE_PATH=./data/georoute.db
SESSION_SECRET=${SESSION_SECRET}
CREDENTIAL_ENCRYPTION_KEY=${ENC_KEY}
DIAGNOSTICS_LOCATION=Apache-Linux-Server
EOF
  chmod 600 "$APP_DIR/.env"
fi

mkdir -p "$APP_DIR/data"
chown -R www-data:www-data "$APP_DIR/data" "$APP_DIR/.env"

a2enmod proxy proxy_http headers rewrite ssl

VHOST_FILE="/etc/apache2/sites-available/georoute.conf"
sed "s/panel\.example\.com/${DOMAIN}/g" "$APP_DIR/deploy/apache/georoute-vhost.conf" > "$VHOST_FILE"
a2ensite georoute.conf

apache2ctl configtest
systemctl reload apache2

sed "s|/opt/georoute-manager|${APP_DIR}|g" "$APP_DIR/deploy/apache/georoute.service" > /etc/systemd/system/georoute.service
systemctl daemon-reload
systemctl enable --now georoute

echo "Done! GeoRoute Manager is running behind Apache for ${DOMAIN}."
echo "Next step (HTTPS): sudo certbot --apache -d ${DOMAIN}"
