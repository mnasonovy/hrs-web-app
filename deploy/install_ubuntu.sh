#!/bin/bash

set -e

export DEBIAN_FRONTEND=noninteractive

APP_DIR="/opt/hrs-web-app"
APP_USER="webadmin"

DB_HOST="127.0.0.1"
DB_PORT="5432"
DB_NAME="hrs_database"
DB_USER="hrs_web_user"
DB_PASSWORD="qwerty!"

echo "[HRS] Checking user..."
if ! id "$APP_USER" >/dev/null 2>&1; then
    echo "[HRS][ERROR] User $APP_USER does not exist."
    echo "Create user $APP_USER or edit deploy/install_ubuntu.sh and deploy/hrs-web-app.service."
    exit 1
fi

echo "[HRS] Installing system packages..."
apt update
apt install -y \
    git \
    python3-venv \
    python3-pip \
    nginx \
    postgresql \
    postgresql-contrib

echo "[HRS] Preparing app directory..."
mkdir -p "$APP_DIR"

echo "[HRS] Copying project files..."
rm -rf "$APP_DIR/app.py" \
       "$APP_DIR/requirements.txt" \
       "$APP_DIR/templates" \
       "$APP_DIR/sql" \
       "$APP_DIR/.env.example"

cp -r app.py requirements.txt templates sql .env.example "$APP_DIR/"

echo "[HRS] Preparing .env..."
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
fi

echo "[HRS] Setting permissions..."
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

echo "[HRS] Creating Python virtual environment..."
sudo -u "$APP_USER" python3 -m venv "$APP_DIR/venv"
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "[HRS] Starting PostgreSQL..."
systemctl enable postgresql
systemctl restart postgresql

echo "[HRS] Creating PostgreSQL user and database..."
sudo -u postgres psql <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DB_USER'
    ) THEN
        CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
    ELSE
        ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE $DB_NAME OWNER $DB_USER'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = '$DB_NAME'
)\gexec

ALTER DATABASE $DB_NAME OWNER TO $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
SQL

echo "[HRS] Granting schema permissions..."
sudo -u postgres psql -d "$DB_NAME" <<SQL
GRANT ALL ON SCHEMA public TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;
SQL

echo "[HRS] Initializing database schema..."
PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -f "$APP_DIR/sql/init.sql"

echo "[HRS] Installing systemd service..."
cp deploy/hrs-web-app.service /etc/systemd/system/hrs-web-app.service

echo "[HRS] Configuring nginx..."
cp deploy/nginx-hrs-web.conf /etc/nginx/sites-available/hrs-web
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/hrs-web /etc/nginx/sites-enabled/hrs-web
nginx -t

echo "[HRS] Starting HRS application..."
systemctl daemon-reload
systemctl enable hrs-web-app
systemctl restart hrs-web-app
systemctl restart nginx

echo "[HRS] Final checks:"
echo "PostgreSQL: $(systemctl is-active postgresql)"
echo "HRS app:    $(systemctl is-active hrs-web-app)"
echo "nginx:      $(systemctl is-active nginx)"

echo "[HRS] Listening ports:"
ss -lntp | grep -E ':80|:8000|:5432' || true

echo "[HRS] Health check:"
curl -s http://127.0.0.1/health || true

echo
echo "[HRS] Installation complete."
echo "Open in browser:"
echo "  http://SERVER_IP/"
