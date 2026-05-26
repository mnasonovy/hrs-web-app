#!/bin/bash

set -e

APP_DIR="/opt/hrs-web-app"
APP_USER="${APP_USER:-webadmin}"

DB_NAME="${DB_NAME:-hrs_database}"
DB_USER="${DB_USER:-hrs_web_user}"
DB_PASSWORD="${DB_PASSWORD:-qwerty!}"

echo "[HRS] Starting deployment..."

if [ "$(id -u)" -ne 0 ]; then
    echo "[HRS][ERROR] Run this script as root:"
    echo "sudo bash deploy/install_ubuntu.sh"
    exit 1
fi

if ! id "$APP_USER" >/dev/null 2>&1; then
    echo "[HRS][ERROR] User '$APP_USER' does not exist."
    echo "Create user or run with existing user:"
    echo "sudo APP_USER=your_user bash deploy/install_ubuntu.sh"
    exit 1
fi

echo "[HRS] Installing system packages..."
apt update
apt install -y python3-venv python3-pip nginx postgresql postgresql-contrib curl

echo "[HRS] Preparing application directory..."
mkdir -p "$APP_DIR"

echo "[HRS] Stopping old services if they exist..."
systemctl stop hrs-web-app 2>/dev/null || true

echo "[HRS] Copying application files..."
rm -rf "$APP_DIR/app.py" \
       "$APP_DIR/requirements.txt" \
       "$APP_DIR/templates" \
       "$APP_DIR/static" \
       "$APP_DIR/sql" \
       "$APP_DIR/.env.example"

cp app.py "$APP_DIR/"
cp requirements.txt "$APP_DIR/"
cp -r templates "$APP_DIR/"
cp -r static "$APP_DIR/"
cp -r sql "$APP_DIR/"
cp .env.example "$APP_DIR/"

echo "[HRS] Preparing .env..."
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
fi

echo "[HRS] Installing systemd and nginx configs..."
cp deploy/hrs-web-app.service /etc/systemd/system/hrs-web-app.service
cp deploy/nginx-hrs-web.conf /etc/nginx/sites-available/hrs-web

echo "[HRS] Setting permissions..."
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

echo "[HRS] Creating Python virtual environment..."
rm -rf "$APP_DIR/venv"
sudo -u "$APP_USER" python3 -m venv "$APP_DIR/venv"
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "[HRS] Starting PostgreSQL..."
systemctl enable postgresql
systemctl restart postgresql

echo "[HRS] Creating PostgreSQL role and database..."
sudo -u postgres psql <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DB_USER'
    ) THEN
        CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
    END IF;
END
\$\$;

ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';

SELECT 'CREATE DATABASE $DB_NAME OWNER $DB_USER'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = '$DB_NAME'
)\gexec
SQL

echo "[HRS] Initializing PostgreSQL schema and demo incidents..."
PGPASSWORD="$DB_PASSWORD" psql \
    -h 127.0.0.1 \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -f "$APP_DIR/sql/init.sql"

echo "[HRS] Configuring nginx..."
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/hrs-web /etc/nginx/sites-enabled/hrs-web

nginx -t

echo "[HRS] Starting application services..."
systemctl daemon-reload
systemctl enable hrs-web-app
systemctl restart hrs-web-app
systemctl enable nginx
systemctl restart nginx

echo "[HRS] Deployment completed successfully."
echo
echo "[HRS] Checks:"
echo "systemctl status hrs-web-app --no-pager"
echo "systemctl status nginx --no-pager"
echo "curl http://127.0.0.1/health"
echo "curl http://127.0.0.1"
