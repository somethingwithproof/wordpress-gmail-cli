#!/bin/bash

# Enterprise Setup Script for WordPress Gmail CLI
# This script implements the enterprise enhancements described in enterprise-enhancements.md

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Function to log messages
log() {
  local level=$1
  local message=$2
  local color=${RESET}

  case ${level} in
    "INFO") color=${BLUE} ;;
    "SUCCESS") color=${GREEN} ;;
    "WARNING") color=${YELLOW} ;;
    "ERROR") color=${RED} ;;
    *)
      color=${RESET}
      echo "Unknown log level: ${level}" >&2
      ;;
  esac

  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}${level}${RESET}: ${message}"
}

# Function to check if command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
  return $?
}

# Function to check if running as root
check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log "ERROR" "This script must be run as root"
    exit 1
  fi
}

# Function to display script usage
usage() {
  echo -e "${BOLD}WordPress Gmail CLI - Enterprise Setup${RESET}"
  echo "A script to implement enterprise enhancements for WordPress Gmail CLI"
  echo
  echo -e "${BOLD}Usage:${RESET}"
  echo "  $0 [options]"
  echo
  echo -e "${BOLD}Options:${RESET}"
  echo "  --vault                  Configure HashiCorp Vault integration"
  echo "  --monitoring             Set up Prometheus monitoring"
  echo "  --logging                Configure centralized logging with ELK"
  echo "  --ldap                   Set up LDAP authentication for admin interface"
  echo "  --api                    Configure management API"
  echo "  --load-balancing         Configure for load balanced environment"
  echo "  --all                    Enable all enterprise features"
  echo "  -h, --help               Display this help message"
  echo
  echo -e "${BOLD}Example:${RESET}"
  echo "  $0 --vault --monitoring"
  exit 0
}

# Function to configure Vault integration
configure_vault_integration() {
  log "INFO" "Configuring Vault integration..."

  # Check if Vault CLI is installed
  if ! command_exists vault; then
    log "ERROR" "Vault CLI not found. Please install HashiCorp Vault."
    return 1
  fi

  # Prompt for Vault address
  read -r -p "Enter Vault server address (e.g., https://vault.example.com:8200): " VAULT_ADDR

  # Prompt for Vault token
  read -r -p "Enter Vault token: " VAULT_TOKEN

  # Create credentials directory if it doesn't exist
  mkdir -p /etc/postfix/gmail-api
  chmod 700 /etc/postfix/gmail-api

  # Create a script to retrieve credentials from Vault
  cat >/etc/postfix/gmail-api/vault-credentials.sh <<EOF
#!/bin/bash
export VAULT_ADDR="${VAULT_ADDR}"
export VAULT_TOKEN="${VAULT_TOKEN}"

# Get credentials from Vault
CREDS=\$(vault kv get -format=json secret/wordpress-gmail-cli/credentials)
CLIENT_ID=\$(echo "\$CREDS" | jq -r '.data.data.client_id')
CLIENT_SECRET=\$(echo "\$CREDS" | jq -r '.data.data.client_secret')
REFRESH_TOKEN=\$(echo "\$CREDS" | jq -r '.data.data.refresh_token')
EMAIL=\$(echo "\$CREDS" | jq -r '.data.data.email')

# Output to credentials file
cat > /etc/postfix/gmail-api/credentials.json << EOT
{
  "client_id": "\${CLIENT_ID}",
  "client_secret": "\${CLIENT_SECRET}",
  "refresh_token": "\${REFRESH_TOKEN}",
  "email": "\${EMAIL}"
}
EOT
chmod 600 /etc/postfix/gmail-api/credentials.json
EOF

  chmod 700 /etc/postfix/gmail-api/vault-credentials.sh

  # Add to cron to periodically refresh credentials
  echo "0 */6 * * * root /etc/postfix/gmail-api/vault-credentials.sh > /dev/null 2>&1" >/etc/cron.d/gmail-api-vault
  chmod 644 /etc/cron.d/gmail-api-vault

  log "INFO" "Testing Vault connection..."
  if /etc/postfix/gmail-api/vault-credentials.sh; then
    log "SUCCESS" "Vault integration configured successfully"
  else
    log "ERROR" "Failed to retrieve credentials from Vault"
    return 1
  fi

  return 0
}

# Function to set up Prometheus monitoring
setup_prometheus_metrics() {
  log "INFO" "Setting up Prometheus metrics..."

  # Install required packages
  apt-get update
  apt-get install -y python3-pip
  pip3 install prometheus_client flask

  # Create metrics directory
  mkdir -p /opt/gmail-metrics

  # Create metrics service
  cat >/opt/gmail-metrics/metrics.py <<'EOF'
#!/usr/bin/env python3
from prometheus_client import Counter, Gauge, generate_latest, start_http_server
from flask import Flask, Response
import json
import os
import time

app = Flask(__name__)

# Define metrics
emails_sent = Counter('wordpress_gmail_emails_sent_total', 'Total number of emails sent')
emails_failed = Counter('wordpress_gmail_emails_failed_total', 'Total number of emails that failed to send')
token_refresh_count = Counter('wordpress_gmail_token_refresh_total', 'Total number of token refreshes')
token_expiry = Gauge('wordpress_gmail_token_expiry_seconds', 'Time until token expiry in seconds')

# Update token expiry metric
def update_token_expiry():
    token_file = '/etc/postfix/gmail-api/token.json'
    if os.path.exists(token_file):
        try:
            with open(token_file, 'r') as f:
                data = json.load(f)
                if 'expiry_time' in data:
                    expiry = data['expiry_time']
                    now = int(time.time())
                    token_expiry.set(max(0, expiry - now))
        except Exception as e:
            print(f"Error updating token expiry: {e}")

@app.route('/metrics')
def metrics():
    update_token_expiry()
    return Response(generate_latest(), mimetype='text/plain')

# Start server
if __name__ == '__main__':
    start_http_server(9090)
    app.run(host='0.0.0.0', port=9091)
EOF

  chmod +x /opt/gmail-metrics/metrics.py

  # Create systemd service
  cat >/etc/systemd/system/gmail-metrics.service <<EOF
[Unit]
Description=Gmail Metrics Exporter
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/opt/gmail-metrics/metrics.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  # Enable and start service
  systemctl daemon-reload
  systemctl enable gmail-metrics
  systemctl start gmail-metrics

  log "SUCCESS" "Prometheus metrics endpoint configured on port 9090"
  log "INFO" "You can now add this endpoint to your Prometheus configuration"

  return 0
}

# Function to configure centralized logging
configure_elk_logging() {
  log "INFO" "Configuring centralized logging..."

  # Prompt for Elasticsearch server
  read -r -p "Enter Elasticsearch server address (e.g., elasticsearch.example.com:9200): " ES_SERVER

  # Prompt for Kibana server
  read -r -p "Enter Kibana server address (e.g., kibana.example.com:5601): " KIBANA_SERVER

  # Prompt for credentials
  read -r -p "Enter Elasticsearch username: " ES_USER
  read -r -p "Enter Elasticsearch password: " ES_PASS

  # Install Filebeat
  if ! command_exists filebeat; then
    log "INFO" "Installing Filebeat..."
    curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.15.0-amd64.deb
    dpkg -i filebeat-7.15.0-amd64.deb
  fi

  # Configure Filebeat
  cat >/etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/mail.log
  fields:
    service: postfix
    environment: production
  fields_under_root: true
  json.keys_under_root: true

- type: log
  enabled: true
  paths:
    - /etc/postfix/gmail-api/token-refresh.log
  fields:
    service: gmail-api
    environment: production
  fields_under_root: true

output.elasticsearch:
  hosts: ["${ES_SERVER}"]
  username: "${ES_USER}"
  password: "${ES_PASS}"
  
setup.kibana:
  host: "${KIBANA_SERVER}"
EOF

  # Create token refresh log file
  touch /etc/postfix/gmail-api/token-refresh.log
  chmod 644 /etc/postfix/gmail-api/token-refresh.log

  # Modify token refresh script to log to a file
  if [[ -f /etc/postfix/gmail-api/refresh-token.sh ]]; then
    sed -i 's|echo "Access token refreshed successfully (expires in \${EXPIRES_IN}s)"|echo "$(date): Access token refreshed successfully (expires in \${EXPIRES_IN}s)" >> /etc/postfix/gmail-api/token-refresh.log|g' /etc/postfix/gmail-api/refresh-token.sh
  else
    log "WARNING" "Token refresh script not found. Logging configuration may be incomplete."
  fi

  # Enable and start Filebeat
  systemctl enable filebeat
  systemctl start filebeat

  log "SUCCESS" "Centralized logging configured"

  return 0
}

# Function to set up LDAP authentication
configure_ldap_auth() {
  log "INFO" "Configuring LDAP authentication..."

  # Prompt for LDAP server details
  read -r -p "Enter LDAP server address: " LDAP_SERVER
  read -r -p "Enter LDAP port (default: 389): " LDAP_PORT
  LDAP_PORT=${LDAP_PORT:-389}
  read -r -p "Enter LDAP base DN (e.g., dc=example,dc=com): " LDAP_BASE_DN
  read -r -p "Enter LDAP users DN (e.g., ou=users,dc=example,dc=com): " LDAP_USER_DN
  read -r -p "Enter LDAP groups DN (e.g., ou=groups,dc=example,dc=com): " LDAP_GROUP_DN
  read -r -p "Enter LDAP admin group (e.g., cn=mail-admins,ou=groups,dc=example,dc=com): " LDAP_ADMIN_GROUP

  # Install required packages
  apt-get update
  apt-get install -y php-ldap php-fpm nginx

  # Create admin interface directory
  mkdir -p /var/www/gmail-admin

  # Create admin interface with LDAP authentication
  cat >/var/www/gmail-admin/index.php <<EOF
<?php
session_start();

// LDAP configuration
\$ldap_server = '${LDAP_SERVER}';
\$ldap_port = ${LDAP_PORT};
\$ldap_base_dn = '${LDAP_BASE_DN}';
\$ldap_user_dn = '${LDAP_USER_DN}';
\$ldap_group_dn = '${LDAP_GROUP_DN}';
\$ldap_admin_group = '${LDAP_ADMIN_GROUP}';

// Authentication function
function ldap_authenticate(\$username, \$password) {
    global \$ldap_server, \$ldap_port, \$ldap_base_dn, \$ldap_user_dn, \$ldap_group_dn, \$ldap_admin_group;
    
    \$ldap = ldap_connect(\$ldap_server, \$ldap_port);
    ldap_set_option(\$ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    \$user_dn = "uid=\$username,\$ldap_user_dn";
    
    if (\$bind = ldap_bind(\$ldap, \$user_dn, \$password)) {
        // Check if user is in admin group
        \$filter = "(memberUid=\$username)";
        \$search = ldap_search(\$ldap, \$ldap_admin_group, \$filter);
        \$entries = ldap_get_entries(\$ldap, \$search);
        
        if (\$entries['count'] > 0) {
            return true;
        }
    }
    
    return false;
}

// Handle login
if (isset(\$_POST['username']) && isset(\$_POST['password'])) {
    if (ldap_authenticate(\$_POST['username'], \$_POST['password'])) {
        \$_SESSION['authenticated'] = true;
        \$_SESSION['username'] = \$_POST['username'];
    } else {
        \$error = "Invalid credentials or insufficient permissions";
    }
}

// Handle logout
if (isset(\$_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Check authentication
\$authenticated = isset(\$_SESSION['authenticated']) && \$_SESSION['authenticated'];

// Display login form or admin interface
if (!\$authenticated) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gmail API Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .login-form { max-width: 400px; margin: 0 auto; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 8px 0; }
            input[type="submit"] { padding: 8px 16px; background: #4285f4; color: white; border: none; cursor: pointer; }
            .error { color: red; }
        </style>
    </head>
    <body>
        <div class="login-form">
            <h2>Gmail API Admin Login</h2>
            <?php if (isset(\$error)) echo "<p class='error'>\$error</p>"; ?>
            <form method="post">
                <div>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div>
                    <input type="submit" value="Login">
                </div>
            </form>
        </div>
    </body>
    </html>
    <?php
} else {
    // Admin interface
    \$token_file = '/etc/postfix/gmail-api/token.json';
    \$credentials_file = '/etc/postfix/gmail-api/credentials.json';
    
    \$token_data = file_exists(\$token_file) ? json_decode(file_get_contents(\$token_file), true) : null;
    \$credentials_data = file_exists(\$credentials_file) ? json_decode(file_get_contents(\$credentials_file), true) : null;
    
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gmail API Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .card { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 4px; }
            .header { display: flex; justify-content: space-between; align-items: center; }
            .status { padding: 4px 8px; border-radius: 4px; }
            .status.active { background: #d4edda; color: #155724; }
            .status.expired { background: #f8d7da; color: #721c24; }
            .logout { text-decoration: none; color: #4285f4; }
            table { width: 100%; border-collapse: collapse; }
            table td, table th { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            .refresh-btn { padding: 8px 16px; background: #4285f4; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Gmail API Admin</h2>
                <a href="?logout=1" class="logout">Logout</a>
            </div>
            
            <div class="card">
                <h3>Token Status</h3>
                <?php if (\$token_data): ?>
                    <?php 
                    \$now = time();
                    \$expires_in = \$token_data['expiry_time'] - \$now;
                    \$status_class = \$expires_in > 0 ? 'active' : 'expired';
                    \$status_text = \$expires_in > 0 ? 'Active' : 'Expired';
                    ?>
                    <div class="status <?php echo \$status_class; ?>"><?php echo \$status_text; ?></div>
                    <table>
                        <tr>
                            <td>Expires in:</td>
                            <td><?php echo \$expires_in > 0 ? gmdate("H:i:s", \$expires_in) : 'Expired'; ?></td>
                        </tr>
                        <tr>
                            <td>Last refreshed:</td>
                            <td><?php echo date('Y-m-d H:i:s', filemtime(\$token_file)); ?></td>
                        </tr>
                    </table>
                    <form method="post" action="/gmail-admin/refresh.php">
                        <input type="submit" value="Refresh Token Now" class="refresh-btn">
                    </form>
                <?php else: ?>
                    <p>No token data available.</p>
                <?php endif; ?>
            </div>
            
            <div class="card">
                <h3>Credentials</h3>
                <?php if (\$credentials_data): ?>
                    <table>
                        <tr>
                            <td>Email:</td>
                            <td><?php echo \$credentials_data['email']; ?></td>
                        </tr>
                        <tr>
                            <td>Client ID:</td>
                            <td><?php echo substr(\$credentials_data['client_id'], 0, 10) . '...'; ?></td>
                        </tr>
                        <tr>
                            <td>Client Secret:</td>
                            <td>***************</td>
                        </tr>
                        <tr>
                            <td>Refresh Token:</td>
                            <td>***************</td>
                        </tr>
                    </table>
                <?php else: ?>
                    <p>No credentials available.</p>
                <?php endif; ?>
            </div>
            
            <div class="card">
                <h3>System Status</h3>
                <table>
                    <tr>
                        <td>Postfix:</td>
                        <td><?php echo shell_exec('systemctl is-active postfix') == 'active' ? 'Running' : 'Stopped'; ?></td>
                    </tr>
                    <tr>
                        <td>Cron Jobs:</td>
                        <td><?php echo file_exists('/etc/cron.d/gmail-api-token') ? 'Configured' : 'Not configured'; ?></td>
                    </tr>
                    <tr>
                        <td>WordPress Plugin:</td>
                        <td><?php echo file_exists('/var/www/html/wp-content/mu-plugins/gmail-api.php') ? 'Installed' : 'Not installed'; ?></td>
                    </tr>
                </table>
            </div>
        </div>
    </body>
    </html>
    <?php
}
EOF

  # Create refresh script
  cat >/var/www/gmail-admin/refresh.php <<'EOF'
<?php
session_start();

// Check authentication
if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
    header('Location: index.php');
    exit;
}

// Run token refresh script
$output = shell_exec('sudo /etc/postfix/gmail-api/refresh-token.sh 2>&1');

// Redirect back to admin page
header('Location: index.php?refreshed=1');
EOF

  # Configure Nginx
  cat >/etc/nginx/conf.d/gmail-admin.conf <<EOF
server {
    listen 8082;
    server_name localhost;
    
    root /var/www/gmail-admin;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Restrict access by IP
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
}
EOF

  # Configure sudo for www-data
  echo "www-data ALL=(root) NOPASSWD: /etc/postfix/gmail-api/refresh-token.sh" >/etc/sudoers.d/gmail-admin
  chmod 440 /etc/sudoers.d/gmail-admin

  # Set permissions
  chown -R www-data:www-data /var/www/gmail-admin

  # Restart Nginx
  systemctl restart nginx

  log "SUCCESS" "LDAP authentication configured"
  log "INFO" "Admin interface available at http://localhost:8082"

  return 0
}

# Function to configure management API
configure_api() {
  log "INFO" "Configuring management API..."

  # Generate API keys
  PROD_KEY=$(openssl rand -hex 16)
  STAGING_KEY=$(openssl rand -hex 16)
  DEV_KEY=$(openssl rand -hex 16)

  # Install required packages
  apt-get update
  apt-get install -y php-fpm nginx

  # Create API directory
  mkdir -p /var/www/gmail-api

  # Create API endpoints
  cat >/var/www/gmail-api/index.php <<EOF
<?php
// Simple API for Gmail integration status and management

// API key authentication
function authenticate() {
    \$api_keys = [
        'production' => '${PROD_KEY}',
        'staging' => '${STAGING_KEY}',
        'development' => '${DEV_KEY}'
    ];
    
    \$headers = getallheaders();
    if (!isset(\$headers['X-API-Key'])) {
        return false;
    }
    
    \$api_key = \$headers['X-API-Key'];
    return in_array(\$api_key, \$api_keys);
}

// Return JSON response
function json_response(\$data, \$status = 200) {
    http_response_code(\$status);
    header('Content-Type: application/json');
    echo json_encode(\$data);
    exit;
}

// Check authentication
if (!authenticate()) {
    json_response(['error' => 'Unauthorized'], 401);
}

// Parse request
\$method = \$_SERVER['REQUEST_METHOD'];
\$path = trim(\$_SERVER['PATH_INFO'] ?? '/', '/');
\$params = \$_GET;

// API routes
switch (\$path) {
    case 'status':
        // Get token and credentials status
        \$token_file = '/etc/postfix/gmail-api/token.json';
        \$credentials_file = '/etc/postfix/gmail-api/credentials.json';
        
        \$token_data = file_exists(\$token_file) ? json_decode(file_get_contents(\$token_file), true) : null;
        \$credentials_data = file_exists(\$credentials_file) ? json_decode(file_get_contents(\$credentials_file), true) : null;
        
        \$now = time();
        \$token_valid = \$token_data && isset(\$token_data['expiry_time']) && \$token_data['expiry_time'] > \$now;
        
        \$response = [
            'status' => \$token_valid ? 'healthy' : 'unhealthy',
            'token' => [
                'valid' => \$token_valid,
                'expires_in' => \$token_valid ? \$token_data['expiry_time'] - \$now : 0,
                'last_refresh' => file_exists(\$token_file) ? date('Y-m-d H:i:s', filemtime(\$token_file)) : null
            ],
            'credentials' => [
                'configured' => \$credentials_data !== null,
                'email' => \$credentials_data['email'] ?? null
            ],
            'postfix' => [
                'running' => trim(shell_exec('systemctl is-active postfix')) === 'active'
            ]
        ];
        
        json_response(\$response);
        break;
        
    case 'refresh':
        // Refresh token
        if (\$method !== 'POST') {
            json_response(['error' => 'Method not allowed'], 405);
        }
        
        \$output = shell_exec('/etc/postfix/gmail-api/refresh-token.sh 2>&1');
        \$success = strpos(\$output, 'successfully') !== false;
        
        json_response([
            'success' => \$success,
            'message' => \$output
        ]);
        break;
        
    case 'logs':
        // Get recent logs
        \$log_file = '/etc/postfix/gmail-api/token-refresh.log';
        \$lines = isset(\$params['lines']) ? intval(\$params['lines']) : 10;
        
        if (file_exists(\$log_file)) {
            \$logs = explode("\n", trim(shell_exec("tail -n \$lines \$log_file")));
        } else {
            \$logs = [];
        }
        
        json_response(['logs' => \$logs]);
        break;
        
    default:
        json_response(['error' => 'Not found'], 404);
}
EOF

  # Configure Nginx
  cat >/etc/nginx/conf.d/gmail-api.conf <<EOF
server {
    listen 8081;
    server_name localhost;
    
    root /var/www/gmail-api;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Restrict access by IP
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
}
EOF

  # Set permissions
  chown -R www-data:www-data /var/www/gmail-api

  # Restart Nginx
  systemctl restart nginx

  log "SUCCESS" "Management API configured on port 8081"
  log "INFO" "API Keys:"
  log "INFO" "  Production: ${PROD_KEY}"
  log "INFO" "  Staging: ${STAGING_KEY}"
  log "INFO" "  Development: ${DEV_KEY}"
  log "INFO" "Example API usage:"
  log "INFO" "  curl -H 'X-API-Key: ${PROD_KEY}' http://localhost:8081/status"

  return 0
}

# Function to configure load balancing
configure_load_balancing() {
  log "INFO" "Configuring for load balanced environment..."

  # Update Postfix configuration for load balanced environment
  if [[ -f /etc/postfix/main.cf ]]; then
    cat >>/etc/postfix/main.cf <<EOF

# Load balancing configuration
smtp_connection_cache_destinations = 
smtp_connection_cache_on_demand = no
smtp_connection_reuse_time_limit = 300s
EOF

    # Restart Postfix
    systemctl restart postfix
  else
    log "WARNING" "Postfix configuration file not found. Load balancing configuration may be incomplete."
  fi

  # Create health check endpoint
  mkdir -p /var/www/health
  cat >/var/www/health/gmail-api-health.php <<'EOF'
<?php
// Check if token file exists and is valid
$token_file = '/etc/postfix/gmail-api/token.json';
$health = array('status' => 'unhealthy');

if (file_exists($token_file)) {
    $token_data = json_decode(file_get_contents($token_file), true);
    if (isset($token_data['access_token']) && isset($token_data['expiry_time'])) {
        $now = time();
        if ($token_data['expiry_time'] > $now) {
            $health = array(
                'status' => 'healthy',
                'expires_in' => $token_data['expiry_time'] - $now,
                'last_refresh' => date('Y-m-d H:i:s', filemtime($token_file))
            );
        }
    }
}

header('Content-Type: application/json');
echo json_encode($health);
EOF

  # Configure Nginx for health checks (if installed)
  if command_exists nginx; then
    cat >/etc/nginx/conf.d/health-check.conf <<EOF
server {
    listen 8080;
    server_name localhost;
    
    location /health {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index gmail-api-health.php;
        fastcgi_param SCRIPT_FILENAME /var/www/health/gmail-api-health.php;
        include fastcgi_params;
    }
}
EOF

    systemctl restart nginx
  fi

  log "SUCCESS" "Load balancing configuration completed"

  return 0
}

# Main script execution
check_root

# Parse command line arguments
ENABLE_VAULT=false
ENABLE_MONITORING=false
ENABLE_LOGGING=false
ENABLE_LDAP=false
ENABLE_API=false
ENABLE_LOAD_BALANCING=false

# Check if no arguments provided
if [[ $# -eq 0 ]]; then
  usage
fi

# Parse arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case ${key} in
    --vault)
      ENABLE_VAULT=true
      shift
      ;;
    --monitoring)
      ENABLE_MONITORING=true
      shift
      ;;
    --logging)
      ENABLE_LOGGING=true
      shift
      ;;
    --ldap)
      ENABLE_LDAP=true
      shift
      ;;
    --api)
      ENABLE_API=true
      shift
      ;;
    --load-balancing)
      ENABLE_LOAD_BALANCING=true
      shift
      ;;
    --all)
      ENABLE_VAULT=true
      ENABLE_MONITORING=true
      ENABLE_LOGGING=true
      ENABLE_LDAP=true
      ENABLE_API=true
      ENABLE_LOAD_BALANCING=true
      shift
      ;;
    -h | --help)
      usage
      ;;
    *)
      log "ERROR" "Unknown option: $1"
      usage
      ;;
  esac
done

# Execute selected features
if [[ ${ENABLE_VAULT} == true ]]; then
  configure_vault_integration
fi

if [[ ${ENABLE_MONITORING} == true ]]; then
  setup_prometheus_metrics
fi

if [[ ${ENABLE_LOGGING} == true ]]; then
  configure_elk_logging
fi

if [[ ${ENABLE_LDAP} == true ]]; then
  configure_ldap_auth
fi

if [[ ${ENABLE_API} == true ]]; then
  configure_api
fi

if [[ ${ENABLE_LOAD_BALANCING} == true ]]; then
  configure_load_balancing
fi

log "SUCCESS" "Enterprise setup completed"
