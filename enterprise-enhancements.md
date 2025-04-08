# Enterprise Enhancements for WordPress Gmail CLI

This document outlines enhancements to make the WordPress Gmail CLI tool more suitable for enterprise environments.

## Security Enhancements

### 1. Vault Integration for Credential Management

```bash
# Add support for HashiCorp Vault
configure_vault_integration() {
    log "INFO" "Configuring Vault integration..."

    # Check if Vault CLI is installed
    if ! command_exists vault; then
        log "ERROR" "Vault CLI not found. Please install HashiCorp Vault."
        exit 1
    }

    # Store credentials in Vault
    vault kv put secret/wordpress-gmail-cli/credentials \
        client_id="${CLIENT_ID}" \
        client_secret="${CLIENT_SECRET}" \
        refresh_token="${REFRESH_TOKEN}" \
        email="${EMAIL}"

    # Create a script to retrieve credentials from Vault
    cat > /etc/postfix/gmail-api/vault-credentials.sh << 'EOF'
#!/bin/bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="$(cat /etc/vault/token)"

# Get credentials from Vault
CREDS=$(vault kv get -format=json secret/wordpress-gmail-cli/credentials)
CLIENT_ID=$(echo "$CREDS" | jq -r '.data.data.client_id')
CLIENT_SECRET=$(echo "$CREDS" | jq -r '.data.data.client_secret')
REFRESH_TOKEN=$(echo "$CREDS" | jq -r '.data.data.refresh_token')
EMAIL=$(echo "$CREDS" | jq -r '.data.data.email')

# Output to credentials file
cat > /etc/postfix/gmail-api/credentials.json << EOT
{
  "client_id": "${CLIENT_ID}",
  "client_secret": "${CLIENT_SECRET}",
  "refresh_token": "${REFRESH_TOKEN}",
  "email": "${EMAIL}"
}
EOT
chmod 600 /etc/postfix/gmail-api/credentials.json
EOF

    chmod 700 /etc/postfix/gmail-api/vault-credentials.sh

    # Add to cron to periodically refresh credentials
    echo "0 */6 * * * root /etc/postfix/gmail-api/vault-credentials.sh > /dev/null 2>&1" > /etc/cron.d/gmail-api-vault

    log "SUCCESS" "Vault integration configured"
}
```

### 2. Enhanced File Permissions and SELinux Contexts

```bash
# Set proper SELinux contexts for enterprise environments
configure_selinux() {
    log "INFO" "Configuring SELinux contexts..."

    if command_exists semanage && command_exists restorecon; then
        # Set proper contexts for credential files
        semanage fcontext -a -t postfix_etc_t "/etc/postfix/gmail-api(/.*)?"
        restorecon -Rv /etc/postfix/gmail-api

        log "SUCCESS" "SELinux contexts configured"
    else
        log "WARNING" "SELinux tools not found, skipping context configuration"
    fi
}
```

## Monitoring and Logging

### 1. Prometheus Metrics Endpoint

```bash
# Set up a metrics endpoint for Prometheus monitoring
setup_prometheus_metrics() {
    log "INFO" "Setting up Prometheus metrics..."

    # Install required packages
    apt-get install -y python3-pip
    pip3 install prometheus_client flask

    # Create metrics service
    cat > /opt/gmail-metrics/metrics.py << 'EOF'
#!/usr/bin/env python3
from prometheus_client import Counter, Gauge, start_http_server
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

    # Create systemd service
    cat > /etc/systemd/system/gmail-metrics.service << EOF
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
}
```

### 2. Centralized Logging with ELK Stack

```bash
# Configure logging to ELK stack
configure_elk_logging() {
    log "INFO" "Configuring centralized logging..."

    # Install Filebeat
    curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.15.0-amd64.deb
    dpkg -i filebeat-7.15.0-amd64.deb

    # Configure Filebeat
    cat > /etc/filebeat/filebeat.yml << EOF
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
  hosts: ["elasticsearch.example.com:9200"]
  username: "elastic"
  password: "your-password"

setup.kibana:
  host: "kibana.example.com:5601"
EOF

    # Enable and start Filebeat
    systemctl enable filebeat
    systemctl start filebeat

    # Configure token refresh script to log to a file
    sed -i 's|echo "Access token refreshed successfully (expires in ${EXPIRES_IN}s)"|echo "$(date): Access token refreshed successfully (expires in ${EXPIRES_IN}s)" >> /etc/postfix/gmail-api/token-refresh.log|g' /etc/postfix/gmail-api/refresh-token.sh

    log "SUCCESS" "Centralized logging configured"
}
```

## Configuration Management

### 1. Ansible Playbook for Deployment

Create an Ansible playbook for automated deployment:

```yaml
---
# wordpress-gmail-cli-deploy.yml
- name: Deploy WordPress Gmail CLI
  hosts: wordpress_servers
  become: yes
  vars:
    gmail_email: "{{ vault_gmail_email }}"
    gmail_client_id: "{{ vault_gmail_client_id }}"
    gmail_client_secret: "{{ vault_gmail_client_secret }}"
    gmail_refresh_token: "{{ vault_gmail_refresh_token }}"
    domain: "example.com"
    wp_path: "/var/www/html"

  tasks:
    - name: Ensure dependencies are installed
      apt:
        name:
          - postfix
          - php
          - curl
          - jq
        state: present
        update_cache: yes

    - name: Create Gmail API directory
      file:
        path: /etc/postfix/gmail-api
        state: directory
        mode: "0700"

    - name: Copy credentials file
      template:
        src: templates/credentials.json.j2
        dest: /etc/postfix/gmail-api/credentials.json
        mode: "0600"

    - name: Copy token refresh script
      template:
        src: templates/refresh-token.sh.j2
        dest: /etc/postfix/gmail-api/refresh-token.sh
        mode: "0700"

    - name: Run token refresh script
      command: /etc/postfix/gmail-api/refresh-token.sh

    - name: Configure cron job for token refresh
      cron:
        name: "Refresh Gmail API token"
        job: "/etc/postfix/gmail-api/refresh-token.sh > /dev/null 2>&1"
        minute: "*/30"
        user: root
        cron_file: gmail-api-token

    - name: Configure Postfix
      template:
        src: templates/main.cf.j2
        dest: /etc/postfix/main.cf
        backup: yes

    - name: Restart Postfix
      service:
        name: postfix
        state: restarted

    - name: Configure WordPress plugin
      template:
        src: templates/gmail-api.php.j2
        dest: "{{ wp_path }}/wp-content/mu-plugins/gmail-api.php"
        mode: "0644"

    - name: Set WordPress plugin permissions
      file:
        path: "{{ wp_path }}/wp-content/mu-plugins"
        owner: www-data
        group: www-data
        recurse: yes
```

### 2. Docker Containerization

Create a Dockerfile for containerized deployment:

```dockerfile
FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    postfix \
    php \
    curl \
    jq \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Set up directories
RUN mkdir -p /etc/postfix/gmail-api

# Copy scripts
COPY scripts/refresh-token.sh /etc/postfix/gmail-api/
RUN chmod 700 /etc/postfix/gmail-api/refresh-token.sh

# Copy configuration templates
COPY templates/main.cf.template /etc/postfix/
COPY templates/gmail-api.php.template /tmp/

# Set up entrypoint
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

# Configure cron
RUN echo "*/30 * * * * /etc/postfix/gmail-api/refresh-token.sh > /dev/null 2>&1" > /etc/cron.d/gmail-api-token \
    && chmod 0644 /etc/cron.d/gmail-api-token

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["postfix", "start-fg"]
```

## Multi-Server Support

### 1. Centralized Credential Management

```bash
# Configure centralized credential management
configure_central_credentials() {
    log "INFO" "Configuring centralized credential management..."

    # Create a script to fetch credentials from a central server
    cat > /etc/postfix/gmail-api/fetch-credentials.sh << 'EOF'
#!/bin/bash

# Fetch credentials from central server
CENTRAL_SERVER="credentials.example.com"
API_KEY="your-api-key"

RESPONSE=$(curl -s -H "Authorization: Bearer ${API_KEY}" "https://${CENTRAL_SERVER}/api/credentials/gmail")

# Parse response
CLIENT_ID=$(echo "$RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.client_secret')
REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r '.refresh_token')
EMAIL=$(echo "$RESPONSE" | jq -r '.email')

# Update credentials file
cat > /etc/postfix/gmail-api/credentials.json << EOT
{
  "client_id": "${CLIENT_ID}",
  "client_secret": "${CLIENT_SECRET}",
  "refresh_token": "${REFRESH_TOKEN}",
  "email": "${EMAIL}"
}
EOT
chmod 600 /etc/postfix/gmail-api/credentials.json

# Run token refresh
/etc/postfix/gmail-api/refresh-token.sh
EOF

    chmod 700 /etc/postfix/gmail-api/fetch-credentials.sh

    # Add to cron to periodically fetch credentials
    echo "0 */12 * * * root /etc/postfix/gmail-api/fetch-credentials.sh > /dev/null 2>&1" > /etc/cron.d/gmail-api-fetch

    log "SUCCESS" "Centralized credential management configured"
}
```

### 2. Load Balancing Configuration

```bash
# Configure for load balanced environment
configure_load_balancing() {
    log "INFO" "Configuring for load balanced environment..."

    # Update Postfix configuration for load balanced environment
    cat >> /etc/postfix/main.cf << EOF

# Load balancing configuration
smtp_connection_cache_destinations =
smtp_connection_cache_on_demand = no
smtp_connection_reuse_time_limit = 300s
EOF

    # Create a health check endpoint
    mkdir -p /var/www/health
    cat > /var/www/health/gmail-api-health.php << 'EOF'
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
        cat > /etc/nginx/conf.d/health-check.conf << EOF
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
}
```

## Enterprise Integration

### 1. LDAP Authentication for Admin Interface

```bash
# Set up LDAP authentication for admin interface
configure_ldap_auth() {
    log "INFO" "Configuring LDAP authentication..."

    # Install required packages
    apt-get install -y php-ldap

    # Create admin interface with LDAP authentication
    mkdir -p /var/www/gmail-admin
    cat > /var/www/gmail-admin/index.php << 'EOF'
<?php
session_start();

// LDAP configuration
$ldap_server = 'ldap.example.com';
$ldap_port = 389;
$ldap_base_dn = 'dc=example,dc=com';
$ldap_user_dn = 'ou=users,dc=example,dc=com';
$ldap_group_dn = 'ou=groups,dc=example,dc=com';
$ldap_admin_group = 'cn=mail-admins,ou=groups,dc=example,dc=com';

// Authentication function
function ldap_authenticate($username, $password) {
    global $ldap_server, $ldap_port, $ldap_base_dn, $ldap_user_dn, $ldap_group_dn, $ldap_admin_group;

    $ldap = ldap_connect($ldap_server, $ldap_port);
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

    $user_dn = "uid=$username,$ldap_user_dn";

    if ($bind = ldap_bind($ldap, $user_dn, $password)) {
        // Check if user is in admin group
        $filter = "(memberUid=$username)";
        $search = ldap_search($ldap, $ldap_admin_group, $filter);
        $entries = ldap_get_entries($ldap, $search);

        if ($entries['count'] > 0) {
            return true;
        }
    }

    return false;
}

// Handle login
if (isset($_POST['username']) && isset($_POST['password'])) {
    if (ldap_authenticate($_POST['username'], $_POST['password'])) {
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $_POST['username'];
    } else {
        $error = "Invalid credentials or insufficient permissions";
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Check authentication
$authenticated = isset($_SESSION['authenticated']) && $_SESSION['authenticated'];

// Display login form or admin interface
if (!$authenticated) {
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
            <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
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
    $token_file = '/etc/postfix/gmail-api/token.json';
    $credentials_file = '/etc/postfix/gmail-api/credentials.json';

    $token_data = file_exists($token_file) ? json_decode(file_get_contents($token_file), true) : null;
    $credentials_data = file_exists($credentials_file) ? json_decode(file_get_contents($credentials_file), true) : null;

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
                <?php if ($token_data): ?>
                    <?php
                    $now = time();
                    $expires_in = $token_data['expiry_time'] - $now;
                    $status_class = $expires_in > 0 ? 'active' : 'expired';
                    $status_text = $expires_in > 0 ? 'Active' : 'Expired';
                    ?>
                    <div class="status <?php echo $status_class; ?>"><?php echo $status_text; ?></div>
                    <table>
                        <tr>
                            <td>Expires in:</td>
                            <td><?php echo $expires_in > 0 ? gmdate("H:i:s", $expires_in) : 'Expired'; ?></td>
                        </tr>
                        <tr>
                            <td>Last refreshed:</td>
                            <td><?php echo date('Y-m-d H:i:s', filemtime($token_file)); ?></td>
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
                <?php if ($credentials_data): ?>
                    <table>
                        <tr>
                            <td>Email:</td>
                            <td><?php echo $credentials_data['email']; ?></td>
                        </tr>
                        <tr>
                            <td>Client ID:</td>
                            <td><?php echo substr($credentials_data['client_id'], 0, 10) . '...'; ?></td>
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
    cat > /var/www/gmail-admin/refresh.php << 'EOF'
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

    # Configure sudo for www-data
    echo "www-data ALL=(root) NOPASSWD: /etc/postfix/gmail-api/refresh-token.sh" > /etc/sudoers.d/gmail-admin
    chmod 440 /etc/sudoers.d/gmail-admin

    # Set permissions
    chown -R www-data:www-data /var/www/gmail-admin

    log "SUCCESS" "LDAP authentication configured"
}
```

### 2. API for Email Status and Management

```bash
# Set up API for email status and management
configure_api() {
    log "INFO" "Configuring management API..."

    # Install required packages
    apt-get install -y php-fpm nginx

    # Create API endpoints
    mkdir -p /var/www/gmail-api
    cat > /var/www/gmail-api/index.php << 'EOF'
<?php
// Simple API for Gmail integration status and management

// API key authentication
function authenticate() {
    $api_keys = [
        'production' => 'your-production-api-key',
        'staging' => 'your-staging-api-key',
        'development' => 'your-development-api-key'
    ];

    $headers = getallheaders();
    if (!isset($headers['X-API-Key'])) {
        return false;
    }

    $api_key = $headers['X-API-Key'];
    return in_array($api_key, $api_keys);
}

// Return JSON response
function json_response($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

// Check authentication
if (!authenticate()) {
    json_response(['error' => 'Unauthorized'], 401);
}

// Parse request
$method = $_SERVER['REQUEST_METHOD'];
$path = trim($_SERVER['PATH_INFO'] ?? '/', '/');
$params = $_GET;

// API routes
switch ($path) {
    case 'status':
        // Get token and credentials status
        $token_file = '/etc/postfix/gmail-api/token.json';
        $credentials_file = '/etc/postfix/gmail-api/credentials.json';

        $token_data = file_exists($token_file) ? json_decode(file_get_contents($token_file), true) : null;
        $credentials_data = file_exists($credentials_file) ? json_decode(file_get_contents($credentials_file), true) : null;

        $now = time();
        $token_valid = $token_data && isset($token_data['expiry_time']) && $token_data['expiry_time'] > $now;

        $response = [
            'status' => $token_valid ? 'healthy' : 'unhealthy',
            'token' => [
                'valid' => $token_valid,
                'expires_in' => $token_valid ? $token_data['expiry_time'] - $now : 0,
                'last_refresh' => file_exists($token_file) ? date('Y-m-d H:i:s', filemtime($token_file)) : null
            ],
            'credentials' => [
                'configured' => $credentials_data !== null,
                'email' => $credentials_data['email'] ?? null
            ],
            'postfix' => [
                'running' => trim(shell_exec('systemctl is-active postfix')) === 'active'
            ]
        ];

        json_response($response);
        break;

    case 'refresh':
        // Refresh token
        if ($method !== 'POST') {
            json_response(['error' => 'Method not allowed'], 405);
        }

        $output = shell_exec('/etc/postfix/gmail-api/refresh-token.sh 2>&1');
        $success = strpos($output, 'successfully') !== false;

        json_response([
            'success' => $success,
            'message' => $output
        ]);
        break;

    case 'logs':
        // Get recent logs
        $log_file = '/etc/postfix/gmail-api/token-refresh.log';
        $lines = isset($params['lines']) ? intval($params['lines']) : 10;

        if (file_exists($log_file)) {
            $logs = explode("\n", trim(shell_exec("tail -n $lines $log_file")));
        } else {
            $logs = [];
        }

        json_response(['logs' => $logs]);
        break;

    default:
        json_response(['error' => 'Not found'], 404);
}
EOF

    # Configure Nginx
    cat > /etc/nginx/conf.d/gmail-api.conf << EOF
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
}
```

## Documentation for Enterprise Use Cases

###
