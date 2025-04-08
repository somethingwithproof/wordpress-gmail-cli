#!/bin/bash

# wordpress-gmail-cli
# Version: 1.1.0
# A CLI tool to configure WordPress and Postfix for sending outbound emails using Google API
# Especially useful for Digital Ocean servers where standard SMTP ports are blocked

set -e

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Function to display script usage
usage() {
	echo -e "${BOLD}WordPress Gmail CLI${RESET}"
	echo "A simple CLI tool to configure WordPress and Postfix for Gmail using Google API"
	echo
	echo -e "${BOLD}Usage:${RESET}"
	echo "  $0 [options]"
	echo
	echo -e "${BOLD}Options:${RESET}"
	echo "  -e, --email EMAIL           Gmail address to use for sending emails"
	echo "  -c, --client-id ID          Google API Client ID"
	echo "  -s, --client-secret SECRET  Google API Client Secret"
	echo "  -r, --refresh-token TOKEN   Google API Refresh Token"
	echo "  -d, --domain DOMAIN         Your website domain (e.g., example.com)"
	echo "  -w, --wp-path PATH          Path to WordPress installation (default: /var/www/html)"
	echo "  -a, --social-auth           Enable social authentication (Google and Facebook login)"
	echo "  --google-auth-id ID         Google OAuth Client ID for login (if different from email client ID)"
	echo "  --google-auth-secret SECRET Google OAuth Client Secret for login"
	echo "  --facebook-app-id ID        Facebook App ID for login"
	echo "  --facebook-app-secret SECRET Facebook App Secret for login"
	echo "  -h, --help                  Display this help message"
	echo
	echo -e "${BOLD}Example:${RESET}"
	echo "  $0 --email your-email@gmail.com --client-id your-client-id --client-secret your-client-secret --refresh-token your-refresh-token --domain example.com"
	echo "  $0 --email your-email@gmail.com --client-id your-client-id --client-secret your-client-secret --refresh-token your-refresh-token --domain example.com --social-auth --google-auth-id your-oauth-client-id --google-auth-secret your-oauth-client-secret --facebook-app-id your-facebook-app-id --facebook-app-secret your-facebook-app-secret"
	exit 1
}

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
	esac

	echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}${level}${RESET}: ${message}"
}

# Function to check if command exists
command_exists() {
	command -v "$1" >/dev/null 2>&1
}

# Function to check if running as root
check_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		log "ERROR" "This script must be run as root"
		exit 1
	fi
}

# Function to check dependencies
check_dependencies() {
	log "INFO" "Checking dependencies..."

	local missing_deps=()

	if ! command_exists postfix; then
		missing_deps+=("postfix")
	fi

	if ! command_exists php; then
		missing_deps+=("php")
	fi

	if ! command_exists curl; then
		missing_deps+=("curl")
	fi

	if ! command_exists jq; then
		missing_deps+=("jq")
	fi

	if [[ ${#missing_deps[@]} -ne 0 ]]; then
		log "ERROR" "Missing dependencies: ${missing_deps[*]}"
		log "INFO" "Please install the missing dependencies and try again"
		log "INFO" "You can install them using: apt-get install ${missing_deps[*]}"
		exit 1
	fi

	log "SUCCESS" "All dependencies are installed"
}

# Function to get a new access token using the refresh token
get_access_token() {
	log "INFO" "Getting access token from Google API..."

	local token_response
	token_response=$(curl -s --request POST \
		--url "https://oauth2.googleapis.com/token" \
		--header "Content-Type: application/x-www-form-urlencoded" \
		--data "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&refresh_token=${REFRESH_TOKEN}&grant_type=refresh_token")

	if echo "${token_response}" | grep -q "error"; then
		log "ERROR" "Failed to get access token: $(echo "${token_response}" | jq -r '.error_description // .error')"
		exit 1
	fi

	ACCESS_TOKEN=$(echo "${token_response}" | jq -r '.access_token')
	EXPIRES_IN=$(echo "${token_response}" | jq -r '.expires_in')

	if [[ -z ${ACCESS_TOKEN} ]] || [[ ${ACCESS_TOKEN} == "null" ]]; then
		log "ERROR" "Failed to extract access token from response"
		exit 1
	fi

	log "SUCCESS" "Successfully obtained access token (expires in ${EXPIRES_IN}s)"
	return 0
}

# Function to configure Postfix
configure_postfix() {
	log "INFO" "Configuring Postfix for Gmail API..."

	# Backup original configuration
	if [[ -f /etc/postfix/main.cf ]]; then
		cp /etc/postfix/main.cf /etc/postfix/main.cf.backup.$(date +%Y%m%d%H%M%S)
		log "INFO" "Backed up original Postfix configuration"
	fi

	# Create credentials directory if it doesn't exist
	mkdir -p /etc/postfix/gmail-api
	chmod 700 /etc/postfix/gmail-api

	# Store Google API credentials
	cat >/etc/postfix/gmail-api/credentials.json <<EOF
{
  "client_id": "${CLIENT_ID}",
  "client_secret": "${CLIENT_SECRET}",
  "refresh_token": "${REFRESH_TOKEN}",
  "email": "${EMAIL}"
}
EOF
	chmod 600 /etc/postfix/gmail-api/credentials.json

	# Create token refresh script
	cat >/etc/postfix/gmail-api/refresh-token.sh <<'EOF'
#!/bin/bash

CREDENTIALS_FILE="/etc/postfix/gmail-api/credentials.json"
TOKEN_FILE="/etc/postfix/gmail-api/token.json"

if [ ! -f "$CREDENTIALS_FILE" ]; then
    echo "Credentials file not found" >&2
    exit 1
fi

CLIENT_ID=$(jq -r '.client_id' "$CREDENTIALS_FILE")
CLIENT_SECRET=$(jq -r '.client_secret' "$CREDENTIALS_FILE")
REFRESH_TOKEN=$(jq -r '.refresh_token' "$CREDENTIALS_FILE")

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ] || [ -z "$REFRESH_TOKEN" ]; then
    echo "Missing required credentials" >&2
    exit 1
fi

TOKEN_RESPONSE=$(curl -s --request POST \
    --url "https://oauth2.googleapis.com/token" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&refresh_token=${REFRESH_TOKEN}&grant_type=refresh_token")

if echo "$TOKEN_RESPONSE" | grep -q "error"; then
    echo "Failed to refresh token: $(echo "$TOKEN_RESPONSE" | jq -r '.error_description // .error')" >&2
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')
EXPIRY_TIME=$(($(date +%s) + EXPIRES_IN))

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    echo "Failed to extract access token from response" >&2
    exit 1
fi

echo "{\"access_token\":\"$ACCESS_TOKEN\",\"expiry_time\":$EXPIRY_TIME}" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"

echo "Access token refreshed successfully (expires in ${EXPIRES_IN}s)"
EOF
	chmod 700 /etc/postfix/gmail-api/refresh-token.sh

	# Run the token refresh script to get initial token
	/etc/postfix/gmail-api/refresh-token.sh

	# Create a cron job to refresh the token every 30 minutes
	echo "*/30 * * * * root /etc/postfix/gmail-api/refresh-token.sh > /dev/null 2>&1" >/etc/cron.d/gmail-api-token
	chmod 644 /etc/cron.d/gmail-api-token

	# Update main.cf configuration
	cat >/etc/postfix/main.cf <<EOF
# Basic Postfix configuration
smtpd_banner = \$myhostname ESMTP \$mail_name
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may
smtp_tls_security_level=encrypt
smtp_tls_CApath=/etc/ssl/certs
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

# Gmail API relay configuration
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt

# General mail configuration
myhostname = ${DOMAIN}
myorigin = ${DOMAIN}
mydestination = \$myhostname, localhost.\$mydomain, localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = loopback-only
inet_protocols = all
EOF

	# Restart Postfix
	systemctl restart postfix

	log "SUCCESS" "Postfix configured to use Gmail API"
}

# Function to configure WordPress
configure_wordpress() {
	log "INFO" "Configuring WordPress to use Google API..."

	# Check if wp-config.php exists
	if [[ ! -f "${WP_PATH}/wp-config.php" ]]; then
		log "ERROR" "WordPress configuration file not found at ${WP_PATH}/wp-config.php"
		log "INFO" "Please check your WordPress installation path and try again"
		exit 1
	fi

	# Create the WordPress Gmail API plugin file
	mkdir -p "${WP_PATH}/wp-content/mu-plugins"
	cat >"${WP_PATH}/wp-content/mu-plugins/gmail-api.php" <<EOF
<?php
/**
 * Plugin Name: Gmail API Configuration
 * Description: Configures WordPress to use Gmail API for sending emails
 * Version: 1.0
 * Author: WordPress Gmail CLI
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class Gmail_API_Mailer {
    private \$client_id;
    private \$client_secret;
    private \$refresh_token;
    private \$access_token;
    private \$token_expiry;
    private \$email;
    private \$domain;
    
    public function __construct() {
        // Load credentials from file
        \$credentials_file = '/etc/postfix/gmail-api/credentials.json';
        \$token_file = '/etc/postfix/gmail-api/token.json';
        
        if (file_exists(\$credentials_file) && is_readable(\$credentials_file)) {
            \$credentials = json_decode(file_get_contents(\$credentials_file), true);
            \$this->client_id = \$credentials['client_id'];
            \$this->client_secret = \$credentials['client_secret'];
            \$this->refresh_token = \$credentials['refresh_token'];
            \$this->email = \$credentials['email'];
        }
        
        if (file_exists(\$token_file) && is_readable(\$token_file)) {
            \$token_data = json_decode(file_get_contents(\$token_file), true);
            \$this->access_token = \$token_data['access_token'];
            \$this->token_expiry = \$token_data['expiry_time'];
        }
        
        \$this->domain = '${DOMAIN}';
        
        // Configure WordPress to use our mailer
        add_action('phpmailer_init', array(\$this, 'configure_phpmailer'));
        
        // Add admin notice
        add_action('admin_notices', array(\$this, 'admin_notice'));
    }
    
    public function configure_phpmailer(\$phpmailer) {
        \$phpmailer->isSMTP();
        \$phpmailer->Host = 'smtp.gmail.com';
        \$phpmailer->SMTPAuth = true;
        \$phpmailer->Port = 587;
        \$phpmailer->Username = \$this->email;
        
        // Use the access token as password (OAuth2)
        if (\$this->access_token) {
            \$phpmailer->Password = \$this->access_token;
            \$phpmailer->AuthType = 'XOAUTH2';
        } else {
            // Fallback to regular SMTP if no token is available
            error_log('Gmail API: No access token available, email sending may fail');
        }
        
        \$phpmailer->SMTPSecure = 'tls';
        \$phpmailer->From = \$this->email;
        \$phpmailer->FromName = \$this->domain;
    }
    
    public function admin_notice() {
        echo '<div class="notice notice-success is-dismissible">';
        echo '<p><strong>Gmail API:</strong> Your WordPress site is configured to send emails through Gmail API.</p>';
        echo '</div>';
    }
}

// Initialize the mailer
new Gmail_API_Mailer();
EOF

	# Set proper permissions
	chown -R www-data:www-data "${WP_PATH}/wp-content/mu-plugins"
	chmod 644 "${WP_PATH}/wp-content/mu-plugins/gmail-api.php"

	log "SUCCESS" "WordPress configured to use Gmail API"
}

# Function to create a helper script for obtaining Google API credentials
create_credentials_helper() {
	log "INFO" "Creating helper script for obtaining Google API credentials..."

	cat >get-gmail-credentials.sh <<'EOF'
#!/bin/bash

# Helper script to obtain Google API credentials for WordPress Gmail CLI

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

echo -e "${BOLD}Google API Credentials Helper${RESET}"
echo "This script will help you obtain the necessary credentials for the WordPress Gmail CLI"
echo

echo -e "${BOLD}Step 1: Create a Google Cloud Project${RESET}"
echo "1. Go to https://console.cloud.google.com/"
echo "2. Create a new project or select an existing one"
echo "3. Enable the Gmail API for your project"
echo

echo -e "${BOLD}Step 2: Create OAuth credentials${RESET}"
echo "1. Go to https://console.cloud.google.com/apis/credentials"
echo "2. Click 'Create Credentials' and select 'OAuth client ID'"
echo "3. Configure the OAuth consent screen if prompted"
echo "4. For Application type, select 'Web application'"
echo "5. Add 'http://localhost:8080' as an Authorized redirect URI"
echo "6. Click 'Create' and note your Client ID and Client Secret"
echo

echo -e "${BOLD}Step 3: Get a refresh token${RESET}"
echo "Enter your Client ID:"
read CLIENT_ID

echo "Enter your Client Secret:"
read CLIENT_SECRET

echo "Enter your Gmail address:"
read EMAIL

# Generate a random state value
STATE=$(openssl rand -hex 12)

# Construct the authorization URL
AUTH_URL="https://accounts.google.com/o/oauth2/auth"
AUTH_URL="${AUTH_URL}?client_id=${CLIENT_ID}"
AUTH_URL="${AUTH_URL}&redirect_uri=http://localhost:8080"
AUTH_URL="${AUTH_URL}&response_type=code"
AUTH_URL="${AUTH_URL}&scope=https://mail.google.com/"
AUTH_URL="${AUTH_URL}&access_type=offline"
AUTH_URL="${AUTH_URL}&prompt=consent"
AUTH_URL="${AUTH_URL}&state=${STATE}"
AUTH_URL="${AUTH_URL}&login_hint=${EMAIL}"

echo -e "\n${BOLD}Please open the following URL in your browser:${RESET}"
echo -e "${BLUE}${AUTH_URL}${RESET}"
echo

echo "After you authorize the application, you will be redirected to localhost:8080 with a code parameter."
echo "Copy the entire URL from your browser and paste it here:"
read REDIRECT_URL

# Extract the authorization code from the redirect URL
CODE=$(echo "$REDIRECT_URL" | grep -oP 'code=\K[^&]+')

if [ -z "$CODE" ]; then
    echo -e "${RED}Failed to extract authorization code from the URL${RESET}"
    exit 1
fi

# Exchange the authorization code for tokens
TOKEN_RESPONSE=$(curl -s --request POST \
    --url "https://oauth2.googleapis.com/token" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&code=${CODE}&redirect_uri=http://localhost:8080&grant_type=authorization_code")

# Extract the refresh token
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -oP '"refresh_token":"\K[^"]+')

if [ -z "$REFRESH_TOKEN" ]; then
    echo -e "${RED}Failed to obtain refresh token${RESET}"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo -e "\n${GREEN}Successfully obtained credentials!${RESET}"
echo
echo -e "${BOLD}Your Google API credentials:${RESET}"
echo -e "Client ID: ${BLUE}${CLIENT_ID}${RESET}"
echo -e "Client Secret: ${BLUE}${CLIENT_SECRET}${RESET}"
echo -e "Refresh Token: ${BLUE}${REFRESH_TOKEN}${RESET}"
echo -e "Email: ${BLUE}${EMAIL}${RESET}"
echo
echo -e "${BOLD}Use these credentials with the WordPress Gmail CLI:${RESET}"
echo -e "${YELLOW}./wordpress-gmail-cli.sh --email ${EMAIL} --client-id ${CLIENT_ID} --client-secret ${CLIENT_SECRET} --refresh-token ${REFRESH_TOKEN} --domain your-domain.com${RESET}"
EOF

	chmod +x get-gmail-credentials.sh

	log "SUCCESS" "Helper script created: get-gmail-credentials.sh"
	log "INFO" "Run this script to obtain the necessary Google API credentials"
}

# Function to test email configuration
test_email() {
	log "INFO" "Testing email configuration..."

	# Create a temporary PHP file for testing
	local test_file="/tmp/wp-mail-test.php"
	cat >"${test_file}" <<EOF
<?php
// Load WordPress
require_once('${WP_PATH}/wp-load.php');

// Send a test email
\$to = '${EMAIL}';
\$subject = 'WordPress Gmail API Test';
\$message = 'This is a test email from your WordPress site using Gmail API.';
\$headers = array('Content-Type: text/html; charset=UTF-8');

\$result = wp_mail(\$to, \$subject, \$message, \$headers);
echo \$result ? "Test email sent successfully!" : "Failed to send test email.";
EOF

	# Run the test
	php "${test_file}"
	rm "${test_file}"

	log "INFO" "Check your inbox for a test email"
	log "INFO" "If you don't receive it, check your spam folder"
}

# Function to configure social authentication
configure_social_auth() {
	log "INFO" "Configuring social authentication for WordPress..."

	# Use email client credentials if specific auth credentials not provided
	GOOGLE_AUTH_ID=${GOOGLE_AUTH_ID:-${CLIENT_ID}}
	GOOGLE_AUTH_SECRET=${GOOGLE_AUTH_SECRET:-${CLIENT_SECRET}}

	# Check if wp-config.php exists
	if [[ ! -f "${WP_PATH}/wp-config.php" ]]; then
		log "ERROR" "WordPress configuration file not found at ${WP_PATH}/wp-config.php"
		log "INFO" "Please check your WordPress installation path and try again"
		return 1
	fi

	# Copy the social auth plugin to WordPress
	mkdir -p "${WP_PATH}/wp-content/mu-plugins"
	cp "$(dirname "$0")/wp-social-auth.php" "${WP_PATH}/wp-content/mu-plugins/"

	# If wp-social-auth.php doesn't exist in the current directory, create it
	if [[ ! -f "$(dirname "$0")/wp-social-auth.php" ]]; then
		log "INFO" "Creating social authentication plugin..."

		# Create the WordPress social authentication plugin file
		cat >"${WP_PATH}/wp-content/mu-plugins/wp-social-auth.php" <<'EOF'
<?php
/**
 * Plugin Name: WordPress Social Authentication
 * Description: Adds Google and Facebook authentication to WordPress login
 * Version: 1.0
 * Author: WordPress Gmail CLI
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class WP_Social_Auth {
    private $google_client_id;
    private $google_client_secret;
    private $facebook_app_id;
    private $facebook_app_secret;
    private $redirect_uri;
    
    public function __construct($config) {
        $this->google_client_id = $config['google_client_id'] ?? '';
        $this->google_client_secret = $config['google_client_secret'] ?? '';
        $this->facebook_app_id = $config['facebook_app_id'] ?? '';
        $this->facebook_app_secret = $config['facebook_app_secret'] ?? '';
        $this->redirect_uri = admin_url('admin-ajax.php?action=social_login_callback');
        
        // Initialize hooks
        add_action('login_form', array($this, 'add_social_login_buttons'));
        add_action('wp_ajax_nopriv_social_login_callback', array($this, 'handle_social_login_callback'));
        add_action('wp_ajax_social_login_callback', array($this, 'handle_social_login_callback'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_menu', array($this, 'add_settings_page'));
    }
    
    /**
     * Add social login buttons to the WordPress login form
     */
    public function add_social_login_buttons() {
        ?>
        <div class="social-login-buttons" style="margin-bottom: 20px; text-align: center;">
            <?php if ($this->google_client_id): ?>
            <a href="<?php echo $this->get_google_auth_url(); ?>" class="button" style="background: #4285F4; color: white; margin-right: 10px; text-decoration: none; padding: 8px 12px; border-radius: 4px;">
                <span style="font-size: 16px; vertical-align: middle;">G</span> Login with Google
            </a>
            <?php endif; ?>
            
            <?php if ($this->facebook_app_id): ?>
            <a href="<?php echo $this->get_facebook_auth_url(); ?>" class="button" style="background: #3b5998; color: white; text-decoration: none; padding: 8px 12px; border-radius: 4px;">
                <span style="font-size: 16px; vertical-align: middle;">f</span> Login with Facebook
            </a>
            <?php endif; ?>
        </div>
        <?php
    }
    
    /**
     * Handle the social login callback
     */
    public function handle_social_login_callback() {
        $provider = isset($_GET['provider']) ? sanitize_text_field($_GET['provider']) : '';
        $code = isset($_GET['code']) ? sanitize_text_field($_GET['code']) : '';
        
        if (empty($code)) {
            wp_redirect(wp_login_url());
            exit;
        }
        
        try {
            $user_data = null;
            
            if ($provider === 'google') {
                $user_data = $this->get_google_user_data($code);
            } elseif ($provider === 'facebook') {
                $user_data = $this->get_facebook_user_data($code);
            }
            
            if ($user_data && isset($user_data['email'])) {
                $this->login_or_create_user($user_data);
            } else {
                wp_redirect(wp_login_url() . '?login=failed');
                exit;
            }
        } catch (Exception $e) {
            wp_redirect(wp_login_url() . '?login=failed&error=' . urlencode($e->getMessage()));
            exit;
        }
    }
    
    /**
     * Get Google authentication URL
     */
    private function get_google_auth_url() {
        $params = array(
            'client_id' => $this->google_client_id,
            'redirect_uri' => $this->redirect_uri . '&provider=google',
            'response_type' => 'code',
            'scope' => 'email profile',
            'access_type' => 'online',
            'state' => wp_create_nonce('google_login')
        );
        
        return 'https://accounts.google.com/o/oauth2/auth?' . http_build_query($params);
    }
    
    /**
     * Get Facebook authentication URL
     */
    private function get_facebook_auth_url() {
        $params = array(
            'client_id' => $this->facebook_app_id,
            'redirect_uri' => $this->redirect_uri . '&provider=facebook',
            'response_type' => 'code',
            'scope' => 'email',
            'state' => wp_create_nonce('facebook_login')
        );
        
        return 'https://www.facebook.com/v12.0/dialog/oauth?' . http_build_query($params);
    }
    
    /**
     * Get Google user data
     */
    private function get_google_user_data($code) {
        // Exchange code for access token
        $token_url = 'https://oauth2.googleapis.com/token';
        $token_params = array(
            'client_id' => $this->google_client_id,
            'client_secret' => $this->google_client_secret,
            'code' => $code,
            'redirect_uri' => $this->redirect_uri . '&provider=google',
            'grant_type' => 'authorization_code'
        );
        
        $response = wp_remote_post($token_url, array(
            'body' => $token_params,
            'headers' => array('Content-Type' => 'application/x-www-form-urlencoded')
        ));
        
        if (is_wp_error($response)) {
            throw new Exception('Failed to get access token: ' . $response->get_error_message());
        }
        
        $token_data = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!isset($token_data['access_token'])) {
            throw new Exception('Failed to get access token');
        }
        
        // Get user info
        $user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo';
        $user_info_response = wp_remote_get($user_info_url, array(
            'headers' => array('Authorization' => 'Bearer ' . $token_data['access_token'])
        ));
        
        if (is_wp_error($user_info_response)) {
            throw new Exception('Failed to get user info: ' . $user_info_response->get_error_message());
        }
        
        $user_info = json_decode(wp_remote_retrieve_body($user_info_response), true);
        
        return array(
            'email' => $user_info['email'] ?? '',
            'first_name' => $user_info['given_name'] ?? '',
            'last_name' => $user_info['family_name'] ?? '',
            'display_name' => $user_info['name'] ?? '',
            'provider' => 'google',
            'provider_id' => $user_info['sub'] ?? ''
        );
    }
    
    /**
     * Get Facebook user data
     */
    private function get_facebook_user_data($code) {
        // Exchange code for access token
        $token_url = 'https://graph.facebook.com/v12.0/oauth/access_token';
        $token_params = array(
            'client_id' => $this->facebook_app_id,
            'client_secret' => $this->facebook_app_secret,
            'code' => $code,
            'redirect_uri' => $this->redirect_uri . '&provider=facebook'
        );
        
        $response = wp_remote_get($token_url . '?' . http_build_query($token_params));
        
        if (is_wp_error($response)) {
            throw new Exception('Failed to get access token: ' . $response->get_error_message());
        }
        
        $token_data = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!isset($token_data['access_token'])) {
            throw new Exception('Failed to get access token');
        }
        
        // Get user info
        $user_info_url = 'https://graph.facebook.com/v12.0/me';
        $user_info_params = array(
            'fields' => 'id,email,first_name,last_name,name',
            'access_token' => $token_data['access_token']
        );
        
        $user_info_response = wp_remote_get($user_info_url . '?' . http_build_query($user_info_params));
        
        if (is_wp_error($user_info_response)) {
            throw new Exception('Failed to get user info: ' . $user_info_response->get_error_message());
        }
        
        $user_info = json_decode(wp_remote_retrieve_body($user_info_response), true);
        
        return array(
            'email' => $user_info['email'] ?? '',
            'first_name' => $user_info['
