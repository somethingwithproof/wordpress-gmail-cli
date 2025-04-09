#!/bin/bash

# enhance-ssl-security.sh
# Version: 1.0.0
# A script to enhance SSL security for WordPress sites
# Addresses issues reported by WP-Encryption plugin

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
	echo -e "${BOLD}WordPress SSL Security Enhancer${RESET}"
	echo "A script to enhance SSL security for WordPress sites"
	echo
	echo -e "${BOLD}Usage:${RESET}"
	echo "  $0 [options]"
	echo
	echo -e "${BOLD}Options:${RESET}"
	echo "  -d, --domain DOMAIN         Your website domain (e.g., example.com)"
	echo "  -w, --wp-path PATH          Path to WordPress installation (default: /var/www/html)"
	echo "  -c, --cert-path PATH        Path to SSL certificate directory (default: /etc/letsencrypt/live/DOMAIN)"
	echo "  -a, --apache                Configure for Apache (default if detected)"
	echo "  -n, --nginx                 Configure for Nginx"
	echo "  -h, --help                  Display this help message"
	echo
	echo -e "${BOLD}Example:${RESET}"
	echo "  $0 --domain example.com --wp-path /var/www/html"
	exit 0
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

# Function to detect web server
detect_web_server() {
	if command_exists apache2 || command_exists httpd; then
		WEB_SERVER="apache"
		log "INFO" "Apache web server detected"
	elif command_exists nginx; then
		WEB_SERVER="nginx"
		log "INFO" "Nginx web server detected"
	else
		log "ERROR" "No supported web server detected (Apache or Nginx)"
		exit 1
	fi
}

# Function to configure SSL for Apache
configure_apache_ssl() {
	log "INFO" "Configuring Apache SSL settings..."

	# Create or update SSL configuration
	local ssl_conf="/etc/apache2/sites-available/${DOMAIN}-ssl.conf"

	# Backup existing configuration if it exists
	if [[ -f ${ssl_conf} ]]; then
		cp "${ssl_conf}" "${ssl_conf}.backup.$(date +%Y%m%d%H%M%S)"
		log "INFO" "Backed up existing Apache SSL configuration"
	fi

	# Create new SSL configuration
	cat >"${ssl_conf}" <<EOF
<IfModule mod_ssl.c>
    <VirtualHost *:443>
        ServerName ${DOMAIN}
        ServerAlias www.${DOMAIN}
        
        DocumentRoot ${WP_PATH}
        
        <Directory ${WP_PATH}>
            Options FollowSymLinks
            AllowOverride All
            Require all granted
        </Directory>
        
        ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}-error.log
        CustomLog \${APACHE_LOG_DIR}/${DOMAIN}-access.log combined
        
        SSLEngine on
        SSLCertificateFile ${CERT_PATH}/fullchain.pem
        SSLCertificateKeyFile ${CERT_PATH}/privkey.pem
        
        # Modern SSL configuration
        SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
        SSLHonorCipherOrder on
        SSLCompression off
        SSLSessionTickets off
        
        # OCSP Stapling
        SSLUseStapling on
        SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
        
        # Security headers
        Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-XSS-Protection "1; mode=block"
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"
        Header always set Content-Security-Policy "upgrade-insecure-requests;"
        Header always set Permissions-Policy "geolocation=(), midi=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), fullscreen=(self), payment=()"
        
        # Enable HTTP/2
        Protocols h2 http/1.1
    </VirtualHost>
</IfModule>
EOF

	# Create HTTP to HTTPS redirect configuration
	local redirect_conf="/etc/apache2/sites-available/${DOMAIN}.conf"

	# Backup existing configuration if it exists
	if [[ -f ${redirect_conf} ]]; then
		cp "${redirect_conf}" "${redirect_conf}.backup.$(date +%Y%m%d%H%M%S)"
		log "INFO" "Backed up existing Apache HTTP configuration"
	fi

	# Create new HTTP configuration with redirect
	cat >"${redirect_conf}" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias www.${DOMAIN}
    
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>
EOF

	# Enable required modules
	a2enmod ssl
	a2enmod headers
	a2enmod rewrite
	a2enmod http2

	# Enable the sites
	a2ensite "${DOMAIN}.conf"
	a2ensite "${DOMAIN}-ssl.conf"

	# Restart Apache
	systemctl restart apache2

	log "SUCCESS" "Apache SSL configuration completed"
}

# Function to configure SSL for Nginx
configure_nginx_ssl() {
	log "INFO" "Configuring Nginx SSL settings..."

	# Create or update SSL configuration
	local ssl_conf="/etc/nginx/sites-available/${DOMAIN}"

	# Backup existing configuration if it exists
	if [[ -f ${ssl_conf} ]]; then
		cp "${ssl_conf}" "${ssl_conf}.backup.$(date +%Y%m%d%H%M%S)"
		log "INFO" "Backed up existing Nginx configuration"
	fi

	# Create new SSL configuration
	cat >"${ssl_conf}" <<EOF
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    
    # HTTP to HTTPS redirect
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};
    
    root ${WP_PATH};
    index index.php index.html index.htm;
    
    # SSL configuration
    ssl_certificate ${CERT_PATH}/fullchain.pem;
    ssl_certificate_key ${CERT_PATH}/privkey.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "upgrade-insecure-requests;" always;
    add_header Permissions-Policy "geolocation=(), midi=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), fullscreen=(self), payment=()" always;
    
    # WordPress configuration
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }
}
EOF

	# Create symbolic link to enable the site
	if [[ ! -L "/etc/nginx/sites-enabled/${DOMAIN}" ]]; then
		ln -s "${ssl_conf}" "/etc/nginx/sites-enabled/${DOMAIN}"
	fi

	# Test Nginx configuration
	nginx -t

	# Restart Nginx
	systemctl restart nginx

	log "SUCCESS" "Nginx SSL configuration completed"
}

# Function to configure WordPress for SSL
configure_wordpress_ssl() {
	log "INFO" "Configuring WordPress for SSL..."

	# Check if wp-config.php exists
	if [[ ! -f "${WP_PATH}/wp-config.php" ]]; then
		log "ERROR" "WordPress configuration file not found at ${WP_PATH}/wp-config.php"
		log "INFO" "Please check your WordPress installation path and try again"
		return 1
	fi

	# Add SSL configuration to wp-config.php if not already present
	if ! grep -q "FORCE_SSL_ADMIN" "${WP_PATH}/wp-config.php"; then
		# Find the line where to insert the SSL configuration
		local insert_line=$(grep -n "That's all, stop editing!" "${WP_PATH}/wp-config.php" | cut -d: -f1)

		if [[ -z ${insert_line} ]]; then
			# If the marker comment is not found, insert before the last line
			insert_line=$(wc -l <"${WP_PATH}/wp-config.php")
		fi

		# Create a temporary file with the SSL configuration
		local temp_file=$(mktemp)

		# Add SSL configuration
		cat >"${temp_file}" <<'EOF'

/* SSL Settings */
define('FORCE_SSL_ADMIN', true);
define('FORCE_SSL_LOGIN', true);

/* Cookie settings for security */
define('COOKIE_DOMAIN', '${DOMAIN}');
define('COOKIEPATH', '/');
define('COOKIE_HTTPONLY', true);
define('COOKIE_SECURE', true);
EOF

		# Insert the SSL configuration into wp-config.php
		sed -i "${insert_line}r ${temp_file}" "${WP_PATH}/wp-config.php"

		# Remove the temporary file
		rm "${temp_file}"

		log "SUCCESS" "Added SSL configuration to wp-config.php"
	else
		log "INFO" "SSL configuration already exists in wp-config.php"
	fi

	# Create or update .htaccess file for SSL
	if [[ -f "${WP_PATH}/.htaccess" ]]; then
		# Backup existing .htaccess
		cp "${WP_PATH}/.htaccess" "${WP_PATH}/.htaccess.backup.$(date +%Y%m%d%H%M%S)"
		log "INFO" "Backed up existing .htaccess file"

		# Check if HTTPS redirect already exists
		if ! grep -q "RewriteCond %{HTTPS} off" "${WP_PATH}/.htaccess"; then
			# Add HTTPS redirect to the beginning of .htaccess
			cat >"${WP_PATH}/.htaccess.new" <<'EOF'
# BEGIN SSL Redirect
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
# END SSL Redirect

EOF
			# Append the existing .htaccess content
			cat "${WP_PATH}/.htaccess" >>"${WP_PATH}/.htaccess.new"

			# Replace the old .htaccess with the new one
			mv "${WP_PATH}/.htaccess.new" "${WP_PATH}/.htaccess"

			log "SUCCESS" "Added HTTPS redirect to .htaccess"
		else
			log "INFO" "HTTPS redirect already exists in .htaccess"
		fi
	else
		# Create a new .htaccess file with HTTPS redirect
		cat >"${WP_PATH}/.htaccess" <<'EOF'
# BEGIN SSL Redirect
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
# END SSL Redirect

# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF

		log "SUCCESS" "Created new .htaccess file with HTTPS redirect"
	fi

	# Set proper permissions
	chown www-data:www-data "${WP_PATH}/.htaccess"
	chmod 644 "${WP_PATH}/.htaccess"

	log "SUCCESS" "WordPress SSL configuration completed"
}

# Function to create SSL certificate auto-renewal script
create_ssl_renewal_script() {
	log "INFO" "Creating SSL certificate auto-renewal script..."

	# Create the renewal script
	local renewal_script="/usr/local/bin/ssl-renew.sh"

	cat >"${renewal_script}" <<'EOF'
#!/bin/bash

# SSL certificate auto-renewal script
# This script is meant to be run as a cron job

# Renew certificates
certbot renew --quiet

# Restart web server to apply new certificates
if command -v apache2 >/dev/null 2>&1; then
    systemctl restart apache2
elif command -v nginx >/dev/null 2>&1; then
    systemctl restart nginx
fi

# Log renewal attempt
echo "$(date): SSL certificate renewal attempt" >> /var/log/ssl-renewal.log
EOF

	# Make the script executable
	chmod +x "${renewal_script}"

	# Create a cron job to run the script twice daily
	echo "0 0,12 * * * root /usr/local/bin/ssl-renew.sh" >/etc/cron.d/ssl-renewal
	chmod 644 /etc/cron.d/ssl-renewal

	log "SUCCESS" "SSL certificate auto-renewal script created"
}

# Function to install and configure WP Encryption plugin
install_wp_encryption() {
	log "INFO" "Installing and configuring WP Encryption plugin..."

	# Check if wp-cli is installed
	if ! command_exists wp; then
		log "INFO" "Installing WP-CLI..."
		curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
		chmod +x wp-cli.phar
		mv wp-cli.phar /usr/local/bin/wp
		log "SUCCESS" "WP-CLI installed"
	fi

	# Change to WordPress directory
	cd "${WP_PATH}"

	# Install WP Encryption plugin if not already installed
	if ! wp plugin is-installed wp-encryption --allow-root; then
		wp plugin install wp-encryption --activate --allow-root
		log "SUCCESS" "WP Encryption plugin installed and activated"
	elif ! wp plugin is-active wp-encryption --allow-root; then
		wp plugin activate wp-encryption --allow-root
		log "SUCCESS" "WP Encryption plugin activated"
	else
		log "INFO" "WP Encryption plugin is already installed and activated"
	fi

	# Configure WP Encryption plugin
	wp option update wple_opts '{"site_url":"https://'"${DOMAIN}"'","email":"admin@'"${DOMAIN}"'","include_wwww":1,"enable_hsts":1,"enable_https":1,"mixed_content_fixer":1,"force_ssl":1}' --format=json --allow-root

	log "SUCCESS" "WP Encryption plugin configured"
}

# Parse command line arguments
WP_PATH="/var/www/html"
WEB_SERVER=""

while [[ $# -gt 0 ]]; do
	key="$1"
	case ${key} in
	-d | --domain)
		DOMAIN="$2"
		shift 2
		;;
	-w | --wp-path)
		WP_PATH="$2"
		shift 2
		;;
	-c | --cert-path)
		CERT_PATH="$2"
		shift 2
		;;
	-a | --apache)
		WEB_SERVER="apache"
		shift
		;;
	-n | --nginx)
		WEB_SERVER="nginx"
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

# Validate required parameters
if [[ -z ${DOMAIN} ]]; then
	log "ERROR" "Domain name is required"
	usage
fi

# Set default certificate path if not provided
if [[ -z ${CERT_PATH} ]]; then
	CERT_PATH="/etc/letsencrypt/live/${DOMAIN}"
fi

# Main execution
check_root

# Detect web server if not specified
if [[ -z ${WEB_SERVER} ]]; then
	detect_web_server
fi

# Configure SSL based on web server
if [[ ${WEB_SERVER} == "apache" ]]; then
	configure_apache_ssl
elif [[ ${WEB_SERVER} == "nginx" ]]; then
	configure_nginx_ssl
fi

# Configure WordPress for SSL
configure_wordpress_ssl

# Create SSL certificate auto-renewal script
create_ssl_renewal_script

# Install and configure WP Encryption plugin
install_wp_encryption

log "SUCCESS" "SSL security enhancement completed"
log "INFO" "Your WordPress site should now have a perfect SSL score"
