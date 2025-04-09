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
	echo -e "<span class="math-inline">\{BOLD\}WordPress SSL Security Enhancer</span>{RESET}"
	echo "A script to enhance SSL security for WordPress sites"
	echo
	echo -e "<span class="math-inline">\{BOLD\}Usage\:</span>{RESET}"
	echo "  <span class="math-inline">0 \[options\]"
echo
echo \-e "</span>{BOLD}Options:<span class="math-inline">\{RESET\}"
echo "  \-d, \-\-domain DOMAIN         Your website domain \(e\.g\., example\.com\)"
echo "  \-w, \-\-wp\-path PATH          Path to WordPress installation \(default\: /var/www/html\)"
echo "  \-c, \-\-cert\-path PATH        Path to SSL certificate directory \(default\: /etc/letsencrypt/live/DOMAIN\)"
echo "  \-a, \-\-apache                Configure for Apache \(default if detected\)"
echo "  \-n, \-\-nginx                 Configure for Nginx"
echo "  \-h, \-\-help                  Display this help message"
echo
echo \-e "</span>{BOLD}Example:${RESET}"
	echo "  $0 --domain example.com --wp-path /var/www/html"
	exit 0
}

# Function to log messages
log() {
	local level=$1
	local message=<span class="math-inline">2
local color\=</span>{RESET}

	case <span class="math-inline">\{level\} in
"INFO"\) color\=</span>{BLUE} ;;
	"SUCCESS") color=<span class="math-inline">\{GREEN\} ;;
"WARNING"\) color\=</span>{YELLOW} ;;
	"ERROR") color=<span class="math-inline">\{RED\} ;;
\*\)
echo \-e "\[</span>(date '+%Y-%m-%d %H:%M:%S')] <span class="math-inline">\{RESET\}</span>{level}${RESET}: <span class="math-inline">\{message\}" \>&2
return
;;
esac
echo \-e "\[</span>(date '+%Y-%m-%d %H:%M:%S')] <span class="math-inline">\{color\}</span>{level}${RESET}: ${message}"
}

# Function to check if command exists
command_exists() {
	# Use command -v for portability and clarity
	command -v "<span class="math-inline">1" \>/dev/null 2\>&1
\}
\# Function to check if running as root
check\_root\(\) \{
if \[\[ "</span>(id -u)" -ne 0 ]]; then
		log "ERROR" "This script must be run as root"
		exit 1
	fi
}

# Function to detect web server
detect_web_server() {
	if command_exists apache2ctl || command_exists httpd; then
		WEB_SERVER="apache"
		log "INFO" "Apache web server detected"
	elif command_exists nginx; then
		WEB_SERVER="nginx"
		log "INFO" "Nginx web server detected"
	else
		log "WARNING" "Could not detect Apache or Nginx. Please specify with --apache or --nginx."
		# Exit or allow user to proceed? Exiting is safer.
		exit 1
	fi
}

# Function to configure SSL for Apache
configure_apache_ssl() {
	log "INFO" "Configuring Apache SSL settings for domain: <span class="math-inline">\{DOMAIN\}"
\# Ensure required paths and variables are set
if \[\[ \-z "</span>{DOMAIN}" || -z "<span class="math-inline">\{WP\_PATH\}" \|\| \-z "</span>{CERT_PATH}" ]]; then
		log "ERROR" "Domain, WP Path, or Cert Path missing for Apache configuration."
		return 1
	fi

	local ssl_conf="/etc/apache2/sites-available/<span class="math-inline">\{DOMAIN\}\-ssl\.conf"
local redirect\_conf\="/etc/apache2/sites\-available/</span>{DOMAIN}.conf"
	local backup_suffix=".backup.<span class="math-inline">\(date \+%Y%m%d%H%M%S\)"
\# Backup existing configurations if they exist
if \[\[ \-f "</span>{ssl_conf}" ]]; then
		if ! cp -a "<span class="math-inline">\{ssl\_conf\}" "</span>{ssl_conf}${backup_suffix}"; then
			log "ERROR" "Failed to back up ${ssl_conf}"
			return 1
		fi
		log "INFO" "Backed up existing Apache SSL configuration to <span class="math-inline">\{ssl\_conf\}</span>{backup_suffix}"
	fi
	if [[ -f "<span class="math-inline">\{redirect\_conf\}" \]\]; then
if \! cp \-a "</span>{redirect_conf}" "<span class="math-inline">\{redirect\_conf\}</span>{backup_suffix}"; then
			log "ERROR" "Failed to back up ${redirect_conf}"
			return 1
		fi
		log "INFO" "Backed up existing Apache HTTP configuration to <span class="math-inline">\{redirect\_conf\}</span>{backup_suffix}"
	fi

	# Create new SSL configuration using 'EOF' to prevent premature expansion
	# Only expand variables explicitly needed within the heredoc if necessary
	# Here, we need expansion, so use EOF
	cat >"${ssl_conf}" <<EOF
<IfModule mod_ssl.c>
	<VirtualHost *:443>
		ServerName <span class="math-inline">\{DOMAIN\}
ServerAlias www\.</span>{DOMAIN}

		DocumentRoot ${WP_PATH}

		<Directory <span class="math-inline">\{WP\_PATH\}\>
Options FollowSymLinks
AllowOverride All
Require all granted
</Directory\>
ErrorLog \\$\{APACHE\_LOG\_DIR\}/</span>{DOMAIN}-error.log
		CustomLog \<span class="math-inline">\{APACHE\_LOG\_DIR\}/</span>{DOMAIN}-access.log combined

		SSLEngine on
		SSLCertificateFile ${CERT_PATH}/fullchain.pem
		SSLCertificateKeyFile ${CERT_PATH}/privkey.pem

		# Modern SSL configuration (Check compatibility if needed)
		SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
		SSLHonorCipherOrder     off
		SSLCompression          off
		SSLSessionTickets       off
		SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

		# OCSP Stapling
		SSLUseStapling On
		SSLStaplingCache "shmcb:logs/ssl_stapling(32768)" # Check path/size

		# Security headers (Consider if these break site functionality)
		Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
		Header always set X-Content-Type-Options "nosniff"
		# Header always set X-XSS-Protection "1; mode=block" # Deprecated, use CSP
		Header always set X-Frame-Options "SAMEORIGIN"
		Header always set Referrer-Policy "strict-origin-when-cross-origin"
		Header always set Content-Security-Policy "upgrade-insecure-requests;" # Start restrictive, broaden if needed
		Header always set Permissions-Policy "geolocation=(), midi=(), sync-xhr=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), fullscreen=(self), payment=()"

		# Enable HTTP/2 if module loaded
		<IfModule http2_module>
			Protocols h2 http/1.1
		</IfModule>
		<IfModule !http2_module>
			Protocols http/1.1
		</IfModule>
	</VirtualHost>
</IfModule>
EOF
	log "INFO" "Created Apache SSL config: <span class="math-inline">\{ssl\_conf\}"
\# Create new HTTP configuration with redirect
cat \>"</span>{redirect_conf}" <<EOF
<VirtualHost *:80>
	ServerName <span class="math-inline">\{DOMAIN\}
ServerAlias www\.</span>{DOMAIN}

	RewriteEngine On
	RewriteCond %{HTTPS} off
	RewriteRule ^/?(.*) https://%{HTTP_HOST}/\$1 [R=301,L]
</VirtualHost>
EOF
	log "INFO" "Created Apache HTTP redirect config: <span class="math-inline">\{redirect\_conf\}"
\# Enable required modules \(check for errors\)
log "INFO" "Enabling Apache modules\.\.\."
if \! a2enmod ssl headers rewrite http2; then
log "WARNING" "Failed to enable one or more Apache modules \(ssl, headers, rewrite, http2\)\. Manual check needed\."
\# Continue cautiously or return 1? Let's warn and continue\.
fi
\# Enable the sites \(check for errors\)
log "INFO" "Enabling Apache sites\.\.\."
if \! a2ensite "</span>{DOMAIN}.conf" "${DOMAIN}-ssl.conf"; then
		log "ERROR" "Failed to enable Apache sites: ${DOMAIN}.conf and/or <span class="math-inline">\{DOMAIN\}\-ssl\.conf"
return 1
fi
\# Check Apache configuration syntax
log "INFO" "Checking Apache configuration syntax\.\.\."
if \! apache2ctl configtest; then
log "ERROR" "Apache configuration test failed\. Please check manually\. Rolling back enablements\."
\# Attempt rollback \(best effort\)
a2dissite "</span>{DOMAIN}.conf" "${DOMAIN}-ssl.conf" >/dev/null 2>&1
		log "INFO" "Attempted to disable sites. Check /etc/apache2/sites-enabled/"
		return 1
	fi

	# Restart Apache
	log "INFO" "Restarting Apache..."
	if ! systemctl restart apache2; then
		log "ERROR" "Failed to restart Apache service."
		return 1
	fi

	log "SUCCESS" "Apache SSL configuration completed"
	return 0
}

# Function to configure SSL for Nginx
configure_nginx_ssl() {
	log "INFO" "Configuring Nginx SSL settings for domain: <span class="math-inline">\{DOMAIN\}"
\# Ensure required paths and variables are set
if \[\[ \-z "</span>{DOMAIN}" || -z "<span class="math-inline">\{WP\_PATH\}" \|\| \-z "</span>{CERT_PATH}" ]]; then
		log "ERROR" "Domain, WP Path, or Cert Path missing for Nginx configuration."
		return 1
	fi

	local ssl_conf="/etc/nginx/sites-available/<span class="math-inline">\{DOMAIN\}"
local enabled\_link\="/etc/nginx/sites\-enabled/</span>{DOMAIN}"
	local backup_suffix=".backup.<span class="math-inline">\(date \+%Y%m%d%H%M%S\)"
\# Backup existing configuration if it exists
if \[\[ \-f "</span>{ssl_conf}" ]]; then
		if ! cp -a "<span class="math-inline">\{ssl\_conf\}" "</span>{ssl_conf}${backup_suffix}"; then
			log "ERROR" "Failed to back up ${ssl_conf}"
			return 1
		fi
		log "INFO" "Backed up existing Nginx configuration to <span class="math-inline">\{ssl\_conf\}</span>{backup_suffix}"
	fi

	# Create new SSL configuration using 'EOF'
	# We need variable expansion here.
	cat >"${ssl_conf}" <<EOF
# Redirect HTTP to HTTPS
server {
	listen 80;
	listen [::]:80;
	server_name <span class="math-inline">\{DOMAIN\} www\.</span>{DOMAIN};

	# Let Certbot handle challenges if needed
	location ~ /.well-known/acme-challenge/ {
		root ${WP_PATH}; # Or a dedicated path
		allow all;
	}

	location / {
		return 301 https://\$host\$request_uri;
	}
}

# Main HTTPS server block
server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	server_name <span class="math-inline">\{DOMAIN\} www\.</span>{DOMAIN};

	root ${WP_PATH};
	index index.php index.html index.htm;

	# SSL configuration
	ssl_certificate ${CERT_PATH}/fullchain.pem;
	ssl_certificate_key <span class="math-inline">\{CERT\_PATH\}/privkey\.pem;
\# Modern SSL configuration \(Consider using Mozilla SSL Config Generator\)
ssl\_protocols TLSv1\.2 TLSv1\.3;
ssl\_prefer\_server\_ciphers off; \# TLSv1\.3 prefers client choice
ssl\_dhparam /etc/nginx/dhparam\.pem; \# Generate with\: openssl dhparam \-out /etc/nginx/dhparam\.pem 4096
ssl\_ciphers ECDHE\-ECDSA\-AES128\-GCM\-SHA256\:ECDHE\-RSA\-AES128\-GCM\-SHA256\:ECDHE\-ECDSA\-AES256\-GCM\-SHA384\:ECDHE\-RSA\-AES256\-GCM\-SHA384\:ECDHE\-ECDSA\-CHACHA20\-POLY1305\:ECDHE\-RSA\-CHACHA20\-POLY1305\:DHE\-RSA\-AES128\-GCM\-SHA256\:DHE\-RSA\-AES256\-GCM\-SHA384;
ssl\_ecdh\_curve secp384r1; \# Example, check compatibility
ssl\_session\_timeout 1d;
ssl\_session\_cache shared\:SSL\:10m; \# Adjust size as needed
ssl\_session\_tickets off;
\# OCSP Stapling
ssl\_stapling on;
ssl\_stapling\_verify on;
\# Use a reliable resolver accessible from your server
resolver 1\.1\.1\.1 8\.8\.8\.8 valid\=300s;
resolver\_timeout 5s;
\# Security headers \(Adjust Content\-Security\-Policy as needed\)
add\_header Strict\-Transport\-Security "max\-age\=63072000; includeSubDomains; preload" always;
add\_header X\-Content\-Type\-Options "nosniff" always;
\# add\_header X\-XSS\-Protection "1; mode\=block" always; \# Deprecated
add\_header X\-Frame\-Options "SAMEORIGIN" always;
add\_header Referrer\-Policy "strict\-origin\-when\-cross\-origin" always;
add\_header Content\-Security\-Policy "upgrade\-insecure\-requests; default\-src 'self'; script\-src 'self' 'unsafe\-inline'; style\-src 'self' 'unsafe\-inline'; img\-src 'self' data\:; font\-src 'self';" always; \# Example restrictive CSP
add\_header Permissions\-Policy "geolocation\=\(\), midi\=\(\), sync\-xhr\=\(\), microphone\=\(\), camera\=\(\), magnetometer\=\(\), gyroscope\=\(\), fullscreen\=\(self\), payment\=\(\)" always;
\# WordPress configuration \(adjust fastcgi\_pass if needed\)
location / \{
try\_files \\$uri \\$uri/ /index\.php?\\$args;
\}
location \= /favicon\.ico \{ log\_not\_found off; access\_log off; \}
location \= /robots\.txt \{ log\_not\_found off; access\_log off; allow all; \}
location \~\* \\\.\(css\|gif\|ico\|jpeg\|jpg\|js\|png\)</span> {
		expires max;
		log_not_found off;
	}

	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
		# Ensure this path matches your PHP-FPM setup
		fastcgi_pass unix:/var/run/php/php-fpm.sock;
		fastcgi_param SCRIPT_FILENAME \<span class="math-inline">document\_root\\$fastcgi\_script\_name;
include fastcgi\_params;
\}
\# Deny access to sensitive files
location \~\* /\(?\:uploads\|files\)/\.\*\\\.php</span> {
		deny all;
	}
	location ~ /\. {
		deny all;
	}
	location ~* ^/wp-config\.php {
        deny all;
    }
}
EOF
	log "INFO" "Created Nginx SSL config: <span class="math-inline">\{ssl\_conf\}"
\# Ensure dhparam file exists \(generate if needed\)
if \[\[ \! \-f /etc/nginx/dhparam\.pem \]\]; then
log "INFO" "Generating DH parameters \(4096 bits\)\.\.\. This may take a while\."
if \! openssl dhparam \-out /etc/nginx/dhparam\.pem 4096; then
log "ERROR" "Failed to generate DH parameters\."
return 1
fi
chmod 600 /etc/nginx/dhparam\.pem
fi
\# Create symbolic link to enable the site if it doesn't exist
if \[\[ \! \-L "</span>{enabled_link}" ]]; then
		if ! ln -s "<span class="math-inline">\{ssl\_conf\}" "</span>{enabled_link}"; then
			log "ERROR" "Failed to create symbolic link in sites-enabled for ${DOMAIN}"
			return 1
		fi
		log "INFO" "Enabled Nginx site by creating symlink: ${enabled_link}"
	else
		log "INFO" "Nginx site already enabled: <span class="math-inline">\{enabled\_link\}"
fi
\# Test Nginx configuration
log "INFO" "Checking Nginx configuration syntax\.\.\."
if \! nginx \-t; then
log "ERROR" "Nginx configuration test failed\. Please check manually\. Rolling back enablement\."
\# Attempt rollback \(best effort\)
rm \-f "</span>{enabled_link}"
		log "INFO" "Attempted to remove symlink. Check /etc/nginx/sites-enabled/"
		return 1
	fi

	# Restart Nginx
	log "INFO" "Restarting Nginx..."
	if ! systemctl restart nginx; then
		log "ERROR" "Failed to restart Nginx service."
		return 1
	fi

	log "SUCCESS" "Nginx SSL configuration completed"
	return 0
}

# Function to configure WordPress for SSL
configure_wordpress_ssl() {
	log "INFO" "Configuring WordPress for SSL in: <span class="math-inline">\{WP\_PATH\}"
local wp\_config\_file\="</span>{WP_PATH}/wp-config.php"
	local htaccess_file="<span class="math-inline">\{WP\_PATH\}/\.htaccess"
local backup\_suffix\="\.backup\.</span>(date +%Y%m%d%H%M%S)"

	# Check if wp-config.php exists
	if [[ ! -f "${wp_config_file}" ]]; then
		log "ERROR" "WordPress configuration file not found at <span class="math-inline">\{wp\_config\_file\}"
log "INFO" "Please check your WordPress installation path \(\-\-wp\-path\) and try again"
return 1
fi
\# Backup wp\-config\.php
if \! cp \-a "</span>{wp_config_file}" "<span class="math-inline">\{wp\_config\_file\}</span>{backup_suffix}"; then
		log "WARNING" "Failed to back up ${wp_config_file}"
		# Continue, but warn user
	else
		log "INFO" "Backed up wp-config.php to <span class="math-inline">\{wp\_config\_file\}</span>{backup_suffix}"
	fi

	# Add SSL configuration to wp-config.php if not already present
	# Use grep -q -F for fixed string search
	if ! grep -q -F "FORCE_SSL_ADMIN" "<span class="math-inline">\{wp\_config\_file\}"; then
\# Find the line '/\* That's all, stop editing\! Happy publishing\. \*/'
\# Use awk for more reliable line number finding
local insert\_line\_num
insert\_line\_num\=</span>(awk '/^\/\*.*That.s all, stop editing!.*\*\/<span class="math-inline">/\{print NR; exit\}' "</span>{wp_config_file}")

		if [[ -z "<span class="math-inline">\{insert\_line\_num\}" \]\]; then
log "WARNING" "'/\* That's all, stop editing\!\.\.\. \*/' marker not found in wp\-config\.php\. Adding settings near the end\."
\# Alternative\: insert before require\_once ABSPATH \. 'wp\-settings\.php';
insert\_line\_num\=</span>(awk '/^require_once.*wp-settings.php.*/{print NR; exit}' "<span class="math-inline">\{wp\_config\_file\}"\)
if \[\[ \-z "</span>{insert_line_num}" ]]; then
				# Fallback: insert at the very end (less ideal)
				insert_line_num=<span class="math-inline">\(wc \-l <"</span>{wp_config_file}")
			fi
		fi

		# Create the SSL configuration content using 'EOF' to prevent expansion
		local ssl_config_content
		# Note: COOKIE_DOMAIN might need adjustment based on www vs non-www preference
		ssl_config_content=<span class="math-inline">\(
cat <<'EOF'
// Force SSL for admin and login areas
define\('FORCE\_SSL\_ADMIN', true\);
// If your site is entirely HTTPS, you might not need FORCE\_SSL\_LOGIN
// define\('FORCE\_SSL\_LOGIN', true\); // Often handled by server redirect
// Set secure cookies \(adjust COOKIE\_DOMAIN if needed\)
// define\('COOKIE\_DOMAIN', '</span>{DOMAIN}'); // Uncomment and set if using subdomain or specific domain setups
define('COOKIEPATH', '/');
define('COOKIE_HTTPONLY', true);
// Ensure COOKIESECURE is true only if site is fully HTTPS
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}
if (isset($_SERVER['HTTPS']) && <span class="math-inline">\_SERVER\['HTTPS'\] \=\=\= 'on'\) \{
define\('COOKIE\_SECURE', true\);
\}
EOF
\)
\# Insert the configuration using sed \(more complex but avoids temp files\)
\# Escape special characters in the content for sed
local escaped\_config\_content
escaped\_config\_content\=</span>(printf '%s\n' "<span class="math-inline">\{ssl\_config\_content\}" \| sed 's/\[&/\\\]/\\\\&/g'\)
\# Use specific line number for insertion 'i' command
if \! sed \-i "</span>{insert_line_num}i <span class="math-inline">\{escaped\_config\_content\}" "</span>{wp_config_file}"; then
			log "ERROR" "Failed to insert SSL settings into <span class="math-inline">\{wp\_config\_file\} using sed\."
return 1
fi
log "SUCCESS" "Added SSL configuration lines to wp\-config\.php"
else
log "INFO" "SSL configuration markers \(FORCE\_SSL\_ADMIN\) already exist in wp\-config\.php\. Skipping addition\."
fi
\# \-\-\- \.htaccess Configuration \(Only for Apache\) \-\-\-
if \[\[ "</span>{WEB_SERVER}" == "apache" ]]; then
		log "INFO" "Configuring .htaccess for Apache SSL redirect..."
		# Check if .htaccess exists
		if [[ -f "<span class="math-inline">\{htaccess\_file\}" \]\]; then
\# Backup existing \.htaccess
if \! cp \-a "</span>{htaccess_file}" "<span class="math-inline">\{htaccess\_file\}</span>{backup_suffix}"; then
				log "WARNING" "Failed to back up ${htaccess_file}"
			else
				log "INFO" "Backed up existing .htaccess file to <span class="math-inline">\{htaccess\_file\}</span>{backup_suffix}"
			fi

			# Check if HTTPS redirect already exists (simple check)
			if ! grep -q 'RewriteCond %{HTTPS} off' "<span class="math-inline">\{htaccess\_file\}"; then
\# Add HTTPS redirect to the beginning of \.htaccess
local redirect\_rules
redirect\_rules\=</span>(
					cat <<'EOF'
# BEGIN HTTPS Redirect Force
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
# END HTTPS Redirect Force

EOF
				)
				# Prepend rules using sed
				if ! sed -i '1i '"<span class="math-inline">\{redirect\_rules\}"'' "</span>{htaccess_file}"; then
					log "ERROR" "Failed to prepend HTTPS redirect rules to <span class="math-inline">\{htaccess\_file\}"
return 1
fi
log "SUCCESS" "Added HTTPS redirect rules to the beginning of \.htaccess"
else
log "INFO" "HTTPS redirect rule seems to exist in \.htaccess\. Skipping addition\."
fi
else
\# Create a new \.htaccess file with HTTPS redirect and basic WordPress rules
log "INFO" "Creating new \.htaccess file\.\.\."
cat \>"</span>{htaccess_file}" <<'EOF'
# BEGIN HTTPS Redirect Force
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
# END HTTPS Redirect Force

# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF
			log "SUCCESS" "Created new .htaccess file with HTTPS redirect and standard WordPress rules."
		fi

		# Set proper ownership and permissions for .htaccess
		# Determine the web server user (common variations)
		local web_user="www-data" # Default for Debian/Ubuntu Apache/Nginx
		if command_exists httpd; then web_user="apache"; fi # Default for RHEL/CentOS Apache
		if id "${web_user}" &>/dev/null; then
			log "INFO" "Setting ownership of ${htaccess_file} to <span class="math-inline">\{web\_user\}\:</span>{web_user}"
			if ! chown "<span class="math-inline">\{web\_user\}\:</span>{web_user}" "${htaccess_file}"; then
				log "WARNING" "Failed to set ownership for <span class="math-inline">\{htaccess\_file\}"
fi
else
log "WARNING" "Web server user '</span>{web_user}' not found. Skipping chown for .htaccess."
		fi

		log "INFO" "Setting permissions of <span class="math-inline">\{htaccess\_file\} to 644"
if \! chmod 644 "</span>{htaccess_file}"; then
			log "WARNING" "Failed to set permissions for <span class="math-inline">\{htaccess\_file\}"
fi
else
log "INFO" "Skipping \.htaccess configuration \(not Apache web server\)\."
fi \# End Apache\-specific \.htaccess handling
log "SUCCESS" "WordPress SSL configuration adjustments completed\."
return 0
\}
\# Function to create SSL certificate auto\-renewal script and cron job
create\_ssl\_renewal\_cron\(\) \{
log "INFO" "Setting up Certbot auto\-renewal\.\.\."
\# Check if Certbot is installed
if \! command\_exists certbot; then
log "WARNING" "Certbot command not found\. Cannot set up automated renewal\. Please install Certbot\."
return 1
fi
\# Certbot usually sets up its own renewal mechanism \(systemd timer or cron job\)
\# during installation or certificate acquisition\. We should check for it first\.
if systemctl list\-timers \| grep \-q 'certbot\.timer' \|\| \[\[ \-f /etc/cron\.d/certbot \]\]; then
log "INFO" "Certbot auto\-renewal mechanism \(systemd timer or cron job\) seems to be already configured\."
\# Optionally, ensure the renewal hook restarts the correct web server
\# This might require editing Certbot's renewal configuration files in /etc/letsencrypt/renewal/
log "INFO" "Verifying Certbot renewal hook for web server restart\.\.\."
\# Example verification \(adjust based on actual Certbot config\)\:
local renewal\_conf\="/etc/letsencrypt/renewal/</span>{DOMAIN}.conf"
		if [[ -f "<span class="math-inline">\{renewal\_conf\}" \]\]; then
local restart\_cmd\=""
if \[\[ "</span>{WEB_SERVER}" == "apache" ]]; then restart_cmd="systemctl restart apache2"; fi
			if [[ "<span class="math-inline">\{WEB\_SERVER\}" \=\= "nginx" \]\]; then restart\_cmd\="systemctl restart nginx"; fi
if \[\[ \-n "</span>{restart_cmd}" ]] && ! grep -q "deploy-hook.*<span class="math-inline">\{restart\_cmd\}" "</span>{renewal_conf}"; then
				log "WARNING" "Certbot renewal config (${renewal_conf}) might not have the correct deploy hook to restart ${WEB_SERVER}. Consider adding: deploy-hook = ${restart_cmd}"
			fi
		else
			log "WARNING" "Could not find Certbot renewal config for ${DOMAIN} at <span class="math-inline">\{renewal\_conf\}\. Cannot verify deploy hook\."
fi
return 0
else
log "WARNING" "Certbot auto\-renewal mechanism not detected\. Attempting to create a basic cron job\."
\# Create a simple renewal script \(less robust than Certbot's own mechanism\)
local renewal\_script\="/usr/local/bin/ssl\-renew\-custom\.sh"
local cron\_file\="/etc/cron\.d/ssl\-renewal\-custom"
cat \>"</span>{renewal_script}" <<'EOF'
#!/bin/bash
# Custom SSL certificate auto-renewal script

# Ensure Certbot command exists
if ! command -v certbot >/dev/null 2>&1; then exit 1; fi

# Run renewal (add --quiet for less output)
certbot renew --deploy-hook "systemctl restart YOUR_WEBSERVER_SERVICE"

# Log attempt
echo "<span class="math-inline">\(date\)\: Custom SSL certificate renewal attempt" \>\> /var/log/ssl\-renewal\-custom\.log
EOF
\# Replace placeholder in the script
local restart\_cmd\=""
if \[\[ "</span>{WEB_SERVER}" == "apache" ]]; then restart_cmd="apache2"; fi
		if [[ "<span class="math-inline">\{WEB\_SERVER\}" \=\= "nginx" \]\]; then restart\_cmd\="nginx"; fi
if \[\[ \-n "</span>{restart_cmd}" ]]; then
			sed -i "s/YOUR_WEBSERVER_SERVICE/<span class="math-inline">\{restart\_cmd\}/g" "</span>{renewal_script}"
		else
			log "ERROR" "Unknown web server for renewal script hook."
			rm -f "<span class="math-inline">\{renewal\_script\}" \# Clean up
return 1
fi
chmod \+x "</span>{renewal_script}"
		# Create cron job (runs twice daily at random minute past midnight and noon)
		local random_minute=<span class="math-inline">\(\(RANDOM % 60\)\)
echo "</span>{random_minute} 0,12 * * * root <span class="math-inline">\{renewal\_script\}" \>"</span>{cron_file}"
		chmod 644 "<span class="math-inline">\{cron\_file\}"
log "SUCCESS" "Basic custom SSL certificate auto\-renewal script and cron job created\."
log "WARNING" "It is highly recommended to use Certbot's built\-in renewal mechanism if possible\."
return 0
fi
\}
\# Function to install and configure WP Encryption plugin \(Optional, potentially redundant\)
\# Consider removing if server\-level SSL config is sufficient and robust\.
install\_wp\_encryption\(\) \{
log "INFO" "Attempting to install/configure WP Encryption plugin via WP\-CLI\.\.\."
\# Check if wp\-cli is installed
if \! command\_exists wp; then
log "INFO" "WP\-CLI not found\. Attempting to install\.\.\."
if \! curl \-sS \-O https\://raw\.githubusercontent\.com/wp\-cli/builds/gh\-pages/phar/wp\-cli\.phar; then
log "ERROR" "Failed to download WP\-CLI phar\."
return 1
fi
chmod \+x wp\-cli\.phar
if \! mv wp\-cli\.phar /usr/local/bin/wp; then
log "ERROR" "Failed to move wp\-cli\.phar to /usr/local/bin/wp\. Check permissions\."
rm \-f wp\-cli\.phar \# Clean up
return 1
fi
log "SUCCESS" "WP\-CLI installed to /usr/local/bin/wp"
fi
\# Check if WP\_PATH is set and exists
if \[\[ \-z "</span>{WP_PATH}" || ! -d "<span class="math-inline">\{WP\_PATH\}" \]\]; then
log "ERROR" "WordPress path \(\-\-wp\-path\) '</span>{WP_PATH}' is not set or not a directory."
		return 1
	fi

	# WP-CLI needs to run as the web server user usually, unless file permissions allow root.
	# Using --allow-root is convenient but less secure. Attempting without first.
	local wp_user="www-data" # Default, adjust if needed
	if ! id "<span class="math-inline">\{wp\_user\}" &\>/dev/null; then wp\_user\="apache"; fi \# Try other common user
local wp\_cli\_cmd\="wp \-\-path\=</span>{WP_PATH}"
	# Try running as web user if possible, otherwise fallback to --allow-root with warning
	if id "<span class="math-inline">\{wp\_user\}" &\>/dev/null && \[\[ "</span>(id -u)" == "0" ]]; then
		wp_cli_cmd="sudo -u ${wp_user} ${wp_cli_cmd}"
		log "INFO" "Running WP-CLI commands as user: <span class="math-inline">\{wp\_user\}"
elif \[\[ "</span>(id -u)" == "0" ]]; then
		wp_cli_cmd="${wp_cli_cmd} --allow-root"
		log "WARNING" "Running WP-CLI commands as root using --allow-root. Ensure file permissions are appropriate."
	else
	    log "WARNING" "Cannot determine web user or not running as root. WP-CLI might fail due to permissions."
	fi


	# Install WP Encryption plugin if not already installed
	log "INFO" "Checking WP Encryption plugin status..."
	# shellcheck disable=SC2086 # wp_cli_cmd contains spaces intentionally
	if ! ${wp_cli_cmd} plugin is-installed wp-encryption; then
		log "INFO" "Installing WP Encryption plugin..."
		# shellcheck disable=SC2086
		if ! ${wp_cli_cmd} plugin install wp-encryption --activate; then
			log "ERROR" "Failed to install WP Encryption plugin using WP-CLI."
			return 1
		fi
		log "SUCCESS" "WP Encryption plugin installed and activated"
	# shellcheck disable=SC2086
	elif ! ${wp_cli_cmd} plugin is-active wp-encryption; then
		log "INFO" "Activating WP Encryption plugin..."
		# shellcheck disable=SC2086
		if ! <span class="math-inline">\{wp\_cli\_cmd\} plugin activate wp\-encryption; then
log "ERROR" "Failed to activate WP Encryption plugin using WP\-CLI\."
return 1
fi
log "SUCCESS" "WP Encryption plugin activated"
else
log "INFO" "WP Encryption plugin is already installed and activated"
fi
\# Configure WP Encryption plugin options \(basic settings\)
log "INFO" "Configuring WP Encryption plugin options\.\.\."
\# Construct options JSON carefully
local wple\_opts\_json
wple\_opts\_json\=</span>(printf '{"site_url":"https://%s","email":"admin@%s","include_wwww":1,"enable_hsts":1,"enable_https":1,"mixed_content_fixer":1,"force_ssl":1}' "<span class="math-inline">\{DOMAIN\}" "</span>{DOMAIN}")

	# shellcheck disable=SC2086
	if ! <span class="math-inline">\{wp\_cli\_cmd\} option update wple\_opts "</span>{wple_opts_json}" --format=json; then
		log "ERROR" "Failed to configure WP Encryption plugin options using WP-CLI."
		return 1
	fi

	log "SUCCESS" "WP Encryption plugin configured (basic settings)"
	return 0
}

# --- Main Script Execution ---

# Declare variables
DOMAIN=""
WP_PATH="/var/www/html" # Default WordPress path
CERT_PATH=""            # Default certificate path (set later based on domain)
WEB_SERVER=""           # Auto-detected or specified by user

# Parse command line arguments
while [[ $# -gt 0 ]]; do
	key="$1"
	case ${key} in
	-d | --domain)
		DOMAIN="$2"
		shift 2 # Consume --domain and its value
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
		shift # Consume --apache flag
		;;
	-n | --nginx)
		WEB_SERVER="nginx"
		shift # Consume --nginx flag
		;;
	-h | --help)
		usage
		;;
	*)
		log "ERROR" "Unknown option: <span class="math-inline">1"
usage \# Exit after usage
;;
esac
done
\# Validate required parameters
if \[\[ \-z "</span>{DOMAIN}" ]]; then
	log "ERROR" "Domain name (--domain) is required."
	usage # Exit after usage
fi

# Set default certificate path if not provided
if [[ -z "<span class="math-inline">\{CERT\_PATH\}" \]\]; then
CERT\_PATH\="/etc/letsencrypt/live/</span>{DOMAIN}"
	log "INFO" "Using default certificate path: <span class="math-inline">\{CERT\_PATH\}"
fi
\# Validate paths
if \[\[ \! \-d "</span>{WP_PATH}" ]]; then
    log "ERROR" "WordPress path (--wp-path) '<span class="math-inline">\{WP\_PATH\}' does not exist or is not a directory\."
exit 1
fi
\# Certificate path might not exist \*yet\* if Certbot hasn't run, so don't validate its existence here rigorously\.
\# Check root privileges
check\_root
\# Detect web server if not specified
if \[\[ \-z "</span>{WEB_SERVER}" ]]; then