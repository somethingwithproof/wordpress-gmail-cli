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

# Logging function
log() {
  local level="$1"
  local message="$2"
  local color="$RESET"

  case "$level" in
    INFO) color="$BLUE";;
    SUCCESS) color="$GREEN";;
    WARNING) color="$YELLOW";;
    ERROR) color="$RED";;
    *) color="$RESET";;
  esac

  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}${level}${RESET}: ${message}"
}

# Check root privileges
check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log "ERROR" "This script must be run as root"
    exit 1
  fi
}

# Detect web server function
detect_web_server() {
  if command -v apache2ctl >/dev/null || command -v httpd >/dev/null; then
    WEB_SERVER="apache"
    log "INFO" "Apache web server detected"
  elif command -v nginx >/dev/null; then
    WEB_SERVER="nginx"
    log "INFO" "Nginx web server detected"
  else
    log "WARNING" "Could not detect Apache or Nginx. Please specify with --apache or --nginx."
    exit 1
  fi
}

# Main script execution
DOMAIN=""
WP_PATH="/var/www/html"
CERT_PATH=""
WEB_SERVER=""

while [[ $# -gt 0 ]]; do
  key="$1"
  case ${key} in
    -d|--domain)
      DOMAIN="$2"
      shift; shift;;
    -w|--wp-path)
      WP_PATH="$2"
      shift; shift;;
    -c|--cert-path)
      CERT_PATH="$2"
      shift; shift;;
    -a|--apache)
      WEB_SERVER="apache"
      shift;;
    -n|--nginx)
      WEB_SERVER="nginx"
      shift;;
    -h|--help)
      usage;;
    *)
      log "ERROR" "Unknown option: $1"
      usage;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  log "ERROR" "Domain name (--domain) is required."
  usage
fi

# Set default certificate path if not provided
if [[ -z "$CERT_PATH" ]]; then
  CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
  log "INFO" "Using default certificate path: $CERT_PATH"
fi

# Check root and detect web server if not specified
check_root
if [[ -z "$WEB_SERVER" ]]; then
  detect_web_server
fi

log "SUCCESS" "Script executed successfully for domain: $DOMAIN"
