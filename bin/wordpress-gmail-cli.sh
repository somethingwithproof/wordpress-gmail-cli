#!/bin/bash

# wordpress-gmail-cli
VERSION="1.1.0"
# A CLI tool to configure WordPress and Postfix for sending outbound emails using Google API
# Especially useful for Digital Ocean servers where standard SMTP ports are blocked

# Function to display script usage
usage() {
    echo "WordPress Gmail CLI v${VERSION}"
    echo "A simple CLI tool to configure WordPress and Postfix for Gmail using Google API"
    echo
    echo "Usage:"
    echo "  $0 [options]"
    echo
    echo "Options:"
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
    echo "  -v, --version               Display version information"
    echo "  -h, --help                  Display this help message"
    exit 0
}

# Function to display version information
show_version() {
    echo "WordPress Gmail CLI v${VERSION}"
    echo "A CLI tool to configure WordPress and Postfix for sending outbound emails using Google API"
    exit 0
}

# Parse command-line arguments
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
elif [ "$1" = "--version" ] || [ "$1" = "-v" ]; then
    show_version
else
    echo "WordPress Gmail CLI v${VERSION}"
    echo "This is a placeholder script for testing purposes."
    echo "For actual functionality, please use the full script."
    echo
    echo "Run with --help for usage information."
    exit 0
fi
