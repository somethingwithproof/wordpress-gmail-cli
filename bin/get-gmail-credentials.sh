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
