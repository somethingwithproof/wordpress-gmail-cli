#!/bin/bash

# Helper script to obtain Google API credentials for WordPress Gmail CLI

# Text formatting (ensure these are defined before use)
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Function to display script usage
usage() {
  echo -e "${BOLD}Google API Credentials Helper${RESET}"
  echo "This script will help you obtain the necessary credentials for the WordPress Gmail CLI"
  echo
  echo -e "${BOLD}Usage:${RESET}"
  echo "  $0 [options]"
  echo
  echo -e "${BOLD}Options:${RESET}"
  echo "  -h, --help                  Display this help message"
  echo
  exit 0
}

# Parse command line arguments
if [[ "$1" = "--help" || "$1" = "-h" ]]; then
  usage
fi

# Declare variables used later
CLIENT_ID=""
CLIENT_SECRET=""
EMAIL=""
STATE=""
REDIRECT_URL=""
CODE=""
TOKEN_RESPONSE=""
REFRESH_TOKEN=""

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
# Use read -r -p for prompt and input
read -r -p "Enter your Client ID: " CLIENT_ID
read -r -p "Enter your Client Secret: " CLIENT_SECRET
read -r -p "Enter your Gmail address: " EMAIL

# Validate inputs (basic check)
if [[ -z "${CLIENT_ID}" || -z "${CLIENT_SECRET}" || -z "${EMAIL}" ]]; then
  echo -e "${RED}Client ID, Client Secret, and Email are required.${RESET}"
  exit 1
fi

# Generate a random state value
if ! STATE=$(openssl rand -hex 12); then
  echo -e "${RED}Failed to generate state value using openssl.${RESET}"
  exit 1
fi

# Construct the authorization URL (ensure variables are quoted)
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

read -r -p "After authorizing, paste the FULL redirect URL from your browser here: " REDIRECT_URL

# Extract the authorization code from the redirect URL more safely
if ! CODE=$(echo "${REDIRECT_URL}" | grep -o 'code=[^&]*' | cut -d= -f2); then
  echo -e "${RED}Could not parse authorization code from the URL.${RESET}"
  exit 1
fi

if [[ -z "${CODE}" ]]; then
  echo -e "${RED}Authorization code is empty. Please check the pasted URL.${RESET}"
  exit 1
fi

# Exchange the authorization code for tokens
# Check curl exit status
if ! TOKEN_RESPONSE=$(curl -s --request POST \
  --url "https://oauth2.googleapis.com/token" \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "code=${CODE}" \
  --data-urlencode "redirect_uri=http://localhost:8080" \
  --data-urlencode "grant_type=authorization_code"); then
  echo -e "${RED}curl command failed to get token (Exit code: $?).${RESET}"
  exit 1
fi

# Extract the refresh token more safely using grep and check status
# shellcheck disable=SC2143 # Grep check is intentional
if ! REFRESH_TOKEN=$(echo "${TOKEN_RESPONSE}" | grep -o '"refresh_token":"[^"]*' | grep -o '[^"]*$'); then
  # Check if grep failed or token wasn't found
  echo -e "${RED}Failed to obtain refresh token. Check API response.${RESET}"
  echo "Response: ${TOKEN_RESPONSE}"
  exit 1
fi

if [[ -z "${REFRESH_TOKEN}" ]]; then
  echo -e "${RED}Refresh token is empty in the API response.${RESET}"
  echo "Response: ${TOKEN_RESPONSE}"
  exit 1
fi

echo -e "\n${GREEN}Successfully obtained credentials!${RESET}"
echo
echo -e "${BOLD}Your Google API credentials:${RESET}"
# Ensure variables are quoted in output
echo -e "Client ID: ${BLUE}${CLIENT_ID}${RESET}"
echo -e "Client Secret: ${BLUE}${CLIENT_SECRET}${RESET}"
echo -e "Refresh Token: ${BLUE}${REFRESH_TOKEN}${RESET}"
echo -e "Email: ${BLUE}${EMAIL}${RESET}"
echo
echo -e "${BOLD}Use these credentials with the WordPress Gmail CLI:${RESET}"
# Quote arguments for the example command
echo -e "${YELLOW}./wordpress-gmail-cli.sh --email \"${EMAIL}\" --client-id \"${CLIENT_ID}\" --client-secret \"${CLIENT_SECRET}\" --refresh-token \"${REFRESH_TOKEN}\" --domain \"your-domain.com\"${RESET}"
