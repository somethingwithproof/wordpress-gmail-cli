#!/bin/bash

# test-scripts.sh
# A script to test the functionality of all shell scripts in the project
# This script is used by GitHub Actions to ensure scripts are working properly

set -e

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
  esac

  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}${level}${RESET}: ${message}"
}

# Function to test a script
test_script() {
  local script=$1
  local test_args=$2
  
  log "INFO" "Testing script: ${script}"
  
  # Check if script exists
  if [[ ! -f "${script}" ]]; then
    log "ERROR" "Script not found: ${script}"
    return 1
  fi
  
  # Check if script is executable
  if [[ ! -x "${script}" ]]; then
    log "WARNING" "Script is not executable, making it executable"
    chmod +x "${script}"
  fi
  
  # Run the script with test arguments
  log "INFO" "Running: ${script} ${test_args}"
  if output=$(${script} ${test_args} 2>&1); then
    log "SUCCESS" "Script executed successfully"
    return 0
  else
    log "ERROR" "Script execution failed with exit code $?"
    log "ERROR" "Output: ${output}"
    return 1
  fi
}

# Main execution
log "INFO" "Starting script tests"

# Make sure we're in the project root directory
cd "$(dirname "$0")/.." || exit 1

# Test wordpress-gmail-cli.sh
test_script "bin/wordpress-gmail-cli.sh" "--help" || exit 1

# Test version.sh
test_script "bin/version.sh" "--help" || exit 1

# Test enhance-ssl-security.sh
test_script "bin/enhance-ssl-security.sh" "--help" || exit 1

# Test get-gmail-credentials.sh (if it exists)
if [[ -f "bin/get-gmail-credentials.sh" ]]; then
  test_script "bin/get-gmail-credentials.sh" "--help" || exit 1
fi

# Test enterprise-setup.sh (if it exists)
if [[ -f "bin/enterprise-setup.sh" ]]; then
  test_script "bin/enterprise-setup.sh" "--help" || exit 1
fi

log "SUCCESS" "All script tests passed"
exit 0
