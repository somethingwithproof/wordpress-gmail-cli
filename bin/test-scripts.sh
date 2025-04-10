#!/bin/bash

# test-scripts.sh
# A script to test the functionality of all shell scripts in the project
# This script is used by GitHub Actions to ensure scripts are working properly

set -e

# shellcheck disable=SC2034 # Used in string formatting for logs
BOLD="\033[1m"
# Text formatting
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
      echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RESET}${level}${RESET}: ${message}" >&2
      return
      ;;
  esac

  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}${level}${RESET}: ${message}"
}

# Function to test a script
test_script() {
  local script=$1
  local test_args=$2
  local output
  local exit_code

  log "INFO" "Testing script: ${script}"

  # Check if script exists
  if [[ ! -f "${script}" ]]; then
    log "ERROR" "Script not found: ${script}"
    return 1
  fi

  # Check if script is executable
  if [[ ! -x "${script}" ]]; then
    log "WARNING" "Script is not executable, attempting to make it executable..."
    if ! chmod +x "${script}"; then
      log "ERROR" "Failed to make script executable: ${script}"
      return 1
    fi
  fi

  # Run the script with test arguments
  log "INFO" "Running: ${script} ${test_args}"
  # Use capturing group to get output and exit code reliably
  # shellcheck disable=SC2086 # We want word splitting for test_args
  if output=$("${script}" ${test_args} 2>&1); then
    exit_code=$?
    log "SUCCESS" "Script executed successfully (Exit code: ${exit_code})"
    # Optional: Log output even on success if needed
    # log "INFO" "Output: ${output}"
    return 0
  else
    exit_code=$?
    log "ERROR" "Script execution failed with exit code ${exit_code}"
    log "ERROR" "Output: ${output}"
    return 1
  fi
}

# Main execution
log "INFO" "Starting script tests"

# Make sure we're in the project root directory relative to this script's location
# Quote the path (Shellcheck SC2164)
project_root
if ! project_root=$(cd "$(dirname "$0")/.." && pwd); then
  log "ERROR" "Could not determine project root directory"
  exit 1
fi
if ! cd "${project_root}"; then
  log "ERROR" "Could not change directory to project root: ${project_root}"
  exit 1
fi
log "INFO" "Changed directory to project root: ${project_root}"

# Define scripts to test
scripts_to_test=(
  "bin/wordpress-gmail-cli.sh"
  "bin/version.sh"
  "bin/enhance-ssl-security.sh"
  "bin/get-gmail-credentials.sh"
  "bin/enterprise-setup.sh"
)

test_failed=false
for script in "${scripts_to_test[@]}"; do
  # Check if file exists before testing (some might be optional)
  if [[ -f "${script}" ]]; then
    # Use "--help" as a basic test argument
    if ! test_script "${script}" "--help"; then
      test_failed=true
    fi
  else
    log "WARNING" "Optional script not found, skipping test: ${script}"
  fi
done

if [[ "${test_failed}" == true ]]; then
  log "ERROR" "One or more script tests failed"
  exit 1
else
  log "SUCCESS" "All script tests passed"
  exit 0
fi
