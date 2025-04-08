#!/bin/bash

# test-docker.sh
# A script to test the Docker image functionality
# This script is used by GitHub Actions to ensure the Docker image works properly

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

# Function to test Docker image
test_docker_image() {
  local image_name=$1
  
  log "INFO" "Testing Docker image: ${image_name}"
  
  # Check if Docker is installed
  if ! command -v docker &> /dev/null; then
    log "ERROR" "Docker is not installed"
    return 1
  fi
  
  # Check if the image exists
  if ! docker image inspect "${image_name}" &> /dev/null; then
    log "ERROR" "Docker image not found: ${image_name}"
    return 1
  fi
  
  # Test 1: Basic help command
  log "INFO" "Test 1: Running help command"
  if ! docker run --rm "${image_name}" --help &> /dev/null; then
    log "ERROR" "Help command test failed"
    return 1
  fi
  log "SUCCESS" "Help command test passed"
  
  # Test 2: Version information
  log "INFO" "Test 2: Checking version information"
  if ! version=$(docker run --rm "${image_name}" --version 2>/dev/null); then
    log "ERROR" "Version command test failed"
    return 1
  fi
  
  if [[ -z "${version}" ]]; then
    log "ERROR" "Version information is empty"
    return 1
  fi
  
  log "SUCCESS" "Version command test passed: ${version}"
  
  # Test 3: Check for expected files in the image
  log "INFO" "Test 3: Checking for expected files in the image"
  if ! docker run --rm --entrypoint ls "${image_name}" /usr/local/bin/wordpress-gmail-cli.sh &> /dev/null; then
    log "ERROR" "Main script not found in the image"
    return 1
  fi
  log "SUCCESS" "Expected files test passed"
  
  log "SUCCESS" "All Docker image tests passed"
  return 0
}

# Main execution
log "INFO" "Starting Docker image tests"

# Default image name
IMAGE_NAME="wordpress-gmail-cli:test"

# Allow overriding the image name
if [[ $# -eq 1 ]]; then
  IMAGE_NAME=$1
fi

# Run the tests
test_docker_image "${IMAGE_NAME}" || exit 1

log "SUCCESS" "Docker image testing completed successfully"
exit 0
