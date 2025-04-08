#!/bin/bash

# version.sh - Script to update version numbers across the project
# Usage: ./version.sh <new-version>
# Example: ./version.sh 1.1.0

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
    echo -e "${BOLD}WordPress Gmail CLI Version Manager${RESET}"
    echo "A script to update version numbers across the project"
    echo
    echo -e "${BOLD}Usage:${RESET}"
    echo "  $0 <new-version>"
    echo
    echo -e "${BOLD}Example:${RESET}"
    echo "  $0 1.1.0"
    exit 1
}

# Function to log messages
log() {
    local level=$1
    local message=$2
    local color=$RESET
    
    case $level in
        "INFO") color=$BLUE ;;
        "SUCCESS") color=$GREEN ;;
        "WARNING") color=$YELLOW ;;
        "ERROR") color=$RED ;;
    esac
    
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}${level}${RESET}: ${message}"
}

# Function to validate semantic version
validate_version() {
    local version=$1
    if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid version format: $version"
        log "INFO" "Version must follow semantic versioning: MAJOR.MINOR.PATCH"
        exit 1
    fi
}

# Function to update version in a file
update_version_in_file() {
    local file=$1
    local old_version=$2
    local new_version=$3
    local pattern=$4
    
    if [ -f "$file" ]; then
        if grep -q "$pattern" "$file"; then
            sed -i "s/$pattern$old_version/$pattern$new_version/g" "$file"
            log "SUCCESS" "Updated version in $file"
        else
            log "WARNING" "Version pattern not found in $file"
        fi
    else
        log "WARNING" "File not found: $file"
    fi
}

# Function to update CHANGELOG.md
update_changelog() {
    local new_version=$1
    local today=$(date +%Y-%m-%d)
    
    if [ -f "CHANGELOG.md" ]; then
        # Check if version already exists in changelog
        if grep -q "## \[$new_version\]" "CHANGELOG.md"; then
            log "WARNING" "Version $new_version already exists in CHANGELOG.md"
            return
        fi
        
        # Add new version section at the top of the changelog
        sed -i "s/## \[[0-9]\+\.[0-9]\+\.[0-9]\+\]/## [$new_version] - $today\n\n### Added\n- \n\n### Changed\n- \n\n### Fixed\n- \n\n## [&/g" "CHANGELOG.md"
        log "SUCCESS" "Added new version $new_version to CHANGELOG.md"
        log "INFO" "Please update the changelog entries manually"
    else
        log "ERROR" "CHANGELOG.md not found"
    fi
}

# Function to commit version changes
commit_version_changes() {
    local new_version=$1
    
    # Check if git is available
    if command -v git >/dev/null 2>&1; then
        # Check if we're in a git repository
        if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            # Add changed files
            git add wordpress-gmail-cli.sh README.md CHANGELOG.md wp-social-auth.php
            
            # Commit changes
            git commit -m "chore: bump version to $new_version"
            
            # Create a tag
            git tag -a "v$new_version" -m "Version $new_version"
            
            log "SUCCESS" "Committed version changes and created tag v$new_version"
            log "INFO" "Run 'git push && git push --tags' to push changes to remote repository"
        else
            log "WARNING" "Not in a git repository, skipping commit"
        fi
    else
        log "WARNING" "Git not found, skipping commit"
    fi
}

# Main execution
if [ $# -ne 1 ]; then
    usage
fi

NEW_VERSION=$1
validate_version "$NEW_VERSION"

# Get current version
CURRENT_VERSION=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" wordpress-gmail-cli.sh | cut -d ' ' -f 2)
if [ -z "$CURRENT_VERSION" ]; then
    # If version not found, add it
    sed -i "s/# wordpress-gmail-cli/# wordpress-gmail-cli\n# Version: $NEW_VERSION/g" wordpress-gmail-cli.sh
    log "SUCCESS" "Added version $NEW_VERSION to wordpress-gmail-cli.sh"
else
    log "INFO" "Current version: $CURRENT_VERSION"
    log "INFO" "New version: $NEW_VERSION"
    
    # Update version in files
    update_version_in_file "wordpress-gmail-cli.sh" "$CURRENT_VERSION" "$NEW_VERSION" "# Version: "
    update_version_in_file "README.md" "$CURRENT_VERSION" "$NEW_VERSION" "Version: "
    update_version_in_file "wp-social-auth.php" "$CURRENT_VERSION" "$NEW_VERSION" " \* Version: "
    
    # Update CHANGELOG.md
    update_changelog "$NEW_VERSION"
    
    # Commit changes
    commit_version_changes "$NEW_VERSION"
fi

log "SUCCESS" "Version updated to $NEW_VERSION"
