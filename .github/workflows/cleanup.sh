#!/bin/bash

# Cleanup script to remove redundant workflow files
# Run this script after reviewing and confirming the new workflows

# Set the directory
WORKFLOWS_DIR=".github/workflows"

# List of files to keep
KEEP_FILES=(
  "ci.yml"
  "release.yml"
  "README.md"
  "cleanup.sh"
)

# Function to check if a file should be kept
should_keep() {
  local file="$1"
  for keep_file in "${KEEP_FILES[@]}"; do
    if [[ "$file" == "$keep_file" ]]; then
      return 0
    fi
  done
  return 1
}

# Remove redundant files
echo "Removing redundant workflow files..."
for file in "$WORKFLOWS_DIR"/*.yml; do
  filename=$(basename "$file")
  if ! should_keep "$filename"; then
    echo "Removing $file"
    rm "$file"
  else
    echo "Keeping $file"
  fi
done

echo "Cleanup complete!"
