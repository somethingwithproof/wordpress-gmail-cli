#!/bin/bash
# Script to fix shell script issues identified by ShellCheck and shfmt

# Check for Homebrew on Apple Silicon and set paths
if [[ "$(uname)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  # Apple Silicon Mac
  if [[ -d "/opt/homebrew/bin" ]]; then
    echo "Found Homebrew for Apple Silicon at /opt/homebrew/bin"
    export PATH="/opt/homebrew/bin:$PATH"
  else
    echo "Warning: Could not find Homebrew in /opt/homebrew/bin for Apple Silicon"
    echo "Checking alternative locations..."
    
    if [[ -d "$HOME/homebrew/bin" ]]; then
      echo "Found Homebrew in $HOME/homebrew/bin"
      export PATH="$HOME/homebrew/bin:$PATH"
    elif [[ -d "/usr/local/bin" && -x "/usr/local/bin/brew" ]]; then
      echo "Found Homebrew in /usr/local/bin"
    else
      echo "Error: Could not locate Homebrew. Please check your installation."
      exit 1
    fi
  fi
fi

# Determine which sed to use (gsed on macOS, sed on Linux)
if [[ "$(uname)" == "Darwin" ]]; then
  SED_CMD="gsed"
  # Check if gsed is installed
  if ! command -v gsed &> /dev/null; then
    echo "GNU sed (gsed) is not installed. Please install it with 'brew install gnu-sed'"
    exit 1
  fi
  echo "Using gsed from: $(which gsed)"
else
  SED_CMD="sed"
  echo "Using sed from: $(which sed)"
fi

# Reformat all shell scripts with shfmt
echo "Reformatting shell scripts with shfmt..."
if ! command -v shfmt &> /dev/null; then
  echo "Error: shfmt is not installed. Please install it with 'brew install shfmt'"
  exit 1
fi
echo "Using shfmt from: $(which shfmt)"
find bin -name "*.sh" -type f -exec shfmt -i 2 -ci -bn -w {} \;

# Fix specific ShellCheck warnings
echo "Fixing specific ShellCheck warnings..."

# Fix SC2034 (unused variables) in bin/enhance-ssl-security.sh
if grep -q "WP_PATH=\"\$2\"" bin/enhance-ssl-security.sh; then
  $SED_CMD -i 's/WP_PATH="\$2"/# WP_PATH="\$2" # Saving for future use/' bin/enhance-ssl-security.sh
fi

# Fix SC2034 (unused variables) in bin/test-docker.sh and bin/test-scripts.sh
for script in bin/test-docker.sh bin/test-scripts.sh; do
  if grep -q "BOLD=\"\\\\033\[1m\"" "$script"; then
    $SED_CMD -i 's/BOLD="\\033\[1m"/BOLD="\\033\[1m" # Used in log function/' "$script"
  fi
done

# Fix SC2016 (expressions don't expand in single quotes) in bin/enterprise-setup.sh
if grep -q "s|echo \"Access token refreshed successfully (expires in \${EXPIRES_IN}s)\"" bin/enterprise-setup.sh; then
  # Replace single quotes with double quotes for the variable to expand
  $SED_CMD -i 's/'\''s|echo "Access token refreshed successfully (expires in ${EXPIRES_IN}s)"|echo "$(date): Access token refreshed successfully (expires in ${EXPIRES_IN}s)" >> \/etc\/postfix\/gmail-api\/token-refresh.log|g'\''/'\''s|echo "Access token refreshed successfully (expires in \\${EXPIRES_IN}s)"|echo "$(date): Access token refreshed successfully (expires in \\${EXPIRES_IN}s)" >> \/etc\/postfix\/gmail-api\/token-refresh.log|g'\''/' bin/enterprise-setup.sh
fi

echo "All issues fixed. Run ShellCheck and shfmt again to verify."

