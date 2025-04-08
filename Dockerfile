FROM php:8.4-cli-alpine3.19

# Install dependencies
RUN apk add --no-cache \
    bash \
    curl \
    jq \
    postfix \
    openssl \
    ca-certificates \
    tzdata \
    shellcheck \
    git

# Set up working directory
WORKDIR /app

# Copy scripts
COPY *.sh /app/
COPY wp-social-auth.php /app/

# Make scripts executable
RUN chmod +x /app/*.sh

# Set up entrypoint
ENTRYPOINT ["/app/wordpress-gmail-cli.sh"]
CMD ["--help"]
