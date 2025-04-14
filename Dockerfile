FROM php:8.4-cli-alpine3.19

# Install dependencies with specific versions to fix security vulnerabilities
RUN apk add --no-cache \
    bash \
    "curl>=8.12.0-r0" \
    jq \
    postfix \
    "openssl>=3.1.8-r0" \
    "libssl3>=3.1.8-r0" \
    "libcrypto3>=3.1.8-r0" \
    ca-certificates \
    tzdata \
    shellcheck \
    git \
    "libxml2>=2.11.8-r2" \
    "xz>=5.4.5-r1" \
    "xz-libs>=5.4.5-r1" \
    "musl>=1.2.4_git20230717-r5" \
    "musl-utils>=1.2.4_git20230717-r5" \
    "libcurl>=8.12.0-r0"

# Set up working directory
WORKDIR /app

# Create bin directory
RUN mkdir -p /app/bin

# Copy scripts
COPY bin/*.sh /app/bin/
COPY wp-social-auth.php /app/

# Make scripts executable and set proper permissions
RUN chmod +x /app/bin/*.sh && \
    chown -R root:root /app && \
    chmod -R 755 /app

# Create a non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD sh -c "/app/bin/wordpress-gmail-cli.sh --help > /dev/null || exit 1"

# Set up entrypoint
ENTRYPOINT ["/app/bin/wordpress-gmail-cli.sh"]
CMD ["--help"]
