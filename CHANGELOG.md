# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-04-07

### Added Features

- SSL security enhancement script to fix issues reported by WP-Encryption plugin
- Automatic configuration of secure headers and TLS settings
- HTTP to HTTPS redirect implementation
- SSL certificate auto-renewal setup
- Support for both Apache and Nginx web servers
- WP Encryption plugin installation and configuration

### Security Enhancements

- HSTS (HTTP Strict Transport Security) implementation
- Secure cookie configuration
- Modern TLS protocols and cipher suites
- Content Security Policy headers
- X-Content-Type-Options and other security headers
- OCSP Stapling for improved certificate validation

## [1.0.0] - 2025-04-07

### Initial Features

- Initial release of WordPress Gmail CLI
- Google API OAuth2 authentication for sending emails
- Automatic token refreshing via cron job
- WordPress mu-plugin for configuring email settings
- Helper script for obtaining Google API credentials
- Social authentication with Google and Facebook login
- Enterprise features documentation and implementation script
- Comprehensive README with detailed setup instructions
- Support for Digital Ocean and other hosts that block standard SMTP ports

### Security Measures

- Secure credential storage with proper file permissions
- OAuth2 authentication instead of less secure app passwords
- Token-based authentication for improved security
