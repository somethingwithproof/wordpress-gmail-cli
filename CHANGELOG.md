# Changelog

All notable changes to the WordPress Social Authentication plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Facebook authentication provider implementation
- Account linking between multiple social providers
- Enhanced error reporting with detailed logs
- Admin dashboard widget for login statistics

### Changed
- Improved user profile synchronization
- Enhanced logging for security events
- Optimized database queries for better performance

### Fixed
- Edge case with email verification status
- State parameter verification for specific browser conditions

## [1.0.0] - 2025-04-23

### Added
- Initial release with Google OAuth2 authentication
- User registration and login via social providers
- Admin settings interface for configuring providers
- Rate limiting to prevent authentication abuse
- WordPress role mapping for new users
- User profile data syncing from OAuth providers
- Avatar support from provider data
- Customizable login button styles
- Redirect URL configuration
- Detailed error logging and debugging options
- Complete PHPUnit test suite
- WordPress coding standards compliance

### Security
- Secure OAuth state parameter verification
- Implementation of WordPress nonces throughout
- Proper escaping and sanitization of all user inputs
- Constant-time string comparison for security tokens
- Rate limiting protection against brute force attempts
- Proper validation of all OAuth responses
- Safe storage of provider credentials

## [0.9.0] - 2025-04-10

### Added
- Beta release for testing
- Complete Google authentication flow
- User creation and profile association
- Basic admin interface for configuration
- Initial test coverage

### Changed
- Refactored provider handling with factory pattern
- Improved error reporting for failed authentication
- Enhanced configuration validation

### Fixed
- OAuth state verification edge cases
- User creation when email already exists
- Redirect handling in specific WordPress configurations

## [0.8.0] - 2025-03-25

### Added
- Alpha release with core functionality
- Google OAuth implementation
- Basic user creation and login
- Minimal configuration options
- Development environment setup

### Security
- Basic security measures implemented
- Input sanitization and output escaping
- Initial OAuth state verification

## [0.7.0] - 2025-03-10

### Added
- Pre-alpha development version
- Initial plugin structure
- OAuth2 client integration
- WordPress hooks framework

## Migration Guides

### Upgrading to 1.0.0
- No breaking changes from 0.9.0
- Review and update provider settings in admin interface
- Ensure https is enabled for production environments
- Test authentication flow after upgrading

[Unreleased]: https://github.com/wordpress-gmail-cli/wp-social-auth/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/wordpress-gmail-cli/wp-social-auth/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/wordpress-gmail-cli/wp-social-auth/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/wordpress-gmail-cli/wp-social-auth/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/wordpress-gmail-cli/wp-social-auth/releases/tag/v0.7.0

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
