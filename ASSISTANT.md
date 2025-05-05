# ASSISTANT.md - Development Instructions

This file contains special instructions for development when working with this codebase.

## WordPress Gmail CLI Security Standards

When working with this codebase, follow these security best practices:

### Security Commands to Run

After making code changes, always run these security checks:

```bash
# Verify code follows WordPress and PHP security practices
composer phpcs

# Run PHP static analysis
composer phpstan

# Run tests
composer test

# Verify all checks pass
composer check
```

### WordPress Security Guidelines

1. **Input Validation**: Always validate and sanitize user input using WordPress functions:
   - `sanitize_text_field()` for general text
   - `sanitize_email()` for email addresses
   - `sanitize_key()` for database keys
   - `sanitize_title()` for post titles/slugs
   - `intval()` or `absint()` for integers

2. **Output Escaping**: Always escape output using WordPress functions:
   - `esc_html()` for HTML content
   - `esc_attr()` for HTML attributes
   - `esc_url()` for URLs
   - `esc_js()` for inline JavaScript
   - `wp_kses()` or `wp_kses_post()` for allowing specific HTML

3. **Database Queries**: Use prepared statements:
   - `$wpdb->prepare()` for all SQL queries with user input
   - Avoid direct SQL if possible

4. **CSRF Protection**: Implement nonces for all form submissions:
   - `wp_nonce_field()` in forms
   - `check_admin_referer()` or `wp_verify_nonce()` when processing forms

5. **Capability Checks**: Verify user permissions:
   - `current_user_can()` for checking user capabilities
   - Never assume user permissions

### Docker Security

Our Docker image follows security best practices:
- Uses a minimal Alpine base image
- Runs as a non-root user
- Pins dependencies to specific versions
- Has proper file permissions

### GitHub Security

The project uses several GitHub security features:
- CodeQL for static analysis
- Dependabot for dependency updates
- Security workflows for vulnerability scanning
- PHP-specific security scanning

### CLI Security

For CLI tools, observe these practices:
- Validate all command arguments
- Avoid shell execution when possible
- Use strict file permissions
- Sanitize all external input
- Never log sensitive information