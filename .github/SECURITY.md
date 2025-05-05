# Security Policy

## Supported Versions

We currently support the following versions of WordPress Social Authentication with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via GitHub's security advisory feature:

1. Go to the [Security tab](https://github.com/wordpress-gmail-cli/wp-social-auth/security) of this repository
2. Click "Report a vulnerability"
3. Fill out the form with all relevant details

Alternatively, you can send an email to security@wordpress-gmail-cli.com with the word "SECURITY" in the subject line.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Measures

Our project implements several security measures:

### Automated Security Testing
- Static Application Security Testing (SAST) with CodeQL
- WordPress-specific vulnerability scanning
- PHP-specific vulnerability scanning with:
  - Progpilot
  - PHPCS Security Audit
  - Psalm Taint Analysis
- Container vulnerability scanning with Trivy
- Dependency vulnerability scanning with:
  - Dependabot
  - OWASP Dependency-Check
  - Composer Audit
- Secret scanning with TruffleHog
- ShellCheck for shell script security

### Secure Coding Practices
- Input validation and sanitization using WordPress security functions
- Secure database queries with prepared statements
- Output escaping to prevent XSS
- CSRF protection using nonces
- Proper file upload handling with MIME type validation
- Capability checks for administrative functions
- Use of WordPress security best practices

### Infrastructure Security
- Regular dependency updates
- Multiple PHP version testing (7.4, 8.0, 8.1, 8.2)
- Secure Docker container configuration
- Minimal container image with non-root user
- Enhanced SSL/TLS security

## Security Updates

Security updates are released as soon as practical after vulnerabilities are confirmed. We prioritize high-severity issues affecting current versions.

Our security patch schedule:
- Critical: Within 24 hours
- High: Within 48 hours
- Medium: Within 7 days
- Low: Within 30 days

## Responsible Disclosure

We follow responsible disclosure principles and request that security researchers do the same:
- Please allow a reasonable time for us to address discovered vulnerabilities before public disclosure
- We commit to acknowledging receipt of vulnerability reports within 24 hours
- We will maintain communication with reporters throughout the remediation process
- We will credit researchers who follow responsible disclosure practices (unless they prefer to remain anonymous)

## Bug Bounty

We do not currently offer a formal bug bounty program, but we appreciate responsible vulnerability disclosures and will publicly acknowledge your contributions (unless you prefer to remain anonymous).

## Acknowledgments

We would like to thank the following individuals for reporting security vulnerabilities:

*This section will be updated as security researchers responsibly disclose vulnerabilities.*

## Security Resources

- [WordPress Security Team](https://wordpress.org/support/article/hardening-wordpress/)
- [OWASP Top Ten Project](https://owasp.org/www-project-top-ten/)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Security_Cheat_Sheet.html)