# Security Policy

## Supported Versions

We provide security updates for the following versions of WordPress Social Authentication:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The WordPress Social Authentication team takes security bugs seriously. We appreciate your efforts to responsibly disclose your findings.

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

We will acknowledge receipt of your vulnerability report as soon as possible and provide regular updates about our progress. If you have followed our vulnerability reporting process, we will not take legal action against you concerning the report.

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the issue and determine its severity
2. Prepare fixes for all supported versions 
3. Release security updates as soon as possible
4. Publicly disclose the issue after the fix has been widely available
5. Credit the reporter for finding and reporting the issue (unless they wish to remain anonymous)

## Response Timeframes

We aim to maintain the following response times:

- **Initial response**: Within 48 hours
- **Confirmation**: Within 1 week
- **Security fixes**: 
  - Critical issues: ASAP (typically within 1 week)
  - High severity: Next release or sooner
  - Medium/Low severity: Incorporated into regular release schedule

## Security Best Practices

For administrators using this plugin, we recommend the following security practices:

### OAuth Configuration
- Always use HTTPS for your WordPress site when using OAuth authentication
- Properly configure redirect URIs in your OAuth provider settings
- Only request the minimum scopes needed for authentication
- Regularly rotate OAuth client secrets
- Store client secrets securely using WordPress constants in wp-config.php instead of database options

### Plugin Settings
- Enable rate limiting to prevent brute force attempts
- Require email verification for new user registrations
- Regularly review authorized applications
- Keep the plugin updated to receive security patches

### WordPress Security
- Keep WordPress core, all plugins, and themes updated
- Use strong passwords and consider requiring 2FA for administrator accounts
- Implement proper user roles and permissions
- Enable security logging

## Code Security

- All code is linted and checked for security issues using automated tools
- Dependencies are regularly updated and monitored for vulnerabilities
- GitHub Dependabot alerts are monitored and addressed promptly
- Regular security audits are performed

## Security Updates

Security updates will be released as quickly as possible for confirmed security issues. Updates will be published through:

1. Plugin updates in the WordPress repository
2. Security advisories in GitHub
3. Announcements on our website or blog

We recommend configuring automatic updates for security releases or monitoring our release announcements closely.

## Compliance

This project aims to comply with:

- OWASP Top 10 security recommendations
- GDPR requirements for data handling
- WordPress security best practices

## Previous Security Vulnerabilities

Any previously disclosed security vulnerabilities will be listed in our [GitHub Security Advisories](https://github.com/wordpress-gmail-cli/wp-social-auth/security/advisories?state=published).

---

This security policy is subject to change. Last updated: April 2025.
