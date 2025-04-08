# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of WordPress Gmail CLI seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly**
2. **Email the details to security@example.com** (replace with your actual security contact)
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggestions for remediation

## Security Measures

This project implements several security measures:

### Code Security

- All code is linted and checked for security issues using automated tools
- Dependencies are regularly updated and monitored for vulnerabilities
- SLSA (Supply chain Levels for Software Artifacts) provenance is generated for all releases

### Authentication & Authorization

- OAuth2 is used for Google API authentication
- Credentials are stored securely with appropriate file permissions
- Token refresh is handled automatically and securely

### Infrastructure Security

- Docker containers are scanned for vulnerabilities
- GitHub Actions workflows use secure practices
- Releases are signed and verified

## Security Best Practices for Users

When using this tool, follow these security best practices:

1. Always use the latest version
2. Keep your Google API credentials secure
3. Use a dedicated Google account for sending emails if possible
4. Regularly rotate your credentials
5. Monitor your email sending activity for unusual patterns
6. Use SSL/TLS for all WordPress sites
7. Follow the principle of least privilege when setting up permissions

## Dependency Security

We use automated tools to scan dependencies for vulnerabilities:

- GitHub Dependabot alerts
- Trivy vulnerability scanner
- Regular manual audits

## Compliance

This project aims to comply with:

- OWASP Top 10 security recommendations
- GDPR requirements for data handling
- WordPress security best practices
