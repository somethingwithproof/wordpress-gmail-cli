# Contributing to WordPress Social Authentication

Thank you for considering contributing to the WordPress Social Authentication plugin! This document provides guidelines and instructions to help you contribute effectively.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)
- [Release Process](#release-process)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. **Fork the Repository**
   - Click the "Fork" button at the top right of the [repository page](https://github.com/wordpress-gmail-cli/wp-social-auth).

2. **Clone Your Fork**
   ```bash
   git clone https://github.com/YOUR-USERNAME/wp-social-auth.git
   cd wp-social-auth
   ```

3. **Set Up Upstream Remote**
   ```bash
   git remote add upstream https://github.com/wordpress-gmail-cli/wp-social-auth.git
   ```

4. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

## Development Environment

### Prerequisites

- PHP 7.4 or higher
- Composer
- WordPress development environment
- Node.js and npm (for frontend assets)

### Setup

1. **Install Dependencies**
   ```bash
   composer install
   ```

2. **Setup WordPress Test Environment** (optional for running integration tests)
   ```bash
   bash bin/install-wp-tests.sh wordpress_test root '' localhost latest
   ```

3. **Build Assets** (if applicable)
   ```bash
   npm install
   npm run build
   ```

### Development Workflow

We recommend using a local WordPress development environment like:
- [Local](https://localwp.com/)
- [XAMPP](https://www.apachefriends.org/)
- [Docker-based WordPress](https://github.com/WordPress/wordpress-develop)

Link your development copy of the plugin to your local WordPress installation to test changes in a real environment.

## Coding Standards

We follow the [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/) with some additional requirements:

1. **PHP Code**
   - PSR-4 autoloading for classes
   - Type declarations where possible (PHP 7.4+ features)
   - PHPDoc blocks for all functions, methods, and classes
   - Namespace all classes under `WordPressGmailCli\SocialAuth`

2. **JavaScript**
   - Follow WordPress JavaScript Coding Standards
   - Use ES6+ features with appropriate polyfills

3. **CSS/SCSS**
   - Use the BEM naming convention
   - Prefix all classes with `wp-social-auth-`

4. **WordPress Hooks**
   - All hooks must be prefixed with `wp_social_auth_`
   - Document all hooks with appropriate PHPDoc

### Code Style Tools

We use automated tools to enforce code style:

```bash
# PHP CodeSniffer
composer run-script phpcs

# PHP CodeSniffer Fixer
composer run-script phpcbf

# PHP Static Analysis
composer run-script phpstan
```

## Testing

All code changes should include appropriate tests.

### Types of Tests

1. **Unit Tests**: Test isolated components
2. **Integration Tests**: Test interaction with WordPress APIs
3. **Functional Tests**: Test end-to-end functionality (optional)

### Running Tests

```bash
# Run all tests
composer test

# Run with coverage report
composer test-coverage

# Run specific test suite
vendor/bin/phpunit --testsuite=Unit
```

### Test Requirements

- All tests must pass
- New features should have at least 80% test coverage
- Bug fixes should include a test that would have caught the bug

## Pull Request Process

1. **Update Documentation**: Update README, PHPDoc, inline comments, etc.
2. **Add Tests**: Add tests for new features or bug fixes
3. **Update Changelog**: Add a meaningful entry to CHANGELOG.md
4. **Check Coding Standards**: Ensure your code meets our standards
5. **Submit PR**: Create a pull request against the `main` branch with a clear description

### PR Title Format

Use semantic commit message format for PR titles:

- `feat: Add new feature X`
- `fix: Resolve issue with Y`
- `docs: Update documentation for Z`
- `refactor: Improve code structure for W`
- `chore: Update build process`
- `test: Add tests for feature V`

### PR Description Template

```
## Description
Brief description of the changes

## Related Issue
Fixes #(issue)

## Type of change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## How Has This Been Tested?
Description of tests that you ran

## Checklist:
- [ ] My code follows the project's coding standards
- [ ] I have added tests that prove my fix/feature works
- [ ] Documentation has been updated
- [ ] The code is properly commented
```

## Documentation

Good documentation is crucial for the project. Please document:

1. **PHPDoc**: All classes, methods, and functions
2. **README**: Update for major changes or new features
3. **Wiki**: Detailed usage instructions and examples
4. **Inline Comments**: Complex code sections

For user-facing changes, provide screenshots or GIFs demonstrating the changes.

## Release Process

Our release process follows semantic versioning:

1. **MAJOR**: Incompatible API changes
2. **MINOR**: Add functionality in a backward-compatible manner
3. **PATCH**: Backward-compatible bug fixes

### Release Procedure (For Maintainers)

1. Update version numbers in:
   - `readme.txt`
   - `wp-social-auth.php`
   - `CHANGELOG.md`

2. Create a release branch:
   ```bash
   git checkout -b release/X.Y.Z
   ```

3. Create a pull request to `main`

4. After merging, tag the release:
   ```bash
   git tag -a vX.Y.Z -m "Version X.Y.Z"
   git push origin vX.Y.Z
   ```

5. Create a GitHub release with release notes

## Questions or Need Help?

Feel free to:
- Open an [Issue](https://github.com/wordpress-gmail-cli/wp-

