# CLAUDE.md

WordPress email configuration via Gmail API with OAuth2.

## Stack
- PHP 8.x
- Bash scripts

## Lint & Test
```bash
# Shell scripts
shellcheck bin/*.sh

# PHP tests
composer test
composer test:unit
composer test:integration
composer test:functional

# Code quality
composer phpstan
composer phpcs
```

## Local Run
```bash
./bin/wordpress-gmail-cli.sh --help
```
