# WordPress Gmail CLI

[![CI/CD Pipeline](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/ci-cd-pipeline.yml/badge.svg)](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/ci-cd-pipeline.yml)
[![Security Scan](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/security-scan.yml/badge.svg)](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/security-scan.yml)
[![CodeQL](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/codeql-analysis.yml)
[![Docker Build](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/docker-build.yml/badge.svg)](https://github.com/thomasvincent/wordpress-gmail-cli/actions/workflows/docker-build.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

A simple CLI tool to quickly configure WordPress and Postfix for sending outbound emails using Google API. Ideal for automating reliable email delivery setup on your WordPress server, especially on platforms like Digital Ocean that block standard SMTP ports.

## Features

- Configures Postfix to use Google API for outbound mail
- Sets up WordPress to use the Google API for sending emails
- Works around port restrictions on hosting providers like Digital Ocean
- Includes error handling and dependency checking
- Provides a test function to verify the configuration
- Automatically refreshes OAuth2 tokens for continuous operation
- Includes a helper script for obtaining Google API credentials

## Prerequisites

- A Linux server with WordPress installed
- Root access to the server
- Postfix, PHP, curl, and jq installed
- A Gmail account with Google API credentials

## Installation

1. Clone this repository or download the script:

```bash
git clone https://github.com/yourusername/wordpress-gmail-cli.git
cd wordpress-gmail-cli
```

2. Make the script executable:

```bash
chmod +x wordpress-gmail-cli.sh
```

## Getting Google API Credentials

### Method 1: Using the Helper Script

The script includes a helper utility to obtain the necessary Google API credentials:

1. Run the helper script:

```bash
./get-gmail-credentials.sh
```

2. Follow the prompts and instructions provided by the script.

### Method 2: Manual Setup (Detailed Instructions)

If you prefer to set up the Google API credentials manually, follow these steps:

#### Step 1: Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Click on the project dropdown at the top of the page
3. Click "New Project"
4. Enter a name for your project and click "Create"
5. Wait for the project to be created and then select it from the dropdown

#### Step 2: Enable the Gmail API

1. In your project, go to the [API Library](https://console.cloud.google.com/apis/library)
2. Search for "Gmail API"
3. Click on "Gmail API" in the results
4. Click "Enable"

#### Step 3: Configure the OAuth Consent Screen

1. Go to [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent)
2. Select "External" as the user type (unless you have a Google Workspace organization)
3. Click "Create"
4. Fill in the required fields:
   - App name: "WordPress Gmail CLI" (or your preferred name)
   - User support email: Your email address
   - Developer contact information: Your email address
5. Click "Save and Continue"
6. On the Scopes page, click "Add or Remove Scopes"
7. Add the scope: `https://mail.google.com/`
8. Click "Save and Continue"
9. Add any test users (including your own email) and click "Save and Continue"
10. Review your settings and click "Back to Dashboard"

#### Step 4: Create OAuth Credentials

1. Go to [Credentials](https://console.cloud.google.com/apis/credentials)
2. Click "Create Credentials" and select "OAuth client ID"
3. Select "Web application" as the application type
4. Name: "WordPress Gmail CLI" (or your preferred name)
5. Add an authorized redirect URI: `http://localhost:8080`
6. Click "Create"
7. Note your Client ID and Client Secret (you'll need these later)

#### Step 5: Get a Refresh Token

1. Construct an authorization URL with your client ID:
   ```
   https://accounts.google.com/o/oauth2/auth?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8080&response_type=code&scope=https://mail.google.com/&access_type=offline&prompt=consent
   ```
   Replace `YOUR_CLIENT_ID` with your actual client ID.

2. Open this URL in your browser and authorize the application

3. After authorization, you'll be redirected to `localhost:8080` with a code parameter in the URL

4. Copy the entire URL from your browser

5. Extract the authorization code from the URL (the value after `code=` and before any `&`)

6. Exchange the authorization code for tokens using curl:
   ```bash
   curl --request POST \
     --url "https://oauth2.googleapis.com/token" \
     --header "Content-Type: application/x-www-form-urlencoded" \
     --data "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&code=YOUR_CODE&redirect_uri=http://localhost:8080&grant_type=authorization_code"
   ```
   Replace `YOUR_CLIENT_ID`, `YOUR_CLIENT_SECRET`, and `YOUR_CODE` with your actual values.

7. From the response, extract the `refresh_token` value

Now you have all the required credentials:
- Client ID
- Client Secret
- Refresh Token
- Your Gmail address

## Usage

Run the script with the required parameters:

```bash
sudo ./wordpress-gmail-cli.sh --email your-email@gmail.com --client-id your-client-id --client-secret your-client-secret --refresh-token your-refresh-token --domain example.com
```

### Parameters

- `-e, --email EMAIL`: Your Gmail address
- `-c, --client-id ID`: Your Google API Client ID
- `-s, --client-secret SECRET`: Your Google API Client Secret
- `-r, --refresh-token TOKEN`: Your Google API Refresh Token
- `-d, --domain DOMAIN`: Your website domain name
- `-w, --wp-path PATH`: Path to WordPress installation (default: /var/www/html)
- `-h, --help`: Display help message

## How It Works

The script performs the following actions:

1. Checks if all dependencies are installed
2. Obtains an access token using the provided refresh token
3. Configures Postfix to use Gmail's SMTP server with OAuth2 authentication
4. Creates a WordPress mu-plugin to configure the WordPress mailer to use OAuth2
5. Sets up a cron job to automatically refresh the access token
6. Offers to send a test email to verify the configuration

## Advantages of Using Google API

- More secure than using app passwords
- No need to enable "Less secure apps" in your Google account
- Works with Google Workspace accounts that have 2FA enabled
- Tokens can be revoked without changing your password
- Provides detailed access control and audit logging

## Troubleshooting

If emails are not being sent:

1. Check if Postfix is running: `systemctl status postfix`
2. Verify your Google API credentials are correct
3. Check Postfix logs: `tail -f /var/log/mail.log`
4. Ensure port 587 is not blocked by your firewall
5. Check the token refresh script logs: `cat /etc/postfix/gmail-api/token.json`

## Security Considerations

- Google API credentials are stored in `/etc/postfix/gmail-api/credentials.json`
- Access tokens are automatically refreshed and stored in `/etc/postfix/gmail-api/token.json`
- Both files are protected with 600 permissions (readable only by root)
- Consider restricting access to these files further in production environments

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Docker Usage

This project includes Docker support for easy deployment and development:

### Using Docker Image

```bash
# Pull the image from GitHub Container Registry
docker pull ghcr.io/thomasvincent/wordpress-gmail-cli:latest

# Run the container with your credentials
docker run --rm \
  -e EMAIL="your-email@gmail.com" \
  -e CLIENT_ID="your-client-id" \
  -e CLIENT_SECRET="your-client-secret" \
  -e REFRESH_TOKEN="your-refresh-token" \
  -e DOMAIN="example.com" \
  ghcr.io/thomasvincent/wordpress-gmail-cli:latest
```

### Local Development with Docker Compose

For local development and testing, use Docker Compose:

```bash
# Start the development environment
docker-compose up -d

# Run the CLI tool within the environment
docker-compose exec cli ./wordpress-gmail-cli.sh --help

# Access WordPress at http://localhost:8080
# Access phpMyAdmin at http://localhost:8081
```

## CI/CD and Security Features

This project uses GitHub Actions for CI/CD and implements several security best practices:

### Continuous Integration

- Automated linting and testing for shell scripts and PHP files
- Security scanning with ShellCheck, Trivy, and CodeQL
- Docker image building and testing

### Continuous Deployment

- Automated releases with semantic versioning
- Docker image publishing to GitHub Container Registry
- SLSA provenance generation for supply chain security

### Security Features

- SLSA Level 3 compliance for supply chain security
- Automated dependency updates with Dependabot
- Comprehensive security scanning in CI pipeline
- Security policy and vulnerability reporting process

For more details on security practices, see the [SECURITY.md](SECURITY.md) file.

## Enterprise Enhancements

For enterprise environments, additional enhancements are available in the `enterprise-enhancements.md` file. These include:

### Security Enhancements
- HashiCorp Vault integration for secure credential management
- Enhanced file permissions and SELinux context configuration

### Monitoring and Logging
- Prometheus metrics endpoint for monitoring email delivery and token status
- Centralized logging with ELK Stack integration

### Configuration Management
- Ansible playbook for automated deployment across multiple servers
- Docker containerization for consistent environments

### Multi-Server Support
- Centralized credential management for server clusters
- Load balancing configuration for high availability

### Enterprise Integration
- LDAP authentication for admin interface
- RESTful API for email status and management

To implement these enterprise features, refer to the code samples and instructions in `enterprise-enhancements.md`.
