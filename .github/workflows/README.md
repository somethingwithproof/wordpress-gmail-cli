# GitHub Actions Workflows

This directory contains the GitHub Actions workflows for the WordPress Gmail CLI project.

## Workflows

### CI Workflow (`ci.yml`)

The CI workflow is triggered on push to the main branch, pull requests, and manual dispatch. It performs the following tasks:

1. **Linting**: Checks code quality for PHP and shell scripts.
2. **Security Scanning**: Runs Trivy and CodeQL to identify vulnerabilities.
3. **Building and Testing**: Builds the Docker image and tests the shell scripts.

### Release Workflow (`release.yml`)

The Release workflow is triggered by:
- Pushing to the main branch with a commit message containing "chore: release vX.Y.Z"
- Pushing a tag in the format "vX.Y.Z"
- Manual dispatch with a version parameter

It performs the following tasks:

1. **Determining Version**: Extracts the version from the trigger source.
2. **Building and Pushing Docker Image**: Builds the Docker image and pushes it to GitHub Container Registry.
3. **Creating GitHub Release**: Creates a GitHub release with the specified version.
4. **Generating Artifacts**: Creates distributable artifacts and uploads them as GitHub Actions artifacts.

## Workflow Consolidation

These workflows have been consolidated from the following original workflows:

- `ci-cd.yml` and `ci-cd-pipeline.yml`: Consolidated into `ci.yml`
- `lint-test.yml`: Consolidated into `ci.yml`
- `codeql-analysis.yml` and `codeql.yml`: Consolidated into `ci.yml`
- `security-scan.yml`: Consolidated into `ci.yml`
- `release-workflow.yml` and `release.yml`: Consolidated into `release.yml`
- `docker-build.yml`: Consolidated into `release.yml`
- `slsa-provenance.yml`: Simplified and consolidated into `release.yml`

## Best Practices

These workflows follow these best practices:

1. **Principle of Least Privilege**: Each job requests only the permissions it needs.
2. **Pinned Action Versions**: Actions are pinned to specific versions to ensure stability.
3. **Caching**: Docker layers are cached to speed up builds.
4. **Comprehensive Testing**: All aspects of the codebase are tested.
5. **Security Scanning**: Multiple security scanning tools are used to identify vulnerabilities.
