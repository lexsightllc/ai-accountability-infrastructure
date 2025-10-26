<!-- SPDX-License-Identifier: MPL-2.0 -->

# Release Process

This document outlines the process for releasing a new version of AI Trust.

## Prerequisites

- Push access to the repository
- Maintainer permissions on PyPI
- `build` and `twine` installed:
  ```bash
  pip install build twine
  ```

## Release Checklist

- Ensure all tests are passing
- Update CHANGELOG.md with the new version
- Update the version in pyproject.toml
- Update the version in VERSION (if it exists)
- Ensure all new features are documented
- Ensure all new dependencies are documented

## Creating a Release

1. Create a release branch:
   ```bash
   git checkout -b release/vX.Y.Z
   ```
2. Update the version in pyproject.toml:
   ```toml
   [project]
   version = "X.Y.Z"
   ```
3. Update CHANGELOG.md with the new version:
   ```markdown
   ## [X.Y.Z] - YYYY-MM-DD

   ### Added
   - New features

   ### Changed
   - Changes to existing features

   ### Fixed
   - Bug fixes
   ```
4. Commit the changes:
   ```bash
   git add pyproject.toml CHANGELOG.md VERSION
   git commit -m "Bump version to vX.Y.Z"
   ```
5. Create a signed tag:
   ```bash
   git tag -s vX.Y.Z -m "Version X.Y.Z"
   ```
6. Push the tag:
   ```bash
   git push origin vX.Y.Z
   ```
7. Build the package:
   ```bash
   python -m build
   ```
8. Upload to TestPyPI (optional):
   ```bash
   python -m twine upload --repository testpypi dist/*
   ```
9. Upload to PyPI:
   ```bash
   python -m twine upload dist/*
   ```
10. Create a GitHub release:
    - Go to the releases page
    - Click "Draft a new release"
    - Select the tag you just pushed
    - Use the version as the title (e.g., "vX.Y.Z")
    - Copy the changelog entry into the description
    - Attach the files from the dist/ directory
    - Publish the release

## Post-Release

1. Merge the release branch into main:
   ```bash
   git checkout main
   git merge --no-ff release/vX.Y.Z
   git push origin main
   ```
2. Update the development version in pyproject.toml:
   ```toml
   [project]
   version = "X.Y.Z+dev"
   ```
3. Commit the version bump:
   ```bash
   git add pyproject.toml
   git commit -m "Bump version to X.Y.Z+dev"
   git push origin main
   ```
4. Delete the release branch:
   ```bash
   git branch -d release/vX.Y.Z
   git push origin --delete release/vX.Y.Z
   ```

## Release Types

### Major Release (X.0.0)
- Breaking changes
- New major features
- Significant architectural changes

### Minor Release (X.Y.0)
- New features
- Backward-compatible API changes
- Deprecations

### Patch Release (X.Y.Z)
- Bug fixes
- Security fixes
- Documentation updates
