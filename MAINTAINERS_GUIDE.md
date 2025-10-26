<!-- SPDX-License-Identifier: MPL-2.0 -->

# Maintainer's Guide

This guide is for maintainers of the AI Trust project.

## Reviewing Pull Requests

When reviewing pull requests:

1. **Check the code**:
   - Does it work as intended?
   - Is the code clean and well-documented?
   - Are there any security concerns?

2. **Check the tests**:
   - Are there tests for new features?
   - Do all tests pass?
   - Is the test coverage adequate?

3. **Check the documentation**:
   - Is the documentation up to date?
   - Are there any new features that need documentation?

4. **Check the changelog**:
   - Is the changelog updated?
   - Are the changes properly documented?

## Making a Release

1. Update the version in [pyproject.toml](pyproject.toml)
2. Update `CHANGELOG.md` with the new version
3. Create a new tag:
   ```bash
   git tag -a vX.Y.Z -m "Version X.Y.Z"
   ```
4. Push the tag:
   ```bash
   git push origin vX.Y.Z
   ```
5. Create a new release on GitHub

## Handling Security Issues

- Acknowledge receipt of the report within 3 business days
- Work on a fix as soon as possible
- Keep the reporter updated on progress
- Release a security update
- Credit the reporter (unless they prefer to remain anonymous)

## Managing Issues

- Triage new issues regularly
- Label issues appropriately
- Close issues that are not actionable
- Reference related issues and pull requests

## Managing the Community

- Be welcoming and inclusive
- Enforce the Code of Conduct
- Be responsive to questions and issues
- Thank contributors for their work

## Making Decisions

We follow a consensus-based decision making process for major decisions. For day-to-day decisions, maintainers can make decisions independently, but should document them in the relevant issue or pull request.

## Communication

- Be clear and professional in all communications
- Be respectful of others' time and contributions
- Be open to feedback and new ideas

## Getting Help

If you need help or have questions, don't hesitate to ask other maintainers or the community.
